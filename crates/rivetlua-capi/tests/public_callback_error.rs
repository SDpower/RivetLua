use std::cell::Cell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_gettop, lua_pushcclosure, lua_pushinteger, lua_settop,
    lua_tointegerx, lua_type,
};
use rivetlua_runtime::RootKind;

#[repr(C)]
struct PublicCallSetup {
    kind: i32,
    base: usize,
    handler: *mut c_void,
}

type Continuation = unsafe extern "C" fn(*mut lua_State, i32, isize) -> i32;

unsafe extern "C" {
    fn lua_atpanic(
        state: *mut lua_State,
        callback: Option<unsafe extern "C" fn(*mut lua_State) -> i32>,
    ) -> Option<unsafe extern "C" fn(*mut lua_State) -> i32>;
    fn lua_callk(
        state: *mut lua_State,
        nargs: i32,
        nresults: i32,
        context: isize,
        continuation: Option<Continuation>,
    );
    fn lua_pcallk(
        state: *mut lua_State,
        nargs: i32,
        nresults: i32,
        errfunc: i32,
        context: isize,
        continuation: Option<Continuation>,
    ) -> i32;
    fn rivetlua_capi_public_preflight_a2(
        state: *mut lua_State,
        nargs: i32,
        nresults: i32,
        errfunc: i32,
    ) -> PublicCallSetup;
    fn rivetlua_capi_public_drop_handler_a2(handler: *mut c_void);
    fn rivetlua_capi_checkpoint_enter_a1(
        state: *mut lua_State,
        generation: *mut u64,
        token: *mut u64,
        previous: *mut u64,
    ) -> i32;
    fn rivetlua_capi_checkpoint_exit_a1(
        state: *mut lua_State,
        generation: u64,
        token: u64,
        previous: u64,
    ) -> i32;
    fn rivetlua_capi_call_depth_b7(state: *mut lua_State) -> i32;
    fn rivetlua_capi_test_nested_lua_error_a2(state: *mut lua_State) -> i32;
    fn rivetlua_capi_test_push_lua_b4(state: *mut lua_State, selector: i32) -> i32;
}

static CONTINUATIONS: AtomicUsize = AtomicUsize::new(0);
static RESULT_FAILURE_OFFSET: AtomicUsize = AtomicUsize::new(0);
static INNER_STATUS: AtomicUsize = AtomicUsize::new(99);
thread_local! {
    static INJECT_OWNER: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
}

unsafe extern "C" fn plus_one(state: *mut lua_State) -> i32 {
    // SAFETY：C driver 在 callback 返回前保活 state，沒有 Rust VM 借用跨越 callback。
    unsafe {
        let value = lua_tointegerx(state, 1, std::ptr::null_mut());
        lua_pushinteger(state, value + 1);
    }
    1
}

unsafe extern "C" fn return_with_alloc_error(state: *mut lua_State) -> i32 {
    // SAFETY：callback stack 上的結果在 returning C frame 中完成發布。
    unsafe { lua_pushinteger(state, 7) };
    INJECT_OWNER.with(|pointer| {
        // SAFETY：owner 在測試 scope 內存活，B4 不持 VM 借用跨 callback。
        let owner = unsafe { &*pointer.get() };
        owner
            .with_vm(|vm| {
                let ordinal = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(
                    ordinal + RESULT_FAILURE_OFFSET.load(Ordering::SeqCst) as u64,
                );
            })
            .unwrap();
    });
    1
}

unsafe extern "C" fn nested_resume_failure_then_continue(state: *mut lua_State) -> i32 {
    // SAFETY：同一 live state 上同步巢狀 protected call，外層 parked core 需續用。
    unsafe {
        lua_pushcclosure(state, Some(return_with_alloc_error), 0);
        let status = lua_pcallk(state, 0, 1, 0, 0, None);
        INNER_STATUS.store(status as usize, Ordering::SeqCst);
        if status != 4 {
            return 0;
        }
        lua_settop(state, 0);
        lua_pushinteger(state, 73);
    }
    1
}

unsafe extern "C" fn unexpected_continuation(
    _state: *mut lua_State,
    _status: i32,
    _context: isize,
) -> i32 {
    CONTINUATIONS.fetch_add(1, Ordering::SeqCst);
    0
}

unsafe extern "C" fn panic_a(_state: *mut lua_State) -> i32 {
    0
}

unsafe extern "C" fn panic_b(_state: *mut lua_State) -> i32 {
    0
}

#[test]
fn public_sync_call_pcall_and_group_panic_binding() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    let sibling_state = sibling.as_ptr();
    CONTINUATIONS.store(0, Ordering::SeqCst);

    // SAFETY：兩個 state 在整個同步呼叫期間有效；continuation 沒有 yield，不應被呼叫。
    unsafe {
        let old = lua_atpanic(state, Some(panic_a));
        assert!(
            lua_atpanic(sibling_state, Some(panic_b))
                .is_some_and(|callback| callback as usize == panic_a as *const () as usize)
        );
        assert!(
            lua_atpanic(state, old)
                .is_some_and(|callback| callback as usize == panic_b as *const () as usize)
        );

        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 41);
        lua_callk(state, 1, 1, 17, Some(unexpected_continuation));
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);

        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 4);
        assert_eq!(
            lua_pcallk(state, 1, 1, 0, 23, Some(unexpected_continuation)),
            0
        );
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 5);
    }
    assert_eq!(CONTINUATIONS.load(Ordering::SeqCst), 0);
}

fn prepare_handler_stack(owner: &StateOwner) {
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state，handler 與目標函式皆為同步 C callback。
    unsafe {
        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 41);
    }
}

fn preflight_snapshot(owner: &StateOwner) -> (rivetlua_runtime::LedgerSnapshot, usize, usize) {
    owner
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.roots().count(RootKind::Host),
                vm.gc_trace().debt_bytes,
            )
        })
        .unwrap()
}

#[test]
fn public_errfunc_preflight_allocation_failures_leave_stack_and_roots_retriable() {
    let dry = StateOwner::new().unwrap();
    prepare_handler_stack(&dry);
    let start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    // SAFETY：只取得預備 handler；未啟動 callback，隨即釋放其 root。
    let setup = unsafe { rivetlua_capi_public_preflight_a2(dry.as_ptr(), 1, 1, 1) };
    assert_eq!(setup.kind, 1);
    assert_eq!(setup.base, 1);
    assert!(!setup.handler.is_null());
    unsafe { rivetlua_capi_public_drop_handler_a2(setup.handler) };
    let end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(end > start);

    for offset in 0..end - start {
        let owner = StateOwner::new().unwrap();
        prepare_handler_stack(&owner);
        let before = preflight_snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
            .unwrap();
        // SAFETY：失敗預備不得消耗 stack；重試使用相同 live state。
        let failed = unsafe { rivetlua_capi_public_preflight_a2(owner.as_ptr(), 1, 1, 1) };
        assert!(failed.kind < 0, "offset={offset}");
        assert!(failed.handler.is_null());
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 3);
        assert_eq!(unsafe { lua_type(owner.as_ptr(), 1) }, 6);
        assert_eq!(unsafe { lua_type(owner.as_ptr(), 2) }, 6);
        assert_eq!(
            unsafe { lua_tointegerx(owner.as_ptr(), 3, std::ptr::null_mut()) },
            41
        );
        let after = preflight_snapshot(&owner);
        assert_eq!(after.0.committed, before.0.committed, "offset={offset}");
        assert_eq!(after.0.reserved, 0, "offset={offset}");
        assert_eq!(after.1, before.1, "offset={offset}");
        assert_eq!(after.2, before.2, "offset={offset}");
        let retry = unsafe { rivetlua_capi_public_preflight_a2(owner.as_ptr(), 1, 1, 1) };
        assert_eq!(retry.kind, 1, "offset={offset}");
        unsafe { rivetlua_capi_public_drop_handler_a2(retry.handler) };
        assert_eq!(preflight_snapshot(&owner).0.committed, before.0.committed);
    }
}

#[test]
fn public_pcall_preflight_allocation_failure_publishes_memory_error_and_retries() {
    fn prepare_at_capacity(owner: &StateOwner) {
        let state = owner.as_ptr();
        // SAFETY：同一 live state；函式與參數佔最後兩格。
        unsafe {
            for value in 0..17 {
                lua_pushinteger(state, value);
            }
            lua_pushcclosure(state, Some(plus_one), 0);
            lua_pushcclosure(state, Some(plus_one), 0);
            lua_pushinteger(state, 41);
            assert_eq!(lua_gettop(state), 20);
        }
    }

    let dry = StateOwner::new().unwrap();
    prepare_at_capacity(&dry);
    let start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    // SAFETY：只盤點 preflight 配置點，handler 隨即釋放。
    let setup = unsafe { rivetlua_capi_public_preflight_a2(dry.as_ptr(), 1, 1, 18) };
    assert_eq!(setup.kind, 1);
    unsafe { rivetlua_capi_public_drop_handler_a2(setup.handler) };
    let end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(end > start);

    for offset in 0..end - start {
        let owner = StateOwner::new().unwrap();
        prepare_at_capacity(&owner);
        let state = owner.as_ptr();
        let before = preflight_snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
            .unwrap();
        // SAFETY：公開 protected 入口應將配置失敗發布成單一錯誤物件。
        unsafe {
            assert_eq!(lua_pcallk(state, 1, 1, 18, 0, None), 4, "offset={offset}");
            assert_eq!(lua_gettop(state), 19, "offset={offset}");
            assert_eq!(lua_type(state, -1), 4, "offset={offset}");
            assert_eq!(rivetlua_capi_call_depth_b7(state), 0);
        }
        let after = preflight_snapshot(&owner);
        assert_eq!(after.0.committed, before.0.committed, "offset={offset}");
        assert_eq!(after.0.reserved, 0, "offset={offset}");
        assert_eq!(after.1, before.1, "offset={offset}");
        // SAFETY：保留 handler，丟棄錯誤後再次使用同一 state。
        unsafe {
            lua_settop(state, 18);
            lua_pushcclosure(state, Some(plus_one), 0);
            lua_pushinteger(state, 5);
            assert_eq!(lua_pcallk(state, 1, 1, 18, 0, None), 0);
            assert_eq!(lua_gettop(state), 19);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 6);
        }
        assert_eq!(preflight_snapshot(&owner).0.reserved, 0);
    }
}

#[test]
fn invalid_public_handler_is_atomic_even_with_pending_allocation_failure() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：填滿初始容量，無效 handler 必須在容量配置前遭拒。
    unsafe {
        for value in 0..18 {
            lua_pushinteger(state, value);
        }
        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 41);
        assert_eq!(lua_gettop(state), 20);
    }
    let before = preflight_snapshot(&owner);
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    // SAFETY：9000 不在 stack 範圍；接著同一注入配置仍須在有效呼叫生效。
    unsafe {
        assert_eq!(lua_pcallk(state, 1, 1, 9000, 0, None), 2);
        assert_eq!(lua_gettop(state), 20);
        assert_eq!(lua_type(state, 19), 6);
        assert_eq!(lua_tointegerx(state, 20, std::ptr::null_mut()), 41);
        assert_eq!(lua_pcallk(state, 1, 1, 0, 0, None), 4);
        assert_eq!(lua_gettop(state), 19);
        assert_eq!(lua_type(state, -1), 4);
    }
    let after = preflight_snapshot(&owner);
    assert_eq!(after.0.committed, before.0.committed);
    assert_eq!(after.0.reserved, 0);
    assert_eq!(after.1, before.1);
}

#[test]
fn public_pcall_callback_argument_allocation_failure_is_memory_error_and_reusable() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：同步 public 呼叫；失敗注入只針對下一次 allocation。
    unsafe {
        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 41);
    }
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    let status = unsafe { lua_pcallk(state, 1, 1, 0, 0, None) };
    assert_eq!(
        status,
        4,
        "trace={:?}",
        owner.with_vm(|vm| vm.allocation_trace()).unwrap()
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        0
    );
    unsafe {
        lua_pushcclosure(state, Some(plus_one), 0);
        lua_pushinteger(state, 5);
        assert_eq!(lua_pcallk(state, 1, 1, 0, 0, None), 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 6);
    }
}

#[test]
fn public_checkpoint_slot_reservation_failure_is_atomic_and_retriable() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：20 格填滿 MIN_STACK；checkpoint 需要額外保留一格 error slot。
    for value in 0..20 {
        unsafe { lua_pushinteger(state, value) };
    }
    assert_eq!(unsafe { lua_gettop(state) }, 20);
    let before = preflight_snapshot(&owner);
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    let (mut generation, mut token, mut previous) = (0, 0, 0);
    // SAFETY：owner 保活 state；三個輸出指標獨立且可寫，成功重試後成對退出。
    let failed = unsafe {
        rivetlua_capi_checkpoint_enter_a1(state, &mut generation, &mut token, &mut previous)
    };
    assert_ne!(failed, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 20);
    let after = preflight_snapshot(&owner);
    assert_eq!(after.0.committed, before.0.committed);
    assert_eq!(after.0.reserved, 0);
    assert_eq!(after.1, before.1);
    assert_eq!(after.2, before.2);
    assert_eq!(
        unsafe {
            rivetlua_capi_checkpoint_enter_a1(state, &mut generation, &mut token, &mut previous)
        },
        0
    );
    assert_eq!(
        unsafe { rivetlua_capi_checkpoint_exit_a1(state, generation, token, previous) },
        0
    );
}

#[test]
fn nested_callback_result_allocation_failure_preserves_outer_parked_core() {
    RESULT_FAILURE_OFFSET.store(1, Ordering::SeqCst);
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    INJECT_OWNER.with(|pointer| pointer.set(&owner));
    // SAFETY：內層 callback 結果暫存配置失敗後，外層仍可產生結果。
    let mut roots_after_first = None;
    for pass in 0..2 {
        unsafe {
            lua_pushcclosure(state, Some(nested_resume_failure_then_continue), 0);
            let status = lua_pcallk(state, 0, 1, 0, 0, None);
            assert_eq!(
                status,
                0,
                "pass={pass} inner={} trace={:?}",
                INNER_STATUS.load(Ordering::SeqCst),
                owner.with_vm(|vm| vm.allocation_trace()).unwrap()
            );
            assert_eq!(lua_gettop(state), 1);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 73);
            assert_eq!(rivetlua_capi_call_depth_b7(state), 0);
            lua_settop(state, 0);
        }
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
        let roots = preflight_snapshot(&owner).1;
        if pass == 0 {
            roots_after_first = Some(roots);
        } else {
            assert_eq!(Some(roots), roots_after_first);
        }
    }
    INJECT_OWNER.with(|pointer| pointer.set(std::ptr::null()));
}

#[test]
fn nested_bytecode_error_reparks_outer_c_callback_and_leaves_reusable_state() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：建立 Lua closure 時 VM 尚未執行；後續兩次呼叫共享此 rooted slot。
    assert_eq!(unsafe { rivetlua_capi_test_push_lua_b4(state, 3) }, 1);
    let mut after_first: Option<(rivetlua_runtime::LedgerSnapshot, usize, usize)> = None;
    for pass in 0..2 {
        // SAFETY：真 C callback 內以 protected call 捕捉不再停入 C 的 Lua bytecode 錯誤。
        unsafe {
            lua_pushcclosure(state, Some(rivetlua_capi_test_nested_lua_error_a2), 0);
            rivetlua_capi::stack::lua_pushvalue(state, 1);
            assert_eq!(lua_pcallk(state, 1, 1, 0, 0, None), 0, "pass={pass}");
            assert_eq!(lua_gettop(state), 2);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 73);
            assert_eq!(rivetlua_capi_call_depth_b7(state), 0);
            lua_settop(state, 1);
        }
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        let snapshot = preflight_snapshot(&owner);
        assert_eq!(snapshot.0.reserved, 0);
        if let Some(previous) = after_first {
            assert_eq!(snapshot.0.committed, previous.0.committed);
            assert_eq!(snapshot.1, previous.1);
        } else {
            after_first = Some(snapshot);
        }
    }
}
