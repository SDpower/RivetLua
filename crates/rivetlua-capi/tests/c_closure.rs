use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_pushinteger, lua_pushvalue, lua_rawequal,
    lua_rawget, lua_rawset, lua_settop, lua_tointegerx, lua_type, lua_xmove,
};
use rivetlua_core::{HostFunctionId, Value};
use rivetlua_runtime::{FailPoint, GcMode, ObjectKind, VmError};

static CALLED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn first(_state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    CALLED.fetch_add(1, Ordering::SeqCst);
    0
}

unsafe extern "C" fn second(_state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    CALLED.fetch_add(1, Ordering::SeqCst);
    1
}

fn same_function(
    actual: Option<unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> c_int>,
    expected: unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> c_int,
) -> bool {
    actual.is_some_and(|actual| std::ptr::fn_addr_eq(actual, expected))
}

fn prime_protected_error(state: *mut rivetlua_capi::stack::lua_State) {
    // SAFETY：呼叫者持有有效 state；無效 n 只預熱公開錯誤槽，不改變 stack。
    assert!(unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, -1, None) } > 0);
}

fn prime_protected_allocation_error(owner: &StateOwner) {
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::ClosureCapturesReserve))
        .unwrap();
    // SAFETY：兩個捕捉值已在 stack；失敗發生在 closure 發布之前。
    assert!(unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, 2, Some(first)) } > 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
}

unsafe extern "C" {
    fn rivetlua_capi_test_protected_error_a4b(
        state: *mut rivetlua_capi::stack::lua_State,
        operation: c_int,
        index: c_int,
        argument: c_int,
        function: Option<unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> c_int>,
    ) -> c_int;
    fn lua_pushcclosure(
        state: *mut rivetlua_capi::stack::lua_State,
        function: Option<unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> c_int>,
        n: c_int,
    );
    fn lua_iscfunction(state: *mut rivetlua_capi::stack::lua_State, index: c_int) -> c_int;
    fn lua_tocfunction(
        state: *mut rivetlua_capi::stack::lua_State,
        index: c_int,
    ) -> Option<unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> c_int>;
    fn lua_getupvalue(
        state: *mut rivetlua_capi::stack::lua_State,
        index: c_int,
        n: c_int,
    ) -> *const c_char;
    fn lua_setupvalue(
        state: *mut rivetlua_capi::stack::lua_State,
        index: c_int,
        n: c_int,
    ) -> *const c_char;
    fn lua_upvalueid(
        state: *mut rivetlua_capi::stack::lua_State,
        index: c_int,
        n: c_int,
    ) -> *mut c_void;
    fn lua_upvaluejoin(
        state: *mut rivetlua_capi::stack::lua_State,
        first_index: c_int,
        first_n: c_int,
        second_index: c_int,
        second_n: c_int,
    );
}

#[test]
fn c_closure_a43_light_identity_and_round_trip() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let before_heap = owner
        .with_vm(|vm| vm.ledger_snapshot().lua_heap_bytes)
        .unwrap();
    CALLED.store(0, Ordering::SeqCst);
    // SAFETY：state 由 owner 保活；函式指標只傳入或取回，從不呼叫。
    unsafe {
        lua_pushcclosure(state, Some(first), 0);
        lua_pushcclosure(state, Some(first), 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, 1), 6);
        assert_eq!(lua_iscfunction(state, 1), 1);
        assert_eq!(lua_rawequal(state, 1, 2), 1);
        assert!(same_function(lua_tocfunction(state, 1), first));
        lua_pushcclosure(state, Some(second), 0);
        assert_eq!(lua_rawequal(state, 1, 3), 0);
        assert!(same_function(lua_tocfunction(state, 3), second));
        assert!(lua_upvalueid(state, 1, 1).is_null());
        assert!(lua_getupvalue(state, 1, 1).is_null());
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(CALLED.load(Ordering::SeqCst), 0);
    }
    assert_eq!(
        owner
            .with_vm(|vm| vm.ledger_snapshot().lua_heap_bytes)
            .unwrap(),
        before_heap
    );
}

#[test]
fn c_closure_a43_capture_get_setup_and_id() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 由 owner 保活；上值名稱只檢查是否為靜態空字串。
    unsafe {
        lua_pushinteger(state, 17);
        lua_pushinteger(state, 29);
        lua_pushcclosure(state, Some(first), 2);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, -1), 6);
        assert_eq!(lua_iscfunction(state, -1), 1);
        assert!(same_function(lua_tocfunction(state, -1), first));
        let first_id = lua_upvalueid(state, -1, 1);
        let second_id = lua_upvalueid(state, -1, 2);
        assert!(!first_id.is_null());
        assert_ne!(first_id, second_id);
        assert_eq!(first_id, lua_upvalueid(state, -1, 1));
        let name = lua_getupvalue(state, 1, 1);
        assert!(!name.is_null());
        assert_eq!(*name, 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 17);
        lua_settop(state, 1);
        let name = lua_getupvalue(state, 1, 2);
        assert!(!name.is_null());
        assert_eq!(*name, 0);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 29);
        lua_settop(state, 1);
        lua_pushinteger(state, 41);
        let name = lua_setupvalue(state, 1, 1);
        assert!(!name.is_null());
        assert_eq!(*name, 0);
        assert_eq!(lua_gettop(state), 1);
        assert!(!lua_getupvalue(state, 1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 41);
        lua_settop(state, 1);
        lua_pushinteger(state, 53);
        assert!(lua_setupvalue(state, 1, 3).is_null());
        assert_eq!(lua_gettop(state), 2);
        assert!(lua_getupvalue(state, 1, 3).is_null());
        assert_eq!(lua_gettop(state), 2);
        lua_pushvalue(state, 1);
        assert_eq!(lua_upvalueid(state, -1, 1), first_id);
        assert!(rivetlua_capi_test_protected_error_a4b(state, 2, 0, 0, None) > 0);
        assert_eq!(lua_upvalueid(state, 1, 1), first_id);
    }
}

#[test]
fn c_closure_a43_invalid_push_preserves_stack() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 由 owner 保活；無效輸入須在任何 pop 前拒絕。
    unsafe {
        lua_pushinteger(state, 7);
        for n in [-1, 2, 256] {
            assert!(rivetlua_capi_test_protected_error_a4b(state, 0, 0, n, Some(first)) > 0);
            assert_eq!(lua_gettop(state), 1);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 7);
        }
        assert!(rivetlua_capi_test_protected_error_a4b(state, 0, 0, 0, None) > 0);
        assert_eq!(lua_gettop(state), 1);
        assert!(rivetlua_capi_test_protected_error_a4b(state, 0, 0, 1, None) > 0);
        assert_eq!(lua_gettop(state), 1);
    }
}

#[test]
fn c_closure_a43_255_boundary_table_key_and_sibling() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    // SAFETY：兩個 state 同屬一個有效 group，且整段測試在 owner thread 執行。
    unsafe {
        for value in 1..=255 {
            lua_pushinteger(state, value);
        }
        lua_pushcclosure(state, Some(first), 255);
        assert_eq!(lua_gettop(state), 1);
        assert!(!lua_getupvalue(state, 1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 1);
        lua_settop(state, 1);
        assert!(!lua_getupvalue(state, 1, 255).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 255);
        lua_settop(state, 0);

        lua_createtable(state, 0, 1);
        lua_pushcclosure(state, Some(first), 0);
        lua_pushinteger(state, 91);
        lua_rawset(state, 1);
        lua_pushcclosure(state, Some(first), 0);
        assert_eq!(lua_rawget(state, 1), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 91);
        lua_settop(state, 1);
        lua_pushcclosure(state, Some(first), 0);
        lua_xmove(state, sibling.as_ptr(), 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_gettop(sibling.as_ptr()), 1);
        assert!(same_function(lua_tocfunction(sibling.as_ptr(), 1), first));
    }
}

#[test]
fn c_closure_a43_null_thread_busy_cross_vm_and_stale_fail_closed() {
    let owner = StateOwner::new().unwrap();
    let other = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：null 是合法拒絕案例；其餘 state 都由 owner 保活。
    unsafe {
        assert_eq!(
            rivetlua_capi_test_protected_error_a4b(std::ptr::null_mut(), 0, 0, 0, Some(first)),
            -1
        );
        assert_eq!(lua_iscfunction(std::ptr::null_mut(), 1), 0);
        assert!(lua_tocfunction(std::ptr::null_mut(), 1).is_none());
        lua_pushcclosure(state, Some(first), 0);
        lua_xmove(state, other.as_ptr(), 1);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_gettop(other.as_ptr()), 0);
    }
    let address = state as usize;
    std::thread::spawn(move || {
        // SAFETY：owner 活到 join 結束；foreign thread 必須在借用前拒絕。
        unsafe {
            let state = address as *mut rivetlua_capi::stack::lua_State;
            assert_eq!(
                rivetlua_capi_test_protected_error_a4b(state, 0, 0, 0, Some(first)),
                -1
            );
            assert_eq!(lua_iscfunction(state, 1), 0);
            assert!(lua_tocfunction(state, 1).is_none());
        }
    })
    .join()
    .unwrap();
    owner
        .with_vm(|_| {
            // SAFETY：同執行緒重入時 RefCell 借用衝突，入口必須拒絕。
            unsafe {
                assert_eq!(
                    rivetlua_capi_test_protected_error_a4b(state, 0, 0, 0, Some(first)),
                    -1
                );
                assert_eq!(lua_iscfunction(state, 1), 0);
            }
        })
        .unwrap();
    // SAFETY：owner 仍保活，busy 期間 push 未執行。
    unsafe { assert_eq!(lua_gettop(state), 1) };
    let stale = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    assert_eq!(
        owner.push_value(Value::Object(stale)),
        Err(rivetlua_capi::stack::StackError::Runtime(
            VmError::StaleObject
        ))
    );
    let unregistered = owner
        .with_vm(|vm| HostFunctionId::new_unique(vm.id()).unwrap())
        .unwrap();
    assert_eq!(
        owner.push_value(Value::CFunction(unregistered)),
        Err(rivetlua_capi::stack::StackError::WrongVm)
    );
}

#[test]
fn c_closure_a43_collectable_capture_survives_then_reclaims() {
    for (mode, stress) in [
        (GcMode::Incremental, false),
        (GcMode::Incremental, true),
        (GcMode::Generational, false),
        (GcMode::Generational, true),
    ] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let captured = owner
            .with_vm(|vm| {
                vm.set_gc_mode(mode).unwrap();
                vm.set_collect_every_allocation(stress);
                vm.allocate_table().unwrap()
            })
            .unwrap();
        owner.push_value(Value::Object(captured)).unwrap();
        // SAFETY：state 由 owner 保活，capture 來源由 stack root 保活。
        unsafe {
            lua_pushcclosure(state, Some(first), 1);
            assert_eq!(lua_gettop(state), 1);
        }
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
            })
            .unwrap();
        // SAFETY：移除 closure 的唯一 stack root 後再收集。
        unsafe { lua_settop(state, 0) };
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));
            })
            .unwrap();
    }
}

fn prepared_capture_owner() -> StateOwner {
    let owner = StateOwner::new().unwrap();
    owner.push_value(Value::Integer(11)).unwrap();
    owner.push_value(Value::Integer(22)).unwrap();
    owner
}

#[test]
fn c_closure_a43_each_allocation_failure_rolls_back_and_retries() {
    let probe = prepared_capture_owner();
    prime_protected_error(probe.as_ptr());
    let first_attempt = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    // SAFETY：probe owner 保活，兩個捕捉值已由 stack 保存。
    unsafe { lua_pushcclosure(probe.as_ptr(), Some(first), 2) };
    let end_attempt = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    let attempts = end_attempt - first_attempt;
    assert!(
        attempts >= 6,
        "必須實際走過 cells、closure、roots 與 registry 配置"
    );
    for ordinal_offset in 0..attempts {
        let owner = prepared_capture_owner();
        let state = owner.as_ptr();
        prime_protected_error(state);
        let before = owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                let ledger = vm.ledger_snapshot();
                let gc = vm.gc_trace();
                let roots = vm.roots().total_count();
                vm.inject_allocation_failure_at(next + ordinal_offset);
                (next, ledger, gc, roots)
            })
            .unwrap();
        // SAFETY：有效 state；注入失敗須在單一 closure slot 發布前回滾。
        assert!(unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, 2, Some(first)) } > 0);
        assert_eq!(
            unsafe { lua_gettop(state) },
            2,
            "ordinal_offset={ordinal_offset}"
        );
        assert_eq!(
            unsafe { lua_tointegerx(state, 1, std::ptr::null_mut()) },
            11
        );
        owner
            .with_vm(|vm| {
                assert_eq!(
                    vm.ledger_snapshot(),
                    before.1,
                    "ordinal_offset={ordinal_offset}"
                );
                assert_eq!(vm.gc_trace(), before.2, "ordinal_offset={ordinal_offset}");
                assert_eq!(vm.roots().total_count(), before.3);
                let failure = vm.allocation_trace().last_failure.unwrap();
                assert_eq!(failure.attempt.ordinal, before.0 + ordinal_offset);
            })
            .unwrap();
        // SAFETY：同一有效 state；單次注入已消耗，立即重試須成功。
        unsafe {
            lua_pushcclosure(state, Some(first), 2);
            assert_eq!(lua_gettop(state), 1);
            assert!(!lua_getupvalue(state, 1, 1).is_null());
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 11);
        }
    }
}

#[test]
fn c_closure_a43_active_gc_failed_publish_keeps_trace() {
    for (mode, stress) in [
        (GcMode::Incremental, false),
        (GcMode::Incremental, true),
        (GcMode::Generational, false),
        (GcMode::Generational, true),
    ] {
        let probe = prepared_capture_owner();
        prime_protected_error(probe.as_ptr());
        probe
            .with_vm(|vm| {
                vm.set_gc_mode(mode).unwrap();
                vm.set_collect_every_allocation(stress);
                vm.incremental_step(1).unwrap();
            })
            .unwrap();
        prime_protected_error(probe.as_ptr());
        prime_protected_allocation_error(&probe);
        let start = probe
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        // SAFETY：probe owner 保活；只量測成功路徑實際配置數。
        unsafe { lua_pushcclosure(probe.as_ptr(), Some(first), 2) };
        let end = probe
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        for offset in 0..end - start {
            let owner = prepared_capture_owner();
            let state = owner.as_ptr();
            prime_protected_error(state);
            owner
                .with_vm(|vm| {
                    vm.set_gc_mode(mode).unwrap();
                    vm.set_collect_every_allocation(stress);
                    vm.incremental_step(1).unwrap();
                })
                .unwrap();
            prime_protected_error(state);
            prime_protected_allocation_error(&owner);
            let before = owner
                .with_vm(|vm| {
                    let next = vm.allocation_trace().next_ordinal;
                    let ledger = vm.ledger_snapshot();
                    let gc = vm.gc_trace();
                    vm.inject_allocation_failure_at(next + offset);
                    (ledger, gc)
                })
                .unwrap();
            // SAFETY：有效 state；各配置點失敗須在發布前回滾。
            assert!(
                unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, 2, Some(first)) } > 0
            );
            assert_eq!(
                unsafe { lua_gettop(state) },
                2,
                "mode={mode:?};stress={stress};offset={offset}"
            );
            owner
                .with_vm(|vm| {
                    assert_eq!(
                        vm.ledger_snapshot(),
                        before.0,
                        "mode={mode:?};stress={stress};offset={offset}"
                    );
                    assert_eq!(
                        vm.gc_trace(),
                        before.1,
                        "mode={mode:?};stress={stress};offset={offset}"
                    );
                })
                .unwrap();
        }
    }
}

#[test]
fn c_closure_a43_setup_collectable_generation_barrier_and_retry() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| vm.set_gc_mode(GcMode::Generational).unwrap())
        .unwrap();
    // SAFETY：state 由 owner 保活，先建立只捕捉整數的 closure。
    unsafe {
        lua_pushinteger(state, 5);
        lua_pushcclosure(state, Some(first), 1);
    }
    owner
        .with_vm(|vm| {
            for _ in 0..4 {
                vm.collect().unwrap();
            }
        })
        .unwrap();
    let replacement = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(replacement)).unwrap();
    assert!(unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, -1, None) } > 0);
    let baseline = owner
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.gc_trace(),
                vm.roots().total_count(),
            )
        })
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    // SAFETY：失敗時 setupvalue 不得 pop 或修改 cell；成功時才提交。
    let failed = unsafe { rivetlua_capi_test_protected_error_a4b(state, 1, 1, 1, None) };
    assert!(
        failed > 0,
        "須命中舊 cell 到新值的世代寫入屏障失敗點: {failed}"
    );
    {
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        owner
            .with_vm(|vm| {
                assert_eq!(vm.ledger_snapshot(), baseline.0);
                assert_eq!(vm.gc_trace(), baseline.1);
                assert_eq!(vm.roots().total_count(), baseline.2);
            })
            .unwrap();
        unsafe {
            assert!(!lua_getupvalue(state, 1, 1).is_null());
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 5);
            lua_settop(state, 2);
        }
    }
    // SAFETY：單次注入已消耗，此輪為立即重試。
    unsafe {
        assert!(!lua_setupvalue(state, 1, 1).is_null());
        assert_eq!(lua_gettop(state), 1);
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(replacement), Ok(ObjectKind::Table));
        })
        .unwrap();
    // SAFETY：移除 closure root 後，replacement 不得永久留存。
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(replacement), Err(VmError::StaleObject));
        })
        .unwrap();
}

#[test]
fn c_closure_a43_named_failpoints_preserve_state_and_retry() {
    for (point, active_gc) in [
        (FailPoint::SlotReserve, false),
        (FailPoint::ObjectReserve, false),
        (FailPoint::ObjectInitialize, false),
        (FailPoint::RootReserve, false),
        (FailPoint::HostLease, false),
        (FailPoint::ClosureCapturesReserve, false),
        (FailPoint::MarkReserve, true),
        (FailPoint::WorkReserve, true),
    ] {
        let owner = prepared_capture_owner();
        let state = owner.as_ptr();
        prime_protected_error(state);
        owner
            .with_vm(|vm| {
                if active_gc {
                    vm.incremental_step(1).unwrap();
                }
            })
            .unwrap();
        if active_gc {
            prime_protected_error(state);
            prime_protected_allocation_error(&owner);
        }
        let before = owner
            .with_vm(|vm| {
                let snapshot = (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                );
                vm.inject_failure_once(point);
                snapshot
            })
            .unwrap();
        // SAFETY：有效 state；命名失敗點只能中斷未發布 closure。
        assert!(unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, 2, Some(first)) } > 0);
        assert_eq!(unsafe { lua_gettop(state) }, 2, "point={point:?}");
        owner
            .with_vm(|vm| {
                assert_eq!(vm.ledger_snapshot(), before.0, "point={point:?}");
                assert_eq!(vm.gc_trace(), before.1, "point={point:?}");
                assert_eq!(vm.roots().total_count(), before.2, "point={point:?}");
            })
            .unwrap();
        // SAFETY：同一有效 state；failpoint 為單次，立即重試須成功。
        unsafe {
            lua_pushcclosure(state, Some(first), 2);
            assert_eq!(lua_gettop(state), 1, "point={point:?}");
        }
    }
}

#[test]
fn c_closure_a43_light_registry_and_stack_preflight_each_ordinal() {
    let probe = StateOwner::new().unwrap();
    prime_protected_error(probe.as_ptr());
    let start = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    // SAFETY：有效 probe state，量測新 pointer 的 registry 與 stack 預備配置。
    assert_eq!(
        unsafe { rivetlua_capi_test_protected_error_a4b(probe.as_ptr(), 0, 0, 0, Some(first)) },
        0
    );
    let end = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(end - start >= 2);
    for offset in 0..end - start {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        prime_protected_error(state);
        let before = owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                let snapshot = (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                );
                vm.inject_allocation_failure_at(next + offset);
                snapshot
            })
            .unwrap();
        // SAFETY：有效 state；任一預備費用失敗不發布 registry entry 或 stack slot。
        assert_ne!(
            unsafe { rivetlua_capi_test_protected_error_a4b(state, 0, 0, 0, Some(first)) },
            0,
            "offset={offset}"
        );
        assert_eq!(unsafe { lua_gettop(state) }, 0, "offset={offset}");
        owner
            .with_vm(|vm| {
                assert_eq!(vm.ledger_snapshot(), before.0, "offset={offset}");
                assert_eq!(vm.gc_trace(), before.1, "offset={offset}");
                assert_eq!(vm.roots().total_count(), before.2);
            })
            .unwrap();
        // SAFETY：注入已消耗，立即重試須建立可回查的 light C function。
        unsafe {
            lua_pushcclosure(state, Some(first), 0);
            assert_eq!(lua_gettop(state), 1);
            assert!(same_function(lua_tocfunction(state, -1), first));
        }
    }
}
