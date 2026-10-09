use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_gettop, lua_isyieldable, lua_pushcclosure, lua_pushinteger,
    lua_settop, lua_status, lua_tointegerx, lua_tolstring, lua_type,
};
use rivetlua_runtime::{GcMode, GcPhase};

unsafe extern "C" {
    fn lua_newthread(state: *mut lua_State) -> *mut lua_State;
    fn lua_resume(
        state: *mut lua_State,
        from: *mut lua_State,
        nargs: i32,
        nresults: *mut i32,
    ) -> i32;
    fn rivetlua_capi_test_prepare_gc_probe_a5(state: *mut lua_State) -> i32;
    fn rivetlua_capi_test_prepare_allocation_probe_a5(state: *mut lua_State) -> i32;
    fn lua_closethread(state: *mut lua_State, from: *mut lua_State) -> i32;
}

unsafe extern "C" fn plus_one(state: *mut lua_State) -> i32 {
    // SAFETY：公開 resume coordinator 在 callback 返回前保活此 C state。
    unsafe {
        let value = lua_tointegerx(state, 1, std::ptr::null_mut());
        lua_pushinteger(state, value + 1);
    }
    1
}

#[test]
fn public_resume_non_yielding_coroutine_a5() {
    let owner = StateOwner::new().unwrap();
    let main = owner.as_ptr();
    // SAFETY：child 由 main stack 的 thread 值保活；回傳數指標有效。
    unsafe {
        assert_eq!(lua_status(main), 0);
        assert_eq!(lua_isyieldable(main), 0);
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(lua_status(child), 0);
        assert_eq!(lua_isyieldable(child), 1);
        lua_pushcclosure(child, Some(plus_one), 0);
        lua_pushinteger(child, 41);
        let mut results = -7;
        assert_eq!(lua_resume(child, main, 1, &mut results), 0);
        assert_eq!(results, 1);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_tointegerx(child, -1, std::ptr::null_mut()), 42);
        assert_eq!(lua_status(child), 0);
        assert_eq!(lua_isyieldable(child), 1);
    }
}

#[test]
fn public_resume_foreign_from_rejects_and_same_child_retries_a5() {
    let owner = StateOwner::new().unwrap();
    let foreign = StateOwner::new().unwrap();
    let main = owner.as_ptr();
    // SAFETY：兩個 VM 的 state 在測試期間有效；foreign 只作身分比較，不供 VM 解參照。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        lua_pushcclosure(child, Some(plus_one), 0);
        lua_pushinteger(child, 41);
        let mut results = -7;
        assert_eq!(lua_resume(child, foreign.as_ptr(), 1, &mut results), 2);
        assert_eq!(results, -7);
        assert_eq!(lua_status(child), 0);
        assert_eq!(lua_gettop(child), 2);
        assert_eq!(lua_type(child, 1), 6);
        assert_eq!(lua_type(child, 2), 4);
        lua_settop(child, 1);
        lua_pushinteger(child, 41);
        assert_eq!(lua_resume(child, main, 1, &mut results), 0);
        assert_eq!(results, 1);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_tointegerx(child, -1, std::ptr::null_mut()), 42);
    }
}

#[test]
fn suspended_c_upvalue_survives_gc_and_releases_child_charge_a5() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let main = owner.as_ptr();
        owner.with_vm(|vm| vm.set_gc_mode(mode).unwrap()).unwrap();
        let mut prior_host_bytes = None;
        for _ in 0..2 {
            // SAFETY：child 由 main stack 保活；所有 callback 都定義於純 C。
            unsafe {
                let child = lua_newthread(main);
                assert!(!child.is_null());
                assert_eq!(rivetlua_capi_test_prepare_gc_probe_a5(child), 1);
                let mut results = -7;
                assert_eq!(lua_resume(child, main, 0, &mut results), 1);
                assert_eq!(results, 1);
                assert_eq!(lua_status(child), 1);
                assert_eq!(lua_tointegerx(child, -1, std::ptr::null_mut()), 7);
                lua_settop(child, 0);
                owner
                    .with_vm(|vm| {
                        while vm.gc_trace().phase != GcPhase::Pause {
                            vm.incremental_step(1024).unwrap();
                        }
                        vm.collect().unwrap();
                    })
                    .unwrap();
                assert_eq!(lua_resume(child, main, 0, &mut results), 0);
                assert_eq!(results, 1);
                assert_eq!(lua_status(child), 0);
                assert_eq!(lua_type(child, -1), 4);
                let mut len = 0;
                let bytes = lua_tolstring(child, -1, &mut len);
                assert!(!bytes.is_null());
                assert_eq!(
                    std::slice::from_raw_parts(bytes.cast::<u8>(), len),
                    b"A5 suspended upvalue"
                );
                lua_settop(child, 0);
                lua_settop(main, 0);
            }
            let snapshot = owner
                .with_vm(|vm| {
                    while vm.gc_trace().phase != GcPhase::Pause {
                        vm.incremental_step(1024).unwrap();
                    }
                    vm.collect().unwrap();
                    vm.ledger_snapshot()
                })
                .unwrap();
            assert_eq!(snapshot.reserved, 0);
            if let Some(bytes) = prior_host_bytes {
                assert_eq!(snapshot.host_allocation_bytes, bytes);
            }
            prior_host_bytes = Some(snapshot.host_allocation_bytes);
        }
    }
}

#[test]
fn suspended_transfer_allocation_failure_cleans_up_and_next_child_retries_a5() {
    let owner = StateOwner::new().unwrap();
    let main = owner.as_ptr();
    // SAFETY：配置失敗在純 C callback 內注入；resume C checkpoint 接住錯誤跳轉。
    unsafe {
        let failed = lua_newthread(main);
        assert!(!failed.is_null());
        assert_eq!(rivetlua_capi_test_prepare_allocation_probe_a5(failed), 1);
        let mut results = -7;
        assert_eq!(lua_resume(failed, main, 0, &mut results), 4);
        assert_eq!(lua_status(failed), 4);
        assert_eq!(lua_gettop(failed), 2);
        assert_eq!(lua_type(failed, -1), 4);
        lua_settop(main, 0);
    }
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
    // SAFETY：前一 child 已死且不再解參照；新 child 使用同一 VM 驗證全域 marker 清理。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(rivetlua_capi_test_prepare_gc_probe_a5(child), 1);
        let mut results = -7;
        assert_eq!(lua_resume(child, main, 0, &mut results), 1);
        lua_settop(child, 0);
        assert_eq!(lua_resume(child, main, 0, &mut results), 0);
        assert_eq!(results, 1);
        assert_eq!(lua_type(child, -1), 4);
        lua_settop(main, 0);
    }
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
}

#[test]
fn reset_suspended_c_callback_releases_context_and_reuses_child_a5() {
    let owner = StateOwner::new().unwrap();
    let main = owner.as_ptr();
    // SAFETY：yield callback／K 都在純 C；reset 在已返回的 C checkpoint 外執行。
    unsafe {
        let child = lua_newthread(main);
        assert!(!child.is_null());
        assert_eq!(rivetlua_capi_test_prepare_gc_probe_a5(child), 1);
        let mut results = -7;
        assert_eq!(lua_resume(child, main, 0, &mut results), 1);
        assert_eq!(lua_status(child), 1);
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
            .unwrap();
        assert_eq!(lua_closethread(child, main), 4);
        assert_eq!(lua_status(child), 1);
        assert_eq!(lua_gettop(child), 1);
        assert_eq!(lua_closethread(child, main), 0);
        assert_eq!(lua_status(child), 0);
        assert_eq!(lua_gettop(child), 0);
        lua_pushcclosure(child, Some(plus_one), 0);
        lua_pushinteger(child, 41);
        assert_eq!(lua_resume(child, main, 1, &mut results), 0);
        assert_eq!(results, 1);
        assert_eq!(lua_tointegerx(child, -1, std::ptr::null_mut()), 42);
        lua_settop(main, 0);
    }
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
}
