use std::ffi::{CStr, c_char, c_int};

use rivetlua_capi::stack::{
    StateOwner, lua_close, lua_gettop, lua_pushinteger, lua_settop, lua_toboolean, lua_tointegerx,
    lua_tolstring, lua_type, luaL_execresult, luaL_newstate,
};
use rivetlua_runtime::{AllocationDomain, FailPoint, GcMode, GcPhase, RootKind};

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn __error() -> *mut c_int;
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn __errno_location() -> *mut c_int;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
unsafe extern "C" {
    fn strerror(errnum: c_int) -> *mut c_char;
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn set_errno(value: c_int) {
    // SAFETY：平台 libc 提供本執行緒有效的 errno 儲存位址；只設定本測試執行緒。
    unsafe {
        #[cfg(target_os = "macos")]
        let location = __error();
        #[cfg(target_os = "linux")]
        let location = __errno_location();
        *location = value;
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn strerror_bytes(value: c_int) -> Vec<u8> {
    // SAFETY：libc 對有效錯誤碼提供 NUL 結尾訊息；本測試立即複製其 bytes。
    unsafe { CStr::from_ptr(strerror(value)).to_bytes().to_vec() }
}

fn stack_bytes(state: *mut rivetlua_capi::stack::lua_State, index: c_int) -> Vec<u8> {
    let mut len = usize::MAX;
    // SAFETY：呼叫端持有有效 state 與存活的字串 slot；依 API 回報長度立即複製。
    let pointer = unsafe { lua_tolstring(state, index, &mut len) };
    assert!(!pointer.is_null());
    // SAFETY：該字串 slot 在複製期間仍存活，pointer 指向至少 len bytes。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len).to_vec() }
}

#[test]
fn exec_result_a41_matrix() {
    const EXIT_SEVEN: c_int = 7 << 8;
    const SIGNAL_FIFTEEN: c_int = 15;
    const CORED_SIGNAL: c_int = 0x80 | SIGNAL_FIFTEEN;
    const STOPPED: c_int = (19 << 8) | 0x7f;

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：Rust owner 在整段測試期間保持 state 存活。
    unsafe { lua_pushinteger(state, 73) };
    for (stat, result_type, what, code) in [
        (0, 1, b"exit".as_slice(), 0),
        (EXIT_SEVEN, 0, b"exit".as_slice(), 7),
        (SIGNAL_FIFTEEN, 0, b"signal".as_slice(), 15),
        (CORED_SIGNAL, 0, b"signal".as_slice(), 15),
        (STOPPED, 0, b"exit".as_slice(), STOPPED),
    ] {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        set_errno(0);
        // SAFETY：有效 state；wait status 只作整數解碼。
        assert_eq!(unsafe { luaL_execresult(state, stat) }, 3, "{stat}");
        // SAFETY：三槽應依官方順序位於原 sentinel 之後。
        unsafe {
            assert_eq!(lua_gettop(state), 4, "{stat}");
            assert_eq!(lua_type(state, -3), result_type, "{stat}");
            if result_type == 1 {
                assert_eq!(lua_toboolean(state, -3), 1);
            }
            assert_eq!(
                lua_tointegerx(state, -1, std::ptr::null_mut()),
                i64::from(code)
            );
        }
        assert_eq!(stack_bytes(state, -2), what, "{stat}");
        // SAFETY：只移除本輪三個結果，保留原 sentinel。
        unsafe {
            lua_settop(state, 1);
            assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        set_errno(2);
        // SAFETY：stat=0 即使 errno 非零仍走成功的 wait status。
        assert_eq!(unsafe { luaL_execresult(state, 0) }, 3);
        // SAFETY：檢查成功三槽並回到 sentinel。
        unsafe {
            assert_eq!(lua_type(state, -3), 1);
            assert_eq!(lua_toboolean(state, -3), 1);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 0);
        }
        assert_eq!(stack_bytes(state, -2), b"exit");
        // SAFETY：只移除成功三槽，保留原 sentinel。
        unsafe { lua_settop(state, 1) };

        let message = strerror_bytes(2);
        for _ in 0..2 {
            set_errno(2);
            // SAFETY：非零 stat 與 errno 必須沿 A40 file-result 失敗分支發布三槽。
            assert_eq!(unsafe { luaL_execresult(state, EXIT_SEVEN) }, 3);
            // SAFETY：三槽依序為 nil、錯誤訊息、保存的 errno。
            unsafe {
                assert_eq!(lua_gettop(state), 4);
                assert_eq!(lua_type(state, -3), 0);
                assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 2);
            }
            assert_eq!(stack_bytes(state, -2), message);
            // SAFETY：退回三槽並確認原 sentinel。
            unsafe {
                lua_settop(state, 1);
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
            }
        }

        let c_owned = luaL_newstate();
        assert!(!c_owned.is_null());
        set_errno(0);
        // SAFETY：C-owned state 存活；成功結果後只移除本次三槽。
        unsafe {
            assert_eq!(luaL_execresult(c_owned, 0), 3);
            assert_eq!(lua_toboolean(c_owned, -3), 1);
            assert_eq!(lua_tointegerx(c_owned, -1, std::ptr::null_mut()), 0);
        }
        assert_eq!(stack_bytes(c_owned, -2), b"exit");
        // SAFETY：只退本次結果，state 稍後 close 一次。
        unsafe { lua_settop(c_owned, 0) };
        set_errno(2);
        // SAFETY：C-owned state 仍存活；失敗路徑發布完整三槽。
        unsafe {
            assert_eq!(luaL_execresult(c_owned, EXIT_SEVEN), 3);
            assert_eq!(lua_type(c_owned, -3), 0);
            assert_eq!(lua_tointegerx(c_owned, -1, std::ptr::null_mut()), 2);
        }
        assert_eq!(stack_bytes(c_owned, -2), message);
        // SAFETY：只關閉本測試建立且仍存活的 C-owned state。
        unsafe { lua_close(c_owned) };
    }

    // SAFETY：null state 必須回零，無 stack 或 VM 可修改。
    assert_eq!(
        unsafe { luaL_execresult(std::ptr::null_mut(), EXIT_SEVEN) },
        0
    );
    let address = state as usize;
    let wrong_thread = std::thread::spawn(move || {
        // SAFETY：owner 在 join 前保持 state 存活；跨執行緒入口只可拒絕。
        unsafe { luaL_execresult(address as *mut rivetlua_capi::stack::lua_State, EXIT_SEVEN) }
    });
    assert_eq!(wrong_thread.join().unwrap(), 0);
    let busy = owner
        .with_vm(|vm| {
            let before = (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace());
            // SAFETY：state 有效但 VM 借用中，入口必須先拒絕。
            let result = unsafe { luaL_execresult(state, EXIT_SEVEN) };
            assert_eq!(
                (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace()),
                before
            );
            result
        })
        .unwrap();
    assert_eq!(busy, 0);
    // SAFETY：拒絕路徑未移動原 sentinel。
    unsafe {
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
    }

    owner
        .with_vm(|vm| {
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
        })
        .unwrap();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    owner
        .with_vm(|vm| {
            for _ in 0..32 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_eq!(vm.gc_trace().mode, GcMode::Incremental);
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        set_errno(0);
        // SAFETY：active GC 下發布三槽並持有字串 root。
        assert_eq!(unsafe { luaL_execresult(state, EXIT_SEVEN) }, 3);
        owner.with_vm(|vm| vm.incremental_step(1).unwrap()).unwrap();
        assert_eq!(stack_bytes(state, -2), b"exit");
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        // SAFETY：退回三個結果後解除字串 stack root。
        unsafe { lua_settop(state, 1) };
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            0
        );
        assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), baseline);

        for point in [
            FailPoint::StringBytesReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
        ] {
            owner
                .with_vm(|vm| {
                    for _ in 0..32 {
                        vm.incremental_step(1).unwrap();
                        if vm.gc_trace().phase != GcPhase::Pause {
                            break;
                        }
                    }
                    assert_eq!(vm.gc_trace().mode, GcMode::Incremental);
                    assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                })
                .unwrap();
            owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
            let snapshot = || {
                owner
                    .with_vm(|vm| {
                        let mut roots = Vec::new();
                        vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
                        (
                            vm.ledger_snapshot(),
                            vm.allocation_trace(),
                            vm.gc_trace(),
                            roots,
                        )
                    })
                    .unwrap()
            };
            let before = snapshot();
            set_errno(0);
            // SAFETY：指定 failpoint 應使三槽全數回滾。
            assert_eq!(
                unsafe { luaL_execresult(state, EXIT_SEVEN) },
                0,
                "{point:?}"
            );
            let after = snapshot();
            assert_eq!(after.0, before.0, "{point:?}: ledger");
            assert_eq!(after.2, before.2, "{point:?}: GC trace");
            assert_eq!(after.3, before.3, "{point:?}: roots");
            if matches!(point, FailPoint::ObjectInitialize | FailPoint::RootReserve) {
                // 兩個 checkpoint 前的配置可記錄，checkpoint 本身沒有 trace event。
                let attempt = after.1.last_attempt.expect("checkpoint 前須先建立物件");
                match point {
                    FailPoint::ObjectInitialize => {
                        assert_eq!(attempt.point, Some(FailPoint::ObjectReserve));
                    }
                    FailPoint::RootReserve => {
                        assert_eq!(attempt.point, None);
                        assert_eq!(attempt.domain, AllocationDomain::Host);
                        assert_eq!(attempt.site.file, "crates/rivetlua-runtime/src/roots.rs");
                    }
                    _ => unreachable!(),
                }
                assert_eq!(after.1.next_ordinal, attempt.ordinal + 1);
                assert!(after.1.next_ordinal > before.1.next_ordinal);
                assert_eq!(after.1.last_failure, before.1.last_failure);
            } else {
                let failure = after
                    .1
                    .last_failure
                    .expect("注入失敗須記錄於 allocation trace");
                assert_eq!(failure.attempt.point, Some(point));
                assert_eq!(after.1.last_attempt, Some(failure.attempt));
                assert_eq!(after.1.next_ordinal, failure.attempt.ordinal + 1);
                assert!(after.1.next_ordinal > before.1.next_ordinal);
                assert_eq!(format!("{:?}", failure.kind), "Injection");
            }
            // SAFETY：原 sentinel 與 failpoint 一次性均須保留。
            unsafe {
                assert_eq!(lua_gettop(state), 1, "{point:?}");
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
            }
            assert_eq!(snapshot().1, after.1, "{point:?}: 失敗後無額外配置嘗試");
            set_errno(0);
            // SAFETY：同一 state 立即重試應成功。
            assert_eq!(
                unsafe { luaL_execresult(state, EXIT_SEVEN) },
                3,
                "{point:?}"
            );
            // SAFETY：重試的三槽依序為 nil、exit、7。
            unsafe {
                assert_eq!(lua_gettop(state), 4, "{point:?}");
                assert_eq!(lua_type(state, -3), 0);
                assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 7);
            }
            assert_eq!(stack_bytes(state, -2), b"exit");
            // SAFETY：僅移除重試推入的三槽。
            unsafe { lua_settop(state, 1) };
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let (ledger, host_roots) = owner
                .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
                .unwrap();
            assert_eq!(ledger, baseline, "{point:?}: 收集後帳本須回到基準");
            assert_eq!(host_roots, 0, "{point:?}: 收集後不可殘留 Host root");
            // SAFETY：重試回收後原 sentinel 仍不變。
            unsafe {
                assert_eq!(lua_gettop(state), 1);
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
            }
        }

        for fill in [1, 0] {
            let limited_owner = StateOwner::new().unwrap();
            let limited_state = limited_owner.as_ptr();
            // SAFETY：一個 nil slot 保留容量；空 stack 需要預備容量。
            unsafe { lua_settop(limited_state, fill) };
            set_errno(0);
            // SAFETY：先完成一次發布、退棧與回收，將首次 heap slot 擴張納入基準。
            assert_eq!(unsafe { luaL_execresult(limited_state, EXIT_SEVEN) }, 3);
            // SAFETY：只退預熱的三槽；空 stack 釋放 capacity。
            unsafe { lua_settop(limited_state, fill) };
            limited_owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let current = limited_owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
            assert_eq!(
                limited_owner
                    .with_vm(|vm| vm.roots().count(RootKind::Host))
                    .unwrap(),
                0
            );
            limited_owner
                .with_vm(|vm| vm.set_allocation_limit(current.committed))
                .unwrap();
            let before = limited_owner
                .with_vm(|vm| {
                    let mut roots = Vec::new();
                    vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
                    (
                        vm.ledger_snapshot(),
                        vm.allocation_trace(),
                        vm.gc_trace(),
                        roots,
                    )
                })
                .unwrap();
            set_errno(0);
            // SAFETY：額度不足不得發布部分結果。
            assert_eq!(unsafe { luaL_execresult(limited_state, EXIT_SEVEN) }, 0);
            // SAFETY：原 stack 仍為一個 nil 或空 stack。
            unsafe {
                assert_eq!(lua_gettop(limited_state), fill);
                if fill > 0 {
                    assert_eq!(lua_type(limited_state, fill), 0);
                }
            }
            let after = limited_owner
                .with_vm(|vm| {
                    let mut roots = Vec::new();
                    vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
                    (
                        vm.ledger_snapshot(),
                        vm.allocation_trace(),
                        vm.gc_trace(),
                        roots,
                    )
                })
                .unwrap();
            assert_eq!(after.0, before.0);
            assert_eq!(after.2, before.2);
            assert_eq!(after.3, before.3);
            let failure = after
                .1
                .last_failure
                .expect("額度不足須記錄 allocation trace");
            assert_eq!(after.1.last_attempt, Some(failure.attempt));
            assert_eq!(after.1.next_ordinal, failure.attempt.ordinal + 1);
            assert!(after.1.next_ordinal > before.1.next_ordinal);
            assert_eq!(format!("{:?}", failure.kind), "Budget");
            if fill == 0 {
                assert!(failure.attempt.bytes > b"exit".len() + 1);
            } else {
                assert_eq!(failure.attempt.bytes, b"exit".len() + 1);
            }
            limited_owner
                .with_vm(|vm| vm.set_allocation_limit(usize::MAX))
                .unwrap();
            set_errno(0);
            // SAFETY：解除額度後立即重試應發布完整三槽。
            assert_eq!(unsafe { luaL_execresult(limited_state, EXIT_SEVEN) }, 3);
            // SAFETY：順序與 exit code 須完整。
            unsafe {
                assert_eq!(lua_gettop(limited_state), fill + 3);
                assert_eq!(lua_type(limited_state, -3), 0);
                assert_eq!(lua_tointegerx(limited_state, -1, std::ptr::null_mut()), 7);
            }
            assert_eq!(stack_bytes(limited_state, -2), b"exit");
            // SAFETY：只退重試三槽。
            unsafe { lua_settop(limited_state, fill) };
            limited_owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let (ledger, host_roots) = limited_owner
                .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
                .unwrap();
            assert_eq!(ledger, current, "{fill}: 回收後帳本須回到基準");
            assert_eq!(host_roots, 0, "{fill}: 不可殘留 Host root");
            // SAFETY：原 nil slot 或空 stack 不變。
            unsafe {
                assert_eq!(lua_gettop(limited_state), fill);
                if fill > 0 {
                    assert_eq!(lua_type(limited_state, fill), 0);
                }
            }
        }
    }
    // SAFETY：先前成功與拒絕後 state 仍可使用。
    unsafe {
        lua_pushinteger(state, 99);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 99);
    }
}
