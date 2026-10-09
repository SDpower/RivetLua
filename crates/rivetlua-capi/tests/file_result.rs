use std::ffi::{CStr, CString, c_char, c_int};

use rivetlua_capi::stack::{
    StateOwner, lua_close, lua_gettop, lua_pushinteger, lua_settop, lua_toboolean, lua_tointegerx,
    lua_tolstring, lua_type, luaL_fileresult, luaL_newstate,
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
    // SAFETY：有效 errno 傳給 libc；回傳文字只在這次呼叫內讀取並複製。
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
fn file_result_a40_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：Rust owner 在整段測試期間保持 state 存活。
    unsafe {
        lua_pushinteger(state, 73);
        for stat in [1, -1] {
            assert_eq!(luaL_fileresult(state, stat, std::ptr::null()), 1);
            assert_eq!(lua_gettop(state), 2);
            assert_eq!(lua_type(state, -1), 1);
            assert_eq!(lua_toboolean(state, -1), 1);
            lua_settop(state, 1);
        }
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        set_errno(0);
        // SAFETY：有效 state；null fname 不解參照。
        assert_eq!(unsafe { luaL_fileresult(state, 0, std::ptr::null()) }, 3);
        // SAFETY：有效 state 的三個新 slot 按官方順序讀取。
        unsafe {
            assert_eq!(lua_gettop(state), 4);
            assert_eq!(lua_type(state, -3), 0);
            assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 0);
        }
        assert_eq!(stack_bytes(state, -2), b"(no extra info)");
        // SAFETY：只退剛建立的三個結果。
        unsafe { lua_settop(state, 1) };

        let code = 2;
        let official = strerror_bytes(code);
        set_errno(code);
        // SAFETY：有效 state；null fname 不解參照。
        assert_eq!(unsafe { luaL_fileresult(state, 0, std::ptr::null()) }, 3);
        assert_eq!(stack_bytes(state, -2), official);
        // SAFETY：有效 state 與存活的 errno slot。
        unsafe {
            assert_eq!(lua_type(state, -3), 0);
            assert_eq!(
                lua_tointegerx(state, -1, std::ptr::null_mut()),
                i64::from(code)
            );
            lua_settop(state, 1);
        }

        let fname = CString::new(&b"bad\xffname"[..]).unwrap();
        let mut expected = fname.as_bytes().to_vec();
        expected.extend_from_slice(b": ");
        expected.extend_from_slice(&official);
        set_errno(code);
        // SAFETY：fname 是呼叫期間有效的 NUL 結尾 C 字串；state 存活。
        assert_eq!(unsafe { luaL_fileresult(state, 0, fname.as_ptr()) }, 3);
        assert_eq!(stack_bytes(state, -2), expected);
        // SAFETY：有效 state；核對 errno 並退回原 stack。
        unsafe {
            assert_eq!(
                lua_tointegerx(state, -1, std::ptr::null_mut()),
                i64::from(code)
            );
            lua_settop(state, 1);
        }

        let c_owned = luaL_newstate();
        assert!(!c_owned.is_null());
        set_errno(0);
        // SAFETY：C-owned state 剛建立且只 close 一次；成功路徑只推 true。
        unsafe {
            assert_eq!(luaL_fileresult(c_owned, -1, std::ptr::null()), 1);
            assert_eq!(lua_toboolean(c_owned, -1), 1);
            lua_settop(c_owned, 0);
        }
        set_errno(code);
        // SAFETY：C-owned state 與 fname 有效；完成後一次 close。
        unsafe {
            assert_eq!(luaL_fileresult(c_owned, 0, fname.as_ptr()), 3);
            assert_eq!(lua_gettop(c_owned), 3);
        }
        assert_eq!(stack_bytes(c_owned, -2), expected);
        // SAFETY：只關閉本測試建立且仍存活的 C-owned state。
        unsafe { lua_close(c_owned) };
    }

    // SAFETY：null state 必須回零；fname 故意無效，驗證前不得解參照。
    assert_eq!(
        unsafe { luaL_fileresult(std::ptr::null_mut(), 0, 1usize as *const c_char) },
        0
    );
    let address = state as usize;
    let wrong_thread = std::thread::spawn(move || {
        // SAFETY：owner 在 join 前保持 state 存活；跨執行緒入口只可拒絕，fname 不得讀取。
        unsafe {
            luaL_fileresult(
                address as *mut rivetlua_capi::stack::lua_State,
                0,
                1usize as *const c_char,
            )
        }
    });
    assert_eq!(wrong_thread.join().unwrap(), 0);
    let busy = owner
        .with_vm(|vm| {
            let before = (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace());
            // SAFETY：state 有效但 VM 借用中；入口必須先拒絕且不讀無效 fname。
            let result = unsafe { luaL_fileresult(state, 0, 1usize as *const c_char) };
            assert_eq!(
                (vm.ledger_snapshot(), vm.allocation_trace(), vm.gc_trace()),
                before
            );
            result
        })
        .unwrap();
    assert_eq!(busy, 0);
    // SAFETY：state 未被拒絕路徑修改，仍可讀原 sentinel。
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
        set_errno(2);
        // SAFETY：state 存活，active GC 下發布失敗三槽。
        assert_eq!(unsafe { luaL_fileresult(state, 0, std::ptr::null()) }, 3);
        owner.with_vm(|vm| vm.incremental_step(1).unwrap()).unwrap();
        assert_eq!(stack_bytes(state, -2), strerror_bytes(2));
        assert_eq!(
            owner
                .with_vm(|vm| vm.roots().count(RootKind::Host))
                .unwrap(),
            1
        );
        // SAFETY：退回三個結果，解除字串 stack root 與 view。
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
            set_errno(2);
            // SAFETY：有效 state，指定 failpoint 應使三槽發布全數回滾。
            assert_eq!(
                unsafe { luaL_fileresult(state, 0, std::ptr::null()) },
                0,
                "{point:?}"
            );
            let after = snapshot();
            assert_eq!(after.0, before.0, "{point:?}: ledger");
            assert_eq!(after.2, before.2, "{point:?}: GC trace");
            assert_eq!(after.3, before.3, "{point:?}: roots");
            if matches!(point, FailPoint::ObjectInitialize | FailPoint::RootReserve) {
                // 這兩個 checkpoint 前的配置可記錄，checkpoint 本身沒有 trace event。
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
            // SAFETY：原 sentinel slot 不可變，且 failpoint 只能消耗一次。
            unsafe {
                assert_eq!(lua_gettop(state), 1, "{point:?}");
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
            }
            assert_eq!(snapshot().1, after.1, "{point:?}: 失敗後無額外配置嘗試");
            set_errno(2);
            // SAFETY：同一 state 重試應成功，證明沒有殘留 failpoint。
            assert_eq!(
                unsafe { luaL_fileresult(state, 0, std::ptr::null()) },
                3,
                "{point:?}"
            );
            // SAFETY：移除重試所推三槽以供下一個注入點測試。
            unsafe { lua_settop(state, 1) };
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let (ledger, host_roots) = owner
                .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
                .unwrap();
            assert_eq!(ledger, baseline, "{point:?}: 收集後帳本須回到基準");
            assert_eq!(host_roots, 0, "{point:?}: 收集後不可殘留 stack root");
            // SAFETY：結果已退回，原 sentinel 仍由有效 state 持有。
            unsafe {
                assert_eq!(lua_gettop(state), 1, "{point:?}");
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
            }
        }

        for fill in [1, 0] {
            let limited_owner = StateOwner::new().unwrap();
            let limited_state = limited_owner.as_ptr();
            // SAFETY：有效 state；一個 nil slot 保留容量，空 stack 則需要先預備容量。
            unsafe { lua_settop(limited_state, fill) };
            set_errno(0);
            // SAFETY：先完成一次發布、退棧與回收，使初次 heap slot 擴張納入基準。
            assert_eq!(
                unsafe { luaL_fileresult(limited_state, 0, std::ptr::null()) },
                3
            );
            // SAFETY：只退預熱建立的三槽；空 stack 會釋放其 capacity。
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
            // SAFETY：額度不足應在預備容量或 StringView 階段拒絕，不發布任何結果。
            assert_eq!(
                unsafe { luaL_fileresult(limited_state, 0, std::ptr::null()) },
                0
            );
            // SAFETY：失敗後原 stack 長度及內容不變。
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
                .expect("額度不足須記錄於 allocation trace");
            assert_eq!(after.1.last_attempt, Some(failure.attempt));
            assert_eq!(after.1.next_ordinal, failure.attempt.ordinal + 1);
            assert!(after.1.next_ordinal > before.1.next_ordinal);
            assert_eq!(format!("{:?}", failure.kind), "Budget");
            if fill == 0 {
                assert!(failure.attempt.bytes > b"(no extra info)".len() + 1);
            } else {
                assert_eq!(failure.attempt.bytes, b"(no extra info)".len() + 1);
            }
            limited_owner
                .with_vm(|vm| vm.set_allocation_limit(usize::MAX))
                .unwrap();
            set_errno(0);
            // SAFETY：解除額度限制後相同入口應可發布完整三槽。
            assert_eq!(
                unsafe { luaL_fileresult(limited_state, 0, std::ptr::null()) },
                3
            );
            // SAFETY：重試後三槽順序完整，並保留原有 nil slot。
            unsafe {
                assert_eq!(lua_gettop(limited_state), fill + 3);
                assert_eq!(lua_type(limited_state, -3), 0);
                assert_eq!(lua_tointegerx(limited_state, -1, std::ptr::null_mut()), 0);
            }
            assert_eq!(stack_bytes(limited_state, -2), b"(no extra info)");
            // SAFETY：僅移除本輪新增三槽。
            unsafe { lua_settop(limited_state, fill) };
            limited_owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let (ledger, host_roots) = limited_owner
                .with_vm(|vm| (vm.ledger_snapshot(), vm.roots().count(RootKind::Host)))
                .unwrap();
            assert_eq!(host_roots, 0, "{fill}: 收集後不可殘留 Host root");
            assert_eq!(ledger, current, "{fill}: 收集後帳本須回到基準");
            // SAFETY：退回三槽後原 stack 長度與 nil slot 未變。
            unsafe {
                assert_eq!(lua_gettop(limited_state), fill);
                if fill > 0 {
                    assert_eq!(lua_type(limited_state, fill), 0);
                }
            }
        }
    }
    // SAFETY：先前成功與拒絕後 state 仍可正常推入 scalar。
    unsafe {
        lua_pushinteger(state, 99);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 99);
    }
}
