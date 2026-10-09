use std::ffi::{c_char, c_void};
use std::mem::MaybeUninit;

use rivetlua_capi::error::{ErrorClass, Reject, consume};
use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushinteger, lua_settop,
    lua_tointegerx, lua_topointer, lua_touserdata, lua_type, luaL_Buffer, luaL_buffinit,
    luaL_buffinitsize, luaL_pushresultsize, rivetlua_capi_buffer_dispatch_a49,
};
use rivetlua_capi::trampoline::{Action, Outcome, protect};
use rivetlua_runtime::{AllocationDomain, AllocationFailureKind, FailPoint, GcMode, GcPhase};

const LUAL_BUFFERSIZE: usize = 1024;

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct TestBuffer {
    b: *mut c_char,
    size: usize,
    n: usize,
    state: *mut lua_State,
    init: [u8; LUAL_BUFFERSIZE],
}

fn patterned_buffer() -> TestBuffer {
    let mut buffer = TestBuffer {
        b: std::ptr::null_mut(),
        size: 17,
        n: 29,
        state: std::ptr::null_mut(),
        init: [0xA5; LUAL_BUFFERSIZE],
    };
    buffer.b = buffer.init.as_mut_ptr().cast();
    buffer
}

fn assert_buffer_unchanged(actual: &TestBuffer, expected: &TestBuffer) {
    assert_eq!(actual.b, expected.b);
    assert_eq!(actual.size, expected.size);
    assert_eq!(actual.n, expected.n);
    assert_eq!(actual.state, expected.state);
    assert_eq!(actual.init, expected.init);
}

fn assert_stack_identity(state: *mut lua_State, top: i32, integer: i64, table: *const c_void) {
    // SAFETY：state 由仍存活的 StateOwner 持有，前兩格是本測試建立的值。
    unsafe {
        assert_eq!(lua_gettop(state), top);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), integer);
        assert_eq!(lua_topointer(state, 2), table);
    }
}

#[test]
fn buffer_init_a38_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();

    // SAFETY：state 在 owner 生命週期內有效，建立的 stack values 由該 state 持有。
    unsafe {
        lua_pushinteger(state, 71);
        lua_createtable(state, 0, 0);
    }
    // SAFETY：state 仍由 owner 持有，三個讀取只查詢本測試建立的 stack slots。
    let (stack_top, stack_integer, table_identity) = unsafe {
        (
            lua_gettop(state),
            lua_tointegerx(state, -2, std::ptr::null_mut()),
            lua_topointer(state, -1),
        )
    };
    assert_eq!(stack_top, 2);
    assert_eq!(stack_integer, 71);
    assert!(!table_identity.is_null());

    owner
        .with_vm(|vm| {
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();

    let before = owner
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.roots().total_count(),
                vm.ledger_probe().snapshot(),
                vm.gc_trace(),
            )
        })
        .unwrap();
    let mut buffer = patterned_buffer();
    let init_before = buffer.init;

    // SAFETY：owner 保證 state 有效；buffer 對齊且具固定 header 的完整公開 prefix 與 init 區。
    unsafe {
        luaL_buffinit(
            state,
            (&mut buffer as *mut TestBuffer).cast::<luaL_Buffer>(),
        )
    };
    assert_eq!(buffer.b, buffer.init.as_mut_ptr().cast());
    assert_eq!(buffer.size, LUAL_BUFFERSIZE);
    assert_eq!(buffer.n, 0);
    assert_eq!(buffer.state, state);
    assert_eq!(buffer.init, init_before);
    assert_stack_identity(state, stack_top + 1, stack_integer, table_identity);
    // SAFETY：官方 buffinit 須在頂端放入 buffer 位址 lightuserdata placeholder。
    unsafe {
        assert_eq!(lua_type(state, -1), 2);
        assert_eq!(
            lua_touserdata(state, -1),
            (&mut buffer as *mut TestBuffer).cast()
        );
        lua_settop(state, stack_top);
    }

    buffer.b = std::ptr::null_mut();
    buffer.size = 31;
    buffer.n = 37;
    buffer.state = std::ptr::null_mut();
    // SAFETY：state 和完整、對齊的 buffer 仍有效；此呼叫驗證重複初始化。
    unsafe {
        luaL_buffinit(
            state,
            (&mut buffer as *mut TestBuffer).cast::<luaL_Buffer>(),
        )
    };
    assert_eq!(buffer.b, buffer.init.as_mut_ptr().cast());
    assert_eq!(buffer.size, LUAL_BUFFERSIZE);
    assert_eq!(buffer.n, 0);
    assert_eq!(buffer.state, state);
    assert_eq!(buffer.init, init_before);
    assert_stack_identity(state, stack_top + 1, stack_integer, table_identity);
    // SAFETY：第二次 buffinit 亦只放一個 placeholder；本片用 settop 結束其生命週期。
    unsafe {
        assert_eq!(lua_type(state, -1), 2);
        assert_eq!(
            lua_touserdata(state, -1),
            (&mut buffer as *mut TestBuffer).cast()
        );
        lua_settop(state, stack_top);
    }

    let after = owner
        .with_vm(|vm| {
            (
                vm.ledger_snapshot(),
                vm.roots().total_count(),
                vm.ledger_probe().snapshot(),
                vm.gc_trace(),
            )
        })
        .unwrap();
    assert_eq!(before.0, after.0);
    assert_eq!(before.1, after.1);
    assert_eq!(before.2.committed, after.2.committed);
    assert_eq!(before.2.reserved, after.2.reserved);
    assert_eq!(before.3, after.3);

    let mut null_buffer = patterned_buffer();
    let null_buffer_before = null_buffer;
    // SAFETY：state 有效；null buffer 是此 API 要 fail-closed 的輸入。
    unsafe { luaL_buffinit(state, std::ptr::null_mut()) };
    assert_buffer_unchanged(&null_buffer, &null_buffer_before);

    // SAFETY：完整且對齊的 buffer 有效；null state 是此 API 要 fail-closed 的輸入。
    unsafe {
        luaL_buffinit(
            std::ptr::null_mut(),
            (&mut null_buffer as *mut TestBuffer).cast::<luaL_Buffer>(),
        )
    };
    assert_buffer_unchanged(&null_buffer, &null_buffer_before);

    let state_address = state as usize;
    let buffer_address = (&mut null_buffer as *mut TestBuffer) as usize;
    let wrong_thread = std::thread::spawn(move || {
        // SAFETY：兩個位址在 join 前仍由主執行緒的 owner 和 buffer 保持有效，且沒有並行存取。
        unsafe {
            luaL_buffinit(
                state_address as *mut lua_State,
                (buffer_address as *mut TestBuffer).cast::<luaL_Buffer>(),
            )
        }
    });
    wrong_thread.join().unwrap();
    assert_buffer_unchanged(&null_buffer, &null_buffer_before);

    let busy_buffer_before = null_buffer;
    owner
        .with_vm(|_| {
            // SAFETY：owner/state/buffer 仍有效；外層 VM 借用使此重入呼叫應 fail-closed。
            unsafe {
                luaL_buffinit(
                    state,
                    (&mut null_buffer as *mut TestBuffer).cast::<luaL_Buffer>(),
                )
            }
        })
        .unwrap();
    assert_buffer_unchanged(&null_buffer, &busy_buffer_before);
    assert_stack_identity(state, stack_top, stack_integer, table_identity);

    // SAFETY：state 仍由 owner 持有且可繼續使用。
    unsafe {
        lua_pushinteger(state, 99);
        assert_eq!(lua_gettop(state), 3);
    }
}

#[test]
fn buffer_overflow_a49_cleans_anchor_roots_and_ledger() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // 預暖可重用的 heap slot 容量；ledger 比較聚焦於活物件而非首次 Vec 擴容。
    owner
        .with_vm(|vm| {
            for _ in 0..8 {
                vm.allocate_byte_string(b"warmup")?;
            }
            vm.collect()
        })
        .unwrap()
        .unwrap();
    let baseline = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    for grow in [false, true] {
        let mut buffer = patterned_buffer();
        // SAFETY：state 由 owner 保活；buffer 是完整、對齊的固定 ABI 配置。此 Rust
        // action 僅直接取得 POD prepare 結果，不呼叫會跨 Rust frame 跳轉的 C facade。
        let outcome = unsafe {
            protect(state, |checkpoint| {
                luaL_buffinit(state, (&mut buffer as *mut TestBuffer).cast());
                if grow {
                    let bytes = [b'x'; LUAL_BUFFERSIZE + 1];
                    let result = rivetlua_capi_buffer_dispatch_a49(
                        state,
                        checkpoint.generation,
                        checkpoint.token,
                        (&mut buffer as *mut TestBuffer).cast(),
                        3,
                        bytes.as_ptr().cast(),
                        std::ptr::null(),
                        std::ptr::null(),
                        bytes.len(),
                    );
                    assert_eq!((result.kind, result.value), (0, 0));
                }
                let result = rivetlua_capi_buffer_dispatch_a49(
                    state,
                    checkpoint.generation,
                    checkpoint.token,
                    (&mut buffer as *mut TestBuffer).cast(),
                    2,
                    std::ptr::null(),
                    std::ptr::null(),
                    std::ptr::null(),
                    usize::MAX,
                );
                assert_eq!((result.kind, result.value), (1, 2));
                Action::Raise(ErrorClass::Lua)
            })
        };
        assert_eq!(outcome, Outcome::Raised(ErrorClass::Lua));
        // SAFETY：錯誤 pending 在相同 state；consume 只將它移入單一頂端 slot。
        assert_eq!(unsafe { consume(state) }, Ok(ErrorClass::Lua));
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        unsafe { lua_settop(state, 0) };
        owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
        let after = owner
            .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
            .unwrap();
        assert_eq!(after, baseline, "grow={grow}");
    }
}

#[test]
fn buffer_grow_a49_allocation_failure_cleans_anchor_and_retries() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；保留一個實際 slot，使 checkpoint 的備用容量已預留。
    unsafe { lua_pushinteger(state, 7) };
    owner
        .with_vm(|vm| {
            for _ in 0..8 {
                vm.allocate_byte_string(b"warmup")?;
            }
            vm.collect()
        })
        .unwrap()
        .unwrap();
    let before = owner
        .with_vm(|vm| {
            (
                vm.roots().total_count(),
                vm.ledger_snapshot(),
                vm.allocation_trace().next_ordinal,
            )
        })
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(before.2))
        .unwrap();
    let mut buffer = patterned_buffer();
    let bytes = [b'x'; LUAL_BUFFERSIZE + 1];
    // SAFETY：buffer 與來源 bytes 完整有效；只呼叫 POD prepare，error action
    // 在 Rust closure 返回後才由 C checkpoint 消費，沒有 foreign unwind。
    let outcome = unsafe {
        protect(state, |checkpoint| {
            luaL_buffinit(state, (&mut buffer as *mut TestBuffer).cast());
            let result = rivetlua_capi_buffer_dispatch_a49(
                state,
                checkpoint.generation,
                checkpoint.token,
                (&mut buffer as *mut TestBuffer).cast(),
                3,
                bytes.as_ptr().cast(),
                std::ptr::null(),
                std::ptr::null(),
                bytes.len(),
            );
            assert_eq!((result.kind, result.value), (1, 5));
            Action::Raise(ErrorClass::Allocation)
        })
    };
    assert_eq!(outcome, Outcome::Raised(ErrorClass::Allocation));
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    let failure = owner
        .with_vm(|vm| vm.allocation_trace().last_failure)
        .unwrap()
        .expect("buffer grow 必須命中真實 allocation failpoint");
    assert_eq!(failure.kind, AllocationFailureKind::Injection);
    assert_eq!(failure.attempt.ordinal, before.2);
    assert_eq!(failure.attempt.domain, AllocationDomain::LuaHeap);
    assert_eq!(failure.attempt.point, Some(FailPoint::UserdataBytesReserve));
    assert!(failure.attempt.site.file.ends_with("heap.rs"));
    assert_eq!(failure.attempt.bytes, 1536);
    assert_eq!(unsafe { consume(state) }, Ok(ErrorClass::Allocation));
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 1) };
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    let after = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    assert_eq!(after, (before.0, before.1));
    // SAFETY：清理後同一 state 仍可進入新 buffer transaction。
    let mut retry = patterned_buffer();
    unsafe { luaL_buffinit(state, (&mut retry as *mut TestBuffer).cast()) };
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 1) };
}

#[test]
fn buffer_initsize_a49_failed_init_never_reads_uninitialized_prefix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut buffer = patterned_buffer();
    let sentinel = buffer;
    let baseline = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    // SAFETY：owner 保活 state，buffer 有完整對齊配置，但 prefix 尚未經 buffinit
    // 初始化。action 先撤掉 checkpoint 預留的空 stack 容量，讓下一個配置 failpoint
    // 精確落在 buffinitsize 的 buffer_init stack reserve；僅呼叫 POD prepare。
    let outcome = unsafe {
        protect(state, |checkpoint| {
            lua_settop(state, 0);
            let ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
                .unwrap();
            let result = rivetlua_capi_buffer_dispatch_a49(
                state,
                checkpoint.generation,
                checkpoint.token,
                (&mut buffer as *mut TestBuffer).cast(),
                8,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                4,
            );
            assert_eq!(
                (result.kind, result.value),
                (2, Reject::StackChanged as i32)
            );
            Action::Reject(Reject::StackChanged)
        })
    };
    assert_eq!(outcome, Outcome::Rejected(Reject::StackChanged));
    assert_buffer_unchanged(&buffer, &sentinel);
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    assert_eq!(unsafe { consume(state) }, Err(Reject::NoPending));
    let failure = owner
        .with_vm(|vm| vm.allocation_trace().last_failure)
        .unwrap()
        .expect("buffer_init stack reserve 必須實際失敗");
    assert_eq!(failure.kind, AllocationFailureKind::Injection);
    let after = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    assert_eq!(after, baseline);

    // SAFETY：一次性 failpoint 已耗盡；同一 state 與原 buffer 應能重新初始化並提交。
    let area = unsafe { luaL_buffinitsize(state, (&mut buffer as *mut TestBuffer).cast(), 4) };
    assert!(!area.is_null());
    unsafe { std::ptr::copy_nonoverlapping(b"okay".as_ptr(), area.cast::<u8>(), 4) };
    unsafe { luaL_pushresultsize((&mut buffer as *mut TestBuffer).cast(), 4) };
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    unsafe { lua_settop(state, 0) };
}

#[test]
fn buffer_initsize_a49_uninitialized_prefix_first_failure_is_reusable() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut buffer = MaybeUninit::<TestBuffer>::uninit();
    let pointer = buffer.as_mut_ptr().cast::<luaL_Buffer>();
    let baseline = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    let mut failed_ordinal = 0;
    // SAFETY：buffer 具完整大小／對齊／可寫生命週期，但公開 prefix 確實尚未初始化。
    // 失敗注入於 buffer_init 的首次 stack reserve；修復後此路徑不得讀 prefix。
    let outcome = unsafe {
        protect(state, |checkpoint| {
            lua_settop(state, 0);
            failed_ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(failed_ordinal))
                .unwrap();
            let result = rivetlua_capi_buffer_dispatch_a49(
                state,
                checkpoint.generation,
                checkpoint.token,
                pointer,
                8,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                4,
            );
            assert_eq!(
                (result.kind, result.value),
                (2, Reject::StackChanged as i32)
            );
            Action::Reject(Reject::StackChanged)
        })
    };
    assert_eq!(outcome, Outcome::Rejected(Reject::StackChanged));
    assert_eq!(unsafe { consume(state) }, Err(Reject::NoPending));
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    let trace = owner.with_vm(|vm| vm.allocation_trace()).unwrap();
    let failure = trace
        .last_failure
        .expect("首次 stack reserve 必須命中 failpoint");
    assert_eq!(failure.kind, AllocationFailureKind::Injection);
    assert_eq!(failure.attempt.ordinal, failed_ordinal);
    let after = owner
        .with_vm(|vm| (vm.roots().total_count(), vm.ledger_snapshot()))
        .unwrap();
    assert_eq!(after, baseline);

    // SAFETY：一次性 failpoint 已耗盡；成功重試會完整初始化 prefix；僅操作 4 個已寫 bytes。
    let area = unsafe { luaL_buffinitsize(state, pointer, 4) };
    assert!(!area.is_null());
    unsafe { std::ptr::copy_nonoverlapping(b"okay".as_ptr(), area.cast::<u8>(), 4) };
    unsafe { luaL_pushresultsize(pointer, 4) };
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    unsafe { lua_settop(state, 0) };
}
