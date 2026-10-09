#![cfg(feature = "lua55")]

use std::alloc::{Layout, alloc, dealloc};
use std::cell::Cell;
use std::ffi::{c_char, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushinteger, lua_pushvalue,
    lua_rawgeti, lua_rawlen, lua_rawseti, lua_settop, lua_tolstring,
};
use rivetlua_runtime::FailPoint;

#[derive(Default)]
struct Release {
    calls: Cell<usize>,
    pointer: Cell<*mut c_void>,
    old_size: Cell<usize>,
    new_size: Cell<usize>,
}

unsafe extern "C" fn release_external(
    ud: *mut c_void,
    pointer: *mut c_void,
    old_size: usize,
    new_size: usize,
) -> *mut c_void {
    // SAFETY：測試將有效 Release 位址交給 C API，並在 state 及所有 callback 結束前保活。
    let release = unsafe { &*(ud.cast::<Release>()) };
    release.calls.set(release.calls.get() + 1);
    release.pointer.set(pointer);
    release.old_size.set(old_size);
    release.new_size.set(new_size);
    if !pointer.is_null() && new_size == 0 {
        // SAFETY：buffer 由下方 allocate_external 以相同 len+1 Layout 配置。
        unsafe { dealloc(pointer.cast(), Layout::array::<u8>(old_size).unwrap()) };
    }
    std::ptr::null_mut()
}

fn allocate_external(bytes: &[u8]) -> *const c_char {
    let size = bytes.len() + 1;
    let layout = Layout::array::<u8>(size).unwrap();
    // SAFETY：layout 為有效非零 byte 陣列；立刻初始化全部 bytes 與結尾 NUL。
    let pointer = unsafe { alloc(layout) };
    assert!(!pointer.is_null());
    // SAFETY：allocation 容量為 size，source 恰 bytes.len()，末端另寫一個 NUL。
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, bytes.len());
        *pointer.add(bytes.len()) = 0;
    }
    pointer.cast()
}

unsafe extern "C" {
    fn lua_pushexternalstring(
        state: *mut lua_State,
        source: *const c_char,
        len: usize,
        falloc: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, usize, usize) -> *mut c_void>,
        ud: *mut c_void,
    ) -> *const c_char;
    fn lua_gc(state: *mut lua_State, what: i32, ...) -> i32;
}

#[test]
fn external_pointer_identity_embedded_nul_and_gc_b9() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let release = Release::default();
    let bytes = [0, b'A', 0x80, 0];
    let source = allocate_external(&bytes);
    // SAFETY：owner 保活 state；source 有 len+1 有效且不可變 bytes，release 在 callback 前保活。
    unsafe {
        assert_eq!(
            lua_pushexternalstring(
                state,
                source,
                bytes.len(),
                Some(release_external),
                (&release as *const Release).cast_mut().cast()
            ),
            source
        );
        assert_eq!(lua_rawlen(state, -1), bytes.len() as u64);
        let mut len = usize::MAX;
        assert_eq!(lua_tolstring(state, -1, &mut len), source);
        assert_eq!(len, bytes.len());
        lua_pushvalue(state, -1);
        assert_eq!(lua_tolstring(state, -1, &mut len), source);
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(release.calls.get(), 0);
        lua_settop(state, 0);
        assert_eq!(lua_gc(state, 2), 0);
    }
    assert_eq!(release.calls.get(), 1);
    assert_eq!(release.pointer.get(), source.cast_mut().cast());
    assert_eq!(release.old_size.get(), bytes.len() + 1);
    assert_eq!(release.new_size.get(), 0);
}

#[test]
fn external_table_roundtrip_and_fixed_buffer_b9() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let release = Release::default();
    let bytes = [0x81; 80];
    let source = allocate_external(&bytes);
    // SAFETY：state／external bytes／callback ud 在同步呼叫及 GC 期間有效。
    unsafe {
        lua_createtable(state, 0, 1);
        assert_eq!(
            lua_pushexternalstring(
                state,
                source,
                bytes.len(),
                Some(release_external),
                (&release as *const Release).cast_mut().cast()
            ),
            source
        );
        lua_rawseti(state, -2, 1);
        assert_eq!(lua_rawgeti(state, -1, 1), 4);
        assert_eq!(lua_tolstring(state, -1, std::ptr::null_mut()), source);
        lua_settop(state, 1);
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(release.calls.get(), 0);
        lua_settop(state, 0);
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(release.calls.get(), 1);

        static FIXED: &[u8] = b"\0fixed\0";
        assert_eq!(
            lua_pushexternalstring(state, FIXED.as_ptr().cast(), 6, None, std::ptr::null_mut()),
            FIXED.as_ptr().cast()
        );
        assert_eq!(lua_rawlen(state, -1), 6);
        lua_settop(state, 0);
        assert_eq!(lua_gc(state, 2), 0);
        assert_eq!(release.calls.get(), 1);
    }
}

#[test]
fn external_admission_failure_calls_owner_once_and_retries_b9() {
    for point in [FailPoint::ObjectReserve, FailPoint::RootReserve] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        let release = Release::default();
        owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        let source = allocate_external(b"failure");
        // SAFETY：有效失敗輸入已交給 C API；無 checkpoint 使用既有 fail-closed NULL 語意。
        unsafe {
            assert!(
                lua_pushexternalstring(
                    state,
                    source,
                    7,
                    Some(release_external),
                    (&release as *const Release).cast_mut().cast()
                )
                .is_null()
            );
            assert_eq!(lua_gettop(state), 0);
        }
        assert_eq!(release.calls.get(), 1);
        assert_eq!(release.pointer.get(), source.cast_mut().cast());
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().committed).unwrap(),
            before.committed
        );
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
        let retry = allocate_external(b"retry");
        // SAFETY：同一 state 上的一次性 failpoint 已消耗；retry bytes 保持有效直到 GC。
        unsafe {
            assert_eq!(
                lua_pushexternalstring(
                    state,
                    retry,
                    5,
                    Some(release_external),
                    (&release as *const Release).cast_mut().cast()
                ),
                retry
            );
            lua_settop(state, 0);
            assert_eq!(lua_gc(state, 2), 0);
        }
        assert_eq!(release.calls.get(), 2);
    }
}

#[test]
fn external_empty_string_releases_on_state_drop_b9() {
    let release = Release::default();
    let owner = StateOwner::new().unwrap();
    let source = allocate_external(b"");
    // SAFETY：空內容仍配置一個 NUL；state 與 callback ud 活到 state Drop 完成。
    unsafe {
        assert_eq!(
            lua_pushexternalstring(
                owner.as_ptr(),
                source,
                0,
                Some(release_external),
                (&release as *const Release).cast_mut().cast()
            ),
            source
        );
        assert_eq!(lua_rawlen(owner.as_ptr(), -1), 0);
    }
    drop(owner);
    assert_eq!(release.calls.get(), 1);
    assert_eq!(release.pointer.get(), source.cast_mut().cast());
    assert_eq!(release.old_size.get(), 1);
    assert_eq!(release.new_size.get(), 0);
}

#[test]
fn external_stack_publication_failure_rolls_back_b9() {
    let mut found_stack_growth = false;
    for offset in 0..16 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：有效 state；20 個值填滿現有 stack，下一次 push 須配置新容量。
        unsafe {
            for index in 0..20 {
                lua_pushinteger(state, index);
            }
            assert_eq!(lua_gettop(state), 20);
        }
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        owner
            .with_vm(|vm| {
                let ordinal = vm.allocation_trace().next_ordinal + offset;
                vm.inject_allocation_failure_at(ordinal);
            })
            .unwrap();
        let release = Release::default();
        let source = allocate_external(b"grow");
        // SAFETY：有效 external 輸入；無 checkpoint 的配置失敗應回傳 NULL。
        let result = unsafe {
            lua_pushexternalstring(
                state,
                source,
                4,
                Some(release_external),
                (&release as *const Release).cast_mut().cast(),
            )
        };
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap();
        if let Some(failure) = failure {
            assert!(result.is_null());
            assert_eq!(
                release.calls.get(),
                1,
                "offset {offset}, failure {failure:?}"
            );
            assert_eq!(unsafe { lua_gettop(state) }, 20);
            assert_eq!(
                owner.with_vm(|vm| vm.ledger_snapshot().committed).unwrap(),
                before.committed
            );
            assert_eq!(
                owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
                0
            );
            if failure.attempt.bytes >= 1024
                && failure.attempt.domain == rivetlua_runtime::AllocationDomain::Host
                && failure.attempt.point.is_none()
            {
                found_stack_growth = true;
            }
        } else {
            assert_eq!(result, source);
            drop(owner);
            assert_eq!(release.calls.get(), 1);
        }
        if found_stack_growth {
            break;
        }
    }
    assert!(found_stack_growth, "未命中 external stack 容量配置失敗點");
}
