use std::ffi::c_char;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rivetlua_capi::error::{ErrorClass, Reject, consume as raw_consume, prepare as raw_prepare};
use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_close, lua_createtable, lua_gettop, lua_pushinteger,
    lua_pushlstring, lua_settop, lua_tolstring, lua_topointer, luaL_newstate,
};
use rivetlua_capi::trampoline::{Action, Checkpoint, Outcome, probe, protect as raw_protect};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{AllocationTrace, GcTrace, LedgerSnapshot, RootId, RootKind};

struct DropMarker(Arc<AtomicUsize>);

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn protect<F: FnOnce(Checkpoint) -> Action>(state: *mut lua_State, action: F) -> Outcome {
    // SAFETY：本測試只傳 owner 持有的有效 state 或 null；wrong-thread 案例在 join 前保持 owner 存活。
    unsafe { raw_protect(state, action) }
}

fn prepare(checkpoint: Checkpoint, class: ErrorClass) -> Action {
    // SAFETY：checkpoint 來自同步 C protect；刻意錯誤的 state 仍是存活 sibling。
    unsafe { raw_prepare(checkpoint, class) }
}

fn consume(state: *mut lua_State) -> Result<ErrorClass, Reject> {
    // SAFETY：consume 只對尚存活的 owner／C-owned state 呼叫。
    unsafe { raw_consume(state) }
}

fn snapshot(
    owner: &StateOwner,
) -> (
    LedgerSnapshot,
    AllocationTrace,
    GcTrace,
    Vec<(RootKind, RootId, ObjectRef)>,
) {
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
}

#[test]
fn callback_a1_c_jump_runs_after_rust_drop_and_normal_does_not_jump() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在所有 C ABI 呼叫期間存活。
    unsafe { lua_pushinteger(state, 42) };
    let before = snapshot(&owner);
    let dropped = Arc::new(AtomicUsize::new(0));
    assert_eq!(
        protect(state, |_| {
            let _marker = DropMarker(dropped.clone());
            Action::Return(19)
        }),
        Outcome::Normal(19)
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(snapshot(&owner), before);

    assert_eq!(
        protect(state, |checkpoint| {
            let _marker = DropMarker(dropped.clone());
            prepare(checkpoint, ErrorClass::Lua)
        }),
        Outcome::Raised(ErrorClass::Lua)
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(snapshot(&owner), before);
    // SAFETY：pending 暫時移出頂端 slot，consume 必須搬回同一 slot。
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    assert_eq!(consume(state), Ok(ErrorClass::Lua));
    assert_eq!(snapshot(&owner), before);
    // SAFETY：state 仍由 owner 保有。
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(
        protect(state, |checkpoint| prepare(
            checkpoint,
            ErrorClass::Allocation
        )),
        Outcome::Raised(ErrorClass::Allocation)
    );
    assert_eq!(consume(state), Ok(ErrorClass::Allocation));
    assert_eq!(snapshot(&owner), before);
}

#[test]
fn callback_a1_nested_lifo_identity_and_pending_rejections() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    // SAFETY：兩個 owner 同時存活。
    unsafe { lua_pushinteger(state, 7) };
    let before = snapshot(&owner);
    assert_eq!(
        protect(state, |outer| {
            let wrong_state = outer.with_state(sibling.as_ptr());
            assert_eq!(probe(wrong_state), Err(Reject::WrongState));
            assert_eq!(
                prepare(wrong_state, ErrorClass::Host),
                Action::Reject(Reject::WrongState)
            );
            assert_eq!(
                probe(outer.with_generation(outer.generation + 1)),
                Err(Reject::WrongGeneration)
            );
            assert_eq!(probe(outer.with_token(outer.token + 1)), Err(Reject::Stale));
            assert_eq!(
                protect(state, |inner| {
                    assert_eq!(probe(outer), Err(Reject::Stale));
                    let raised = prepare(inner, ErrorClass::Host);
                    assert_eq!(
                        prepare(inner, ErrorClass::Lua),
                        Action::Reject(Reject::Pending)
                    );
                    raised
                }),
                Outcome::Raised(ErrorClass::Host)
            );
            assert_eq!(
                prepare(outer, ErrorClass::Lua),
                Action::Reject(Reject::Pending)
            );
            assert_eq!(consume(state), Ok(ErrorClass::Host));
            prepare(outer, ErrorClass::Lua)
        }),
        Outcome::Raised(ErrorClass::Lua)
    );
    assert_eq!(consume(state), Ok(ErrorClass::Lua));
    assert_eq!(snapshot(&owner), before);
    // SAFETY：state 存活且錯誤 slot 已復原。
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    let mut old = None;
    assert_eq!(
        protect(state, |checkpoint| {
            old = Some(checkpoint);
            Action::Return(0)
        }),
        Outcome::Normal(0)
    );
    assert_eq!(probe(old.unwrap()), Err(Reject::NoCheckpoint));
}

#[test]
fn callback_a1_pending_moves_original_root_and_value_without_allocation() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    for kind in 0..3 {
        // SAFETY：bytes 在呼叫期間有效，state 由 owner 保有。
        unsafe {
            match kind {
                0 => {
                    let bytes = [b'a', 0, b'b'];
                    assert!(
                        !lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len())
                            .is_null()
                    );
                }
                1 => lua_createtable(state, 0, 0),
                _ => lua_pushinteger(state, -31),
            }
        }
        let original_pointer = if kind == 0 {
            let mut len = 0;
            // SAFETY：頂端是仍存活的 byte string。
            let pointer = unsafe { lua_tolstring(state, -1, &mut len) };
            assert_eq!(len, 3);
            pointer.cast()
        } else if kind == 1 {
            // SAFETY：頂端是仍存活的 table。
            unsafe { lua_topointer(state, -1) }
        } else {
            std::ptr::null()
        };
        let before = snapshot(&owner);
        assert_eq!(
            protect(state, |checkpoint| prepare(checkpoint, ErrorClass::Policy)),
            Outcome::Raised(ErrorClass::Policy)
        );
        assert_eq!(
            snapshot(&owner),
            before,
            "kind={kind}: pending 必須保留同一 root 與零配置 trace"
        );
        // SAFETY：只有頂端 slot 移入 pending。
        assert_eq!(unsafe { lua_gettop(state) }, 0);
        assert_eq!(consume(state), Ok(ErrorClass::Policy));
        assert_eq!(
            snapshot(&owner),
            before,
            "kind={kind}: consume 不可配置新 root"
        );
        // SAFETY：consume 復原頂端 slot 後指標身分相同。
        unsafe {
            assert_eq!(lua_gettop(state), 1);
            if kind == 0 {
                assert_eq!(
                    lua_tolstring(state, -1, std::ptr::null_mut()).cast(),
                    original_pointer
                );
            }
            if kind == 1 {
                assert_eq!(lua_topointer(state, -1), original_pointer);
            }
            lua_settop(state, 0);
        }
    }
}

#[test]
fn callback_a1_null_busy_wrong_thread_close_and_panic_fail_closed() {
    assert_eq!(
        protect(std::ptr::null_mut(), |_| Action::Return(1)),
        Outcome::Rejected(Reject::Null)
    );
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_eq!(
        owner
            .with_vm(|_| protect(state, |_| Action::Return(1)))
            .unwrap(),
        Outcome::Rejected(Reject::Busy)
    );
    let address = state as usize;
    assert_eq!(
        std::thread::spawn(move || protect(address as *mut _, |_| Action::Return(1)))
            .join()
            .unwrap(),
        Outcome::Rejected(Reject::WrongThread)
    );
    assert_eq!(
        protect(state, |_| panic!("A1 邊界 panic")),
        Outcome::Rejected(Reject::Panic)
    );
    assert_eq!(
        protect(state, |_| Action::Raise(ErrorClass::Lua)),
        Outcome::Rejected(Reject::InvalidAction)
    );
    // SAFETY：owner 保持存活；panic 發生在 prepare 後，C 必須先讓 Rust frame 退出再取消 pending。
    unsafe { lua_pushinteger(state, 29) };
    let before = snapshot(&owner);
    assert_eq!(
        protect(state, |checkpoint| {
            assert_eq!(
                prepare(checkpoint, ErrorClass::Lua),
                Action::Raise(ErrorClass::Lua)
            );
            panic!("A1 prepare 後 panic");
        }),
        Outcome::Rejected(Reject::Panic)
    );
    assert_eq!(snapshot(&owner), before);
    assert_eq!(consume(state), Err(Reject::NoPending));

    let c_owned = luaL_newstate();
    assert!(!c_owned.is_null());
    // SAFETY：C-owned state 建立成功，直到最後一次 close 都保持有效。
    unsafe { lua_pushinteger(c_owned, 8) };
    assert_eq!(
        protect(c_owned, |_| {
            // SAFETY：active checkpoint 必須使 close 拒絕釋放。
            unsafe { lua_close(c_owned) };
            // SAFETY：拒絕 close 後 pointer 仍有效。
            assert_eq!(unsafe { lua_gettop(c_owned) }, 1);
            Action::Return(9)
        }),
        Outcome::Normal(9)
    );
    assert_eq!(
        protect(c_owned, |checkpoint| prepare(
            checkpoint,
            ErrorClass::Aborted
        )),
        Outcome::Raised(ErrorClass::Aborted)
    );
    // SAFETY：pending 期間 close 必須拒絕釋放，consume 後才可重試。
    unsafe { lua_close(c_owned) };
    assert_eq!(consume(c_owned), Ok(ErrorClass::Aborted));
    // SAFETY：state 在此呼叫前仍有效；其後不得再使用 pointer。
    unsafe { lua_close(c_owned) };
}
