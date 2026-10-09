use std::ffi::{c_char, c_int, c_void};
use std::ptr;

use rivetlua_capi::stack::{StateOwner, lua_State, lua_gettop, lua_pushinteger, lua_settop};
use rivetlua_runtime::RootKind;

type WarnFunction = unsafe extern "C" fn(*mut c_void, *const c_char, c_int);

unsafe extern "C" {
    fn lua_setwarnf(state: *mut lua_State, callback: Option<WarnFunction>, ud: *mut c_void);
    fn lua_warning(state: *mut lua_State, message: *const c_char, tocont: c_int);
    fn lua_newthread(state: *mut lua_State) -> *mut lua_State;
}

#[derive(Default)]
struct Observation {
    calls: usize,
    ud: usize,
    message: usize,
    tocont: c_int,
}

unsafe extern "C" fn observe(ud: *mut c_void, message: *const c_char, tocont: c_int) {
    // SAFETY：測試在 callback 與其 stack-local ud 存活期間同步呼叫。
    let observation = unsafe { &mut *ud.cast::<Observation>() };
    observation.calls += 1;
    observation.ud = ud as usize;
    observation.message = message as usize;
    observation.tocont = tocont;
}

#[test]
fn warning_binding_is_global_and_preserves_pointer_and_integer_b6() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let main = owner.as_ptr();
    let child = unsafe { lua_newthread(main) };
    assert!(!child.is_null());
    let mut first = Observation::default();
    let mut second = Observation::default();
    let first_ud = (&mut first as *mut Observation).cast();
    let second_ud = (&mut second as *mut Observation).cast();
    let message = c"exact warning";
    let snapshot = || {
        owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.roots().count(RootKind::Host),
                    vm.allocation_trace().next_ordinal,
                )
            })
            .unwrap()
    };
    let before = snapshot();
    // SAFETY：三個 state 與兩個 ud 均由本測試保活；字串為 NUL 結尾。
    unsafe {
        lua_warning(main, message.as_ptr(), -7);
        lua_setwarnf(main, Some(observe), first_ud);
        owner
            .with_vm(|_| {
                lua_warning(main, message.as_ptr(), -7);
                lua_setwarnf(main, Some(observe), second_ud);
            })
            .unwrap();
        assert_eq!(first.calls, 0);
        assert_eq!(second.calls, 0);
        lua_warning(child, message.as_ptr(), -7);
        assert_eq!(first.calls, 1);
        assert_eq!(first.ud, first_ud as usize);
        assert_eq!(first.message, message.as_ptr() as usize);
        assert_eq!(first.tocont, -7);
        lua_setwarnf(sibling.as_ptr(), Some(observe), second_ud);
        lua_warning(main, message.as_ptr(), 42);
        assert_eq!(first.calls, 1);
        assert_eq!(second.calls, 1);
        assert_eq!(second.tocont, 42);
        lua_setwarnf(child, None, ptr::null_mut());
        lua_warning(sibling.as_ptr(), message.as_ptr(), 1);
        lua_setwarnf(ptr::null_mut(), Some(observe), first_ud);
        lua_warning(ptr::null_mut(), message.as_ptr(), 1);
    }
    assert_eq!(second.calls, 1);
    assert_eq!(snapshot(), before);
}

#[test]
fn warning_binding_outlives_main_owner_while_sibling_is_alive_b6() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let mut observation = Observation::default();
    let ud = (&mut observation as *mut Observation).cast();
    // SAFETY：sibling 在 main owner drop 後仍持有同一 StateGroup。
    unsafe { lua_setwarnf(owner.as_ptr(), Some(observe), ud) };
    drop(owner);
    // SAFETY：sibling 與 ud 在 callback 期間有效。
    unsafe { lua_warning(sibling.as_ptr(), c"survivor".as_ptr(), 0) };
    assert_eq!(observation.calls, 1);
    assert_eq!(observation.ud, ud as usize);
    drop(sibling);
}

struct Reentry {
    owner: *const StateOwner,
    state: *mut lua_State,
    sibling: *mut lua_State,
    outer_calls: usize,
    inner_calls: usize,
    top_ok: bool,
    gc_ok: bool,
    outer_message: usize,
    inner_message: usize,
}

unsafe extern "C" fn inner(ud: *mut c_void, message: *const c_char, tocont: c_int) {
    // SAFETY：context 在同步 callback 期間存活，沒有並行存取。
    let context = unsafe { &mut *ud.cast::<Reentry>() };
    context.inner_calls += 1;
    context.inner_message = message as usize;
    context.top_ok &= tocont == 9 && unsafe { lua_gettop(context.sibling) } == 0;
}

unsafe extern "C" fn outer(ud: *mut c_void, message: *const c_char, tocont: c_int) {
    // SAFETY：context 與 owner 在同步 callback 期間存活；所有操作同一執行緒。
    let context = unsafe { &mut *ud.cast::<Reentry>() };
    context.outer_calls += 1;
    context.outer_message = message as usize;
    context.top_ok &= tocont == 3 && unsafe { lua_gettop(context.sibling) } == 0;
    unsafe { lua_pushinteger(context.sibling, 91) };
    context.top_ok &= unsafe { lua_gettop(context.sibling) } == 1;
    unsafe { lua_settop(context.sibling, 0) };
    context.gc_ok = unsafe { &*context.owner }
        .with_vm(|vm| vm.collect().is_ok())
        .unwrap_or(false);
    unsafe { lua_setwarnf(context.sibling, Some(inner), ud) };
    unsafe { lua_warning(context.state, c"nested".as_ptr(), 9) };
}

#[test]
fn warning_callback_can_reenter_replace_nest_and_collect_b6() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let mut context = Reentry {
        owner: &owner,
        state: owner.as_ptr(),
        sibling: sibling.as_ptr(),
        outer_calls: 0,
        inner_calls: 0,
        top_ok: true,
        gc_ok: false,
        outer_message: 0,
        inner_message: 0,
    };
    let ud = (&mut context as *mut Reentry).cast();
    let before_roots = owner
        .with_vm(|vm| vm.roots().count(RootKind::Host))
        .unwrap();
    // SAFETY：owner、sibling、context 與字串在同步 callback 期間有效。
    unsafe {
        lua_setwarnf(owner.as_ptr(), Some(outer), ud);
        lua_warning(owner.as_ptr(), c"outer".as_ptr(), 3);
        lua_warning(sibling.as_ptr(), c"later".as_ptr(), 9);
    }
    assert_eq!((context.outer_calls, context.inner_calls), (1, 2));
    assert_eq!(context.outer_message, c"outer".as_ptr() as usize);
    assert_eq!(context.inner_message, c"later".as_ptr() as usize);
    assert!(context.top_ok && context.gc_ok);
    assert_eq!(unsafe { lua_gettop(sibling.as_ptr()) }, 0);
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        before_roots
    );
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        0
    );
}
