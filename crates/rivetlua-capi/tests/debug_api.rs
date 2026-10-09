use std::cell::Cell;
use std::ffi::{CStr, c_char, c_int, c_void};
use std::mem::{offset_of, size_of};
use std::sync::Mutex;
use std::sync::atomic::{AtomicI32, AtomicIsize, AtomicUsize, Ordering};

use rivetlua_capi::stack::{
    StateOwner, lua_gettop, lua_pushcclosure, lua_pushinteger, lua_pushvalue, lua_rawequal,
    lua_settop, lua_tointegerx, lua_tolstring, lua_type,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeInstruction, BytecodeModule, BytecodePrototype, BytecodeSpan,
    EnvironmentSource, FrameLayout, Instruction, LuaProfile, NativeDebugCandidate, NativeLocal,
    NativePrototypeDebug, OfficialWorkBudget, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register,
    ResultMode, Value, VerifyLimits, encode_module,
};
use rivetlua_runtime::{FailPoint, HostHandle, ObjectKind, RootKind, RunOutcome};

const DEBUG_SOURCE: &[u8] =
    b"@debug_api.lua:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

#[cfg(feature = "lua54")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LuaDebug {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    istailcall: c_char,
    ftransfer: u16,
    ntransfer: u16,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

#[cfg(feature = "lua55")]
#[repr(C)]
#[derive(Clone, Copy)]
struct LuaDebug {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    extraargs: u8,
    istailcall: c_char,
    ftransfer: c_int,
    ntransfer: c_int,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

impl LuaDebug {
    fn blank() -> Self {
        // 所有欄位皆為 C 純資料；零值是測試用的未填入 lua_Debug。
        unsafe { std::mem::zeroed() }
    }

    fn sentinel() -> Self {
        let mut ar = Self::blank();
        ar.event = -123;
        ar.name = 1usize as *const c_char;
        ar.namewhat = 2usize as *const c_char;
        ar.what = 3usize as *const c_char;
        ar.source = 4usize as *const c_char;
        ar.srclen = usize::MAX;
        ar.currentline = -77;
        ar.linedefined = -88;
        ar.lastlinedefined = -99;
        ar.nups = 250;
        ar.nparams = 251;
        ar.isvararg = -1;
        #[cfg(feature = "lua55")]
        {
            ar.extraargs = 252;
        }
        ar.istailcall = -1;
        ar.ftransfer = !0;
        ar.ntransfer = !0;
        ar.short_src.fill(b'Q' as c_char);
        ar.i_ci = 13usize as *mut c_void;
        ar
    }
}

type LuaHook = unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State, *mut LuaDebug);
static HOOK_EVENTS_B10B2: AtomicUsize = AtomicUsize::new(0);
static HOOK_VALID_B10B2: AtomicI32 = AtomicI32::new(1);
static TAIL_EVENTS_B10B2: AtomicUsize = AtomicUsize::new(0);
static REPLACING_CALLS_B10B2: AtomicUsize = AtomicUsize::new(0);
static DISABLING_CALLS_B10B2: AtomicUsize = AtomicUsize::new(0);
static REENTRY_VALID_B10B2: AtomicI32 = AtomicI32::new(1);
static PROBE_HOOK_CALLS_B10B2: AtomicUsize = AtomicUsize::new(0);
static SELECTOR_EVENTS_B10C: AtomicUsize = AtomicUsize::new(0);
static SELECTOR_VALID_B10C: AtomicI32 = AtomicI32::new(1);
thread_local! {
    static REENTRY_OWNER_B10B2: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
    static REENTRY_FUNCTION_B10B2: Cell<Option<Value>> = const { Cell::new(None) };
}

unsafe extern "C" fn sample_hook_b10b2(
    _state: *mut rivetlua_capi::stack::lua_State,
    _ar: *mut LuaDebug,
) {
}

unsafe extern "C" fn probe_hook_b10b2(
    _state: *mut rivetlua_capi::stack::lua_State,
    _ar: *mut LuaDebug,
) {
    PROBE_HOOK_CALLS_B10B2.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn selector_hook_b10c(
    state: *mut rivetlua_capi::stack::lua_State,
    ar: *mut LuaDebug,
) {
    // SAFETY：fixture C driver 保活完整 lua_Debug 與 state；此處不持有跨回呼 borrow。
    unsafe {
        if ar.is_null() || (*ar).i_ci.is_null() || !(0..=4).contains(&(*ar).event) {
            SELECTOR_VALID_B10C.store(0, Ordering::SeqCst);
            return;
        }
        let event = (*ar).event;
        if (event == 2 && (*ar).currentline != 3)
            || (event != 2 && (*ar).currentline != -1)
            || lua_getinfo(state, c"nSlutr".as_ptr(), ar) != 1
            || (*ar).source.is_null()
            || CStr::from_ptr((*ar).source).to_bytes() != b"@debug_api_b10.lua"
            || (event == 4 && (*ar).istailcall == 0)
        {
            SELECTOR_VALID_B10C.store(0, Ordering::SeqCst);
        }
        SELECTOR_EVENTS_B10C.fetch_or(1usize << event, Ordering::SeqCst);
    }
}

unsafe extern "C" fn tail_hook_b10b2(
    state: *mut rivetlua_capi::stack::lua_State,
    ar: *mut LuaDebug,
) {
    // SAFETY：C trampoline 保活 hook 專用 lua_Debug，並於 callback 返回後再恢復外層 stack。
    unsafe {
        if ar.is_null() || (*ar).i_ci.is_null() || !(0..=4).contains(&(*ar).event) {
            return;
        }
        TAIL_EVENTS_B10B2.fetch_or(1usize << (*ar).event, Ordering::SeqCst);
        if (*ar).event == 4
            && lua_getinfo(state, c"nSlutr".as_ptr(), ar) == 1
            && (*ar).istailcall != 0
            && (*ar).ftransfer == 1
            && (*ar).ntransfer == 2
        {
            TAIL_EVENTS_B10B2.fetch_or(1 << 5, Ordering::SeqCst);
        }
    }
}

unsafe extern "C" fn disabling_hook_b10b2(
    state: *mut rivetlua_capi::stack::lua_State,
    _ar: *mut LuaDebug,
) {
    DISABLING_CALLS_B10B2.fetch_add(1, Ordering::SeqCst);
    // SAFETY：更新同一有效 state；目前事件使用已取樣的函式指標。
    unsafe { lua_sethook(state, None, 0, 0) };
}

unsafe extern "C" fn replacing_hook_b10b2(
    state: *mut rivetlua_capi::stack::lua_State,
    ar: *mut LuaDebug,
) {
    let calls = REPLACING_CALLS_B10B2.fetch_add(1, Ordering::SeqCst) + 1;
    // SAFETY：同一執行緒同步 C driver；thread local 的 owner/function 於外層測試保活。
    unsafe {
        if ar.is_null() || (*ar).event != 0 || calls != 1 || lua_gettop(state) != 0 {
            REENTRY_VALID_B10B2.store(0, Ordering::SeqCst);
            return;
        }
        let nested = REENTRY_FUNCTION_B10B2.with(Cell::get);
        let pushed = REENTRY_OWNER_B10B2.with(|slot| {
            let owner = slot.get();
            !owner.is_null() && nested.is_some_and(|value| (&*owner).push_value(value).is_ok())
        });
        if !pushed {
            REENTRY_VALID_B10B2.store(0, Ordering::SeqCst);
            return;
        }
        lua_pushcclosure(state, Some(noop_callback), 0);
        lua_pushinteger(state, 7);
        if rivetlua_capi_call_b4(state, 2, 1) != 0
            || REPLACING_CALLS_B10B2.load(Ordering::SeqCst) != 1
            || DISABLING_CALLS_B10B2.load(Ordering::SeqCst) != 0
            || lua_gettop(state) != 1
        {
            REENTRY_VALID_B10B2.store(0, Ordering::SeqCst);
        }
        lua_settop(state, 0);
        lua_sethook(state, Some(disabling_hook_b10b2), 0x0f, 1);
        if lua_gethookmask(state) != 0x0f {
            REENTRY_VALID_B10B2.store(0, Ordering::SeqCst);
        }
    }
}

unsafe extern "C" fn inspect_hook_b10b2(
    state: *mut rivetlua_capi::stack::lua_State,
    ar: *mut LuaDebug,
) {
    if ar.is_null() {
        HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        return;
    }
    // SAFETY：trampoline 在同步 C frame 中保活完整 lua_Debug，且 state 仍存活。
    unsafe {
        let event = (*ar).event;
        if !(0..=4).contains(&event) || (*ar).i_ci.is_null() {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
            return;
        }
        if (event == 2 && (*ar).currentline != 3 && (*ar).currentline != 4)
            || (event != 2 && (*ar).currentline != -1)
            || lua_gettop(state) != 0
        {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        }
        HOOK_EVENTS_B10B2.fetch_or(1usize << event, Ordering::SeqCst);
        if lua_getinfo(state, c"nSlutr".as_ptr(), ar) != 1 {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
            return;
        }
        if (*ar).source.is_null()
            || (*ar).what.is_null()
            || (*ar).namewhat.is_null()
            || CStr::from_ptr((*ar).source).to_bytes() != DEBUG_SOURCE
            || CStr::from_ptr((*ar).what).to_bytes() != b"Lua"
            || (*ar).nparams != 2
            || (*ar).isvararg == 0
            || (event == 0 && ((*ar).ftransfer != 1 || (*ar).ntransfer != 2))
        {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        }
        let mut stack_frame = LuaDebug::blank();
        if lua_getstack(state, 0, &mut stack_frame) != 1
            || lua_getinfo(state, c"S".as_ptr(), &mut stack_frame) != 1
            || stack_frame.what.is_null()
            || CStr::from_ptr(stack_frame.what).to_bytes() != b"Lua"
        {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        }
        if event == 0 {
            let local = lua_getlocal(state, ar, 2);
            if local.is_null()
                || CStr::from_ptr(local).to_bytes() != b"second"
                || lua_tointegerx(state, -1, std::ptr::null_mut()) != 7
            {
                HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
            }
            lua_settop(state, 0);
            lua_pushinteger(state, 9);
            let local = lua_setlocal(state, ar, 2);
            if local.is_null() || CStr::from_ptr(local).to_bytes() != b"second" {
                HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
            }
        }
        lua_pushinteger(state, 1234);
        if lua_gettop(state) != 1 {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        }
    }
}

unsafe extern "C" fn checked_argument_b10b2(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    // SAFETY：C driver 同步傳入一個整數，回傳值供外層驗證。
    unsafe {
        if lua_tointegerx(state, 1, std::ptr::null_mut()) != 9 {
            HOOK_VALID_B10B2.store(0, Ordering::SeqCst);
        }
        lua_pushinteger(state, 91);
    }
    1
}

fn assert_same_debug(left: &LuaDebug, right: &LuaDebug) {
    assert_eq!(left.event, right.event);
    assert_eq!(left.name, right.name);
    assert_eq!(left.namewhat, right.namewhat);
    assert_eq!(left.what, right.what);
    assert_eq!(left.source, right.source);
    assert_eq!(left.srclen, right.srclen);
    assert_eq!(left.currentline, right.currentline);
    assert_eq!(left.linedefined, right.linedefined);
    assert_eq!(left.lastlinedefined, right.lastlinedefined);
    assert_eq!(left.nups, right.nups);
    assert_eq!(left.nparams, right.nparams);
    assert_eq!(left.isvararg, right.isvararg);
    #[cfg(feature = "lua55")]
    assert_eq!(left.extraargs, right.extraargs);
    assert_eq!(left.istailcall, right.istailcall);
    assert_eq!(left.ftransfer, right.ftransfer);
    assert_eq!(left.ntransfer, right.ntransfer);
    assert_eq!(left.short_src, right.short_src);
    assert_eq!(left.i_ci, right.i_ci);
}

unsafe extern "C" {
    fn lua_sethook(
        state: *mut rivetlua_capi::stack::lua_State,
        callback: Option<LuaHook>,
        mask: c_int,
        count: c_int,
    );
    fn lua_gethook(state: *mut rivetlua_capi::stack::lua_State) -> Option<LuaHook>;
    fn lua_gethookmask(state: *mut rivetlua_capi::stack::lua_State) -> c_int;
    fn lua_gethookcount(state: *mut rivetlua_capi::stack::lua_State) -> c_int;
    fn lua_getstack(
        state: *mut rivetlua_capi::stack::lua_State,
        level: c_int,
        ar: *mut LuaDebug,
    ) -> c_int;
    fn lua_getinfo(
        state: *mut rivetlua_capi::stack::lua_State,
        what: *const c_char,
        ar: *mut LuaDebug,
    ) -> c_int;
    fn lua_getlocal(
        state: *mut rivetlua_capi::stack::lua_State,
        ar: *const LuaDebug,
        n: c_int,
    ) -> *const c_char;
    fn lua_setlocal(
        state: *mut rivetlua_capi::stack::lua_State,
        ar: *const LuaDebug,
        n: c_int,
    ) -> *const c_char;
    fn luaL_where(state: *mut rivetlua_capi::stack::lua_State, level: c_int);
    fn rivetlua_capi_call_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        nargs: c_int,
        nresults: c_int,
    ) -> c_int;
    fn rivetlua_capi_test_push_lua_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        selector: c_int,
    ) -> c_int;
}

#[test]
fn hook_getters_roundtrip_red_b10b2() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let sibling = owner.new_sibling().unwrap();
    // SAFETY：owner 保活 state；callback 只取位址，不會在本測試執行。
    unsafe {
        assert!(lua_gethook(state).is_none());
        assert_eq!(lua_gethookmask(state), 0);
        assert_eq!(lua_gethookcount(state), 0);
        lua_sethook(state, Some(sample_hook_b10b2), 0x1ff, 3);
        assert_eq!(
            lua_gethook(state).map(|f| f as *const () as usize),
            Some(sample_hook_b10b2 as *const () as usize)
        );
        assert_eq!(lua_gethookmask(state), 0xff);
        assert_eq!(lua_gethookcount(state), 3);
        let runtime = owner
            .with_vm(|vm| vm.debug_get_hook(None).unwrap())
            .unwrap()
            .unwrap();
        assert!(runtime.call && runtime.ret && runtime.line);
        assert_eq!(runtime.count, 3);

        lua_sethook(state, Some(sample_hook_b10b2), 0x110, 0);
        assert_eq!(lua_gethookmask(state), 0x10);
        assert_eq!(lua_gethookcount(state), 0);
        let runtime = owner
            .with_vm(|vm| vm.debug_get_hook(None).unwrap())
            .unwrap()
            .unwrap();
        assert!(!runtime.call && !runtime.ret && !runtime.line);
        assert_eq!(runtime.count, 0);

        lua_sethook(state, Some(sample_hook_b10b2), 8, -7);
        assert_eq!(lua_gethookmask(state), 8);
        assert_eq!(lua_gethookcount(state), -7);
        assert_eq!(
            owner
                .with_vm(|vm| vm.debug_get_hook(None).unwrap().unwrap().count)
                .unwrap(),
            0
        );

        lua_sethook(state, Some(inspect_hook_b10b2), 4, 1);
        assert_eq!(
            lua_gethook(state).map(|f| f as *const () as usize),
            Some(inspect_hook_b10b2 as *const () as usize)
        );
        assert_eq!(lua_gethookmask(state), 4);
        assert_eq!(lua_gethookcount(state), 1);

        lua_sethook(sibling.as_ptr(), Some(sample_hook_b10b2), 1, 4);
        assert!(lua_gethook(sibling.as_ptr()).is_none());
        assert_eq!(lua_gethookmask(sibling.as_ptr()), 0);
        assert_eq!(lua_gethookcount(sibling.as_ptr()), 0);
        assert_eq!(lua_gethookmask(state), 4);

        lua_sethook(state, None, 0xff, -3);
        assert!(lua_gethook(state).is_none());
        assert_eq!(lua_gethookmask(state), 0);
        assert_eq!(lua_gethookcount(state), -3);
        assert!(
            owner
                .with_vm(|vm| vm.debug_get_hook(None).unwrap())
                .unwrap()
                .is_none()
        );

        lua_sethook(state, Some(sample_hook_b10b2), 0, 5);
        assert!(lua_gethook(state).is_none());
        assert_eq!(lua_gethookmask(state), 0);
        assert_eq!(lua_gethookcount(state), 5);
    }
}

#[test]
fn hook_main_and_coroutine_bindings_are_independent_b10b2() {
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let owner = StateOwner::new().unwrap();
    let (coroutine, object, environment_root) = owner
        .with_vm(|vm| {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            let function = {
                let mut execution = vm
                    .load_with_environment(suspended_fixture(profile), Value::Object(environment))
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("fixture 須建立 Lua closure")
                };
                values[0]
            };
            let Value::Object(closure) = function else {
                panic!("fixture 須為 closure")
            };
            let closure_root = vm.add_root(RootKind::Host, closure).unwrap();
            let coroutine = vm.new_coroutine(function).unwrap();
            vm.remove_root(closure_root).unwrap();
            let Value::Object(object) = coroutine.as_value(vm).unwrap() else {
                panic!("須為 coroutine object")
            };
            (coroutine, object, environment_root)
        })
        .unwrap();
    let thread = owner
        .debug_test_attach_suspended_coroutine_once(object)
        .unwrap();
    // SAFETY：main/thread 擁有獨立 StateControl，且 coroutine HostHandle 保活 target。
    unsafe {
        lua_sethook(owner.as_ptr(), Some(sample_hook_b10b2), 1, 2);
        lua_sethook(thread.as_ptr(), Some(inspect_hook_b10b2), 6, 7);
        assert_eq!(lua_gethookmask(owner.as_ptr()), 1);
        assert_eq!(lua_gethookcount(owner.as_ptr()), 2);
        assert_eq!(lua_gethookmask(thread.as_ptr()), 6);
        assert_eq!(lua_gethookcount(thread.as_ptr()), 7);
        assert_eq!(
            lua_gethook(thread.as_ptr()).map(|f| f as *const () as usize),
            Some(inspect_hook_b10b2 as *const () as usize)
        );
        owner
            .with_vm(|vm| {
                let main = vm.debug_get_hook(None).unwrap().unwrap();
                let child = vm.debug_get_hook(Some(object)).unwrap().unwrap();
                assert!(main.call && !main.ret && !main.line && main.count == 0);
                assert!(!child.call && child.ret && child.line && child.count == 0);
                vm.collect().unwrap();
            })
            .unwrap();
        lua_sethook(thread.as_ptr(), None, 0, -9);
        assert_eq!(lua_gethookcount(thread.as_ptr()), -9);
        assert_eq!(lua_gethookmask(owner.as_ptr()), 1);
        owner
            .with_vm(|vm| {
                assert!(vm.debug_get_hook(Some(object)).unwrap().is_none());
                assert!(vm.debug_get_hook(None).unwrap().is_some());
                vm.collect().unwrap();
            })
            .unwrap();
        lua_sethook(owner.as_ptr(), None, 0, 0);
    }
    drop(thread);
    drop(coroutine);
    owner
        .with_vm(|vm| vm.remove_root(environment_root).unwrap())
        .unwrap();
}

#[test]
fn hook_setter_root_refusal_keeps_binding_and_runtime_atomic_b10b2() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    // SAFETY：RootReserve 拒絕僅作用於 runtime hook 交易；void API 必須保留舊設定。
    unsafe {
        lua_sethook(state, Some(sample_hook_b10b2), 0x0f, 4);
        assert!(lua_gethook(state).is_none());
        assert_eq!(lua_gethookmask(state), 0);
        assert_eq!(lua_gethookcount(state), 0);
        assert!(
            owner
                .with_vm(|vm| vm.debug_get_hook(None).unwrap())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
        lua_sethook(state, Some(sample_hook_b10b2), 0x0f, 4);
        assert_eq!(lua_gethookmask(state), 0x0f);
        assert_eq!(lua_gethookcount(state), 4);
        assert_eq!(
            owner
                .with_vm(|vm| vm.debug_get_hook(None).unwrap().unwrap().count)
                .unwrap(),
            4
        );
    }
}

#[test]
fn hook_callback_frame_and_token_refusal_retry_b10b2() {
    // 兩個 profile 的實測交易序列：offset 30 是 CallbackFrame 容量 320 bytes；
    // offset 31 是 hook overlay 容量 2880 bytes；offset 32 是 i_ci token 136 bytes。
    // 三者都在 hook callback 前失敗，交易須恢復外層 stack 並可立即重試。
    for (offset, bytes) in [
        (30_u64, 320_usize),
        (31_u64, 2880_usize),
        (32_u64, 136_usize),
    ] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：私有 B4 fixture 與 C driver 均以同步 owner 保活；失敗後清空 C stack 重試。
        unsafe {
            assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
            lua_pushcclosure(state, Some(noop_callback), 0);
            lua_pushinteger(state, 7);
            lua_sethook(state, Some(probe_hook_b10b2), 0x0f, 1);
            PROBE_HOOK_CALLS_B10B2.store(0, Ordering::SeqCst);
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            let first = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            let before = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.roots().total_count(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(first + offset))
                .unwrap();
            let status = rivetlua_capi_call_b4(state, 2, 1);
            let trace = owner.with_vm(|vm| vm.allocation_trace()).unwrap();
            let after = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.roots().total_count(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            let collected = owner
                .with_vm(|vm| {
                    vm.collect().unwrap();
                    vm.ledger_snapshot()
                })
                .unwrap();
            assert_eq!(status, -1, "offset {offset}");
            assert_eq!(PROBE_HOOK_CALLS_B10B2.load(Ordering::SeqCst), 0);
            let attempt = trace.last_failure.unwrap().attempt;
            assert_eq!(attempt.ordinal, first + offset);
            assert_eq!(attempt.bytes, bytes);
            assert_eq!(attempt.site.file, "crates/rivetlua-runtime/src/heap.rs");
            assert_eq!(
                after.0.host_allocation_bytes,
                before.0.host_allocation_bytes
            );
            assert_eq!(after.0.reserved, 0);
            assert_eq!(
                collected.host_allocation_bytes,
                before.0.host_allocation_bytes
            );
            assert_eq!(collected.reserved, 0);
            assert!(collected.lua_heap_bytes < after.0.lua_heap_bytes);
            assert_eq!((after.1, after.2), (before.1, before.2));
            let mut frame = LuaDebug::blank();
            assert_eq!(lua_getstack(state, 0, &mut frame), 0);
            assert_eq!(lua_gethookmask(state), 0x0f);
            assert_eq!(lua_gethookcount(state), 1);
            assert_eq!(
                owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
                0
            );
            assert_eq!(lua_gettop(state), 3);
            assert_eq!(
                rivetlua_capi_call_b4(state, 2, 1),
                0,
                "offset {offset} retry"
            );
            assert!(PROBE_HOOK_CALLS_B10B2.load(Ordering::SeqCst) > 0);
            assert_eq!(
                owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
                0
            );
        }
    }
}

#[test]
fn native_debug_tail_fixture_selector_has_all_hook_events_b10c() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    SELECTOR_EVENTS_B10C.store(0, Ordering::SeqCst);
    SELECTOR_VALID_B10C.store(1, Ordering::SeqCst);
    // SAFETY：私有 selector 只建立固定已驗證 bytecode，C driver 同步保活 state。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 2), 1);
        lua_pushvalue(state, 1);
        lua_pushcclosure(state, Some(noop_callback), 0);
        lua_sethook(state, Some(selector_hook_b10c), 0x0f, 1);
        assert_eq!(rivetlua_capi_call_b4(state, 2, 1), 0);
        // 尾呼叫改由下一個 Lua frame 發出 tail event；此路徑不走普通 Return。
        assert_eq!(SELECTOR_EVENTS_B10C.load(Ordering::SeqCst) & 0x1f, 0x1d);
        assert_eq!(SELECTOR_VALID_B10C.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn hook_dispatches_through_c_driver_red_b10b2() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let fixture_root = owner
        .with_vm(|vm| {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            let output = {
                let mut execution = vm
                    .load_with_environment(suspended_fixture(profile), Value::Object(environment))
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("fixture 須回傳 Lua closure")
                };
                values[0]
            };
            let Value::Object(function) = output else {
                panic!("fixture 須回傳 closure")
            };
            let root = HostHandle::<Value>::new(vm, function).unwrap();
            vm.remove_root(environment_root).unwrap();
            root
        })
        .unwrap();
    let fixture = owner
        .with_vm(|vm| fixture_root.as_value(vm).unwrap())
        .unwrap();
    owner.push_value(fixture).unwrap();
    drop(fixture_root);
    HOOK_EVENTS_B10B2.store(0, Ordering::SeqCst);
    HOOK_VALID_B10B2.store(1, Ordering::SeqCst);
    // SAFETY：先建立 fixture，之後才啟用 hook；driver 在 C checkpoint 中呼叫 callback。
    unsafe {
        lua_pushcclosure(state, Some(checked_argument_b10b2), 0);
        lua_pushinteger(state, 7);
        lua_sethook(state, Some(inspect_hook_b10b2), 0x0f, 1);
        assert_eq!(rivetlua_capi_call_b4(state, 2, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 91);
        let events = HOOK_EVENTS_B10B2.load(Ordering::SeqCst);
        assert_eq!(events & 0x0f, 0x0f, "實際 hook event bits {events:#x}");
        assert_eq!(HOOK_VALID_B10B2.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn hook_tail_call_event_uses_real_c_dispatch_b10b2() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let fixture_root = owner
        .with_vm(|vm| {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            let output = {
                let mut execution = vm
                    .load_with_environment(
                        suspended_fixture_with_tail(profile, true),
                        Value::Object(environment),
                    )
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("tail fixture 須回傳 Lua closure")
                };
                values[0]
            };
            let Value::Object(function) = output else {
                panic!("tail fixture 須回傳 closure")
            };
            let root = HostHandle::<Value>::new(vm, function).unwrap();
            vm.remove_root(environment_root).unwrap();
            root
        })
        .unwrap();
    let fixture = owner
        .with_vm(|vm| fixture_root.as_value(vm).unwrap())
        .unwrap();
    owner.push_value(fixture).unwrap();
    drop(fixture_root);
    TAIL_EVENTS_B10B2.store(0, Ordering::SeqCst);
    // SAFETY：tail fixture 進入 C closure；hook 在 C driver 中以新 kind 呼叫。
    unsafe {
        lua_pushvalue(state, 1);
        lua_pushcclosure(state, Some(noop_callback), 0);
        lua_sethook(state, Some(tail_hook_b10b2), 0x0f, 1);
        assert_eq!(rivetlua_capi_call_b4(state, 2, 1), 0);
        let events = TAIL_EVENTS_B10B2.load(Ordering::SeqCst);
        assert_ne!(events & (1 << 4), 0, "tail fixture events {events:#x}");
        assert_ne!(events & (1 << 5), 0);
    }
}

#[test]
fn hook_nested_call_suppresses_reentry_and_replacement_b10b2() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let fixture_root = owner
        .with_vm(|vm| {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            let output = {
                let mut execution = vm
                    .load_with_environment(suspended_fixture(profile), Value::Object(environment))
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("fixture 須回傳 Lua closure")
                };
                values[0]
            };
            let Value::Object(function) = output else {
                panic!("fixture 須回傳 closure")
            };
            let root = HostHandle::<Value>::new(vm, function).unwrap();
            vm.remove_root(environment_root).unwrap();
            root
        })
        .unwrap();
    let fixture = owner
        .with_vm(|vm| fixture_root.as_value(vm).unwrap())
        .unwrap();
    owner.push_value(fixture).unwrap();
    REPLACING_CALLS_B10B2.store(0, Ordering::SeqCst);
    DISABLING_CALLS_B10B2.store(0, Ordering::SeqCst);
    REENTRY_VALID_B10B2.store(1, Ordering::SeqCst);
    REENTRY_OWNER_B10B2.with(|slot| slot.set(&owner));
    REENTRY_FUNCTION_B10B2.with(|slot| slot.set(Some(fixture)));
    drop(fixture_root);
    // SAFETY：外層 Lua closure 由 C stack 保根；hook 在同一 C driver 中巢狀呼叫。
    unsafe {
        lua_pushcclosure(state, Some(noop_callback), 0);
        lua_pushinteger(state, 7);
        lua_sethook(state, Some(replacing_hook_b10b2), 0x0f, 1);
        assert_eq!(rivetlua_capi_call_b4(state, 2, 1), 0);
        assert_eq!(REPLACING_CALLS_B10B2.load(Ordering::SeqCst), 1);
        assert_eq!(DISABLING_CALLS_B10B2.load(Ordering::SeqCst), 1);
        assert_eq!(REENTRY_VALID_B10B2.load(Ordering::SeqCst), 1);
        assert!(lua_gethook(state).is_none());
        assert_eq!(lua_gethookmask(state), 0);
        assert_eq!(lua_gettop(state), 1);
    }
    REENTRY_FUNCTION_B10B2.with(|slot| slot.set(None));
    REENTRY_OWNER_B10B2.with(|slot| slot.set(std::ptr::null()));
}

fn suspended_fixture(profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    suspended_fixture_with_tail(profile, false)
}

fn suspended_fixture_with_tail(profile: LuaProfile, tail: bool) -> rivetlua_core::VerifiedModule {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let root_env = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let child_env = BytecodeBindingId {
        function: 1,
        ordinal: 0,
    };
    let first = BytecodeBindingId {
        function: 1,
        ordinal: 1,
    };
    let second = BytecodeBindingId {
        function: 1,
        ordinal: 2,
    };
    let instructions = |items: Vec<Instruction>| {
        items
            .into_iter()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect()
    };
    let root = BytecodePrototype {
        id: ProtoId(0),
        function: 0,
        parent: None,
        span,
        register_count: 4,
        parameter_count: 0,
        is_variadic: false,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(4),
            dynamic_top: Register(4),
            return_base: Register(0),
            environment: Register(3),
            environment_source: EnvironmentSource::RootExternal,
            registers_start_as_nil: true,
        },
        global_environment: Register(3),
        global_environment_binding: root_env,
        binding_registers: vec![(root_env, Register(3))],
        constants: vec![],
        upvalues: vec![],
        instructions: instructions(vec![
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]),
        close_paths: vec![],
    };
    let child = BytecodePrototype {
        id: ProtoId(1),
        function: 1,
        parent: Some(ProtoId(0)),
        span,
        register_count: 4,
        parameter_count: 2,
        is_variadic: true,
        named_vararg: None,
        frame: FrameLayout {
            register_limit: 4096,
            initial_top: Register(4),
            dynamic_top: Register(4),
            return_base: Register(0),
            environment: Register(3),
            environment_source: EnvironmentSource::ParentFrame {
                parent: ProtoId(0),
                register: Register(3),
            },
            registers_start_as_nil: true,
        },
        global_environment: Register(3),
        global_environment_binding: child_env,
        binding_registers: vec![
            (child_env, Register(3)),
            (first, Register(1)),
            (second, Register(2)),
        ],
        constants: vec![],
        upvalues: vec![],
        instructions: instructions({
            let mut code = vec![
                Instruction::Move {
                    dest: Register(0),
                    src: Register(1),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(2),
                },
            ];
            if tail {
                code.push(Instruction::TailCall {
                    base: Register(0),
                    arg_count: 1,
                    result_mode: ResultMode::All,
                });
            } else {
                code.push(Instruction::Call {
                    base: Register(0),
                    arg_count: 1,
                    result_mode: ResultMode::Fixed(1),
                });
                code.push(Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                });
            }
            code
        }),
        close_paths: vec![],
    };
    let limits = VerifyLimits::default();
    let encoded = encode_module(
        BytecodeModule {
            format_version: RVLU_V2,
            profile,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0)), (1, ProtoId(1))],
            prototypes: vec![root, child],
        },
        profile,
        &limits,
    )
    .unwrap();
    let metadata = NativeDebugCandidate {
        source_name: DEBUG_SOURCE.to_vec(),
        prototypes: vec![
            NativePrototypeDebug {
                prototype: ProtoId(0),
                line_defined: 0,
                last_line_defined: 0,
                lines: vec![1, 1],
                locals: vec![],
                upvalue_names: vec![],
                max_active_locals: 0,
            },
            NativePrototypeDebug {
                prototype: ProtoId(1),
                line_defined: 2,
                last_line_defined: 4,
                lines: if tail {
                    vec![3, 3, 3]
                } else {
                    vec![3, 3, 3, 4]
                },
                locals: vec![
                    NativeLocal {
                        binding: first,
                        register: Register(1),
                        slot: 0,
                        initialized_pc: 0,
                        start_pc: 0,
                        end_pc: if tail { 3 } else { 4 },
                        name: b"first".to_vec(),
                    },
                    NativeLocal {
                        binding: second,
                        register: Register(2),
                        slot: 1,
                        initialized_pc: 0,
                        start_pc: 0,
                        end_pc: if tail { 3 } else { 4 },
                        name: b"second".to_vec(),
                    },
                ],
                upvalue_names: vec![],
                max_active_locals: 2,
            },
        ],
        temporaries: vec![],
        initializer_temporaries: vec![],
        non_counted_pcs: vec![],
    };
    encoded
        .with_native_debug(metadata, &limits, &mut OfficialWorkBudget::new(u64::MAX))
        .unwrap()
        .verified()
        .clone()
}

static CALLBACK_LEVEL: AtomicI32 = AtomicI32::new(-1);
static SIBLING_STATE: AtomicUsize = AtomicUsize::new(0);
static SIBLING_RESULT: AtomicI32 = AtomicI32::new(-1);
static NESTED_RESULT: AtomicI32 = AtomicI32::new(-1);
static NESTED_TOKEN: AtomicUsize = AtomicUsize::new(0);
static ALLOCATION_RESULT: AtomicI32 = AtomicI32::new(-1);
static LIVE_ALLOCATIONS: AtomicIsize = AtomicIsize::new(0);
static ALLOCATOR_TEST_LOCK: Mutex<()> = Mutex::new(());
thread_local! {
    static CALLBACK_OWNER: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
}

unsafe extern "C" fn noop_callback(_state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    0
}

unsafe extern "C" {
    fn malloc(size: usize) -> *mut c_void;
    fn realloc(pointer: *mut c_void, size: usize) -> *mut c_void;
    fn free(pointer: *mut c_void);
}

unsafe extern "C" fn tracking_allocator(
    _ud: *mut c_void,
    pointer: *mut c_void,
    _old_size: usize,
    new_size: usize,
) -> *mut c_void {
    if new_size == 0 {
        if !pointer.is_null() {
            LIVE_ALLOCATIONS.fetch_sub(1, Ordering::SeqCst);
            // SAFETY：pointer 只來自此 callback 的 malloc/realloc，釋放一次。
            unsafe { free(pointer) };
        }
        return std::ptr::null_mut();
    }
    if pointer.is_null() {
        // SAFETY：非零大小向 C allocator 申請新 token。
        let result = unsafe { malloc(new_size) };
        if !result.is_null() {
            LIVE_ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        result
    } else {
        // SAFETY：存活 token 經同一 C allocator resize；失敗時舊 token 仍存活。
        unsafe { realloc(pointer, new_size) }
    }
}

unsafe extern "C" fn allocation_probe(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    let injected = CALLBACK_OWNER.with(|current| {
        let pointer = current.get();
        if pointer.is_null() {
            return false;
        }
        // SAFETY：測試在同一執行緒同步保活 owner，callback 返回前不移除它。
        unsafe { &*pointer }
            .with_vm(|vm| {
                let ordinal = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(ordinal);
            })
            .is_ok()
    });
    let mut failed = LuaDebug::blank();
    let mut retry = LuaDebug::blank();
    // SAFETY：state 在同步 callback 內有效，兩個 ar 皆為完整 profile ABI。
    unsafe {
        let top = lua_gettop(state);
        let first = lua_getstack(state, 0, &mut failed);
        let unchanged = failed.i_ci.is_null() && lua_gettop(state) == top;
        let second = lua_getstack(state, 0, &mut retry);
        ALLOCATION_RESULT.store(
            i32::from(injected && first == 0 && unchanged && second == 1 && !retry.i_ci.is_null()),
            Ordering::SeqCst,
        );
    }
    0
}

unsafe extern "C" fn inspect_callback(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    let mut ar = LuaDebug::blank();
    // SAFETY：C driver 同步保活 state 與 callback；ar 是完整 profile ABI 結構。
    unsafe {
        CALLBACK_LEVEL.store(lua_getstack(state, 0, &mut ar), Ordering::SeqCst);
        assert!(!ar.i_ci.is_null());
        assert_eq!(lua_getinfo(state, c"nSlutrfL".as_ptr(), &mut ar), 1);
        assert_eq!(CStr::from_ptr(ar.what).to_bytes(), b"C");
        assert_eq!(lua_type(state, -1), 0);
        lua_settop(state, -2);
        let top = lua_gettop(state);
        let name = lua_getlocal(state, &ar, 1);
        assert!(!name.is_null());
        assert_eq!(lua_gettop(state), top + 1);
        lua_settop(state, top);
        lua_pushinteger(state, 99);
        assert!(lua_setlocal(state, &ar, 0).is_null());
        assert_eq!(lua_gettop(state), top + 1);
        let replaced = lua_setlocal(state, &ar, 1);
        assert!(!replaced.is_null());
        assert_eq!(lua_gettop(state), top);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 99);
        luaL_where(state, 0);
        let mut where_len = usize::MAX;
        let where_pointer = lua_tolstring(state, -1, &mut where_len);
        assert!(!where_pointer.is_null());
        assert_eq!(
            std::slice::from_raw_parts(where_pointer.cast::<u8>(), where_len),
            b""
        );
        lua_settop(state, top);
        lua_pushinteger(state, 42);
    }
    1
}

unsafe extern "C" fn inspect_sibling(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    let sibling = SIBLING_STATE.load(Ordering::SeqCst) as *mut rivetlua_capi::stack::lua_State;
    let mut active = LuaDebug::blank();
    let mut foreign = LuaDebug::blank();
    // SAFETY：測試擁有者保活兩個同 group state，debug API 僅檢視自己的 frame/token。
    unsafe {
        let own = lua_getstack(state, 0, &mut active);
        let other = lua_getstack(sibling, 0, &mut foreign);
        foreign.i_ci = active.i_ci;
        let rejected = lua_getinfo(sibling, c"nSl".as_ptr(), &mut foreign) == 0
            && lua_getlocal(sibling, &foreign, 1).is_null()
            && lua_setlocal(sibling, &foreign, 1).is_null();
        SIBLING_RESULT.store(
            i32::from(own == 1 && other == 0 && rejected),
            Ordering::SeqCst,
        );
    }
    0
}

unsafe extern "C" fn nested_inner(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    let mut kinds = [LuaDebug::blank(), LuaDebug::blank(), LuaDebug::blank()];
    // SAFETY：三個 frame 同屬同步 C driver；所有 ar 均為完整 profile ABI 結構。
    unsafe {
        let mut valid = true;
        for (level, ar) in kinds.iter_mut().enumerate() {
            valid &= lua_getstack(state, level as c_int, ar) == 1;
            valid &= lua_getinfo(state, c"S".as_ptr(), ar) == 1;
        }
        if valid && kinds.iter().all(|ar| !ar.what.is_null()) {
            valid &= CStr::from_ptr(kinds[0].what).to_bytes() == b"C";
            valid &= CStr::from_ptr(kinds[1].what).to_bytes() == b"Lua";
            valid &= CStr::from_ptr(kinds[2].what).to_bytes() == b"C";
        } else {
            valid = false;
        }
        NESTED_TOKEN.store(kinds[0].i_ci as usize, Ordering::SeqCst);
        let top = lua_gettop(state);
        let name = lua_getlocal(state, &kinds[2], 1);
        valid &= !name.is_null();
        if !name.is_null() {
            valid &= CStr::from_ptr(name).to_bytes() == b"(C temporary)";
        }
        valid &= lua_gettop(state) == top + 1
            && lua_type(state, -1) == 3
            && lua_tointegerx(state, -1, std::ptr::null_mut()) == 5;
        let collected = CALLBACK_OWNER.with(|current| {
            let pointer = current.get();
            !pointer.is_null()
                && (&*pointer)
                    .with_vm(|vm| vm.collect())
                    .is_ok_and(|result| result.is_ok())
        });
        valid &= collected && lua_type(state, -1) == 3;
        lua_settop(state, top);
        lua_pushinteger(state, 99);
        valid &= !lua_setlocal(state, &kinds[2], 1).is_null() && lua_gettop(state) == top;
        NESTED_RESULT.store(i32::from(valid), Ordering::SeqCst);
        lua_pushinteger(state, 41);
    }
    1
}

unsafe extern "C" fn nested_outer(state: *mut rivetlua_capi::stack::lua_State) -> c_int {
    #[cfg(feature = "lua54")]
    const UPVALUE_1: c_int = -1_001_001;
    #[cfg(feature = "lua55")]
    const UPVALUE_1: c_int = -(c_int::MAX / 2 + 1000) - 1;
    // SAFETY：私有 B4 C driver 在同一 parked core 內同步執行 Lua → C。
    unsafe {
        lua_pushinteger(state, 5);
        lua_pushvalue(state, UPVALUE_1);
        lua_pushcclosure(state, Some(nested_inner), 0);
        lua_pushinteger(state, 7);
        if rivetlua_capi_call_b4(state, 2, 1) != 0 {
            return -1;
        }
        if lua_tointegerx(state, 1, std::ptr::null_mut()) != 99 {
            NESTED_RESULT.store(0, Ordering::SeqCst);
        }
    }
    1
}

#[test]
fn profile_layout_and_callback_frame_basics_b10b1() {
    assert_eq!(size_of::<[c_char; 60]>(), 60);
    #[cfg(feature = "lua54")]
    {
        assert_eq!(offset_of!(LuaDebug, ftransfer), 64);
        assert_eq!(offset_of!(LuaDebug, short_src), 68);
        assert_eq!(offset_of!(LuaDebug, i_ci), 128);
        assert_eq!(size_of::<LuaDebug>(), 136);
    }
    #[cfg(feature = "lua55")]
    {
        assert_eq!(offset_of!(LuaDebug, extraargs), 63);
        assert_eq!(offset_of!(LuaDebug, istailcall), 64);
        assert_eq!(offset_of!(LuaDebug, ftransfer), 68);
        assert_eq!(offset_of!(LuaDebug, ntransfer), 72);
        assert_eq!(offset_of!(LuaDebug, short_src), 76);
        assert_eq!(offset_of!(LuaDebug, i_ci), 136);
        assert_eq!(size_of::<LuaDebug>(), 144);
    }
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state，私有 C driver 同步完成 callback。
    unsafe {
        lua_pushcclosure(state, Some(inspect_callback), 0);
        lua_pushinteger(state, 7);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(CALLBACK_LEVEL.load(Ordering::SeqCst), 1);
        assert_eq!(lua_gettop(state), 1);
    }
}

#[test]
fn empty_stack_and_invalid_token_are_atomic_b10b1() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut ar = LuaDebug::blank();
    ar.i_ci = 0x12345usize as *mut c_void;
    // SAFETY：owner 保活 state；無 frame 時函式應 fail-closed。
    unsafe {
        assert_eq!(lua_getstack(state, -1, &mut ar), 0);
        assert_eq!(lua_getstack(state, 0, &mut ar), 0);
        assert_eq!(ar.i_ci as usize, 0x12345);
        assert_eq!(lua_getinfo(state, c"nSlutrfL".as_ptr(), &mut ar), 0);
        assert!(lua_getlocal(state, &ar, 1).is_null());
        assert!(lua_setlocal(state, &ar, 1).is_null());
        luaL_where(state, 0);
        assert_eq!(lua_gettop(state), 1);
        let mut length = usize::MAX;
        let text = lua_tolstring(state, -1, &mut length);
        assert!(!text.is_null());
        assert_eq!(length, 0);
    }
}

#[test]
fn function_only_allocation_refusal_preserves_top_and_retries_b10b1() {
    let mut failures = 0;
    let mut attempts = Vec::new();
    for offset in 0..64 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：填滿既有 40-slot 容量，使 >SfL 的最終 41-slot 預備也有配置點。
        unsafe {
            assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
            for filler in 0..38 {
                lua_pushinteger(state, filler);
            }
            lua_pushvalue(state, 1);
            assert_eq!(lua_gettop(state), 40);
        }
        let before = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    RootKind::ALL.map(|kind| vm.roots().count(kind)),
                )
            })
            .unwrap();
        let first = owner
            .with_vm(|vm| {
                let first = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(first + offset);
                first
            })
            .unwrap();
        let mut ar = LuaDebug::sentinel();
        let before_ar = ar;
        // SAFETY：ar 是完整 ABI；任一拒絕不得消耗原函式或發布欄位。
        let result = unsafe { lua_getinfo(state, c">SfL".as_ptr(), &mut ar) };
        if result == 1 {
            // SAFETY：第一個未命中的 ordinal 已完成 f/L；f 與原函式相同。
            unsafe {
                assert_eq!(lua_gettop(state), 41);
                assert_eq!(lua_rawequal(state, 1, 40), 1);
                assert_eq!(lua_type(state, 41), 5);
            }
            assert!(failures >= 5, "配置點覆蓋不足：{failures}");
            eprintln!("B10b1 >SfL 配置拒絕命中 {failures} 個 ordinal：{attempts:?}");
            return;
        }
        assert_eq!(result, 0, "offset {offset}");
        failures += 1;
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap()
            .expect("每個失敗 offset 都應命中注入點");
        assert_eq!(failure.attempt.ordinal, first + offset);
        attempts.push(failure.attempt);
        // SAFETY：失敗後 top/function 未變，未請求欄位也未被寫入。
        unsafe {
            assert_eq!(lua_gettop(state), 40, "offset {offset}");
            assert_eq!(lua_type(state, 40), 6, "offset {offset}");
        }
        assert_same_debug(&ar, &before_ar);
        let after = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    RootKind::ALL.map(|kind| vm.roots().count(kind)),
                )
            })
            .unwrap();
        assert_eq!(after.0.committed, before.0.committed, "offset {offset}");
        assert_eq!(after.0.reserved, 0, "offset {offset}");
        assert_eq!(after.1, before.1, "offset {offset}");
        assert_eq!(after.2, before.2, "offset {offset}");
        // SAFETY：單次拒絕消耗後，相同 state 必須能完整發布 f 與 L。
        unsafe {
            assert_eq!(lua_getinfo(state, c">SfL".as_ptr(), &mut ar), 1);
            assert_eq!(lua_gettop(state), 41);
            assert_eq!(lua_rawequal(state, 1, 40), 1);
            assert_eq!(lua_type(state, 41), 5);
        }
    }
    panic!("64 個 ordinal 仍未遇到第一個未命中的配置點");
}

#[test]
fn c_function_local_invalid_and_function_only_parameter_name_b10b1() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；C 函式沒有 Lua 參數名稱，null ar 不得改 stack。
    unsafe {
        lua_pushcclosure(state, Some(noop_callback), 0);
        assert!(lua_getlocal(state, std::ptr::null(), 1).is_null());
        assert_eq!(lua_gettop(state), 1);
        let mut ar = LuaDebug::blank();
        ar.i_ci = 0x12345usize as *mut c_void;
        lua_pushinteger(state, 99);
        assert!(lua_getlocal(state, &ar, 1).is_null());
        assert!(lua_setlocal(state, &ar, 1).is_null());
        assert_eq!(lua_gettop(state), 2);
    }
}

#[test]
fn token_allocation_refusal_and_callback_release_b10b1() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    ALLOCATION_RESULT.store(-1, Ordering::SeqCst);
    CALLBACK_OWNER.with(|current| current.set(&owner));
    // SAFETY：owner 於 callback 期間存活；拒絕僅作用於第一個 debug 交易。
    unsafe {
        lua_pushcclosure(state, Some(allocation_probe), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 0), 0);
        assert_eq!(lua_gettop(state), 0);
    }
    CALLBACK_OWNER.with(|current| current.set(std::ptr::null()));
    assert_eq!(ALLOCATION_RESULT.load(Ordering::SeqCst), 1);
    assert_eq!(
        owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
        0
    );
}

#[test]
fn debug_backing_and_token_allocator_tokens_release_on_close_b10b1() {
    let _guard = ALLOCATOR_TEST_LOCK.lock().unwrap();
    let baseline = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
    let owner = StateOwner::new_with_allocator(tracking_allocator, std::ptr::null_mut()).unwrap();
    let state = owner.as_ptr();
    let mut ar = LuaDebug::blank();
    // SAFETY：owner 保活 state；函式-only info 配置 source/name backing 與 f/L stack 值。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        assert_eq!(lua_getinfo(state, c">nSfL".as_ptr(), &mut ar), 1);
        lua_settop(state, 0);
        lua_pushcclosure(state, Some(inspect_callback), 0);
        lua_pushinteger(state, 4);
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
    }
    assert!(LIVE_ALLOCATIONS.load(Ordering::SeqCst) > baseline);
    drop(owner);
    assert_eq!(LIVE_ALLOCATIONS.load(Ordering::SeqCst), baseline);
}

#[test]
fn hook_gc_bridge_and_allocator_release_b10b2() {
    let _guard = ALLOCATOR_TEST_LOCK.lock().unwrap();
    let baseline = LIVE_ALLOCATIONS.load(Ordering::SeqCst);
    let owner = StateOwner::new_with_allocator(tracking_allocator, std::ptr::null_mut()).unwrap();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let state = owner.as_ptr();
    // SAFETY：hook pointer 僅由本 state 保管；collect 在同步無借用期間執行。
    unsafe {
        lua_sethook(state, Some(sample_hook_b10b2), 0x0f, 1);
        let first = owner
            .with_vm(|vm| vm.debug_get_hook(None).unwrap().unwrap().function)
            .unwrap();
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(first), Ok(ObjectKind::CClosure));
            })
            .unwrap();
        lua_sethook(state, Some(inspect_hook_b10b2), 2, 0);
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.debug_get_hook(None).unwrap().unwrap().function, first);
                assert_eq!(vm.object_kind(first), Ok(ObjectKind::CClosure));
            })
            .unwrap();
        lua_sethook(state, None, 0, 0);
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert!(vm.debug_get_hook(None).unwrap().is_none());
                assert_eq!(vm.object_kind(first), Ok(ObjectKind::CClosure));
            })
            .unwrap();
    }
    assert!(LIVE_ALLOCATIONS.load(Ordering::SeqCst) > baseline);
    drop(owner);
    assert_eq!(LIVE_ALLOCATIONS.load(Ordering::SeqCst), baseline);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn suspended_coroutine_local_vararg_write_and_revision_b10b1() {
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let owner = StateOwner::new().unwrap();
    let (coroutine, object, environment_root, function) = owner
        .with_vm(|vm| {
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_coroutine_builtins(environment).unwrap();
            let coroutine_key = vm.allocate_byte_string(b"coroutine").unwrap();
            let Value::Object(coroutine_table) = vm
                .raw_get(environment, Value::Object(coroutine_key))
                .unwrap()
            else {
                panic!("須有 coroutine table")
            };
            let yield_key = vm.allocate_byte_string(b"yield").unwrap();
            let yield_function = vm
                .raw_get(coroutine_table, Value::Object(yield_key))
                .unwrap();
            let function = {
                let mut execution = vm
                    .load_with_environment(suspended_fixture(profile), Value::Object(environment))
                    .unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("fixture 須建立 Lua closure")
                };
                values[0]
            };
            let Value::Object(closure) = function else {
                panic!("須為 closure")
            };
            let closure_root = vm.add_root(RootKind::Host, closure).unwrap();
            let coroutine = vm.new_coroutine(function).unwrap();
            vm.remove_root(closure_root).unwrap();
            let Value::Object(object) = coroutine.as_value(vm).unwrap() else {
                panic!("須為 coroutine object")
            };
            let mut execution = vm
                .resume(
                    Value::Object(object),
                    &[yield_function, Value::Integer(9), Value::Integer(11)],
                )
                .unwrap();
            assert_eq!(
                execution.run().unwrap(),
                RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(9)])
            );
            drop(execution);
            (coroutine, object, environment_root, function)
        })
        .unwrap();
    let thread = owner
        .debug_test_attach_suspended_coroutine_once(object)
        .unwrap();
    let state = thread.as_ptr();
    let main = owner.as_ptr();
    let mut ar = LuaDebug::blank();
    thread.push_value(function).unwrap();
    // SAFETY：function-only 參數名稱只讀 top，不能消耗該函式或增加值。
    unsafe {
        let top = lua_gettop(state);
        let first = lua_getlocal(state, std::ptr::null(), 1);
        assert!(!first.is_null());
        assert_eq!(CStr::from_ptr(first).to_bytes(), b"first");
        assert!(lua_getlocal(state, std::ptr::null(), 3).is_null());
        assert_eq!(lua_gettop(state), top);
        lua_settop(state, 0);
    }
    // SAFETY：coroutine HostHandle、thread owner 與主 state 均存活。
    unsafe {
        assert_eq!(lua_getstack(state, 0, &mut ar), 1);
        assert!(!ar.i_ci.is_null());
        assert_eq!(lua_getstack(state, 1, &mut LuaDebug::blank()), 0);
        let mut main_ar = LuaDebug::blank();
        assert_eq!(lua_getstack(main, 0, &mut main_ar), 0);
        main_ar.i_ci = ar.i_ci;
        assert_eq!(lua_getinfo(main, c"S".as_ptr(), &mut main_ar), 0);
        ar.name = 1usize as *const c_char;
        ar.namewhat = 1usize as *const c_char;
        ar.what = 1usize as *const c_char;
        ar.source = 1usize as *const c_char;
        ar.currentline = -77;
        ar.nups = u8::MAX;
        ar.nparams = u8::MAX;
        ar.isvararg = -1;
        ar.istailcall = -1;
        ar.ftransfer = !0;
        ar.ntransfer = !0;
        #[cfg(feature = "lua55")]
        {
            ar.extraargs = u8::MAX;
        }
        assert_eq!(lua_getinfo(state, c"nSlutrfL".as_ptr(), &mut ar), 1);
        assert_ne!(ar.name as usize, 1);
        assert_ne!(ar.namewhat as usize, 1);
        assert_eq!(CStr::from_ptr(ar.what).to_bytes(), b"Lua");
        assert_eq!(CStr::from_ptr(ar.source).to_bytes(), DEBUG_SOURCE);
        assert_eq!(CStr::from_ptr(ar.short_src.as_ptr()).to_bytes().len(), 59);
        let source_pointer = ar.source;
        assert_eq!(lua_getinfo(state, c"l".as_ptr(), &mut ar), 1);
        assert_eq!(ar.source, source_pointer);
        assert_eq!(CStr::from_ptr(ar.source).to_bytes(), DEBUG_SOURCE);
        assert_eq!(ar.nparams, 2);
        assert_eq!(ar.isvararg, 1);
        assert_eq!(ar.nups, 0);
        assert_eq!(ar.istailcall, 0);
        assert_eq!(ar.ftransfer, 0);
        assert_eq!(ar.ntransfer, 0);
        #[cfg(feature = "lua55")]
        assert_eq!(ar.extraargs, 0);
        assert!(ar.currentline > 0);
        assert_eq!(lua_type(state, -2), 6);
        assert_eq!(lua_type(state, -1), 5);
        lua_settop(state, 0);
        let name = lua_getlocal(state, &ar, 2);
        assert!(!name.is_null());
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"second");
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 9);
        lua_settop(state, 0);
        let vararg = lua_getlocal(state, &ar, -1);
        assert!(!vararg.is_null());
        assert_eq!(CStr::from_ptr(vararg).to_bytes(), b"(vararg)");
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 11);
        lua_settop(state, 0);
        let synthetic = lua_getlocal(state, &ar, 3);
        #[cfg(feature = "lua55")]
        {
            assert!(!synthetic.is_null());
            assert_eq!(CStr::from_ptr(synthetic).to_bytes(), b"(vararg table)");
            lua_settop(state, 0);
        }
        #[cfg(feature = "lua54")]
        assert!(synthetic.is_null());
        luaL_where(state, 0);
        let mut len = 0;
        let where_pointer = lua_tolstring(state, -1, &mut len);
        assert!(!where_pointer.is_null());
        let where_bytes = std::slice::from_raw_parts(where_pointer.cast::<u8>(), len);
        assert!(where_bytes.starts_with(b"..."));
        assert!(where_bytes.ends_with(b":3: "));
        lua_settop(state, 0);
        assert!(lua_getlocal(state, &ar, 0).is_null());
        assert!(lua_getlocal(state, &ar, -2).is_null());
    }
    let table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    thread.push_value(Value::Object(table)).unwrap();
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    // SAFETY：RootReserve 拒絕時不得消耗 source top 或改變 coroutine local。
    unsafe {
        assert!(lua_setlocal(state, &ar, 2).is_null());
        assert_eq!(lua_gettop(state), 1);
        let name = lua_setlocal(state, &ar, 2);
        assert!(!name.is_null());
        assert_eq!(CStr::from_ptr(name).to_bytes(), b"second");
        assert_eq!(lua_gettop(state), 0);
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        })
        .unwrap();
    // SAFETY：寫入的 object 應由 suspended coroutine frame 保根。
    unsafe {
        assert!(!lua_getlocal(state, &ar, 2).is_null());
        assert_eq!(lua_type(state, -1), 5);
        lua_settop(state, 0);
    }
    owner
        .with_vm(|vm| {
            let mut execution = vm.resume(Value::Object(object), &[]).unwrap();
            let _ = execution.run().unwrap();
        })
        .unwrap();
    // SAFETY：coroutine revision 改變後，先前 i_ci 不得更新或彈出 stack。
    unsafe {
        lua_pushinteger(state, 123);
        assert_eq!(lua_getinfo(state, c"nSl".as_ptr(), &mut ar), 0);
        assert!(lua_setlocal(state, &ar, 2).is_null());
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_getstack(state, 0, &mut LuaDebug::blank()), 0);
    }
    drop(thread);
    drop(coroutine);
    owner
        .with_vm(|vm| vm.remove_root(environment_root).unwrap())
        .unwrap();
}

#[test]
fn getinfo_function_only_selectors_and_failure_are_atomic_b10b1() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut ar = LuaDebug::blank();
    ar.name = 1usize as *const c_char;
    ar.namewhat = 1usize as *const c_char;
    ar.what = 1usize as *const c_char;
    ar.source = 1usize as *const c_char;
    ar.currentline = -77;
    ar.nups = u8::MAX;
    ar.nparams = u8::MAX;
    ar.isvararg = -1;
    ar.istailcall = -1;
    ar.ftransfer = !0;
    ar.ntransfer = !0;
    #[cfg(feature = "lua55")]
    {
        ar.extraargs = u8::MAX;
    }
    // SAFETY：owner 保活 state；fixture 只推入已驗證的 Lua closure。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        lua_pushvalue(state, -1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_getinfo(state, c">x".as_ptr(), &mut ar), 0);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_getinfo(state, c">nSlutrfL".as_ptr(), &mut ar), 1);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_rawequal(state, 1, 2), 1);
        assert_eq!(lua_type(state, 3), 5);
        assert_ne!(ar.name as usize, 1);
        assert_ne!(ar.namewhat as usize, 1);
        assert_eq!(CStr::from_ptr(ar.what).to_bytes(), b"Lua");
        assert!(!ar.source.is_null());
        assert_eq!(ar.short_src[59], 0);
        assert_eq!(ar.currentline, -1);
        assert_eq!(ar.nparams, 2);
        assert_eq!(ar.isvararg, 0);
        assert_eq!(ar.nups, 0);
        assert_eq!(ar.istailcall, 0);
        assert_eq!(ar.ftransfer, 0);
        assert_eq!(ar.ntransfer, 0);
        #[cfg(feature = "lua55")]
        assert_eq!(ar.extraargs, 0);
        lua_settop(state, 0);
        lua_pushinteger(state, 17);
        assert_eq!(lua_getinfo(state, c">SfL".as_ptr(), &mut ar), 0);
        assert_eq!(lua_gettop(state), 1);
        lua_settop(state, 0);
        lua_pushcclosure(state, Some(inspect_callback), 0);
        assert_eq!(lua_getinfo(state, c">Lf".as_ptr(), &mut ar), 1);
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, 1), 6);
        assert_eq!(lua_type(state, 2), 0);
    }
}

#[test]
fn sibling_cannot_use_another_states_callback_token_b10b1() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    SIBLING_STATE.store(sibling.as_ptr() as usize, Ordering::SeqCst);
    SIBLING_RESULT.store(-1, Ordering::SeqCst);
    let state = owner.as_ptr();
    // SAFETY：兩個 owner 於同步 callback 結束前存活。
    unsafe {
        lua_pushcclosure(state, Some(inspect_sibling), 0);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 0), 0);
        assert_eq!(SIBLING_RESULT.load(Ordering::SeqCst), 1);
    }
    SIBLING_STATE.store(0, Ordering::SeqCst);
}

#[test]
fn nested_c_lua_c_overlay_and_stale_token_b10b1() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    NESTED_RESULT.store(-1, Ordering::SeqCst);
    NESTED_TOKEN.store(0, Ordering::SeqCst);
    CALLBACK_OWNER.with(|current| current.set(&owner));
    // SAFETY：owner 保活 state，B4 C driver 在返回前同步完成全部 callback。
    unsafe {
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        lua_pushcclosure(state, Some(nested_outer), 1);
        assert_eq!(rivetlua_capi_call_b4(state, 0, 1), 0);
        assert_eq!(NESTED_RESULT.load(Ordering::SeqCst), 1);
        let mut stale = LuaDebug::blank();
        stale.i_ci = NESTED_TOKEN.load(Ordering::SeqCst) as *mut c_void;
        assert!(!stale.i_ci.is_null());
        let top = lua_gettop(state);
        assert_eq!(lua_getinfo(state, c"nSl".as_ptr(), &mut stale), 0);
        assert_eq!(lua_gettop(state), top);
    }
    CALLBACK_OWNER.with(|current| current.set(std::ptr::null()));
}
