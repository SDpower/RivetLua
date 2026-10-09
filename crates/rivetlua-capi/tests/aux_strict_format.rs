use std::ffi::{CString, c_char, c_void};

use rivetlua_capi::error::{ErrorClass, consume};
use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_checkstack, lua_gettop, lua_newuserdatauv, lua_pushinteger,
    lua_pushlightuserdata, lua_pushnil, lua_pushnumber, lua_setmetatable, lua_settop,
    lua_tolstring, lua_type, luaL_newmetatable,
};
use rivetlua_capi::trampoline::{Action, Outcome, protect};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{FailPoint, GcMode, LedgerSnapshot, RootId, RootKind};

#[repr(C)]
struct StrictResult {
    kind: i32,
    value: i32,
    pointer: *mut c_void,
}

unsafe extern "C" {
    fn luaL_checktype(state: *mut lua_State, arg: i32, tag: i32);
    fn luaL_checkany(state: *mut lua_State, arg: i32);
    fn luaL_checkudata(state: *mut lua_State, arg: i32, name: *const c_char) -> *mut c_void;
    fn luaL_checkoption(
        state: *mut lua_State,
        arg: i32,
        default: *const c_char,
        choices: *const *const c_char,
    ) -> i32;
    fn lua_pushfstring(state: *mut lua_State, format: *const c_char, ...) -> *const c_char;
    fn rivetlua_capi_aux_dispatch_b2(
        state: *mut lua_State,
        generation: u64,
        token: u64,
        operation: i32,
        arg: i32,
        tag: i32,
        name: *const c_char,
        choices: *const *const c_char,
    ) -> StrictResult;
}

const LUA_TNIL: i32 = 0;
const LUA_TNUMBER: i32 = 3;
const LUA_TSTRING: i32 = 4;
const LUA_TUSERDATA: i32 = 7;
const CHECKTYPE: i32 = 1;
const CHECKANY: i32 = 2;
const CHECKUDATA: i32 = 3;
const CHECKOPTION: i32 = 4;

// SAFETY：各測試維持 StateOwner 的生命週期；C 指標只在同步呼叫內使用。
macro_rules! c_call {
    ($expression:expr) => {{ unsafe { $expression } }};
}

fn top_bytes(state: *mut lua_State) -> Vec<u8> {
    let mut len = 0;
    let pointer = c_call!(lua_tolstring(state, -1, &mut len));
    assert!(!pointer.is_null());
    // SAFETY：頂端 slot 持有字串，長度由同一次 C API 呼叫取得。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) }.to_vec()
}

fn snapshot(owner: &StateOwner) -> (LedgerSnapshot, Vec<(RootKind, RootId, ObjectRef)>) {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), roots)
        })
        .unwrap()
}

fn raised(
    owner: &StateOwner,
    operation: i32,
    arg: i32,
    tag: i32,
    name: *const c_char,
    choices: *const *const c_char,
) -> ErrorClass {
    let state = owner.as_ptr();
    let before = c_call!(lua_gettop(state));
    let outcome = c_call!(protect(state, |checkpoint| {
        // SAFETY：Rust action 僅取得 POD；跳轉由它返回後的 C checkpoint 執行。
        let result = rivetlua_capi_aux_dispatch_b2(
            state,
            checkpoint.generation,
            checkpoint.token,
            operation,
            arg,
            tag,
            name,
            choices,
        );
        assert_eq!(result.kind, 1);
        assert!(result.pointer.is_null());
        match result.value {
            2 => Action::Raise(ErrorClass::Lua),
            5 => Action::Raise(ErrorClass::Allocation),
            other => panic!("非預期錯誤分類 {other}"),
        }
    }));
    let Outcome::Raised(class) = outcome else {
        panic!("未進入 C checkpoint：{outcome:?}");
    };
    assert_eq!(c_call!(lua_gettop(state)), before);
    assert_eq!(c_call!(consume(state)), Ok(class));
    assert_eq!(c_call!(lua_gettop(state)), before + 1);
    class
}

#[test]
fn aux_strict_b2_success_and_conversion() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    c_call!(lua_pushnil(state));
    c_call!(luaL_checkany(state, 1));
    c_call!(luaL_checktype(state, -1, LUA_TNIL));
    assert_eq!(c_call!(lua_gettop(state)), 1);

    let first = CString::new("first").unwrap();
    let second = CString::new("second").unwrap();
    let choices = [first.as_ptr(), second.as_ptr(), std::ptr::null()];
    assert_eq!(
        c_call!(luaL_checkoption(
            state,
            1,
            second.as_ptr(),
            choices.as_ptr()
        )),
        1
    );
    c_call!(lua_pushinteger(state, 42));
    let numeral = CString::new("42").unwrap();
    let values = [numeral.as_ptr(), std::ptr::null()];
    assert_eq!(
        c_call!(luaL_checkoption(
            state,
            -1,
            std::ptr::null(),
            values.as_ptr()
        )),
        0
    );
    assert_eq!(c_call!(lua_type(state, -1)), LUA_TSTRING);
    assert_eq!(top_bytes(state), b"42");
    assert_eq!(c_call!(lua_gettop(state)), 2);

    c_call!(lua_settop(state, 0));
    let pointer = c_call!(lua_newuserdatauv(state, 17, 0));
    assert!(!pointer.is_null());
    let name = CString::new("B2Thing").unwrap();
    assert_eq!(c_call!(luaL_newmetatable(state, name.as_ptr())), 1);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    assert_eq!(c_call!(luaL_checkudata(state, 1, name.as_ptr())), pointer);
    assert_eq!(c_call!(luaL_checkudata(state, -1, name.as_ptr())), pointer);
    c_call!(luaL_checktype(state, 1, LUA_TUSERDATA));
    assert_eq!(c_call!(lua_gettop(state)), 1);
}

#[test]
fn aux_strict_b2_error_bytes_pending_and_recovery() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_eq!(c_call!(lua_checkstack(state, 4)), 1);
    c_call!(lua_pushinteger(state, 9));
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    let baseline = snapshot(&owner);
    assert_eq!(
        raised(&owner, CHECKANY, 2, 0, std::ptr::null(), std::ptr::null()),
        ErrorClass::Lua
    );
    assert_eq!(top_bytes(state), b"bad argument #2 (value expected)");
    c_call!(lua_settop(state, 1));
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    let after = snapshot(&owner);
    assert_eq!(
        after.0.host_allocation_bytes,
        baseline.0.host_allocation_bytes
    );
    assert_eq!(after.1, baseline.1);

    c_call!(lua_pushlightuserdata(state, 0x1234usize as *mut c_void));
    assert_eq!(
        raised(
            &owner,
            CHECKTYPE,
            -1,
            LUA_TNUMBER,
            std::ptr::null(),
            std::ptr::null()
        ),
        ErrorClass::Lua
    );
    assert_eq!(
        top_bytes(state),
        b"bad argument #-1 (number expected, got light userdata)"
    );
    c_call!(lua_settop(state, 2));
    let name = CString::new("B2Thing").unwrap();
    assert_eq!(
        raised(&owner, CHECKUDATA, 2, 0, name.as_ptr(), std::ptr::null()),
        ErrorClass::Lua
    );
    assert_eq!(
        top_bytes(state),
        b"bad argument #2 (B2Thing expected, got light userdata)"
    );
    c_call!(lua_settop(state, 2));

    let alpha = CString::new("alpha").unwrap();
    let choices = [alpha.as_ptr(), std::ptr::null()];
    assert_eq!(
        raised(
            &owner,
            CHECKOPTION,
            2,
            0,
            std::ptr::null(),
            choices.as_ptr()
        ),
        ErrorClass::Lua
    );
    assert_eq!(
        top_bytes(state),
        b"bad argument #2 (string expected, got light userdata)"
    );
    c_call!(lua_settop(state, 1));
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    let after = snapshot(&owner);
    assert_eq!(
        after.0.host_allocation_bytes,
        baseline.0.host_allocation_bytes
    );
    assert_eq!(after.1, baseline.1);
}

#[test]
fn aux_strict_b2_allocation_failure_is_canonical_and_retryable() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        assert_eq!(c_call!(lua_checkstack(state, 4)), 1);
        c_call!(lua_pushnumber(state, 2.5));
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        let before = snapshot(&owner);
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::StringBytesReserve))
            .unwrap();
        assert_eq!(
            raised(
                &owner,
                CHECKTYPE,
                1,
                LUA_TSTRING,
                std::ptr::null(),
                std::ptr::null()
            ),
            ErrorClass::Allocation
        );
        assert_eq!(top_bytes(state), b"not enough memory");
        c_call!(lua_settop(state, 1));
        assert_eq!(snapshot(&owner), before);
        assert_eq!(
            raised(
                &owner,
                CHECKTYPE,
                1,
                LUA_TSTRING,
                std::ptr::null(),
                std::ptr::null()
            ),
            ErrorClass::Lua
        );
        assert_eq!(
            top_bytes(state),
            b"bad argument #1 (string expected, got number)"
        );
    }
}

#[test]
fn format_b2_varargs_stack_bytes_and_long_result() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let text = CString::new("A").unwrap();
    let marker = 0x1234usize as *mut c_void;
    let returned = c_call!(lua_pushfstring(
        state,
        c"%s|%c|%d|%I|%f|%p|%U|%%".as_ptr(),
        text.as_ptr(),
        0_i32,
        -7_i32,
        i64::MIN,
        1.0_f64,
        marker,
        0x10FFFF_u64
    ));
    assert!(!returned.is_null());
    let bytes = top_bytes(state);
    assert!(bytes.starts_with(b"A|\0|-7|-9223372036854775808|1.0|"));
    assert!(bytes.ends_with("|\u{10ffff}|%".as_bytes()));
    assert_eq!(c_call!(lua_gettop(state)), 1);
    assert_eq!(
        returned,
        c_call!(lua_tolstring(state, -1, std::ptr::null_mut()))
    );
    c_call!(lua_settop(state, 0));

    let long = CString::new(vec![b'x'; 4096]).unwrap();
    let returned = c_call!(lua_pushfstring(state, c"%s".as_ptr(), long.as_ptr()));
    assert!(!returned.is_null());
    assert_eq!(top_bytes(state), long.as_bytes());
    assert_eq!(c_call!(lua_gettop(state)), 1);
    c_call!(lua_settop(state, 0));
    let returned = c_call!(lua_pushfstring(state, c"".as_ptr()));
    assert!(!returned.is_null());
    assert_eq!(top_bytes(state), b"");
}

fn userdata_owner(mode: GcMode) -> (StateOwner, *mut c_void) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_eq!(c_call!(lua_checkstack(state, 4)), 1);
    let pointer = c_call!(lua_newuserdatauv(state, 13, 0));
    assert!(!pointer.is_null());
    assert_eq!(c_call!(luaL_newmetatable(state, c"B2Ordinal".as_ptr())), 1);
    assert_eq!(c_call!(lua_setmetatable(state, 1)), 1);
    owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
    (owner, pointer)
}

fn protected_userdata(owner: &StateOwner) -> (Outcome, *mut c_void) {
    let state = owner.as_ptr();
    let mut pointer = std::ptr::null_mut();
    let outcome = c_call!(protect(state, |checkpoint| {
        // SAFETY：Rust action 只調用回傳 POD 的 private dispatch；跳轉留在 C checkpoint。
        let result = rivetlua_capi_aux_dispatch_b2(
            state,
            checkpoint.generation,
            checkpoint.token,
            CHECKUDATA,
            1,
            0,
            c"B2Ordinal".as_ptr(),
            std::ptr::null(),
        );
        match (result.kind, result.value) {
            (0, 0) => {
                pointer = result.pointer;
                Action::Return(0)
            }
            (1, 5) => Action::Raise(ErrorClass::Allocation),
            other => panic!("非預期 userdata dispatch 狀態 {other:?}"),
        }
    }));
    (outcome, pointer)
}

#[test]
fn aux_strict_b2_userdata_ordinal_gc_and_named_failure() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let (dry, expected) = userdata_owner(mode);
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert_eq!(protected_userdata(&dry), (Outcome::Normal(0), expected));
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start);
        for offset in 0..end - start {
            let (owner, pointer) = userdata_owner(mode);
            let state = owner.as_ptr();
            let before = snapshot(&owner);
            let ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
                .unwrap();
            assert_eq!(
                protected_userdata(&owner).0,
                Outcome::Raised(ErrorClass::Allocation),
                "mode={mode:?} offset={offset}"
            );
            assert_eq!(c_call!(lua_gettop(state)), 1);
            assert_eq!(c_call!(consume(state)), Ok(ErrorClass::Allocation));
            assert_eq!(top_bytes(state), b"not enough memory");
            c_call!(lua_settop(state, 1));
            owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
            let after = snapshot(&owner);
            assert_eq!(
                after.0.host_allocation_bytes, before.0.host_allocation_bytes,
                "mode={mode:?} offset={offset}"
            );
            assert_eq!(after.1, before.1, "mode={mode:?} offset={offset}");
            assert_eq!(after.0.reserved, 0);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            assert_eq!(protected_userdata(&owner), (Outcome::Normal(0), pointer));
        }

        let (owner, pointer) = userdata_owner(mode);
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::StringBytesReserve))
            .unwrap();
        assert_eq!(
            protected_userdata(&owner).0,
            Outcome::Raised(ErrorClass::Allocation)
        );
        assert_eq!(c_call!(consume(owner.as_ptr())), Ok(ErrorClass::Allocation));
        assert_eq!(top_bytes(owner.as_ptr()), b"not enough memory");
        c_call!(lua_settop(owner.as_ptr(), 1));
        assert_eq!(protected_userdata(&owner), (Outcome::Normal(0), pointer));
    }
}
