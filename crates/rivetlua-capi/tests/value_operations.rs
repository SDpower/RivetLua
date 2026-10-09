use rivetlua_capi::stack::{
    StateOwner, lua_compare, lua_createtable, lua_gettop, lua_newuserdatauv, lua_pushboolean,
    lua_pushcclosure, lua_pushinteger, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_pushvalue,
    lua_rawset, lua_setmetatable, lua_settop, lua_tointegerx, lua_tolstring, lua_topointer,
    luaL_len,
};
use rivetlua_runtime::{FailPoint, GcMode, RootKind};
use std::cell::Cell;

thread_local! {
    static GC_OWNER_B5: Cell<*const StateOwner> = const { Cell::new(std::ptr::null()) };
}

#[repr(C)]
struct OperationStepB5 {
    kind: i32,
    value: i32,
    function: Option<unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> i32>,
    hook: Option<
        unsafe extern "C" fn(
            *mut rivetlua_capi::stack::lua_State,
            *mut rivetlua_capi::stack::lua_Debug,
        ),
    >,
    event: i32,
    currentline: i32,
    token: *mut std::ffi::c_void,
}

unsafe extern "C" {
    fn lua_arith(state: *mut rivetlua_capi::stack::lua_State, operation: i32);
    fn lua_concat(state: *mut rivetlua_capi::stack::lua_State, count: i32);
    fn lua_len(state: *mut rivetlua_capi::stack::lua_State, index: i32);
    fn luaL_tolstring(
        state: *mut rivetlua_capi::stack::lua_State,
        index: i32,
        length: *mut usize,
    ) -> *const std::ffi::c_char;
    fn rivetlua_capi_call_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        nargs: i32,
        nresults: i32,
    ) -> i32;
    fn rivetlua_capi_test_push_lua_b4(
        state: *mut rivetlua_capi::stack::lua_State,
        selector: i32,
    ) -> i32;
    fn rivetlua_capi_operation_prepare_b5(
        state: *mut rivetlua_capi::stack::lua_State,
        kind: i32,
        operation: i32,
        left: i32,
        right: i32,
        count: i32,
    ) -> OperationStepB5;
}

#[test]
fn operation_named_and_ordinal_allocation_failures_restore_state_b5() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let make_owner = || {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            // SAFETY：owner 保活 state；兩個整數是本測試操作的原始 stack。
            unsafe {
                lua_pushinteger(state, 20);
                lua_pushinteger(state, 22);
            }
            owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
            owner
        };
        let dry = make_owner();
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        // SAFETY：dry run 的私有 step 只使用已建立的有效 state。
        let successful = unsafe { rivetlua_capi_operation_prepare_b5(dry.as_ptr(), 0, 0, 0, 0, 0) };
        assert_eq!((successful.kind, successful.value), (0, 1));
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start, "{mode:?}");
        drop(dry);

        for offset in 0..end - start {
            let owner = make_owner();
            let state = owner.as_ptr();
            let before = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            let ordinal = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
                .unwrap();
            // SAFETY：私有 step 在任何 C callback 前返回 POD；失敗不發布 stack 結果。
            let failed = unsafe { rivetlua_capi_operation_prepare_b5(state, 0, 0, 0, 0, 0) };
            assert_eq!(
                (failed.kind, failed.value),
                (-1, 5),
                "{mode:?} offset={offset}"
            );
            assert_eq!(unsafe { lua_gettop(state) }, 2);
            let after = owner
                .with_vm(|vm| {
                    (
                        vm.ledger_snapshot(),
                        vm.gc_trace(),
                        vm.roots().count(RootKind::Host),
                    )
                })
                .unwrap();
            assert_eq!(
                after.0.committed, before.0.committed,
                "{mode:?} offset={offset}"
            );
            assert_eq!(after.0.reserved, 0, "{mode:?} offset={offset}");
            assert_eq!(
                after.1.debt_bytes, before.1.debt_bytes,
                "{mode:?} offset={offset}"
            );
            assert_eq!(after.2, before.2, "{mode:?} offset={offset}");
            // SAFETY：單次注入已消耗，原 stack 立即可重試同一運算。
            unsafe {
                lua_arith(state, 0);
                assert_eq!(lua_gettop(state), 1);
                assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 42);
            }
        }

        let owner = make_owner();
        let state = owner.as_ptr();
        owner
            .with_vm(|vm| vm.inject_failure_once(FailPoint::ReturnReserve))
            .unwrap();
        // SAFETY：具名 fault 在 operation 預備階段被轉為 allocation 類別。
        let failed = unsafe { rivetlua_capi_operation_prepare_b5(state, 0, 0, 0, 0, 0) };
        assert_eq!((failed.kind, failed.value), (-1, 5));
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
        // SAFETY：同一 state 的原 stack 保留，可重試成功。
        unsafe {
            lua_arith(state, 0);
            assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 42);
        }
    }
}

unsafe extern "C" fn outer_operation_b5(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：B4 callback frame 有效，B5 operation 於 C-only checkpoint 續接同一 core。
    unsafe {
        lua_pushvalue(state, 1);
        lua_pushvalue(state, 2);
        lua_arith(state, 0);
    }
    1
}

unsafe extern "C" fn inner_gc_b5(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    let collected = GC_OWNER_B5.with(|cell| {
        let owner = cell.get();
        if owner.is_null() {
            return false;
        }
        // SAFETY：測試同步持有 StateOwner；callback 結束後清除 thread-local 指標。
        unsafe { &*owner }
            .with_vm(|vm| vm.collect())
            .is_ok_and(|result| result.is_ok())
    });
    if !collected {
        return -1;
    }
    // SAFETY：driver 保活 callback state；只發布一個結果。
    unsafe { lua_pushinteger(state, 42) };
    1
}

#[test]
fn callback_operation_lua_metamethod_c_callback_and_gc_share_execution_b5() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        owner.with_vm(|vm| vm.set_gc_mode(mode)).unwrap().unwrap();
        // SAFETY：全部 C API 同步使用 owner 保活的 state；Lua fixture 在沒有 parked core 時先建立。
        unsafe {
            lua_pushcclosure(state, Some(outer_operation_b5), 0);
            lua_createtable(state, 0, 0);
            lua_createtable(state, 0, 2);
            lua_pushlstring(state, b"__add".as_ptr().cast(), 5);
            assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
            lua_rawset(state, -3);
            lua_pushlstring(state, b"__call".as_ptr().cast(), 6);
            lua_pushcclosure(state, Some(inner_gc_b5), 0);
            lua_rawset(state, -3);
            assert_eq!(lua_setmetatable(state, 2), 1);
            lua_pushinteger(state, 2);
            GC_OWNER_B5.with(|cell| cell.set(&owner));
            let status = rivetlua_capi_call_b4(state, 2, 1);
            GC_OWNER_B5.with(|cell| cell.set(std::ptr::null()));
            assert_eq!(status, 0);
            assert_eq!(lua_gettop(state), 1);
            assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 42);
        }
        assert_eq!(
            owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap(),
            0
        );
    }
}

unsafe extern "C" fn return_number(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：B5 driver 同步保活 state，結果留在同一 callback stack。
    unsafe { lua_pushinteger(state, 42) };
    1
}

unsafe extern "C" fn return_capture_b5(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    #[cfg(feature = "lua54")]
    const UPVALUE_1: i32 = -1_001_001;
    #[cfg(feature = "lua55")]
    const UPVALUE_1: i32 = -(i32::MAX / 2 + 1000) - 1;
    // SAFETY：driver 保活 C closure 捕獲值，並將其複製成單一結果。
    unsafe { lua_pushvalue(state, UPVALUE_1) };
    1
}

unsafe extern "C" fn capture_operations_b5(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    #[cfg(feature = "lua54")]
    const UPVALUE_1: i32 = -1_001_001;
    #[cfg(feature = "lua55")]
    const UPVALUE_1: i32 = -(i32::MAX / 2 + 1000) - 1;
    // SAFETY：B4 C closure 捕獲值由 parked core 保活；B5 driver 同步使用 pseudo-index。
    unsafe {
        if luaL_len(state, UPVALUE_1) != 3 || lua_compare(state, UPVALUE_1, 1, 0) != 1 {
            return -1;
        }
        lua_len(state, UPVALUE_1);
    }
    1
}

#[test]
fn operation_accepts_c_closure_upvalue_pseudo_index_b5() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let text = b"a\0b";
    // SAFETY：owner 保活 state；捕獲值與參數各自有 stack root，callback 返回單一結果。
    unsafe {
        lua_pushlstring(state, text.as_ptr().cast(), text.len());
        lua_pushcclosure(state, Some(capture_operations_b5), 1);
        lua_pushlstring(state, text.as_ptr().cast(), text.len());
        assert_eq!(rivetlua_capi_call_b4(state, 1, 1), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 3);
    }
}

unsafe extern "C" fn return_true(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：driver 保活 state；只發布一個 boolean 結果。
    unsafe { lua_pushboolean(state, 1) };
    1
}

unsafe extern "C" fn return_37(state: *mut rivetlua_capi::stack::lua_State) -> i32 {
    // SAFETY：driver 保活 state；只發布一個 integer 結果。
    unsafe { lua_pushinteger(state, 37) };
    1
}

unsafe fn attach_c_metamethod(
    state: *mut rivetlua_capi::stack::lua_State,
    target: i32,
    name: &[u8],
    function: unsafe extern "C" fn(*mut rivetlua_capi::stack::lua_State) -> i32,
) {
    // SAFETY：呼叫者保活 state 與 target；metatable/key/function 在此同步呼叫內使用。
    unsafe {
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, name.as_ptr().cast(), name.len());
        lua_pushcclosure(state, Some(function), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, target), 1);
    }
}

#[test]
fn raw_and_c_metamethod_compare_and_len_b5() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 存活，metamethod 的 C callback 只同步使用 stack。
    unsafe {
        for bytes in [b"a\0b".as_slice(), b"a\0c"] {
            lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len());
        }
        assert_eq!(lua_compare(state, 1, 2, 0), 0);
        assert_eq!(lua_compare(state, 1, 2, 1), 1);
        assert_eq!(lua_compare(state, 1, 2, 2), 1);
        assert_eq!(lua_compare(state, 1, 99, 0), 0);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        attach_c_metamethod(state, 1, b"__len", return_37);
        assert_eq!(luaL_len(state, 1), 37);
        assert_eq!(lua_gettop(state), 1);
        lua_len(state, 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 37);
        lua_settop(state, 0);

        assert!(!lua_newuserdatauv(state, 11, 0).is_null());
        attach_c_metamethod(state, 1, b"__len", return_37);
        assert_eq!(luaL_len(state, 1), 37);
        assert_eq!(lua_gettop(state), 1);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, b"__len".as_ptr().cast(), 5);
        lua_pushinteger(state, 37);
        lua_pushcclosure(state, Some(return_capture_b5), 1);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, 1), 1);
        assert_eq!(luaL_len(state, 1), 37);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        attach_c_metamethod(state, 1, b"__eq", return_true);
        attach_c_metamethod(state, 2, b"__eq", return_true);
        assert_eq!(lua_compare(state, 1, 2, 0), 1);
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);

        assert!(!lua_newuserdatauv(state, 8, 0).is_null());
        assert!(!lua_newuserdatauv(state, 8, 0).is_null());
        attach_c_metamethod(state, 1, b"__eq", return_true);
        attach_c_metamethod(state, 2, b"__eq", return_true);
        assert_eq!(lua_compare(state, 1, 2, 0), 1);
        lua_settop(state, 0);

        assert!(!lua_newuserdatauv(state, 8, 0).is_null());
        assert!(!lua_newuserdatauv(state, 8, 0).is_null());
        attach_c_metamethod(state, 1, b"__lt", return_true);
        assert_eq!(lua_compare(state, 1, 2, 1), 1);
        assert_eq!(lua_gettop(state), 2);
    }
}

fn stack_bytes(state: *mut rivetlua_capi::stack::lua_State, index: i32) -> Vec<u8> {
    let mut length = 0;
    // SAFETY：state 有效且結果仍在 stack，立即複製回傳位元組。
    let pointer = unsafe { lua_tolstring(state, index, &mut length) };
    assert!(!pointer.is_null());
    // SAFETY：lua_tolstring 的指標在 stack slot 未變時至少可讀 length 位元組。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), length).to_vec() }
}

#[test]
fn tolstring_vendor_fallback_and_c_metamethod_b5() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在測試期間保活 state，所有結果在改動 stack 前立即檢查。
    unsafe {
        lua_pushinteger(state, 42);
        let mut length = usize::MAX;
        let pointer = luaL_tolstring(state, -1, &mut length);
        assert_eq!(length, 2);
        assert_eq!(pointer, lua_tolstring(state, -1, std::ptr::null_mut()));
        assert_eq!(stack_bytes(state, -1), b"42");
        lua_settop(state, 0);

        lua_pushnumber(state, 1.5);
        let pointer = luaL_tolstring(state, -1, &mut length);
        assert!(!pointer.is_null());
        assert_eq!(stack_bytes(state, -1), b"1.5");
        lua_settop(state, 0);

        lua_pushboolean(state, 1);
        luaL_tolstring(state, -1, &mut length);
        assert_eq!(stack_bytes(state, -1), b"true");
        lua_settop(state, 0);

        lua_pushnil(state);
        luaL_tolstring(state, -1, &mut length);
        assert_eq!(stack_bytes(state, -1), b"nil");
        lua_settop(state, 0);

        let source = b"a\0b";
        lua_pushlstring(state, source.as_ptr().cast(), source.len());
        luaL_tolstring(state, -1, &mut length);
        assert_eq!(length, source.len());
        assert_eq!(stack_bytes(state, -1), source);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        let identity = lua_topointer(state, -1);
        lua_createtable(state, 0, 2);
        let name = b"__name";
        lua_pushlstring(state, name.as_ptr().cast(), name.len());
        let type_name = b"Widget";
        lua_pushlstring(state, type_name.as_ptr().cast(), type_name.len());
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        luaL_tolstring(state, -1, &mut length);
        let rendered = stack_bytes(state, -1);
        assert!(rendered.starts_with(b"Widget: "));
        assert!(!identity.is_null());
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        let tostring = b"__tostring";
        lua_pushlstring(state, tostring.as_ptr().cast(), tostring.len());
        lua_pushcclosure(state, Some(return_number), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        let pointer = luaL_tolstring(state, -1, &mut length);
        assert_eq!(length, 2);
        assert_eq!(stack_bytes(state, -1), b"42");
        assert_eq!(pointer, lua_tolstring(state, -1, std::ptr::null_mut()));
        assert_eq!(lua_gettop(state), 2);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushlstring(state, tostring.as_ptr().cast(), tostring.len());
        lua_pushinteger(state, 42);
        lua_pushcclosure(state, Some(return_capture_b5), 1);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        luaL_tolstring(state, -1, &mut length);
        assert_eq!(stack_bytes(state, -1), b"42");
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 2);
        lua_pushlstring(state, tostring.as_ptr().cast(), tostring.len());
        assert_eq!(rivetlua_capi_test_push_lua_b4(state, 1), 1);
        lua_rawset(state, -3);
        lua_pushlstring(state, b"__call".as_ptr().cast(), 6);
        lua_pushcclosure(state, Some(return_number), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        luaL_tolstring(state, -1, &mut length);
        assert_eq!(stack_bytes(state, -1), b"42");
    }
}

#[test]
fn fixed_header_operation_symbols_preserve_stack_effects_b5() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 在整個測試期間持有有效 state；三個符號遵循固定 C header。
    unsafe {
        lua_pushinteger(state, 20);
        lua_pushinteger(state, 22);
        lua_arith(state, 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
        let text = b"abc";
        lua_pushlstring(state, text.as_ptr().cast(), text.len());
        lua_len(state, -1);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 3);
        lua_concat(state, 0);
        assert_eq!(lua_gettop(state), 4);
    }
}
