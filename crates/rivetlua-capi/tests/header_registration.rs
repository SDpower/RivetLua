use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_getfield, lua_getglobal, lua_gettop,
    lua_pushcclosure, lua_setglobal, lua_settop, lua_tocfunction, lua_type, luaL_Reg,
    luaL_setfuncs,
};

type LuaCFunction = unsafe extern "C" fn(*mut lua_State) -> i32;

unsafe extern "C" {
    fn luaL_checkversion_(state: *mut lua_State, version: f64, sizes: usize);
}

#[cfg(feature = "lua54")]
const LUA_VERSION: f64 = 504.0;
#[cfg(feature = "lua55")]
const LUA_VERSION: f64 = 505.0;
const LUA_NUMSIZES: usize = 16 * std::mem::size_of::<i64>() + std::mem::size_of::<f64>();

unsafe extern "C" fn registered(state: *mut lua_State) -> i32 {
    let _ = state;
    0
}

unsafe extern "C" fn second_registered(state: *mut lua_State) -> i32 {
    let _ = state;
    0
}

unsafe extern "C" fn after_sentinel(state: *mut lua_State) -> i32 {
    let _ = state;
    0
}

fn same_function(actual: Option<LuaCFunction>, expected: LuaCFunction) -> bool {
    actual.is_some_and(|actual| std::ptr::fn_addr_eq(actual, expected))
}

fn entry(name: &'static std::ffi::CStr, func: LuaCFunction) -> luaL_Reg {
    luaL_Reg {
        name: name.as_ptr(),
        func: Some(func),
    }
}

fn sentinel() -> luaL_Reg {
    luaL_Reg {
        name: std::ptr::null(),
        func: None,
    }
}

#[test]
fn header_registration_b0_rust_primitive_contract() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();

    // SAFETY：owner 持續保活 state；字串與 callback 在呼叫期間有效。
    unsafe {
        lua_pushcclosure(state, Some(registered), 0);
        lua_setglobal(state, c"b0_registered".as_ptr());
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_getglobal(state, c"b0_registered".as_ptr()), 6);
        assert!(same_function(lua_tocfunction(state, -1), registered));
        lua_settop(state, 0);

        luaL_checkversion_(state, LUA_VERSION, LUA_NUMSIZES);
        let entries = [
            entry(c"first", registered),
            entry(c"second", second_registered),
            sentinel(),
            entry(c"after_sentinel", after_sentinel),
            sentinel(),
        ];
        lua_createtable(state, 0, 4);
        luaL_setfuncs(state, entries.as_ptr(), 0);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_type(state, 1), 5);

        assert_eq!(lua_getfield(state, 1, c"first".as_ptr()), 6);
        assert!(same_function(lua_tocfunction(state, -1), registered));
        lua_settop(state, 1);

        assert_eq!(lua_getfield(state, 1, c"second".as_ptr()), 6);
        assert!(same_function(lua_tocfunction(state, -1), second_registered));
        lua_settop(state, 1);

        assert_eq!(lua_getfield(state, 1, c"after_sentinel".as_ptr()), 0);
        lua_settop(state, 0);
    }
}
