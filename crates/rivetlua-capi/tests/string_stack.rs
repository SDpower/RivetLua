use std::ffi::{CString, c_char};

#[cfg(feature = "lua55")]
use rivetlua_capi::stack::lua_numbertocstring;
use rivetlua_capi::stack::{
    StackError, StateOwner, lua_checkstack, lua_copy, lua_gettop, lua_isnumber, lua_isstring,
    lua_pushinteger, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_pushstring, lua_pushvalue,
    lua_settop, lua_stringtonumber, lua_tointegerx, lua_tolstring, lua_tonumberx, lua_type,
    lua_xmove,
};
use rivetlua_core::Value;
use rivetlua_runtime::{AllocationDomain, FailPoint, LedgerSnapshot, RootKind, VmError};

fn snapshot(owner: &StateOwner) -> LedgerSnapshot {
    owner.with_vm(|vm| vm.ledger_snapshot()).unwrap()
}

fn returned_bytes(pointer: *const c_char, len: usize) -> Vec<u8> {
    assert!(!pointer.is_null());
    // SAFETY：呼叫者保證對應 string slot 仍存活；只讀取已回報的 len bytes。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len).to_vec() }
}

#[test]
fn string_stack_push_empty_embedded_null_and_nil_contract() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let initial = snapshot(&owner);
    // SAFETY：state 存活；非空來源陣列與 C 字串在整個呼叫期間有效。
    unsafe {
        let empty = lua_pushlstring(state, std::ptr::null(), 0);
        assert_eq!(returned_bytes(empty, 0), b"");
        assert_eq!(*empty, 0);
        let mut len = usize::MAX;
        assert_eq!(lua_tolstring(state, -1, &mut len), empty);
        assert_eq!(len, 0);

        assert!(lua_pushstring(state, std::ptr::null()).is_null());
        assert_eq!(lua_type(state, -1), 0);
        assert_eq!(lua_gettop(state), 2);
        assert!(lua_pushlstring(state, std::ptr::null(), 1).is_null());
        assert_eq!(lua_gettop(state), 2);

        let hello = CString::new("hello").unwrap();
        let pointer = lua_pushstring(state, hello.as_ptr());
        assert_eq!(returned_bytes(pointer, 5), b"hello");
        assert_ne!(pointer, hello.as_ptr());
        let source = [b'A', 0, b'B'];
        let binary = lua_pushlstring(state, source.as_ptr().cast::<c_char>(), source.len());
        assert_eq!(returned_bytes(binary, 3), source);
        assert_eq!(*binary.add(3), 0);
        let mut binary_len = 0;
        assert_eq!(lua_tolstring(state, -1, &mut binary_len), binary);
        assert_eq!(binary_len, 3);
        assert_eq!(lua_isstring(state, -1), 1);
        assert_eq!(lua_isnumber(state, -1), 0);
        lua_settop(state, 0);
    }
    assert_eq!(
        snapshot(&owner).host_allocation_bytes,
        initial.host_allocation_bytes
    );
    assert_eq!(
        owner
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap(),
        0
    );
}

#[test]
fn string_stack_numeric_string_coercion_and_stringtonumber_boundaries() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    for (source, integer, number) in [
        ("  -12  ", Some(-12), -12.0),
        ("0xff", Some(255), 255.0),
        ("0x1.8p+2", Some(6), 6.0),
        ("9223372036854775807", Some(i64::MAX), i64::MAX as f64),
    ] {
        let input = CString::new(source).unwrap();
        // SAFETY：state 與 input 均在呼叫期間有效。
        unsafe {
            assert!(!lua_pushstring(state, input.as_ptr()).is_null());
            assert_eq!(lua_isnumber(state, -1), 1);
            assert_eq!(lua_isstring(state, -1), 1);
            let mut isnum = -1;
            assert_eq!(lua_tonumberx(state, -1, &mut isnum), number);
            assert_eq!(isnum, 1);
            assert_eq!(lua_tointegerx(state, -1, &mut isnum), integer.unwrap());
            assert_eq!(isnum, 1);
            lua_settop(state, 0);
            assert_eq!(lua_stringtonumber(state, input.as_ptr()), source.len() + 1);
            assert_eq!(lua_tonumberx(state, -1, &mut isnum), number);
            assert_eq!(isnum, 1);
            lua_settop(state, 0);
        }
    }
    for source in ["nan", "inf", "0xG", "9223372036854775808"] {
        let input = CString::new(source).unwrap();
        // SAFETY：state 與 input 均有效；失敗分支不改變 stack。
        unsafe {
            let top = lua_gettop(state);
            assert_eq!(
                lua_stringtonumber(state, input.as_ptr()),
                if source.starts_with('9') {
                    source.len() + 1
                } else {
                    0
                }
            );
            if source.starts_with('9') {
                let mut isnum = -1;
                assert_eq!(lua_tointegerx(state, -1, &mut isnum), 0);
                assert_eq!(isnum, 0);
                lua_settop(state, top);
            } else {
                assert_eq!(lua_gettop(state), top);
                assert!(!lua_pushstring(state, input.as_ptr()).is_null());
                assert_eq!(lua_isnumber(state, -1), 0);
                lua_settop(state, top);
            }
        }
    }
    let negative_zero = CString::new("-0.0").unwrap();
    // SAFETY：state 與 input 均有效；數值字串解析不改原 slot。
    unsafe {
        lua_pushstring(state, negative_zero.as_ptr());
        let mut isnum = 0;
        let value = lua_tonumberx(state, -1, &mut isnum);
        assert_eq!(isnum, 1);
        assert_eq!(value, 0.0);
        assert!(value.is_sign_negative());
        lua_settop(state, 0);
    }
}

#[test]
fn string_stack_tolstring_number_replaces_slot_and_numbertocstring_does_not() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：state 存活；緩衝區符合固定 header 的大小。
    unsafe {
        lua_pushnumber(state, -0.0);
        assert_eq!(lua_type(state, -1), 3);
        assert_eq!(lua_isstring(state, -1), 1);
        #[cfg(feature = "lua55")]
        {
            let mut buffer = [0x7f_u8; 64];
            assert_eq!(
                lua_numbertocstring(state, -1, buffer.as_mut_ptr().cast()),
                5
            );
            assert_eq!(&buffer[..5], b"-0.0\0");
            assert_eq!(lua_type(state, -1), 3);
            lua_pushnil(state);
            assert_eq!(
                lua_numbertocstring(state, -1, buffer.as_mut_ptr().cast()),
                0
            );
            assert_eq!(&buffer[..5], b"-0.0\0");
            lua_settop(state, 1);
        }
        let mut len = usize::MAX;
        let string = lua_tolstring(state, -1, &mut len);
        assert_eq!(returned_bytes(string, len), b"-0.0");
        assert_eq!(lua_type(state, -1), 4);
        assert_eq!(lua_tolstring(state, -1, &mut len), string);
        assert_eq!(len, 4);
        lua_pushinteger(state, 7);
        let seven = lua_tolstring(state, -1, &mut len);
        assert_eq!(returned_bytes(seven, len), b"7");
        lua_pushnil(state);
        len = usize::MAX;
        assert!(lua_tolstring(state, -1, &mut len).is_null());
        assert_eq!(len, 0);
        assert_eq!(returned_bytes(string, 4), b"-0.0");
        lua_settop(state, 0);
    }
}

#[test]
fn string_stack_view_pointer_survives_growth_gc_clone_copy_xmove_and_drop() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let other = StateOwner::new().unwrap();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let state = owner.as_ptr();
    let moved = sibling.as_ptr();
    let source = b"rooted\0binary";
    // SAFETY：三個 owner 均存活；source 有固定長度，pointer 僅在至少一個 slot 存活時讀取。
    unsafe {
        let pointer = lua_pushlstring(state, source.as_ptr().cast(), source.len());
        assert_eq!(returned_bytes(pointer, source.len()), source);
        assert_eq!(lua_checkstack(state, 256), 1);
        for _ in 0..128 {
            lua_pushnil(state);
        }
        assert_eq!(returned_bytes(pointer, source.len()), source);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(returned_bytes(pointer, source.len()), source);
        lua_pushvalue(state, 1);
        let clone = lua_tolstring(state, -1, std::ptr::null_mut());
        assert_eq!(clone, pointer);
        lua_copy(state, 1, 2);
        assert_eq!(lua_tolstring(state, 2, std::ptr::null_mut()), pointer);
        lua_xmove(state, moved, 1);
        assert_eq!(lua_tolstring(moved, -1, std::ptr::null_mut()), pointer);
        lua_settop(state, 0);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(returned_bytes(pointer, source.len()), source);
        let object = sibling
            .with_vm(|vm| vm.roots().count(RootKind::Host))
            .unwrap();
        assert_eq!(object, 1);
    }
    let foreign = owner
        .with_vm(|vm| vm.allocate_byte_string(b"foreign").unwrap())
        .unwrap();
    assert_eq!(
        other.push_value(Value::Object(foreign)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    assert_eq!(snapshot(&other).reserved, 0);
    drop(owner);
    // SAFETY：sibling 仍持有 group／string slot，pointer 仍有效。
    unsafe {
        let pointer = lua_tolstring(moved, -1, std::ptr::null_mut());
        assert_eq!(returned_bytes(pointer, source.len()), source);
        lua_settop(moved, 0);
    }
    sibling.with_vm(|vm| vm.collect().unwrap()).unwrap();
    drop(sibling);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn string_stack_failures_preserve_slots_views_and_ledger() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let held = CString::new("held").unwrap();
    // SAFETY：state 與 held 存活；用既有 slot pointer 驗證失敗後未懸空。
    let pointer = unsafe { lua_pushstring(state, held.as_ptr()) };
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    let attempted = CString::new("attempted").unwrap();
    // SAFETY：state 與 attempted 有效，失敗時 stack 不可有部分 slot。
    unsafe {
        assert!(lua_pushstring(state, attempted.as_ptr()).is_null());
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tolstring(state, 1, std::ptr::null_mut()), pointer);
    }
    assert_eq!(snapshot(&owner), before);

    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(vm.allocation_trace().next_ordinal))
        .unwrap();
    // SAFETY：注入失敗應由 FFI 吃下且不改原 slot。
    unsafe {
        assert!(lua_pushlstring(state, b"x".as_ptr().cast(), 1).is_null());
        assert_eq!(lua_gettop(state), 1);
    }
    assert_eq!(snapshot(&owner), before);
    // 填滿現有 stack capacity，讓下一個成功解析結果必須先擴容。
    unsafe { lua_settop(state, 20) };
    let filled = snapshot(&owner);
    owner
        .with_vm(|vm| vm.set_allocation_limit(filled.committed))
        .unwrap();
    let limited = snapshot(&owner);
    let answer = CString::new("42").unwrap();
    // SAFETY：額度不足時兩個入口均 fail-closed，原 view 仍有效。
    unsafe {
        assert!(lua_pushlstring(state, b"x".as_ptr().cast(), 1).is_null());
        assert_eq!(lua_stringtonumber(state, answer.as_ptr()), 0);
        assert_eq!(lua_gettop(state), 20);
        assert_eq!(returned_bytes(pointer, 4), b"held");
    }
    assert_eq!(snapshot(&owner), limited);
    owner
        .with_vm(|vm| vm.set_allocation_limit(before.limit))
        .unwrap();

    let numeric = StateOwner::new().unwrap();
    let numeric_state = numeric.as_ptr();
    // SAFETY：numeric_state 有效；將 number 轉字串失敗後仍須是 number。
    unsafe { lua_pushinteger(numeric_state, 77) };
    let numeric_before = snapshot(&numeric);
    numeric
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RootReserve))
        .unwrap();
    // SAFETY：RootReserve 注入點在新 ByteString 建立後，rollback 不改既有 number slot。
    unsafe {
        let mut len = usize::MAX;
        assert!(lua_tolstring(numeric_state, -1, &mut len).is_null());
        assert_eq!(len, 0);
        assert_eq!(lua_type(numeric_state, -1), 3);
    }
    assert_eq!(snapshot(&numeric), numeric_before);
}

#[test]
fn string_stack_each_publication_allocation_failure_refunds_unpublished_bytes() {
    let mut failed_sites = Vec::new();
    let mut successful_offsets = Vec::new();
    for offset in 0..24 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：先填滿初始 stack capacity，讓發布字串時也必須擴容。
        unsafe { lua_settop(state, 128) };
        let before = snapshot(&owner);
        owner
            .with_vm(|vm| {
                let start = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(start + offset);
            })
            .unwrap();
        // SAFETY：來源陣列在呼叫期間有效；注入失敗由 FFI 轉為 NULL。
        let pointer = unsafe { lua_pushlstring(state, b"publication".as_ptr().cast(), 11) };
        if pointer.is_null() {
            assert_eq!(unsafe { lua_gettop(state) }, 128, "offset {offset}");
            assert_eq!(snapshot(&owner), before, "offset {offset}");
            assert_eq!(
                owner
                    .with_vm(|vm| vm.roots().count(RootKind::Host))
                    .unwrap(),
                0
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            failed_sites.push((
                offset,
                failure.attempt.domain,
                failure.attempt.bytes,
                failure.attempt.site.file,
            ));
        } else {
            assert_eq!(returned_bytes(pointer, 11), b"publication");
            assert_eq!(unsafe { lua_gettop(state) }, 129, "offset {offset}");
            successful_offsets.push(offset);
            unsafe { lua_settop(state, 0) };
        }
    }
    assert_eq!(
        failed_sites
            .iter()
            .map(|(offset, _, _, _)| *offset)
            .collect::<Vec<_>>(),
        (0..7).collect::<Vec<_>>(),
        "{failed_sites:?}"
    );
    assert_eq!(successful_offsets, (7..24).collect::<Vec<_>>());
    assert_eq!(
        failed_sites
            .iter()
            .map(|(_, domain, _, _)| *domain)
            .collect::<Vec<_>>(),
        [
            AllocationDomain::Host,
            AllocationDomain::Host,
            AllocationDomain::LuaHeap,
            AllocationDomain::LuaHeap,
            AllocationDomain::LuaHeap,
            AllocationDomain::Host,
            AllocationDomain::Host,
        ]
    );
}
