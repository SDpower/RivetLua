use std::ffi::{CString, c_char, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_gettop, lua_pushinteger, lua_pushlstring, lua_settop,
    lua_tointegerx, lua_tolstring, lua_touserdata, lua_type, luaL_Buffer, luaL_addgsub,
    luaL_addlstring, luaL_addstring, luaL_addvalue, luaL_buffinit, luaL_buffinitsize,
    luaL_prepbuffsize, luaL_pushresult, luaL_pushresultsize,
};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{GcMode, GcPhase, RootId, RootKind, VmError};

const LUAL_BUFFERSIZE: usize = 1024;
const LUA_TLIGHTUSERDATA: i32 = 2;
const LUA_TNUMBER: i32 = 3;
const LUA_TSTRING: i32 = 4;

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;

#[repr(C, align(16))]
struct TestBuffer {
    b: *mut c_char,
    size: usize,
    n: usize,
    state: *mut lua_State,
    init: [u8; LUAL_BUFFERSIZE],
}

fn empty_buffer() -> TestBuffer {
    TestBuffer {
        b: std::ptr::null_mut(),
        size: 0,
        n: 0,
        state: std::ptr::null_mut(),
        init: [0xA5; LUAL_BUFFERSIZE],
    }
}

fn buffer_ptr(buffer: &mut TestBuffer) -> *mut luaL_Buffer {
    (buffer as *mut TestBuffer).cast()
}

fn stack_top(state: *mut lua_State) -> i32 {
    // SAFETY：呼叫端持有尚未關閉的 StateOwner，state 在本次讀取期間有效。
    unsafe { lua_gettop(state) }
}

fn roots(owner: &StateOwner) -> RootSnapshot {
    owner
        .with_vm(|vm| {
            let mut snapshot = Vec::new();
            vm.visit_roots(|kind, id, object| snapshot.push((kind, id, object)));
            snapshot
        })
        .unwrap()
}

fn assert_buffer_anchor(state: *mut lua_State, buffer: &mut TestBuffer, expected_top: i32) {
    let buffer_address = (buffer as *mut TestBuffer).cast::<c_void>();
    // SAFETY：state 與 buffer 均由本測試持有；buffinit 已在頂端 push 該 buffer 位址。
    unsafe {
        assert_eq!(lua_gettop(state), expected_top);
        assert_eq!(lua_type(state, -1), LUA_TLIGHTUSERDATA);
        assert_eq!(lua_touserdata(state, -1), buffer_address);
    }
}

fn assert_top_string(state: *mut lua_State, expected_top: i32, expected: &[u8]) {
    // SAFETY：state 仍有效，頂端是本測試剛 push 的 Lua string；回傳指標在讀取期間由該 slot 保活。
    unsafe {
        assert_eq!(lua_gettop(state), expected_top);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        let mut len = usize::MAX;
        let pointer = lua_tolstring(state, -1, &mut len);
        assert!(!pointer.is_null());
        assert_eq!(len, expected.len());
        assert_eq!(
            std::slice::from_raw_parts(pointer.cast::<u8>(), len),
            expected
        );
    }
}

fn assert_integer_at(state: *mut lua_State, index: i32, expected: i64) {
    // SAFETY：state 仍有效，index 指向本測試先前 push 的整數 slot。
    unsafe {
        assert_eq!(lua_type(state, index), LUA_TNUMBER);
        assert_eq!(lua_tointegerx(state, index, std::ptr::null_mut()), expected);
    }
}

fn collect_full(owner: &StateOwner) {
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
}

fn assert_restored(
    owner: &StateOwner,
    state: *mut lua_State,
    baseline_top: i32,
    baseline_roots: &RootSnapshot,
) {
    // SAFETY：state 由仍存活的 owner 持有；settop 只移除本測試已驗證的結果 slot。
    unsafe {
        lua_settop(state, baseline_top);
        assert_eq!(lua_gettop(state), baseline_top);
    }
    assert_eq!(&roots(owner), baseline_roots);
}

fn append_lstring(buffer: &mut TestBuffer, bytes: &[u8]) {
    // SAFETY：buffer 由呼叫端持有；bytes 的指標在本次同步呼叫期間有效，空 slice 也使用非 null 指標。
    unsafe {
        luaL_addlstring(
            buffer_ptr(buffer),
            bytes.as_ptr().cast::<c_char>(),
            bytes.len(),
        )
    };
}

#[test]
fn aux_buffer_small_inline_binary_and_empty_appends() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_top = stack_top(state);
    assert_eq!(baseline_top, 0);
    let baseline_roots = roots(&owner);
    let mut buffer = empty_buffer();

    // SAFETY：owner 保證 state 有效；buffer 依兩版固定 header 的欄位順序與對齊配置。
    unsafe { luaL_buffinit(state, buffer_ptr(&mut buffer)) };
    assert_buffer_anchor(state, &mut buffer, baseline_top + 1);
    assert_eq!(roots(&owner), baseline_roots);

    append_lstring(&mut buffer, b"A\0B");
    let suffix = CString::new("C").unwrap();
    // SAFETY：buffer 仍有效；suffix 是以 NUL 結尾且在呼叫期間存活的 C string。
    unsafe { luaL_addstring(buffer_ptr(&mut buffer), suffix.as_ptr()) };
    append_lstring(&mut buffer, b"");
    let empty = CString::new("").unwrap();
    // SAFETY：buffer 仍有效；empty 是合法的空 C string。
    unsafe { luaL_addstring(buffer_ptr(&mut buffer), empty.as_ptr()) };

    assert_eq!(buffer.n, 4);
    assert_eq!(buffer.size, LUAL_BUFFERSIZE);
    assert_eq!(buffer.b, buffer.init.as_mut_ptr().cast::<c_char>());
    assert_eq!(stack_top(state), baseline_top + 1);

    // SAFETY：buffer anchor 仍在 state stack 上，buffer 的完整 header 與 inline storage 均有效。
    unsafe { luaL_pushresult(buffer_ptr(&mut buffer)) };
    assert_top_string(state, baseline_top + 1, b"A\0BC");
    collect_full(&owner);
    assert_top_string(state, baseline_top + 1, b"A\0BC");
    assert_restored(&owner, state, baseline_top, &baseline_roots);
}

#[test]
fn aux_buffer_repeated_growth_preserves_content_and_stack_anchor() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_top = stack_top(state);
    assert_eq!(baseline_top, 0);
    let baseline_roots = roots(&owner);
    let mut buffer = empty_buffer();

    // SAFETY：owner 保證 state 有效；buffer 依固定 header layout 配置且存活至 pushresult。
    unsafe { luaL_buffinit(state, buffer_ptr(&mut buffer)) };
    assert_buffer_anchor(state, &mut buffer, baseline_top + 1);
    assert_eq!(roots(&owner), baseline_roots);
    append_lstring(&mut buffer, &vec![b'A'; 900]);
    assert_eq!(buffer.size, LUAL_BUFFERSIZE);
    assert_eq!(buffer.b, buffer.init.as_mut_ptr().cast::<c_char>());

    let mut expected = vec![b'A'; 900];
    let mut growth_count = 0;
    for index in 0..3 {
        let old_capacity = buffer.size;
        assert!(buffer.n <= old_capacity);
        let chunk_len = old_capacity - buffer.n + 1;
        let byte = b'B' + index as u8;
        let chunk = vec![byte; chunk_len];
        append_lstring(&mut buffer, &chunk);
        expected.extend_from_slice(&chunk);
        assert!(buffer.size > old_capacity);
        assert_eq!(stack_top(state), baseline_top + 1);
        growth_count += 1;

        if index == 0 {
            assert_ne!(roots(&owner), baseline_roots);
        }

        if index == 1 {
            let rooted_growth_box = roots(&owner);
            collect_full(&owner);
            assert_eq!(stack_top(state), baseline_top + 1);
            assert_eq!(roots(&owner), rooted_growth_box);
        }
    }
    assert_eq!(growth_count, 3);
    assert!(buffer.size > LUAL_BUFFERSIZE);

    let suffix = CString::new("tail").unwrap();
    // SAFETY：buffer 仍由本測試持有，suffix 是有效且以 NUL 結尾的 C string。
    unsafe { luaL_addstring(buffer_ptr(&mut buffer), suffix.as_ptr()) };
    expected.extend_from_slice(b"tail");

    // SAFETY：buffer 的 stack anchor 仍在頂端，所有追加內容已由 buffer 擁有。
    unsafe { luaL_pushresult(buffer_ptr(&mut buffer)) };
    assert_top_string(state, baseline_top + 1, &expected);
    let rooted_result = roots(&owner);
    assert_eq!(rooted_result.len(), baseline_roots.len() + 1);
    let result_object = rooted_result
        .iter()
        .find(|entry| !baseline_roots.contains(entry))
        .unwrap()
        .2;
    collect_full(&owner);
    assert_top_string(state, baseline_top + 1, &expected);
    assert_eq!(roots(&owner), rooted_result);

    owner
        .with_vm(|vm| {
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
            assert_ne!(vm.incremental_step(1).unwrap().phase, GcPhase::Pause);
        })
        .unwrap();
    collect_full(&owner);
    assert_top_string(state, baseline_top + 1, &expected);
    assert_eq!(roots(&owner), rooted_result);
    assert_restored(&owner, state, baseline_top, &baseline_roots);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(result_object), Err(VmError::StaleObject));
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
}

#[test]
fn aux_buffer_prepbuffsize_and_pushresultsize_commit_direct_bytes() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_top = stack_top(state);
    assert_eq!(baseline_top, 0);
    let baseline_roots = roots(&owner);
    let mut buffer = empty_buffer();

    // SAFETY：owner 保證 state 有效；buffer 依固定 header layout 配置且存活至 pushresultsize。
    unsafe { luaL_buffinit(state, buffer_ptr(&mut buffer)) };
    assert_buffer_anchor(state, &mut buffer, baseline_top + 1);
    assert_eq!(roots(&owner), baseline_roots);

    let payload = b"prep\0bytes";
    // SAFETY：buffer 有效；prep 只預留 payload.len() 可寫 bytes，回傳區域在下一次 buffer 操作前有效。
    let destination = unsafe { luaL_prepbuffsize(buffer_ptr(&mut buffer), payload.len()) };
    assert!(!destination.is_null());
    assert_eq!(roots(&owner), baseline_roots);
    // SAFETY：destination 由 prepbuffsize 預留至少 payload.len() bytes，來源與目的區域不重疊。
    unsafe {
        std::ptr::copy_nonoverlapping(payload.as_ptr(), destination.cast::<u8>(), payload.len())
    };
    // SAFETY：buffer 仍有效；payload.len() bytes 已直接寫入 prep 回傳的預留區域。
    unsafe { luaL_pushresultsize(buffer_ptr(&mut buffer), payload.len()) };
    assert_top_string(state, baseline_top + 1, payload);
    assert_restored(&owner, state, baseline_top, &baseline_roots);
}

#[test]
fn aux_buffer_buffinitsize_commits_only_directly_written_bytes() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_top = stack_top(state);
    assert_eq!(baseline_top, 0);
    let baseline_roots = roots(&owner);
    let mut buffer = empty_buffer();

    let payload = b"reserved\0payload";
    let reserved = LUAL_BUFFERSIZE + 64;
    // SAFETY：owner 保證 state 有效；buffer 依固定 header layout 配置並存活至 pushresultsize。
    let destination = unsafe { luaL_buffinitsize(state, buffer_ptr(&mut buffer), reserved) };
    assert!(!destination.is_null());
    assert_eq!(stack_top(state), baseline_top + 1);
    assert_ne!(roots(&owner), baseline_roots);
    assert!(buffer.size >= reserved);
    assert_eq!(buffer.n, 0);
    // SAFETY：buffinitsize 預留 reserved bytes，payload.len() 不超出該區域且兩區不重疊。
    unsafe {
        std::ptr::copy_nonoverlapping(payload.as_ptr(), destination.cast::<u8>(), payload.len())
    };
    // SAFETY：buffer 仍有效；只有 payload.len() 個已寫入的 bytes 會加入結果。
    unsafe { luaL_pushresultsize(buffer_ptr(&mut buffer), payload.len()) };
    assert_top_string(state, baseline_top + 1, payload);
    collect_full(&owner);
    assert_top_string(state, baseline_top + 1, payload);
    assert_restored(&owner, state, baseline_top, &baseline_roots);
}

#[test]
fn aux_buffer_addvalue_pops_only_top_value_and_appends_its_bytes() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_roots = roots(&owner);
    let baseline_top = stack_top(state);
    assert_eq!(baseline_top, 0);

    // SAFETY：owner 保證 state 有效；整數是本測試用來確認下方 stack slot 未被 pop 的 sentinel。
    unsafe { lua_pushinteger(state, 73) };
    let buffer_base_top = baseline_top + 1;
    let roots_with_sentinel = roots(&owner);
    let mut buffer = empty_buffer();
    // SAFETY：owner 保證 state 有效；buffer 依固定 header layout 配置且存活至 pushresult。
    unsafe { luaL_buffinit(state, buffer_ptr(&mut buffer)) };
    assert_buffer_anchor(state, &mut buffer, buffer_base_top + 1);
    assert_eq!(roots(&owner), roots_with_sentinel);

    let prefix = CString::new("prefix:").unwrap();
    // SAFETY：buffer anchor 有效；prefix 是有效且以 NUL 結尾的 C string。
    unsafe { luaL_addstring(buffer_ptr(&mut buffer), prefix.as_ptr()) };
    let value = b"top\0value";
    // SAFETY：state 有效，value 指標在同步 push 呼叫期間有效，且指定長度包含 embedded NUL。
    let pushed = unsafe { lua_pushlstring(state, value.as_ptr().cast::<c_char>(), value.len()) };
    assert!(!pushed.is_null());
    let before_addvalue_top = stack_top(state);
    assert_eq!(before_addvalue_top, buffer_base_top + 2);
    let roots_with_value = roots(&owner);
    assert_ne!(roots_with_value, roots_with_sentinel);

    // SAFETY：頂端是本測試剛 push 的 Lua string；buffer anchor 位於它正下方且仍有效。
    unsafe { luaL_addvalue(buffer_ptr(&mut buffer)) };
    assert_eq!(stack_top(state), before_addvalue_top - 1);
    assert_integer_at(state, 1, 73);
    assert_buffer_anchor(state, &mut buffer, buffer_base_top + 1);
    assert_eq!(roots(&owner), roots_with_sentinel);

    // SAFETY：buffer anchor 仍在 stack 上，pushresult 應移除 anchor 並留下組成後的 string。
    unsafe { luaL_pushresult(buffer_ptr(&mut buffer)) };
    assert_eq!(stack_top(state), buffer_base_top + 1);
    assert_integer_at(state, 1, 73);
    assert_top_string(state, buffer_base_top + 1, b"prefix:top\0value");
    assert_restored(&owner, state, buffer_base_top, &roots_with_sentinel);
    assert_restored(&owner, state, baseline_top, &baseline_roots);
}

fn assert_gsub_case(input: &str, pattern: &str, replacement: &str, expected: &[u8]) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline_top = stack_top(state);
    let baseline_roots = roots(&owner);
    let mut buffer = empty_buffer();
    // SAFETY：owner 保證 state 有效；buffer 依固定 header layout 配置且存活至 pushresult。
    unsafe { luaL_buffinit(state, buffer_ptr(&mut buffer)) };
    assert_buffer_anchor(state, &mut buffer, baseline_top + 1);
    assert_eq!(roots(&owner), baseline_roots);

    let input = CString::new(input).unwrap();
    let pattern = CString::new(pattern).unwrap();
    let replacement = CString::new(replacement).unwrap();
    // SAFETY：buffer 與所有 C strings 均在呼叫期間有效；本案例使用非空 pattern。
    unsafe {
        luaL_addgsub(
            buffer_ptr(&mut buffer),
            input.as_ptr(),
            pattern.as_ptr(),
            replacement.as_ptr(),
        )
    };
    assert_eq!(stack_top(state), baseline_top + 1);

    // SAFETY：buffer anchor 仍在頂端；pushresult 應以單一結果字串取代 anchor。
    unsafe { luaL_pushresult(buffer_ptr(&mut buffer)) };
    assert_top_string(state, baseline_top + 1, expected);
    assert_restored(&owner, state, baseline_top, &baseline_roots);
}

#[test]
fn aux_buffer_addgsub_zero_and_multiple_nonempty_matches() {
    assert_gsub_case("unchanged", "xyz", "!", b"unchanged");
    assert_gsub_case("afoofoo", "foo", "foo!", b"afoo!foo!");

    // 固定 Lua 5.4.9／5.5.1 對空 pattern 會令 strstr 命中目前位置且不前進；依 A49 決議不直接呼叫此非終止輸入。
}
