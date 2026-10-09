use std::ffi::{CStr, c_char, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_rawequal,
    lua_toboolean, lua_tolstring, lua_tonumberx, lua_touserdata, lua_type, lua_typename,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationTrace, GcTrace, HostHandle, LedgerProbe, LedgerSnapshot, ObjectKind, RootId,
    RootKind, Vm,
};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

const LUA_TNONE: i32 = -1;
const LUA_TNIL: i32 = 0;
const LUA_TBOOLEAN: i32 = 1;
const LUA_TLIGHTUSERDATA: i32 = 2;
const LUA_TNUMBER: i32 = 3;
const LUA_TSTRING: i32 = 4;
const LUA_TTABLE: i32 = 5;
const LUA_TFUNCTION: i32 = 6;
const LUA_TTHREAD: i32 = 8;

#[derive(Clone, Copy)]
struct PredicateCase {
    label: &'static str,
    index: i32,
    tag: i32,
    name: &'static [u8],
}

fn registry(vm: &Vm) -> ObjectRef {
    let mut found = Vec::new();
    vm.visit_roots(|kind, _, object| {
        if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
            found.push(object);
        }
    });
    assert_eq!(found.len(), 1);
    found[0]
}

fn install_function_and_coroutine(owner: &StateOwner) -> (HostHandle<Value>, HostHandle<Value>) {
    owner
        .with_vm(|vm| {
            let registry = registry(vm);
            let Value::Object(globals) = vm.raw_get(registry, Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須是 table");
            };
            assert_eq!(vm.object_kind(globals), Ok(ObjectKind::Table));
            vm.install_basic_builtins(globals).unwrap();

            let type_key = vm.allocate_byte_string(b"type").unwrap();
            let function = vm.raw_get(globals, Value::Object(type_key)).unwrap();
            let Value::Object(function_object) = function else {
                panic!("basic type 必須是 function");
            };
            assert_eq!(vm.object_kind(function_object), Ok(ObjectKind::Builtin));
            let function_handle = HostHandle::<Value>::new(vm, function_object).unwrap();
            let coroutine_handle = vm.new_coroutine(function).unwrap();
            (function_handle, coroutine_handle)
        })
        .unwrap()
}

fn static_name(pointer: *const c_char) -> Option<Vec<u8>> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY：lua_typename 僅回傳固定靜態 NUL 結尾字串；null 已在上方排除。
    Some(unsafe { CStr::from_ptr(pointer).to_bytes().to_vec() })
}

fn expected_predicates(tag: i32) -> [bool; 8] {
    match tag {
        LUA_TNONE => [false, false, false, false, false, false, true, true],
        LUA_TNIL => [false, false, false, true, false, false, false, true],
        LUA_TBOOLEAN => [false, false, false, false, true, false, false, false],
        LUA_TLIGHTUSERDATA => [false, false, true, false, false, false, false, false],
        LUA_TNUMBER | LUA_TSTRING => [false, false, false, false, false, false, false, false],
        LUA_TTABLE => [false, true, false, false, false, false, false, false],
        LUA_TFUNCTION => [true, false, false, false, false, false, false, false],
        LUA_TTHREAD => [false, false, false, false, false, true, false, false],
        _ => panic!("A7 matrix 不接受 tag {tag}"),
    }
}

fn assert_case(state: *mut rivetlua_capi::stack::lua_State, case: PredicateCase) {
    // SAFETY：StateOwner 在每次呼叫期間存活；indices 由本測試指定且 C API 對 invalid index fail-closed。
    unsafe {
        let tag = lua_type(state, case.index);
        assert_eq!(tag, case.tag, "{} 的 lua_type", case.label);

        // Rust 測試無法展開 C 巨集；此表直接對應固定 header 的 tag comparisons。
        let actual = [
            tag == LUA_TFUNCTION,
            tag == LUA_TTABLE,
            tag == LUA_TLIGHTUSERDATA,
            tag == LUA_TNIL,
            tag == LUA_TBOOLEAN,
            tag == LUA_TTHREAD,
            tag == LUA_TNONE,
            tag <= LUA_TNIL,
        ];
        assert_eq!(
            actual,
            expected_predicates(case.tag),
            "{} 的 predicate matrix",
            case.label
        );

        let expanded_tag = lua_type(state, case.index);
        let expanded_name = lua_typename(state, expanded_tag);
        assert_eq!(
            static_name(expanded_name).as_deref(),
            Some(case.name),
            "{} 的 luaL_typename 展開",
            case.label
        );
    }
}

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;

fn vm_snapshot(owner: &StateOwner) -> (LedgerSnapshot, AllocationTrace, GcTrace, RootSnapshot) {
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

fn slot_fingerprints(owner: &StateOwner) -> Vec<(i32, i32, u64, usize, Vec<u8>)> {
    let state = owner.as_ptr();
    // SAFETY：owner 保持 state 與所有 stack slot 有效；byte string slot 已由 pushlstring 建立固定 view。
    unsafe {
        let top = lua_gettop(state);
        (1..=top)
            .map(|slot| {
                let tag = lua_type(state, slot);
                let boolean = if tag == LUA_TBOOLEAN {
                    lua_toboolean(state, slot)
                } else {
                    0
                };
                let number = if tag == LUA_TNUMBER {
                    lua_tonumberx(state, slot, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let pointer = if tag == LUA_TLIGHTUSERDATA {
                    lua_touserdata(state, slot).expose_provenance()
                } else {
                    0
                };
                let bytes = if tag == LUA_TSTRING {
                    let mut len = 0;
                    let ptr = lua_tolstring(state, slot, &mut len);
                    assert!(!ptr.is_null());
                    std::slice::from_raw_parts(ptr.cast::<u8>(), len).to_vec()
                } else {
                    Vec::new()
                };
                (tag, boolean, number, pointer, bytes)
            })
            .collect()
    }
}

fn observation(owner: &StateOwner) -> (i32, Vec<(i32, i32, u64, usize, Vec<u8>)>, Vec<i32>) {
    let state = owner.as_ptr();
    // SAFETY：owner 保持 state 有效；rawequal 僅比較本測試仍 rooted 的既有 slots。
    let (top, identities) = unsafe {
        let top = lua_gettop(state);
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        (top, identities)
    };
    (top, slot_fingerprints(owner), identities)
}

#[test]
fn type_predicates_a7_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保持 state 有效；lightuserdata 使用合法 null opaque pointer。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 41);
        lua_pushnumber(state, 2.5);
        lua_pushlightuserdata(state, std::ptr::null_mut::<c_void>());
        let bytes = b"a7\0\xff";
        assert!(!lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()).is_null());
        lua_createtable(state, 0, 0);
    }

    let (function_handle, coroutine_handle) = install_function_and_coroutine(&owner);
    let (function_value, coroutine_value) = owner
        .with_vm(|vm| {
            (
                function_handle.as_value(vm).unwrap(),
                coroutine_handle.as_value(vm).unwrap(),
            )
        })
        .unwrap();
    owner.push_value(function_value).unwrap();
    owner.push_value(coroutine_value).unwrap();

    let none = LUA_TNONE;
    let cases = [
        PredicateCase {
            label: "nil",
            index: 1,
            tag: LUA_TNIL,
            name: b"nil",
        },
        PredicateCase {
            label: "boolean",
            index: 2,
            tag: LUA_TBOOLEAN,
            name: b"boolean",
        },
        PredicateCase {
            label: "integer",
            index: 3,
            tag: LUA_TNUMBER,
            name: b"number",
        },
        PredicateCase {
            label: "float",
            index: 4,
            tag: LUA_TNUMBER,
            name: b"number",
        },
        PredicateCase {
            label: "lightuserdata",
            index: 5,
            tag: LUA_TLIGHTUSERDATA,
            name: b"userdata",
        },
        PredicateCase {
            label: "byte string",
            index: 6,
            tag: LUA_TSTRING,
            name: b"string",
        },
        PredicateCase {
            label: "table",
            index: 7,
            tag: LUA_TTABLE,
            name: b"table",
        },
        PredicateCase {
            label: "builtin function",
            index: 8,
            tag: LUA_TFUNCTION,
            name: b"function",
        },
        PredicateCase {
            label: "coroutine thread",
            index: 9,
            tag: LUA_TTHREAD,
            name: b"thread",
        },
        PredicateCase {
            label: "registry pseudo-index",
            index: REGISTRY_INDEX,
            tag: LUA_TTABLE,
            name: b"table",
        },
        PredicateCase {
            label: "zero index",
            index: 0,
            tag: none,
            name: b"no value",
        },
        PredicateCase {
            label: "positive invalid index",
            index: 10,
            tag: none,
            name: b"no value",
        },
        PredicateCase {
            label: "negative invalid index",
            index: -10,
            tag: none,
            name: b"no value",
        },
        PredicateCase {
            label: "other profile registry pseudo-index",
            index: OTHER_REGISTRY_INDEX,
            tag: none,
            name: b"no value",
        },
        PredicateCase {
            label: "upvalue pseudo-index",
            index: REGISTRY_INDEX - 1,
            tag: none,
            name: b"no value",
        },
    ];

    let before = (observation(&owner), vm_snapshot(&owner));
    for _ in 0..3 {
        for case in cases {
            assert_case(state, case);
        }
        // LUA_TNONE 仍由固定 lua_typename 的有效 static name 處理；越界 tag 則回 null。
        // SAFETY：owner 有效；99 不是固定 Lua type tag，API 對未知 tag 回傳 null。
        unsafe {
            assert!(lua_typename(state, 99).is_null());
        }
    }
    let after = (observation(&owner), vm_snapshot(&owner));
    assert_eq!(
        after, before,
        "重複 tag/name 讀取不得改變 stack、roots、ledger 或 GC trace"
    );

    let probe: LedgerProbe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            let function = function_handle.as_value(vm).unwrap();
            let Value::Object(function) = function else {
                panic!("function handle 必須仍指向 object");
            };
            assert_eq!(vm.object_kind(function), Ok(ObjectKind::Builtin));
            let coroutine = coroutine_handle.as_value(vm).unwrap();
            let Value::Object(coroutine) = coroutine else {
                panic!("coroutine handle 必須仍指向 object");
            };
            assert_eq!(vm.object_kind(coroutine), Ok(ObjectKind::Coroutine));
        })
        .unwrap();
    // SAFETY：owner 與兩個 stack root 仍存活；GC 後原 slots 必須保留既有 tag。
    unsafe {
        assert_eq!(lua_type(state, 8), LUA_TFUNCTION);
        assert_eq!(lua_type(state, 9), LUA_TTHREAD);
    }

    // SAFETY：with_vm 期間故意持有 VM borrow；reentrant C entry points 必須 fail-closed。
    owner
        .with_vm(|_| unsafe {
            assert_eq!(lua_type(state, 1), LUA_TNONE);
            assert!(lua_typename(state, LUA_TSTRING).is_null());
        })
        .unwrap();

    drop(owner);
    drop(function_handle);
    drop(coroutine_handle);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}
