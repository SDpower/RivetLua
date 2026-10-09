use std::ffi::{c_char, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_isinteger, lua_newuserdatauv,
    lua_pushboolean, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil,
    lua_pushnumber, lua_pushvalue, lua_rawequal, lua_toboolean, lua_tointegerx, lua_tolstring,
    lua_tonumberx, lua_topointer, lua_touserdata, lua_type, lua_xmove,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationTrace, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind, Vm,
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

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, Roots);
type Slot = (i32, i32, i64, u64, i32, usize, Vec<u8>);
type StackSnapshot = (i32, Vec<Slot>, Vec<i32>);

fn vm_snapshot(owner: &StateOwner) -> VmSnapshot {
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

fn stack_snapshot(state: *mut lua_State) -> StackSnapshot {
    // SAFETY：StateOwner 在呼叫期間持有 state 與 slots；只讀取 top 範圍內的值。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer_tag = lua_isinteger(state, index);
                let integer = if integer_tag != 0 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let number_bits = if tag == LUA_TNUMBER && integer_tag == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let boolean = lua_toboolean(state, index);
                let pointer = if tag == LUA_TLIGHTUSERDATA {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                let bytes = if tag == LUA_TSTRING {
                    let mut len = 0;
                    let value = lua_tolstring(state, index, &mut len);
                    assert!(!value.is_null());
                    std::slice::from_raw_parts(value.cast::<u8>(), len).to_vec()
                } else {
                    Vec::new()
                };
                (
                    tag,
                    integer_tag,
                    integer,
                    number_bits,
                    boolean,
                    pointer,
                    bytes,
                )
            })
            .collect();
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        (top, slots, identities)
    }
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

#[derive(Clone, Copy)]
struct ReadCase {
    label: &'static str,
    index: i32,
    tag: i32,
    integer: i32,
    boolean: i32,
}

fn assert_read_case(owner: &StateOwner, case: ReadCase) {
    let state = owner.as_ptr();
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(owner);
    // SAFETY：owner 持有有效 state；無效與 pseudo index 由既有入口 fail-closed。
    unsafe {
        for _ in 0..3 {
            assert_eq!(lua_type(state, case.index), case.tag, "{} type", case.label);
            assert_eq!(
                lua_isinteger(state, case.index),
                case.integer,
                "{} isinteger",
                case.label
            );
            assert_eq!(
                lua_toboolean(state, case.index),
                case.boolean,
                "{} toboolean",
                case.label
            );
        }
    }
    assert_eq!(stack_snapshot(state), before_stack, "{} stack", case.label);
    assert_eq!(vm_snapshot(owner), before_vm, "{} VM/GC", case.label);
}

fn enter_active_gc(owner: &StateOwner) {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        })
        .unwrap();
}

fn scalar_queries() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 7_u8;
    let pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：owner 持有有效 state；lightuserdata 只保存 opaque pointer，不解參照。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 0);
        lua_pushboolean(state, -9);
        lua_pushinteger(state, 0);
        lua_pushinteger(state, i64::MIN);
        lua_pushnumber(state, 0.0);
        lua_pushnumber(state, 42.0);
        lua_pushnumber(state, 2.5);
        lua_pushnumber(state, f64::NAN);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, pointer);
        let empty = b"";
        assert!(!lua_pushlstring(state, empty.as_ptr().cast::<c_char>(), empty.len()).is_null());
        let numeric = b"123";
        assert!(
            !lua_pushlstring(state, numeric.as_ptr().cast::<c_char>(), numeric.len()).is_null()
        );
        lua_createtable(state, 0, 0);
    }

    let (function_handle, coroutine_handle) = owner
        .with_vm(|vm| {
            let registry = registry(vm);
            let Value::Object(globals) = vm.raw_get(registry, Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須是 table");
            };
            vm.install_basic_builtins(globals).unwrap();
            let type_key = vm.allocate_byte_string(b"type").unwrap();
            let function = vm.raw_get(globals, Value::Object(type_key)).unwrap();
            let Value::Object(function_object) = function else {
                panic!("basic type 必須是 function");
            };
            assert_eq!(vm.object_kind(function_object), Ok(ObjectKind::Builtin));
            (
                rivetlua_runtime::HostHandle::<Value>::new(vm, function_object).unwrap(),
                vm.new_coroutine(function).unwrap(),
            )
        })
        .unwrap();
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
    drop(function_handle);
    drop(coroutine_handle);

    // 物件保活以目前 stack Host roots 為準，避免獨立 handle 掩蓋 root 缺口。
    let objects = owner
        .with_vm(|vm| {
            let mut objects = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host {
                    objects.push((object, vm.object_kind(object).unwrap()));
                }
            });
            objects
        })
        .unwrap();
    assert!(
        objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::ByteString)
    );
    assert!(objects.iter().any(|(_, kind)| *kind == ObjectKind::Table));
    assert!(objects.iter().any(|(_, kind)| *kind == ObjectKind::Builtin));
    assert!(
        objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::Coroutine)
    );

    let cases = [
        ReadCase {
            label: "nil",
            index: 1,
            tag: LUA_TNIL,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "false",
            index: 2,
            tag: LUA_TBOOLEAN,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "true",
            index: 3,
            tag: LUA_TBOOLEAN,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "integer zero",
            index: 4,
            tag: LUA_TNUMBER,
            integer: 1,
            boolean: 1,
        },
        ReadCase {
            label: "integer min",
            index: 5,
            tag: LUA_TNUMBER,
            integer: 1,
            boolean: 1,
        },
        ReadCase {
            label: "float zero",
            index: 6,
            tag: LUA_TNUMBER,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "integral float",
            index: 7,
            tag: LUA_TNUMBER,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "fractional float",
            index: 8,
            tag: LUA_TNUMBER,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "NaN",
            index: 9,
            tag: LUA_TNUMBER,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "null lightuserdata",
            index: 10,
            tag: LUA_TLIGHTUSERDATA,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "lightuserdata",
            index: 11,
            tag: LUA_TLIGHTUSERDATA,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "empty string",
            index: 12,
            tag: LUA_TSTRING,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "numeric string",
            index: 13,
            tag: LUA_TSTRING,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "table",
            index: 14,
            tag: LUA_TTABLE,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "function",
            index: 15,
            tag: LUA_TFUNCTION,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "thread",
            index: 16,
            tag: LUA_TTHREAD,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "negative thread",
            index: -1,
            tag: LUA_TTHREAD,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "registry",
            index: REGISTRY_INDEX,
            tag: LUA_TTABLE,
            integer: 0,
            boolean: 1,
        },
        ReadCase {
            label: "zero index",
            index: 0,
            tag: LUA_TNONE,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "out of range",
            index: 17,
            tag: LUA_TNONE,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "negative out of range",
            index: -17,
            tag: LUA_TNONE,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "other registry",
            index: OTHER_REGISTRY_INDEX,
            tag: LUA_TNONE,
            integer: 0,
            boolean: 0,
        },
        ReadCase {
            label: "upvalue pseudo",
            index: REGISTRY_INDEX - 1,
            tag: LUA_TNONE,
            integer: 0,
            boolean: 0,
        },
    ];

    enter_active_gc(&owner);
    for case in cases {
        assert_read_case(&owner, case);
    }

    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            for (object, kind) in &objects {
                assert_eq!(vm.object_kind(*object), Ok(*kind));
            }
        })
        .unwrap();
    for case in cases {
        assert_read_case(&owner, case);
    }

    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(&owner);
    owner
        .with_vm(|_| {
            // SAFETY：有效 state 正在 VM busy borrow；三個純讀入口應 fail-closed。
            unsafe {
                assert_eq!(lua_type(state, 1), LUA_TNONE);
                assert_eq!(lua_isinteger(state, 4), 0);
                assert_eq!(lua_toboolean(state, 16), 0);
            }
        })
        .unwrap();
    // SAFETY：null state 由 C API 既有入口拒絕，不能碰觸有效 owner。
    unsafe {
        assert_eq!(lua_type(std::ptr::null_mut(), 1), LUA_TNONE);
        assert_eq!(lua_isinteger(std::ptr::null_mut(), 4), 0);
        assert_eq!(lua_toboolean(std::ptr::null_mut(), 16), 0);
    }
    assert_eq!(stack_snapshot(state), before_stack);
    assert_eq!(vm_snapshot(&owner), before_vm);
}

#[cfg(feature = "lua54")]
fn unsigned_macro_cases() {
    let header = include_str!("../../../include/rivetlua/lua54/lua.h");
    assert!(
        header.contains("#define lua_tounsignedx(L,i,is)\t((lua_Unsigned)lua_tointegerx(L,i,is))")
    );
    assert!(header.contains("#define lua_tounsigned(L,i)\tlua_tounsignedx(L,(i),NULL)"));

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 持有有效 state；固定巨集展開只呼叫既有 lua_tointegerx。
    unsafe {
        for value in [0, 42, -1, i64::MIN, i64::MAX] {
            lua_pushinteger(state, value);
        }
        let invalid = b"not a number";
        assert!(!lua_pushlstring(state, invalid.as_ptr().cast(), invalid.len()).is_null());
        for (index, value) in [0, 42, -1, i64::MIN, i64::MAX].into_iter().enumerate() {
            let mut isnum = -1;
            let actual = lua_tointegerx(state, index as i32 + 1, &mut isnum) as u64;
            assert_eq!(isnum, 1);
            assert_eq!(actual, value as u64);
            assert_eq!(
                lua_tointegerx(state, index as i32 + 1, std::ptr::null_mut()) as u64,
                actual
            );
        }
        let mut isnum = -1;
        assert_eq!(lua_tointegerx(state, 6, &mut isnum) as u64, 0);
        assert_eq!(isnum, 0);
        assert_eq!(lua_tointegerx(state, 6, std::ptr::null_mut()) as u64, 0);
    }
}

#[cfg(feature = "lua55")]
fn unsigned_macro_cases() {
    let header = include_str!("../../../include/rivetlua/lua55/lua.h");
    assert!(!header.contains("#define lua_tounsignedx("));
    assert!(!header.contains("#define lua_tounsigned("));
}

#[test]
fn scalar_read_a11_matrix() {
    scalar_queries();
    unsigned_macro_cases();
}

#[test]
fn pointer_identity_a37_matrix() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    let peer = sibling.as_ptr();
    let mut light_byte = 7_u8;
    let light = (&mut light_byte as *mut u8).cast::<c_void>();
    // SAFETY：兩個 owner 保持 state 有效；回傳的 identity pointer 僅比較，絕不解參照。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 0);
        lua_pushinteger(state, 42);
        lua_pushnumber(state, 2.5);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, light);
        for bytes in [b"first".as_slice(), b"second".as_slice()] {
            assert!(!lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()).is_null());
        }
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        assert!(!lua_newuserdatauv(state, 0, 0).is_null());
        assert!(!lua_newuserdatauv(state, 8, 0).is_null());
    }
    let (function_handle, coroutine_handle) = owner
        .with_vm(|vm| {
            let registry = registry(vm);
            let Value::Object(globals) = vm.raw_get(registry, Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須是 table");
            };
            vm.install_basic_builtins(globals).unwrap();
            let type_key = vm.allocate_byte_string(b"type").unwrap();
            let Value::Object(function) = vm.raw_get(globals, Value::Object(type_key)).unwrap()
            else {
                panic!("basic type 必須是 function");
            };
            (
                rivetlua_runtime::HostHandle::<Value>::new(vm, function).unwrap(),
                vm.new_coroutine(Value::Object(function)).unwrap(),
            )
        })
        .unwrap();
    let (function, coroutine) = owner
        .with_vm(|vm| {
            (
                function_handle.as_value(vm).unwrap(),
                coroutine_handle.as_value(vm).unwrap(),
            )
        })
        .unwrap();
    owner.push_value(function).unwrap();
    owner.push_value(coroutine).unwrap();
    drop(function_handle);
    drop(coroutine_handle);

    // 為四種 collectable 各建立同 stack 複本及 sibling overlay 複本。
    // SAFETY：owner／sibling 有效，xmove 僅在同一 VM 的兩個 overlay 之間移動根。
    unsafe {
        for index in [7, 9, 13, 14] {
            lua_pushvalue(state, index);
        }
        for index in [7, 9, 13, 14] {
            lua_pushvalue(state, index);
        }
        lua_xmove(state, peer, 4);
        assert_eq!(lua_gettop(state), 18);
        assert_eq!(lua_gettop(peer), 4);
    }
    enter_active_gc(&owner);
    // SAFETY：state 有效；以下僅保存資訊指標數值，後續不解參照。
    let before_gc_identities = unsafe {
        [7, 8, 9, 10, 11, 12, 13, 14, REGISTRY_INDEX].map(|index| lua_topointer(state, index))
    };

    let verify = || {
        let before_stack = stack_snapshot(state);
        let before_peer = stack_snapshot(peer);
        let before_vm = vm_snapshot(&owner);
        // SAFETY：有效 state，僅比較 opaque identity 與 stable userdata memory pointer。
        unsafe {
            for index in [1, 2, 3, 4, 5] {
                assert!(lua_topointer(state, index).is_null(), "scalar {index}");
            }
            assert_eq!(lua_topointer(state, 6), light.cast_const());
            for (original, duplicate, sibling_index) in
                [(7, 15, 1), (9, 16, 2), (13, 17, 3), (14, 18, 4)]
            {
                let identity = lua_topointer(state, original);
                assert!(!identity.is_null(), "object {original}");
                assert_eq!(lua_topointer(state, duplicate), identity);
                assert_eq!(lua_topointer(peer, sibling_index), identity);
                assert_eq!(lua_topointer(state, original - 19), identity);
            }
            for index in [8, 10] {
                assert!(!lua_topointer(state, index).is_null());
            }
            assert_ne!(lua_topointer(state, 7), lua_topointer(state, 8));
            assert_ne!(lua_topointer(state, 9), lua_topointer(state, 10));
            let identities =
                [7, 8, 9, 10, 13, 14].map(|index| lua_topointer(state, index).expose_provenance());
            for (left, value) in identities.iter().enumerate() {
                for other in &identities[left + 1..] {
                    assert_ne!(value, other);
                }
            }
            for index in [11, 12] {
                let pointer = lua_topointer(state, index);
                assert!(!pointer.is_null());
                assert_eq!(pointer, lua_touserdata(state, index).cast_const());
                assert_eq!(lua_topointer(state, index - 19), pointer);
            }
            assert_ne!(lua_topointer(state, 11), lua_topointer(state, 12));
            let registry = lua_topointer(state, REGISTRY_INDEX);
            assert!(!registry.is_null());
            assert_eq!(registry, lua_topointer(peer, REGISTRY_INDEX));
            for index in [0, 19, -19, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
                assert!(lua_topointer(state, index).is_null(), "invalid {index}");
            }
        }
        assert_eq!(stack_snapshot(state), before_stack);
        assert_eq!(stack_snapshot(peer), before_peer);
        assert_eq!(vm_snapshot(&owner), before_vm);
    };
    for _ in 0..3 {
        verify();
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
        })
        .unwrap();
    verify();
    // SAFETY：stack／registry roots 仍存活；GC 前後同物件資訊身分不變。
    unsafe {
        assert_eq!(
            [7, 8, 9, 10, 11, 12, 13, 14, REGISTRY_INDEX].map(|index| lua_topointer(state, index)),
            before_gc_identities
        );
    }

    let before_stack = stack_snapshot(state);
    let before_peer = stack_snapshot(peer);
    let before_vm = vm_snapshot(&owner);
    owner
        .with_vm(|_| {
            // SAFETY：busy VM borrow 必須由入口 fail-closed。
            unsafe {
                assert!(lua_topointer(state, 9).is_null());
                assert!(lua_topointer(peer, 2).is_null());
            }
        })
        .unwrap();
    // SAFETY：有效 state 的跨 thread 查詢應在建立共享參照前拒絕；null 亦 fail-closed。
    unsafe {
        assert!(lua_topointer(std::ptr::null_mut(), 9).is_null());
    }
    let address = state as usize;
    std::thread::spawn(move || {
        // SAFETY：owner 在 join 前存活；入口先驗 thread owner 而不建立非 Sync 參照。
        assert!(unsafe { lua_topointer(address as *mut lua_State, 9) }.is_null());
    })
    .join()
    .unwrap();
    assert_eq!(stack_snapshot(state), before_stack);
    assert_eq!(stack_snapshot(peer), before_peer);
    assert_eq!(vm_snapshot(&owner), before_vm);
}
