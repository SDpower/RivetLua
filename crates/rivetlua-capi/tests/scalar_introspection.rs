use std::ffi::{c_char, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_isuserdata, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_rawequal,
    lua_toboolean, lua_tolstring, lua_tonumberx, lua_touserdata, lua_type, lua_version,
};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{
    AllocationTrace, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind,
};

#[cfg(feature = "lua55")]
use rivetlua_capi::{luaL_alloc, luaL_makeseed};

#[cfg(feature = "lua55")]
const EXPECTED_VERSION: f64 = 505.0;
#[cfg(feature = "lua54")]
const EXPECTED_VERSION: f64 = 504.0;

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
const LUA_TUSERDATA: i32 = 7;

#[derive(Clone, Copy)]
struct UserdataCase {
    label: &'static str,
    index: i32,
    tag: i32,
    expected: bool,
}

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, Roots);
type SlotFingerprint = (i32, i32, u64, usize, Vec<u8>);
type StateSnapshot = (i32, Vec<SlotFingerprint>, Vec<i32>);

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

fn state_snapshot(state: *mut rivetlua_capi::stack::lua_State) -> StateSnapshot {
    // SAFETY：StateOwner 在呼叫期間存活，所有正索引均由目前 top 限定。
    let top = unsafe { lua_gettop(state) };
    // SAFETY：每個 C API 呼叫都使用仍有效的 state；byte-string slot 由本測試建立且不為空。
    let slots = unsafe {
        (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let boolean = if tag == LUA_TBOOLEAN {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                let number = if tag == LUA_TNUMBER {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let pointer = if tag == LUA_TLIGHTUSERDATA {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                let bytes = if tag == LUA_TSTRING {
                    let mut len = 0;
                    let pointer = lua_tolstring(state, index, &mut len);
                    assert!(!pointer.is_null());
                    std::slice::from_raw_parts(pointer.cast::<u8>(), len).to_vec()
                } else {
                    Vec::new()
                };
                (tag, boolean, number, pointer, bytes)
            })
            .collect()
    };
    // SAFETY：indices 僅遍歷有效 slots；rawequal 只讀取本測試仍 rooted 的值。
    let identities = unsafe {
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        identities
    };
    (top, slots, identities)
}

#[test]
fn scalar_introspection_a8_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 1_u8;
    let token_pointer = (&mut token as *mut u8).cast::<c_void>();

    // SAFETY：owner 保持 state 有效；lightuserdata 只保存 opaque pointer，不解參照。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 41);
        lua_pushnumber(state, 2.5);
        lua_pushlightuserdata(state, std::ptr::null_mut::<c_void>());
        lua_pushlightuserdata(state, token_pointer);
        let bytes = b"a8\0\xff";
        assert!(!lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len()).is_null());
        lua_createtable(state, 0, 0);
    }

    let cases = [
        UserdataCase {
            label: "none index",
            index: 0,
            tag: LUA_TNONE,
            expected: false,
        },
        UserdataCase {
            label: "invalid index",
            index: 100,
            tag: LUA_TNONE,
            expected: false,
        },
        UserdataCase {
            label: "nil",
            index: 1,
            tag: LUA_TNIL,
            expected: false,
        },
        UserdataCase {
            label: "boolean",
            index: 2,
            tag: LUA_TBOOLEAN,
            expected: false,
        },
        UserdataCase {
            label: "integer",
            index: 3,
            tag: LUA_TNUMBER,
            expected: false,
        },
        UserdataCase {
            label: "float",
            index: 4,
            tag: LUA_TNUMBER,
            expected: false,
        },
        UserdataCase {
            label: "null lightuserdata",
            index: 5,
            tag: LUA_TLIGHTUSERDATA,
            expected: true,
        },
        UserdataCase {
            label: "non-null lightuserdata",
            index: 6,
            tag: LUA_TLIGHTUSERDATA,
            expected: true,
        },
        UserdataCase {
            label: "byte string",
            index: 7,
            tag: LUA_TSTRING,
            expected: false,
        },
        UserdataCase {
            label: "table",
            index: 8,
            tag: LUA_TTABLE,
            expected: false,
        },
        UserdataCase {
            label: "current registry",
            index: REGISTRY_INDEX,
            tag: LUA_TTABLE,
            expected: false,
        },
        UserdataCase {
            label: "other-profile registry",
            index: OTHER_REGISTRY_INDEX,
            tag: LUA_TNONE,
            expected: false,
        },
        UserdataCase {
            label: "upvalue pseudo-index",
            index: REGISTRY_INDEX - 1,
            tag: LUA_TNONE,
            expected: false,
        },
    ];

    // SAFETY：有效 owner pointer 與 null pointer 都符合本片契約；lua_version 不檢查 state。
    unsafe {
        for _ in 0..4 {
            assert_eq!(lua_version(state), EXPECTED_VERSION);
            assert_eq!(lua_version(std::ptr::null_mut()), EXPECTED_VERSION);
        }
        assert_eq!(lua_isuserdata(std::ptr::null_mut(), 1), 0);
    }

    // 開始一個仍在進行中的 incremental GC cycle，讓純度檢查涵蓋 active GC 狀態。
    let active_gc = owner.with_vm(|vm| vm.incremental_step(1).unwrap()).unwrap();
    assert_ne!(active_gc.phase, GcPhase::Pause);
    let before_state = state_snapshot(state);
    let before_vm = vm_snapshot(&owner);

    // SAFETY：state 與所有有效／pseudo indices 均屬於仍存活的 owner；C API 對無效索引 fail-closed。
    unsafe {
        for case in cases {
            let tag = lua_type(state, case.index);
            assert_eq!(tag, case.tag, "{} 的 lua_type", case.label);
            let expected_from_tag = matches!(tag, LUA_TLIGHTUSERDATA | LUA_TUSERDATA);
            assert_eq!(
                expected_from_tag, case.expected,
                "{} 的 expected tag",
                case.label
            );
            for _ in 0..3 {
                assert_eq!(
                    lua_isuserdata(state, case.index),
                    i32::from(case.expected),
                    "{} 的 lua_isuserdata",
                    case.label
                );
            }
        }
        for _ in 0..4 {
            assert_eq!(lua_version(state), EXPECTED_VERSION);
            assert_eq!(lua_version(std::ptr::null_mut()), EXPECTED_VERSION);
        }
    }
    assert_eq!(state_snapshot(state), before_state);
    assert_eq!(
        vm_snapshot(&owner),
        before_vm,
        "introspection 必須保持 roots、ledger、allocation 與 GC trace 不變"
    );
    assert_eq!(
        vm_snapshot(&owner).2,
        before_vm.2,
        "active GC 下不可產生 GC transition"
    );

    // 後續 minor／major collection 不得回收仍由 stack slots rooted 的 string/table。
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            let mut host_objects = Vec::new();
            vm.visit_roots(|kind, id, object| {
                if kind == RootKind::Host {
                    host_objects.push((id, object));
                }
            });
            assert!(!host_objects.is_empty());
            for (_, object) in host_objects {
                assert!(matches!(
                    vm.object_kind(object),
                    Ok(ObjectKind::ByteString | ObjectKind::Table)
                ));
            }
        })
        .unwrap();
    assert_eq!(state_snapshot(state), before_state);

    let before_busy_state = state_snapshot(state);
    let before_busy_vm = vm_snapshot(&owner);
    // with_vm 期間故意持有 VM borrow；userdata predicate 必須 fail-closed，version 仍忽略 L。
    owner
        .with_vm(|_| unsafe {
            assert_eq!(lua_version(state), EXPECTED_VERSION);
            assert_eq!(lua_isuserdata(state, 5), 0);
        })
        .unwrap();
    assert_eq!(state_snapshot(state), before_busy_state);
    assert_eq!(vm_snapshot(&owner), before_busy_vm);

    // SAFETY：owner 仍有效；null state 只驗證兩個指定的 fail-closed／version 行為。
    unsafe {
        assert_eq!(lua_version(std::ptr::null_mut()), EXPECTED_VERSION);
        assert_eq!(lua_isuserdata(std::ptr::null_mut(), 5), 0);
    }

    #[cfg(feature = "lua55")]
    makeseed_a14_matrix();
}

#[cfg(feature = "lua55")]
fn makeseed_a14_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();

    // SAFETY：owner 保持 state 有效；此處建立的值由 C stack roots 保活。
    unsafe {
        lua_pushinteger(state, 55);
        let bytes = b"makeseed\0\xff";
        assert!(!lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len()).is_null());
        lua_createtable(state, 0, 0);
    }

    let active_gc = owner.with_vm(|vm| vm.incremental_step(1).unwrap()).unwrap();
    assert_ne!(active_gc.phase, GcPhase::Pause);
    let before_state = state_snapshot(state);
    let before_vm = vm_snapshot(&owner);

    // luaL_makeseed 明確忽略 state；輸出不承諾非零、相異或單調。
    let _null_seed = luaL_makeseed(std::ptr::null_mut());
    let _valid_seed = luaL_makeseed(state);
    owner
        .with_vm(|_| {
            let _busy_seed = luaL_makeseed(state);
        })
        .unwrap();

    assert_eq!(state_snapshot(state), before_state);
    assert_eq!(vm_snapshot(&owner), before_vm);
    assert_ne!(before_vm.2.phase, GcPhase::Pause);
}

#[cfg(feature = "lua55")]
#[test]
fn aux_alloc_a46_matrix() {
    let mut ignored_ud_storage = 0_u8;
    let ignored_ud = (&mut ignored_ud_storage as *mut u8).cast::<c_void>();
    let initial_bytes = b"a46-prefix-preserved";

    // SAFETY：NULL ptr 是 C realloc 的合法配置要求；ud 與故意不相符的 osize 必須忽略。
    let mut allocation = unsafe {
        luaL_alloc(
            ignored_ud,
            std::ptr::null_mut(),
            usize::MAX,
            initial_bytes.len(),
        )
    };
    assert!(
        !allocation.is_null(),
        "C realloc(NULL, small size) must allocate"
    );
    let initially_aligned = (allocation as usize) % std::mem::align_of::<usize>() == 0;
    if !initially_aligned {
        // SAFETY：allocation 是剛由 C allocator 回傳的有效 block；即使 alignment 斷言失敗也先釋放一次。
        let freed = unsafe { luaL_alloc(ignored_ud, allocation, usize::MAX, 0) };
        assert!(freed.is_null());
    }
    assert!(
        initially_aligned,
        "C allocation must preserve fundamental usize alignment"
    );

    // SAFETY：allocation 是 luaL_alloc 成功回傳、目前仍有效且至少 initial_bytes.len() bytes 的 C block。
    unsafe {
        std::slice::from_raw_parts_mut(allocation.cast::<u8>(), initial_bytes.len())
            .copy_from_slice(initial_bytes);
    }

    let grown_size = initial_bytes.len() + 32;
    // SAFETY：allocation 是尚未釋放的 C allocator block；realloc 失敗時原 block 仍有效；ud/osize 均忽略。
    let grown = unsafe { luaL_alloc(ignored_ud, allocation, 0, grown_size) };
    if grown.is_null() {
        // SAFETY：realloc 失敗保留原 block；讀取範圍仍在初始配置內。
        let prefix_preserved = unsafe {
            std::slice::from_raw_parts(allocation.cast::<u8>(), initial_bytes.len())
                == initial_bytes
        };
        // SAFETY：allocation 仍是原 C allocator block，且此處只釋放一次。
        let freed = unsafe { luaL_alloc(ignored_ud, allocation, usize::MAX, 0) };
        assert!(freed.is_null());
        assert!(prefix_preserved);
        panic!("small C realloc growth unexpectedly failed");
    }
    allocation = grown;
    // SAFETY：allocation 是 grow 成功後的新 block，至少 grown_size bytes。
    let grown_prefix_preserved = unsafe {
        std::slice::from_raw_parts(allocation.cast::<u8>(), initial_bytes.len()) == initial_bytes
    };

    let shrink_size = initial_bytes.len() - 4;
    // SAFETY：allocation 是目前有效的 C allocator block；realloc 失敗時它仍有效；ud/osize 均忽略。
    let shrunk = unsafe { luaL_alloc(ignored_ud, allocation, usize::MAX, shrink_size) };
    if shrunk.is_null() {
        // SAFETY：realloc 失敗保留原 grown block；讀取範圍仍在 grown_size 內。
        let prefix_preserved = unsafe {
            std::slice::from_raw_parts(allocation.cast::<u8>(), initial_bytes.len())
                == initial_bytes
        };
        // SAFETY：allocation 仍是原 C allocator block，且此處只釋放一次。
        let freed = unsafe { luaL_alloc(ignored_ud, allocation, 0, 0) };
        assert!(freed.is_null());
        assert!(prefix_preserved);
        panic!("small C realloc shrink unexpectedly failed");
    }
    allocation = shrunk;
    // SAFETY：allocation 是 shrink 成功後的新 block，至少 shrink_size bytes。
    let shrunk_prefix_preserved = unsafe {
        std::slice::from_raw_parts(allocation.cast::<u8>(), shrink_size)
            == &initial_bytes[..shrink_size]
    };

    // SAFETY：allocation 仍是該 C allocator 回傳且尚未釋放的 block；nsize=0 要求 free 並回 NULL。
    let freed = unsafe { luaL_alloc(ignored_ud, allocation, usize::MAX, 0) };
    assert!(freed.is_null());
    allocation = std::ptr::null_mut();
    assert!(
        grown_prefix_preserved,
        "growing realloc must preserve the old prefix"
    );
    assert!(
        shrunk_prefix_preserved,
        "shrinking realloc must preserve the new-size prefix"
    );

    // SAFETY：free(NULL) 合法；nsize=0 必須回 NULL，且 osize 被忽略。
    assert!(unsafe { luaL_alloc(ignored_ud, allocation, 0, 0) }.is_null());

    let failure_bytes = b"old-block-survives";
    // SAFETY：NULL ptr 是 C realloc 的合法配置要求，且 size 很小。
    let failure_block =
        unsafe { luaL_alloc(ignored_ud, std::ptr::null_mut(), 0, failure_bytes.len()) };
    assert!(!failure_block.is_null());
    // SAFETY：failure_block 是仍有效、至少 failure_bytes.len() bytes 的 C block。
    unsafe {
        std::slice::from_raw_parts_mut(failure_block.cast::<u8>(), failure_bytes.len())
            .copy_from_slice(failure_bytes);
    }

    // SAFETY：failure_block 是有效 C allocator block；SIZE_MAX 不可配置，失敗時舊 block 仍有效。
    let failed_realloc =
        unsafe { luaL_alloc(ignored_ud, failure_block, failure_bytes.len(), usize::MAX) };
    if !failed_realloc.is_null() {
        // SAFETY：若不符合預期而配置成功，僅釋放 realloc 回傳的新有效 block 一次。
        let freed = unsafe { luaL_alloc(ignored_ud, failed_realloc, 0, 0) };
        assert!(freed.is_null());
        panic!("realloc(SIZE_MAX) unexpectedly succeeded on this target");
    }
    // SAFETY：realloc 失敗時原 block 必須仍有效且內容不變。
    let old_bytes_preserved = unsafe {
        std::slice::from_raw_parts(failure_block.cast::<u8>(), failure_bytes.len()) == failure_bytes
    };
    // SAFETY：realloc 失敗後的原 block 仍由 C allocator 所有；在此只釋放一次。
    assert!(unsafe { luaL_alloc(ignored_ud, failure_block, 0, 0) }.is_null());
    assert!(
        old_bytes_preserved,
        "failed realloc must leave the old block valid and unchanged"
    );
}
