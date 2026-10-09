use std::ffi::c_int;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_isinteger, lua_pushinteger,
    lua_pushlstring, lua_rawequal, lua_rawlen, lua_rawseti, lua_setmetatable, lua_settop,
    lua_toboolean, lua_tointegerx, lua_tolstring, lua_tonumberx, lua_type, luaL_len,
};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{GcMode, GcTrace, LedgerSnapshot, RootId, RootKind};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: c_int = -(c_int::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: c_int = -1_001_000;

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (
    LedgerSnapshot,
    rivetlua_runtime::AllocationTrace,
    GcTrace,
    RootSnapshot,
);
type StackSnapshot = (i32, Vec<(i32, i64, u64, i32, u64, Vec<u8>)>, Vec<i32>);
type LuaLenC = unsafe extern "C" fn(*mut lua_State, c_int) -> i64;

fn stack_bytes(state: *mut lua_State, index: c_int) -> Vec<u8> {
    let mut len = usize::MAX;
    // SAFETY：state 與字串 slot 均存活；依 API 回報長度立即複製原始位元組。
    let pointer = unsafe { lua_tolstring(state, index, &mut len) };
    assert!(!pointer.is_null());
    // SAFETY：字串 slot 在複製期間仍位於 stack，指標至少含 len 個位元組。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len).to_vec() }
}

fn stack_snapshot(state: *mut lua_State) -> StackSnapshot {
    // SAFETY：呼叫端持有有效 state；所有查詢只讀取目前 stack slot。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer = if tag == 3 && lua_isinteger(state, index) != 0 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let number = if tag == 3 && lua_isinteger(state, index) == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let boolean = if tag == 1 {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                let raw_len = lua_rawlen(state, index);
                let bytes = if tag == 4 {
                    stack_bytes(state, index)
                } else {
                    Vec::new()
                };
                (tag, integer, number, boolean, raw_len, bytes)
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

fn assert_len_stable(
    owner: &StateOwner,
    state: *mut lua_State,
    index: c_int,
    expected: i64,
    call: impl FnOnce() -> i64,
) {
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(owner);
    assert_eq!(call(), expected, "index={index}");
    assert_eq!(stack_snapshot(state), before_stack, "index={index}");
    let after_vm = vm_snapshot(owner);
    assert_eq!(after_vm.0.reserved, 0, "index={index}");
    assert_eq!(
        after_vm.0.host_allocation_bytes, before_vm.0.host_allocation_bytes,
        "index={index}"
    );
    assert_eq!(after_vm.2.mode, before_vm.2.mode, "index={index}");
    assert_eq!(
        after_vm.1.last_failure, before_vm.1.last_failure,
        "index={index}"
    );
    assert!(
        after_vm.1.next_ordinal >= before_vm.1.next_ordinal,
        "index={index}"
    );
    let root_values = |roots: &RootSnapshot| {
        roots
            .iter()
            .map(|(kind, _, object)| (*kind, *object))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        root_values(&after_vm.3),
        root_values(&before_vm.3),
        "index={index}"
    );

    // 每個案例後確認 state 仍可正常使用，再恢復原 top。
    let top = unsafe { lua_gettop(state) };
    // SAFETY：state 有效；以整數 push/pop 驗證拒絕及成功路徑後仍可重用。
    unsafe {
        lua_pushinteger(state, 947);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 947);
        lua_settop(state, top);
    }
}

fn enter_active_gc(owner: &StateOwner, mode: GcMode) {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(mode).unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.collect().unwrap();
            for _ in 0..256 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != rivetlua_runtime::GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, rivetlua_runtime::GcPhase::Pause);
        })
        .unwrap();
}

#[test]
fn aux_len_a42_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();

    let empty = b"";
    // SAFETY：空輸入長度為零；非空 slice 指標在呼叫期間仍有效。
    unsafe { lua_pushlstring(state, empty.as_ptr().cast(), empty.len()) };
    assert_len_stable(&owner, state, -1, 0, || {
        // SAFETY：state 由上方 owner 持有，-1 指向剛推入的字串。
        unsafe { luaL_len(state, -1) }
    });
    unsafe { lua_settop(state, 0) };

    let bytes = b"raw\0length\xff";
    // SAFETY：來源在指定長度內可讀，且 API 會複製其內容。
    unsafe { lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()) };
    let c_len: LuaLenC = luaL_len;
    assert_len_stable(&owner, state, -1, bytes.len() as i64, || {
        // SAFETY：C 相容函式指標指向匯出 API，且 state 仍有效。
        unsafe { c_len(state, -1) }
    });
    assert_eq!(stack_bytes(state, -1), bytes);
    unsafe { lua_settop(state, 0) };

    // 空表與連續序列都直接沿用既有 raw border 長度。
    unsafe { lua_createtable(state, 0, 0) };
    assert_len_stable(&owner, state, -1, 0, || unsafe { luaL_len(state, -1) });
    unsafe { lua_settop(state, 0) };

    unsafe {
        lua_createtable(state, 3, 0);
        for value in [11, 22, 33] {
            lua_pushinteger(state, value);
            lua_rawseti(state, -2, i64::from(value / 11));
        }
    }
    let dense_len = unsafe { lua_rawlen(state, -1) } as i64;
    assert_eq!(dense_len, 3);
    assert_len_stable(&owner, state, -1, dense_len, || unsafe {
        luaL_len(state, -1)
    });
    unsafe { lua_settop(state, 0) };

    unsafe {
        lua_createtable(state, 4, 0);
        for (key, value) in [(1, 11), (3, 33), (4, 44)] {
            lua_pushinteger(state, value);
            lua_rawseti(state, -2, key);
        }
    }
    let hole_border = unsafe { lua_rawlen(state, -1) } as i64;
    assert_len_stable(&owner, state, -1, hole_border, || unsafe {
        luaL_len(state, -1)
    });
    unsafe { lua_settop(state, 0) };

    // registry pseudo-index 的表長度同樣走 typed operation，保留原 stack。
    let registry_len = unsafe { lua_rawlen(state, REGISTRY_INDEX) } as i64;
    assert_len_stable(&owner, state, REGISTRY_INDEX, registry_len, || unsafe {
        luaL_len(state, REGISTRY_INDEX)
    });

    // 沒有 __len 的 table metatable 應沿用 raw border，而不再 fail-closed。
    unsafe {
        lua_createtable(state, 0, 0);
        let table_index = lua_gettop(state);
        lua_createtable(state, 0, 0);
        assert_eq!(lua_setmetatable(state, table_index), 1);
    }
    assert_len_stable(&owner, state, -1, 0, || unsafe { luaL_len(state, -1) });
    unsafe { lua_settop(state, 0) };

    // userdata/無效 index/非整數 __len 的錯誤改由固定 header C fixture
    // 在純 C checkpoint 驗證，避免錯誤 longjmp 跨越 Rust 測試 frame。
    // Incremental 與 generational GC 執行中，原始長度查詢不配置、不改根也不推進 GC。
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let gc_owner = StateOwner::new().unwrap();
        let gc_state = gc_owner.as_ptr();
        // SAFETY：來源在指定長度內可讀，API 會複製位元組並由 stack root 保活。
        unsafe { lua_pushlstring(gc_state, bytes.as_ptr().cast(), bytes.len()) };
        enter_active_gc(&gc_owner, mode);
        assert_len_stable(&gc_owner, gc_state, -1, bytes.len() as i64, || unsafe {
            luaL_len(gc_state, -1)
        });
    }
}
