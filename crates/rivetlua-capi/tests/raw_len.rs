use rivetlua_capi::stack::{
    StateOwner, lua_createtable, lua_gettop, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber, lua_rawequal, lua_rawgeti,
    lua_rawlen, lua_rawset, lua_rawseti, lua_settop, lua_toboolean, lua_tolstring, lua_tonumberx,
    lua_touserdata, lua_type,
};
use rivetlua_core::Value;
use rivetlua_runtime::{GcPhase, ObjectKind, RootKind};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

fn slot_fingerprints(owner: &StateOwner) -> Vec<(i32, i32, u64, usize, Vec<u8>)> {
    let state = owner.as_ptr();
    let top = unsafe { lua_gettop(state) };
    (1..=top)
        .map(|slot| {
            // SAFETY：owner 有效；字串 view 在該 slot 存活時保持有效。
            unsafe {
                let ty = lua_type(state, slot);
                let boolean = if ty == 1 {
                    lua_toboolean(state, slot)
                } else {
                    0
                };
                let number = if ty == 3 {
                    lua_tonumberx(state, slot, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let pointer = if ty == 2 {
                    lua_touserdata(state, slot).expose_provenance()
                } else {
                    0
                };
                let bytes = if ty == 4 {
                    let mut len = 0;
                    let ptr = lua_tolstring(state, slot, &mut len);
                    assert!(!ptr.is_null());
                    std::slice::from_raw_parts(ptr.cast::<u8>(), len).to_vec()
                } else {
                    Vec::new()
                };
                (ty, boolean, number, pointer, bytes)
            }
        })
        .collect()
}

fn assert_pure(owner: &StateOwner, index: i32, expected: u64) {
    let state = owner.as_ptr();
    let top = unsafe { lua_gettop(state) };
    let slots = slot_fingerprints(owner);
    let before = owner
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
        .unwrap();
    // SAFETY：owner 於所有呼叫期間持有有效 state；無效 index 須 fail-closed。
    unsafe {
        assert_eq!(lua_rawlen(state, index), expected);
        assert_eq!(lua_rawlen(state, index), expected);
        assert_eq!(lua_gettop(state), top);
        for slot in 1..=top {
            assert_eq!(lua_rawequal(state, slot, slot), 1);
        }
    }
    assert_eq!(slot_fingerprints(owner), slots);
    let after = owner
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
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn raw_len_a6_matrix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保持 state 有效；所有字串來源於本測試固定 byte slice。
    unsafe {
        assert_pure(&owner, 0, 0);
        assert_pure(&owner, -1, 0);
        for bytes in [
            &b""[..],
            &b"abc"[..],
            &b"a\0b"[..],
            &b"\xff\x80"[..],
            &b"12345"[..],
            &b"a longer byte string"[..],
        ] {
            assert!(!lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()).is_null());
            assert_pure(&owner, -1, bytes.len() as u64);
            assert_pure(&owner, 1, bytes.len() as u64);
            lua_settop(state, 0);
        }

        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushinteger(state, 91);
        lua_pushnumber(state, 2.5);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        for slot in 1..=5 {
            assert_pure(&owner, slot, 0);
        }
        assert_pure(&owner, OTHER_REGISTRY_INDEX, 0);
        assert_pure(&owner, REGISTRY_INDEX - 1, 0);
        assert_pure(&owner, 6, 0);
        assert_pure(&owner, -6, 0);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        assert_pure(&owner, -1, 0);
        for key in 1..=5 {
            lua_pushinteger(state, key);
            lua_rawseti(state, -2, key);
        }
        assert_pure(&owner, 1, 5);
        lua_pushinteger(state, 999);
        lua_rawseti(state, -2, 0);
        lua_pushinteger(state, 999);
        lua_rawseti(state, -2, -1);
        lua_pushinteger(state, 999);
        lua_rawseti(state, -2, 10_000);
        assert_pure(&owner, -1, 5);
        lua_pushnil(state);
        lua_rawseti(state, -2, 3);
        let border = lua_rawlen(state, -1) as i64;
        let table = owner
            .with_vm(|vm| {
                let mut tables = Vec::new();
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Table) {
                        tables.push(object);
                    }
                });
                assert_eq!(tables.len(), 1);
                tables[0]
            })
            .unwrap();
        owner
            .with_vm(|vm| {
                if border == 0 {
                    assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
                } else {
                    assert_ne!(vm.raw_get(table, Value::Integer(border)), Ok(Value::Nil));
                }
                assert_eq!(
                    vm.raw_get(table, Value::Integer(border + 1)),
                    Ok(Value::Nil)
                );
            })
            .unwrap();
        assert_pure(&owner, -1, border as u64);
        lua_pushnumber(state, 3.0);
        lua_pushboolean(state, 1);
        lua_rawset(state, -3);
        assert_pure(&owner, -1, 5);
        lua_settop(state, 0);

        lua_createtable(state, 0, 0);
        for key in 1..=80 {
            lua_pushboolean(state, 1);
            lua_rawseti(state, -2, key);
        }
        assert_pure(&owner, -1, 80);
        owner
            .with_vm(|vm| {
                vm.set_collect_every_allocation(true);
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
        assert_pure(&owner, -1, 80);
        assert_pure(&owner, 1, 80);
        let registry_len = lua_rawlen(state, REGISTRY_INDEX);
        assert_pure(&owner, REGISTRY_INDEX, registry_len);
        assert_pure(&owner, OTHER_REGISTRY_INDEX, 0);
        owner
            .with_vm(|vm| {
                let mut registry = None;
                vm.visit_roots(|kind, _, object| {
                    if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table)
                    {
                        registry = Some(object);
                    }
                });
                let registry = registry.unwrap();
                let len = registry_len as i64;
                if len == 0 {
                    assert_eq!(vm.raw_get(registry, Value::Integer(1)), Ok(Value::Nil));
                } else {
                    assert_ne!(vm.raw_get(registry, Value::Integer(len)), Ok(Value::Nil));
                }
                assert_eq!(
                    vm.raw_get(registry, Value::Integer(len + 1)),
                    Ok(Value::Nil)
                );
            })
            .unwrap();
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), 5);
        assert_pure(&owner, -1, 0);
        assert_pure(&owner, 2, 0);
        lua_settop(state, 1);
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                vm.collect().unwrap();
            })
            .unwrap();
        assert_pure(&owner, 1, 80);
        assert_pure(&owner, REGISTRY_INDEX, registry_len);
    }

    let other = owner
        .with_vm(|vm| vm.allocate(Value::Integer(1)).unwrap())
        .unwrap();
    owner.push_value(Value::Object(other)).unwrap();
    assert_pure(&owner, -1, 0);
    assert_eq!(owner.with_vm(|_| unsafe { lua_rawlen(state, -1) }), Ok(0));
}
