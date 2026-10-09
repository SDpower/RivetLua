use std::collections::BTreeSet;
use std::ffi::{CString, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_next, lua_pushboolean, lua_pushinteger,
    lua_pushlightuserdata, lua_pushnil, lua_pushstring, lua_pushvalue, lua_rawequal, lua_rawset,
    lua_settop, lua_toboolean, lua_tointegerx, lua_tolstring, lua_touserdata, lua_type,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationFailureKind, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind,
};

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, GcTrace, RootSnapshot);
type StackSnapshot = (i32, Vec<(i32, i64, i32, usize)>, Vec<i32>);

fn vm_snapshot(owner: &StateOwner) -> VmSnapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap()
}

fn stack_snapshot(state: *mut lua_State) -> StackSnapshot {
    // SAFETY：呼叫期間的 owner 持有有效 state；只讀取現有 slots。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer = if tag == 3 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let boolean = if tag == 1 {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                let pointer = if tag == 2 {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                (tag, integer, boolean, pointer)
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

fn assert_fail_closed(owner: &StateOwner, index: i32) {
    let state = owner.as_ptr();
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(owner);
    // SAFETY：owner 有效；無效 index/key 是本測試的預期輸入。
    assert_eq!(unsafe { lua_next(state, index) }, 0);
    assert_eq!(stack_snapshot(state), before_stack);
    assert_eq!(vm_snapshot(owner), before_vm);
}

fn only_stack_table(owner: &StateOwner) -> ObjectRef {
    owner
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
        .unwrap()
}

fn mixed_and_content_continuation() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let key_name = CString::new("same-key").unwrap();
    let value_name = CString::new("one").unwrap();
    let mut token = 5_u8;
    let pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：owner 與兩個 C 字串存活至呼叫結束；lightuserdata 不解參照。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 1);
        lua_pushstring(state, value_name.as_ptr());
        lua_rawset(state, 1);
        lua_pushinteger(state, 2);
        lua_pushboolean(state, 1);
        lua_rawset(state, 1);
        lua_pushstring(state, key_name.as_ptr());
        lua_pushlightuserdata(state, pointer);
        lua_rawset(state, 1);
        lua_pushboolean(state, 0);
        lua_pushinteger(state, 4);
        lua_rawset(state, 1);
        lua_pushlightuserdata(state, pointer);
        lua_createtable(state, 0, 0);
        lua_rawset(state, 1);
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 0);
        lua_rawset(state, 1);
        assert_eq!(lua_gettop(state), 1);
    }
    let table = only_stack_table(&owner);
    let (string_key, object_key, object_value) = owner
        .with_vm(|vm| {
            let mut previous = Value::Nil;
            let mut string = None;
            let mut object_pair = None;
            while let Some((key, value)) = vm.raw_next_value(table, previous).unwrap() {
                if let Value::Object(object) = key {
                    match vm.object_kind(object).unwrap() {
                        ObjectKind::ByteString => string = Some(object),
                        ObjectKind::Table => object_pair = Some((object, value)),
                        _ => {}
                    }
                }
                previous = key;
            }
            let (object_key, Value::Object(object_value)) = object_pair.unwrap() else {
                panic!("物件鍵和值必須存在");
            };
            (string.unwrap(), object_key, object_value)
        })
        .unwrap();

    let mut seen = BTreeSet::new();
    // SAFETY：table 固定在 index 1；每次只 pop value 並保留 continuation key。
    unsafe {
        lua_pushnil(state);
        for _ in 0..7 {
            if lua_next(state, -2) == 0 {
                break;
            }
            assert_eq!(lua_gettop(state), 3);
            let label = match lua_type(state, 2) {
                3 => {
                    let integer = lua_tointegerx(state, 2, std::ptr::null_mut());
                    assert!(matches!(integer, 1 | 2));
                    if integer == 1 {
                        assert_eq!(lua_type(state, 3), 4);
                    } else {
                        assert_eq!(lua_toboolean(state, 3), 1);
                    }
                    format!("integer:{integer}")
                }
                1 => {
                    assert_eq!(lua_toboolean(state, 2), 0);
                    assert_eq!(lua_tointegerx(state, 3, std::ptr::null_mut()), 4);
                    "boolean".to_owned()
                }
                2 => {
                    assert_eq!(lua_touserdata(state, 2), pointer);
                    assert_eq!(lua_type(state, 3), 5);
                    "pointer".to_owned()
                }
                4 => {
                    let mut len = 0;
                    let bytes = std::slice::from_raw_parts(
                        lua_tolstring(state, 2, &mut len).cast::<u8>(),
                        len,
                    );
                    assert_eq!(bytes, b"same-key");
                    assert_eq!(lua_touserdata(state, 3), pointer);
                    "string".to_owned()
                }
                5 => {
                    assert_eq!(lua_type(state, 3), 5);
                    "object".to_owned()
                }
                tag => panic!("未知鍵 tag {tag}"),
            };
            assert!(seen.insert(label));
            lua_settop(state, 2);
        }
        assert_eq!(seen.len(), 6);
        assert_eq!(lua_gettop(state), 1);

        let expected = owner
            .with_vm(|vm| vm.raw_next_value(table, Value::Object(string_key)).unwrap())
            .unwrap();
        lua_pushstring(state, key_name.as_ptr());
        let actual = lua_next(state, -2);
        assert_eq!(actual, i32::from(expected.is_some()));
        if let Some((key, value)) = expected {
            assert_eq!(lua_gettop(state), 3);
            match key {
                Value::Integer(integer) => {
                    assert_eq!(lua_type(state, 2), 3);
                    assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), integer);
                }
                Value::Boolean(boolean) => {
                    assert_eq!(lua_type(state, 2), 1);
                    assert_eq!(lua_toboolean(state, 2), i32::from(boolean));
                }
                Value::LightUserdata(address) => {
                    assert_eq!(lua_type(state, 2), 2);
                    assert_eq!(lua_touserdata(state, 2).expose_provenance(), address);
                }
                Value::Object(object) => {
                    let kind = owner.with_vm(|vm| vm.object_kind(object).unwrap()).unwrap();
                    assert_eq!(
                        lua_type(state, 2),
                        if kind == ObjectKind::Table { 5 } else { 4 }
                    );
                }
                _ => panic!("本案例不應有此 continuation 鍵"),
            }
            assert_eq!(
                owner.with_vm(|vm| vm.raw_get(table, key)).unwrap(),
                Ok(value)
            );
            lua_settop(state, 1);
        } else {
            assert_eq!(lua_gettop(state), 1);
        }
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(string_key), Ok(ObjectKind::ByteString));
            assert_eq!(vm.object_kind(object_key), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(object_value), Ok(ObjectKind::Table));
        })
        .unwrap();
}

fn validation_registry_and_gc() {
    let empty = StateOwner::new().unwrap();
    let state = empty.as_ptr();
    assert_fail_closed(&empty, REGISTRY_INDEX);
    // SAFETY：空 stack 下 registry 可讀但缺少 top key；其餘 index 只驗錯誤行為。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushnil(state);
        assert_eq!(lua_next(state, -2), 0);
        assert_eq!(lua_gettop(state), 1);
        lua_pushinteger(state, 999);
        assert_fail_closed(&empty, -2);
        assert_fail_closed(&empty, OTHER_REGISTRY_INDEX);
        assert_fail_closed(&empty, REGISTRY_INDEX - 1);
        lua_settop(state, 0);
        lua_pushinteger(state, 7);
        lua_pushnil(state);
        assert_fail_closed(&empty, 1);
        lua_settop(state, 0);
        lua_pushinteger(state, 77);
        lua_pushboolean(state, 1);
        lua_rawset(state, REGISTRY_INDEX);
        lua_pushnil(state);
        let mut found = false;
        for _ in 0..16 {
            if lua_next(state, REGISTRY_INDEX) == 0 {
                break;
            }
            if lua_type(state, -2) == 3 && lua_tointegerx(state, -2, std::ptr::null_mut()) == 77 {
                assert_eq!(lua_toboolean(state, -1), 1);
                found = true;
            }
            lua_settop(state, lua_gettop(state) - 1);
        }
        assert!(found);
        assert_eq!(lua_gettop(state), 0);
        assert_eq!(lua_next(std::ptr::null_mut(), REGISTRY_INDEX), 0);
    }
    let busy = empty
        .with_vm(|_| {
            // SAFETY：state 有效；借用期間入口須 fail-closed。
            unsafe { lua_next(state, REGISTRY_INDEX) }
        })
        .unwrap();
    assert_eq!(busy, 0);

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保持 table stack slot 有效；讀取期間不要求配置。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_pushinteger(state, 1);
        lua_pushboolean(state, 1);
        lua_rawset(state, 1);
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
                vm.set_collect_every_allocation(true);
            })
            .unwrap();
        lua_pushnil(state);
        let before = owner
            .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
            .unwrap();
        assert_eq!(lua_next(state, -2), 1);
        assert_eq!(
            owner
                .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
                .unwrap(),
            before
        );
        lua_settop(state, 2);
        let before = owner
            .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
            .unwrap();
        assert_eq!(lua_next(state, -2), 0);
        assert_eq!(
            owner
                .with_vm(|vm| (vm.allocation_trace(), vm.gc_trace()))
                .unwrap(),
            before
        );
        assert_eq!(lua_gettop(state), 1);
    }
}

fn fault_matrix() {
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..20_u64 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：owner 有效；三個 table 依序建立 outer、key、value。
        unsafe {
            lua_createtable(state, 0, 0);
            lua_createtable(state, 0, 0);
            lua_createtable(state, 0, 0);
            lua_rawset(state, 1);
            lua_settop(state, 19);
            lua_pushnil(state);
            assert_eq!(lua_gettop(state), 20);
        }
        let table = only_stack_table(&owner);
        let (key, value) = owner
            .with_vm(|vm| {
                let Some((Value::Object(key), Value::Object(value))) =
                    vm.raw_next_value(table, Value::Nil).unwrap()
                else {
                    panic!("唯一欄位必須有物件鍵值");
                };
                vm.set_gc_debt_threshold(usize::MAX);
                for _ in 0..128 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause {
                        break;
                    }
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                (key, value)
            })
            .unwrap();
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        let ordinal = owner
            .with_vm(|vm| {
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
                next + offset
            })
            .unwrap();
        // SAFETY：有效 state；ordinal failure 必須回 0 並保留原 stack。
        let result = unsafe { lua_next(state, 1) };
        if result == 0 {
            assert_eq!(stack_snapshot(state), before_stack, "offset {offset}");
            let after_vm = vm_snapshot(&owner);
            assert_eq!(after_vm.0, before_vm.0, "offset {offset}");
            assert_eq!(after_vm.2, before_vm.2, "offset {offset}");
            assert_eq!(after_vm.1.phase, before_vm.1.phase, "offset {offset}");
            assert_eq!(
                after_vm.1.transition_count, before_vm.1.transition_count,
                "offset {offset}"
            );
            assert_eq!(
                owner
                    .with_vm(|vm| vm.raw_get(table, Value::Object(key)))
                    .unwrap(),
                Ok(Value::Object(value)),
                "offset {offset}"
            );
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure)
                .unwrap()
                .unwrap();
            assert_eq!(failure.attempt.ordinal, ordinal, "offset {offset}");
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            failures.push((offset, failure.attempt.site.file));
        } else {
            assert_eq!(result, 1, "offset {offset}");
            // SAFETY：成功後 key/value 佔最後兩個 slots。
            unsafe {
                assert_eq!(lua_gettop(state), 21);
                assert_eq!(lua_type(state, 20), 5);
                assert_eq!(lua_type(state, 21), 5);
            }
            owner
                .with_vm(|vm| {
                    vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
                    vm.inject_allocation_failure_at(u64::MAX);
                    vm.collect().unwrap();
                    vm.collect().unwrap();
                    assert_eq!(vm.object_kind(key), Ok(ObjectKind::Table));
                    assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
                })
                .unwrap();
            successes.push(offset);
        }
    }
    assert_eq!(
        failures.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert_eq!(successes, (3..20).collect::<Vec<_>>());
    assert_eq!(failures[0].1, "crates/rivetlua-runtime/src/roots.rs");
    assert_eq!(failures[1].1, "crates/rivetlua-runtime/src/roots.rs");
    assert_eq!(failures[2].1, "crates/rivetlua-runtime/src/heap.rs");
}

#[test]
fn next_stack_a9_matrix() {
    mixed_and_content_continuation();
    validation_registry_and_gc();
    fault_matrix();
}

#[test]
fn next_stack_deleted_current_key_b13() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：有效 C stack；刪除前一個迭代鍵後保留原 key slot 呼叫 next。
    unsafe {
        lua_createtable(state, 2, 0);
        for (key, value) in [(1, 11), (2, 22)] {
            lua_pushinteger(state, key);
            lua_pushinteger(state, value);
            lua_rawset(state, 1);
        }
        lua_pushnil(state);
        assert_eq!(lua_next(state, 1), 1);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 1);
        assert_eq!(lua_tointegerx(state, 3, std::ptr::null_mut()), 11);
        lua_pushvalue(state, 2);
        lua_pushnil(state);
        lua_rawset(state, 1);
        lua_settop(state, -2);
        assert_eq!(lua_next(state, 1), 1);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 2);
        assert_eq!(lua_tointegerx(state, 3, std::ptr::null_mut()), 22);
        lua_settop(state, 0);

        lua_createtable(state, 0, 4);
        for (key, value) in [(false, 31), (true, 32)] {
            lua_pushboolean(state, i32::from(key));
            lua_pushinteger(state, value);
            lua_rawset(state, 1);
        }
        lua_pushlightuserdata(state, 17usize as *mut c_void);
        lua_pushinteger(state, 33);
        lua_rawset(state, 1);
        lua_pushnil(state);
        assert_eq!(lua_next(state, 1), 1);
        lua_pushvalue(state, 2);
        lua_pushnil(state);
        lua_rawset(state, 1);
        lua_settop(state, -2);
        assert_eq!(lua_next(state, 1), 1);
        assert_eq!(lua_type(state, 3), 3);
        lua_settop(state, 1);
        lua_pushinteger(state, 999);
        assert_fail_closed(&owner, 1);
    }
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}
