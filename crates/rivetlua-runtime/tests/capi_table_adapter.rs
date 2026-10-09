use rivetlua_core::{LuaProfile, Value};
use rivetlua_runtime::{
    ExternalStringStorage, FailPoint, GcPhase, HostHandle, ObjectKind, RootKind, RuntimeErrorKind,
    Vm, VmError,
};
use std::cell::Cell;
use std::rc::Rc;

#[test]
fn capi_raw_next_adapter_is_pure_content_equal_and_roots_objects() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let key = vm.allocate_byte_string(b"same\0\xff").unwrap();
        let key_root = HostHandle::<Value>::new(&mut vm, key).unwrap();
        let value = vm.allocate_table().unwrap();
        let value_root = HostHandle::<Value>::new(&mut vm, value).unwrap();
        let object_key = vm.allocate_table().unwrap();
        let object_root = HostHandle::<Value>::new(&mut vm, object_key).unwrap();
        let fields = [
            (Value::Integer(1), Value::Integer(11)),
            (Value::Integer(2), Value::Boolean(true)),
            (Value::Boolean(false), Value::LightUserdata(17)),
            (Value::LightUserdata(0), Value::Integer(44)),
            (Value::Object(key), Value::Object(value)),
            (Value::Object(object_key), Value::Object(key)),
        ];
        for (key, value) in fields {
            vm.raw_set(table, key, value).unwrap();
        }
        drop(key_root);
        drop(value_root);
        drop(object_root);

        vm.set_gc_debt_threshold(usize::MAX);
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        vm.set_collect_every_allocation(true);
        let ledger = vm.ledger_snapshot();
        let allocation = vm.allocation_trace();
        let gc = vm.gc_trace();
        let roots = vm.roots().total_count();
        let mut previous = Value::Nil;
        let mut seen = Vec::new();
        while let Some((key, value)) = vm.raw_next_value(table, previous).unwrap() {
            let matched = fields
                .iter()
                .position(|(candidate, expected)| {
                    vm.raw_equal_value(*candidate, key).unwrap() && *expected == value
                })
                .unwrap();
            assert!(!seen.contains(&matched));
            seen.push(matched);
            previous = key;
        }
        assert_eq!(seen.len(), fields.len());
        assert_eq!(vm.ledger_snapshot(), ledger);
        assert_eq!(vm.allocation_trace(), allocation);
        assert_eq!(vm.gc_trace(), gc);
        assert_eq!(vm.roots().total_count(), roots);

        let same_content = vm.allocate_byte_string(b"same\0\xff").unwrap();
        let same_root = HostHandle::<Value>::new(&mut vm, same_content).unwrap();
        assert_ne!(same_content, key);
        let ledger = vm.ledger_snapshot();
        let allocation = vm.allocation_trace();
        let gc = vm.gc_trace();
        assert_eq!(
            vm.raw_next_value(table, Value::Object(same_content))
                .unwrap(),
            vm.raw_next_value(table, Value::Object(key)).unwrap()
        );
        assert_eq!(vm.ledger_snapshot(), ledger);
        assert_eq!(vm.allocation_trace(), allocation);
        assert_eq!(vm.gc_trace(), gc);
        assert_eq!(
            vm.raw_next_value(table, Value::Integer(999))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );
        let empty = vm.allocate_table().unwrap();
        let empty_root = HostHandle::<Value>::new(&mut vm, empty).unwrap();
        assert_eq!(vm.raw_next_value(empty, Value::Nil).unwrap(), None);
        assert_eq!(
            vm.raw_next_value(empty, Value::Integer(1))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );
        assert!(vm.raw_next_value(value, Value::Nil).is_ok());
        assert!(vm.raw_next_value(key, Value::Nil).is_err());
        drop(empty_root);
        drop(same_root);
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
        assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
        assert_eq!(vm.object_kind(object_key), Ok(ObjectKind::Table));
        drop(table_root);
    }
}

#[test]
fn capi_raw_next_deleted_current_key_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();

        let array = vm.allocate_table().unwrap();
        let _array_root = HostHandle::<Value>::new(&mut vm, array).unwrap();
        vm.raw_set(array, Value::Integer(1), Value::Integer(11))
            .unwrap();
        vm.raw_set(array, Value::Integer(2), Value::Integer(22))
            .unwrap();
        assert_eq!(
            vm.raw_next_value(array, Value::Nil).unwrap(),
            Some((Value::Integer(1), Value::Integer(11)))
        );
        vm.raw_set(array, Value::Integer(1), Value::Nil).unwrap();
        let ledger = vm.ledger_snapshot();
        let allocation = vm.allocation_trace();
        let gc = vm.gc_trace();
        assert_eq!(
            vm.raw_next_value(array, Value::Integer(1)).unwrap(),
            Some((Value::Integer(2), Value::Integer(22)))
        );
        assert_eq!(vm.ledger_snapshot(), ledger);
        assert_eq!(vm.allocation_trace(), allocation);
        assert_eq!(vm.gc_trace(), gc);
        vm.raw_set(array, Value::Integer(2), Value::Nil).unwrap();
        assert_eq!(vm.raw_next_value(array, Value::Integer(2)).unwrap(), None);
        assert_eq!(
            vm.raw_next_value(array, Value::Integer(99))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );

        let scalar = vm.allocate_table().unwrap();
        let _scalar_root = HostHandle::<Value>::new(&mut vm, scalar).unwrap();
        vm.raw_set(scalar, Value::Boolean(false), Value::Integer(31))
            .unwrap();
        vm.raw_set(scalar, Value::Boolean(true), Value::Integer(32))
            .unwrap();
        let (current, _) = vm.raw_next_value(scalar, Value::Nil).unwrap().unwrap();
        let successor = vm.raw_next_value(scalar, current).unwrap();
        vm.raw_set(scalar, current, Value::Nil).unwrap();
        assert_eq!(vm.raw_get(scalar, current), Ok(Value::Nil));
        assert_eq!(vm.raw_next_value(scalar, current).unwrap(), successor);
        vm.raw_set(scalar, current, Value::Integer(99)).unwrap();
        assert_eq!(vm.raw_get(scalar, current), Ok(Value::Integer(99)));
        assert_eq!(vm.raw_next_value(scalar, current).unwrap(), successor);
        let mut seen = 0;
        let mut previous = Value::Nil;
        while let Some((key, _)) = vm.raw_next_value(scalar, previous).unwrap() {
            seen += 1;
            previous = key;
        }
        assert_eq!(seen, 2, "重新插入不得留下重複 live key");

        let strings = vm.allocate_table().unwrap();
        let _strings_root = HostHandle::<Value>::new(&mut vm, strings).unwrap();
        let first_string = vm.allocate_byte_string(b"first\0key").unwrap();
        let first_root = HostHandle::<Value>::new(&mut vm, first_string).unwrap();
        let second_string = vm.allocate_byte_string(b"second\0key").unwrap();
        let second_root = HostHandle::<Value>::new(&mut vm, second_string).unwrap();
        vm.raw_set(strings, Value::Object(first_string), Value::Integer(41))
            .unwrap();
        vm.raw_set(strings, Value::Object(second_string), Value::Integer(42))
            .unwrap();
        let (current, _) = vm.raw_next_value(strings, Value::Nil).unwrap().unwrap();
        let Value::Object(dead_string) = current else {
            panic!("字串 table 的首鍵必須是 byte string");
        };
        let successor = vm.raw_next_value(strings, current).unwrap();
        let equal_string = vm
            .allocate_byte_string(if dead_string == first_string {
                b"first\0key"
            } else {
                b"second\0key"
            })
            .unwrap();
        assert_ne!(equal_string, dead_string);
        let _equal_root = HostHandle::<Value>::new(&mut vm, equal_string).unwrap();
        vm.raw_set(strings, current, Value::Nil).unwrap();
        if dead_string == first_string {
            drop(first_root);
            drop(second_root);
        } else {
            drop(second_root);
            drop(first_root);
        }
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(dead_string), Err(VmError::StaleObject));
        let ledger = vm.ledger_snapshot();
        let allocation = vm.allocation_trace();
        let gc = vm.gc_trace();
        assert_eq!(
            vm.raw_next_value(strings, Value::Object(equal_string))
                .unwrap(),
            successor
        );
        assert_eq!(vm.ledger_snapshot(), ledger);
        assert_eq!(vm.allocation_trace(), allocation);
        assert_eq!(vm.gc_trace(), gc);

        let objects = vm.allocate_table().unwrap();
        let _objects_root = HostHandle::<Value>::new(&mut vm, objects).unwrap();
        let key_a = vm.allocate_table().unwrap();
        let key_a_root = HostHandle::<Value>::new(&mut vm, key_a).unwrap();
        let key_b = vm.allocate_table().unwrap();
        let key_b_root = HostHandle::<Value>::new(&mut vm, key_b).unwrap();
        let deleted_value = vm.allocate_table().unwrap();
        vm.raw_set(objects, Value::Object(key_a), Value::Object(deleted_value))
            .unwrap();
        vm.raw_set(objects, Value::Object(key_b), Value::Integer(52))
            .unwrap();
        let (current, _) = vm.raw_next_value(objects, Value::Nil).unwrap().unwrap();
        let successor = vm.raw_next_value(objects, current).unwrap();
        vm.set_gc_debt_threshold(usize::MAX);
        for _ in 0..128 {
            vm.incremental_step(1).unwrap();
            if vm.gc_trace().phase != GcPhase::Pause {
                break;
            }
        }
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        vm.raw_set(objects, current, Value::Nil).unwrap();
        assert_eq!(vm.raw_next_value(objects, current).unwrap(), successor);
        if current == Value::Object(key_a) {
            drop(key_a_root);
            drop(key_b_root);
            vm.collect().unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(key_a), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(deleted_value), Err(VmError::StaleObject));
        } else {
            drop(key_b_root);
            drop(key_a_root);
            vm.collect().unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(key_b), Err(VmError::StaleObject));
        }
        assert_eq!(
            vm.raw_next_value(objects, Value::Integer(999))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );
    }
}

#[test]
fn capi_deleted_long_key_charge_rehash_and_drop_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.allocate_table().unwrap();
        vm.allocate_byte_string(b"").unwrap();
        vm.collect_major().unwrap();
        let baseline = vm.ledger_snapshot().lua_heap_bytes;
        let table = vm.allocate_table().unwrap();
        let table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let bytes = vec![0x91; 64 * 1024];
        let key = vm.allocate_byte_string(&bytes).unwrap();
        let key_root = HostHandle::<Value>::new(&mut vm, key).unwrap();
        let bucket_size = std::mem::size_of::<Option<(rivetlua_runtime::CanonicalKey, Value)>>();
        let before_key_insert = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(key), Value::Integer(1))
            .unwrap();
        let key_backing_bytes =
            vm.ledger_snapshot().lua_heap_bytes - before_key_insert - bytes.len() - bucket_size;
        assert!(key_backing_bytes >= std::mem::size_of::<rivetlua_runtime::CanonicalKey>());
        vm.raw_set(table, Value::Boolean(true), Value::Integer(2))
            .unwrap();
        let before_delete = vm.ledger_snapshot().lua_heap_bytes;
        let old_bucket_bytes = vm
            .with_table(table, |stored| stored.hash_capacity())
            .unwrap()
            * bucket_size;
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, before_delete);
        drop(key_root);
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        let before_rehash = vm.ledger_snapshot().lua_heap_bytes;
        assert!(before_rehash + bytes.len() <= before_delete);
        assert_eq!(
            vm.raw_get(table, Value::Boolean(true)),
            Ok(Value::Integer(2))
        );
        vm.raw_set(table, Value::Integer(-100), Value::Integer(3))
            .unwrap();
        let new_bucket_bytes = vm
            .with_table(table, |stored| stored.hash_capacity())
            .unwrap()
            * bucket_size;
        assert!(new_bucket_bytes > old_bucket_bytes);
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes
                + bytes.len()
                + key_backing_bytes
                + old_bucket_bytes,
            before_rehash + new_bucket_bytes
        );
        drop(table_root);
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, baseline);
    }
}

#[test]
fn capi_final_long_deleted_key_charge_releases_on_insert_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let bytes = vec![0x94; 4096];
        let key = vm.allocate_byte_string(&bytes).unwrap();
        let key_root = HostHandle::<Value>::new(&mut vm, key).unwrap();
        let bucket_size = std::mem::size_of::<Option<(rivetlua_runtime::CanonicalKey, Value)>>();
        let before_key_insert = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(key), Value::Integer(1))
            .unwrap();
        let key_backing_bytes =
            vm.ledger_snapshot().lua_heap_bytes - before_key_insert - bytes.len() - bucket_size;
        assert!(key_backing_bytes >= std::mem::size_of::<rivetlua_runtime::CanonicalKey>());
        let before_delete = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(1));
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, before_delete);
        drop(key_root);
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        let equal = vm.allocate_byte_string(&bytes).unwrap();
        let _equal_root = HostHandle::<Value>::new(&mut vm, equal).unwrap();
        assert_eq!(
            vm.raw_next_value(table, Value::Object(equal)).unwrap(),
            None
        );
        let before_insert = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Boolean(true), Value::Integer(2))
            .unwrap();
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes + bytes.len() + key_backing_bytes,
            before_insert + bucket_size
        );
        assert_eq!(
            vm.raw_next_value(table, Value::Nil).unwrap(),
            Some((Value::Boolean(true), Value::Integer(2)))
        );
    }
}

#[test]
fn capi_weak_value_cleanup_keeps_deleted_current_position_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
        let mode = vm.allocate_byte_string(b"v").unwrap();
        vm.raw_set(metatable, Value::Object(mode_key), Value::Object(mode))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        let value = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Boolean(false), Value::Object(value))
            .unwrap();
        vm.raw_set(table, Value::Boolean(true), Value::Integer(7))
            .unwrap();
        let expected = vm.raw_next_value(table, Value::Boolean(false)).unwrap();
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        assert_eq!(vm.raw_get(table, Value::Boolean(false)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_next_value(table, Value::Boolean(false)).unwrap(),
            expected
        );
    }
}

#[test]
fn capi_external_deleted_key_detaches_owner_atomically_b13() {
    struct Storage {
        bytes: Vec<u8>,
        drops: Rc<Cell<usize>>,
    }
    impl ExternalStringStorage for Storage {
        fn bytes(&self) -> &[u8] {
            &self.bytes
        }
    }
    impl Drop for Storage {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let bytes = vec![0x83; 4096];
        let drops = Rc::new(Cell::new(0));
        let key = vm
            .allocate_external_byte_string(Rc::new(Storage {
                bytes: bytes.clone(),
                drops: Rc::clone(&drops),
            }))
            .unwrap();
        vm.raw_set(table, Value::Object(key), Value::Integer(1))
            .unwrap();
        vm.raw_set(table, Value::Boolean(true), Value::Integer(2))
            .unwrap();
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();
        vm.inject_failure_once(FailPoint::StringBytesReserve);
        assert_eq!(
            vm.raw_set(table, Value::Object(key), Value::Nil),
            Err(VmError::InjectedFailure(FailPoint::StringBytesReserve))
        );
        assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Integer(1)));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(drops.get(), 0);
        let expected = vm.raw_next_value(table, Value::Object(key)).unwrap();
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(drops.get(), 1);
        let equal = vm.allocate_byte_string(&bytes).unwrap();
        let _equal_root = HostHandle::<Value>::new(&mut vm, equal).unwrap();
        assert_eq!(
            vm.raw_next_value(table, Value::Object(equal)).unwrap(),
            expected
        );
    }
}

#[test]
fn capi_all_deleted_hash_positions_remain_valid_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let keys = [
            Value::Boolean(false),
            Value::Boolean(true),
            Value::LightUserdata(0x13),
        ];
        for (ordinal, key) in keys.into_iter().enumerate() {
            vm.raw_set(table, key, Value::Integer(ordinal as i64 + 1))
                .unwrap();
        }
        let mut ordered = Vec::new();
        let mut previous = Value::Nil;
        while let Some((key, _)) = vm.raw_next_value(table, previous).unwrap() {
            ordered.push(key);
            previous = key;
        }
        assert_eq!(ordered.len(), 3);
        let current = ordered[0];
        for key in ordered {
            vm.raw_set(table, key, Value::Nil).unwrap();
        }
        let bucket_count = vm
            .with_table(table, |stored| stored.hash_capacity())
            .unwrap();
        assert!(bucket_count >= keys.len());
        let charged_before_reinsert = vm.ledger_snapshot().lua_heap_bytes;
        assert_eq!(vm.raw_next_value(table, current).unwrap(), None);
        assert_eq!(
            vm.raw_next_value(table, Value::Integer(999))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );
        vm.raw_set(table, current, Value::Integer(77)).unwrap();
        assert_eq!(
            vm.with_table(table, |stored| stored.hash_capacity()),
            Ok(bucket_count)
        );
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, charged_before_reinsert);
        assert_eq!(
            vm.raw_next_value(table, Value::Nil).unwrap(),
            Some((current, Value::Integer(77)))
        );
        assert_eq!(vm.raw_next_value(table, current).unwrap(), None);
    }
}

#[test]
fn capi_weak_value_all_clear_keeps_first_position_b13() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let metatable = vm.allocate_table().unwrap();
        let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
        let mode = vm.allocate_byte_string(b"v").unwrap();
        vm.raw_set(metatable, Value::Object(mode_key), Value::Object(mode))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        let string_key = vm.allocate_byte_string(b"weak-key").unwrap();
        let _key_root = HostHandle::<Value>::new(&mut vm, string_key).unwrap();
        let keys = [Value::Boolean(false), Value::Object(string_key)];
        let values = [vm.allocate_table().unwrap(), vm.allocate_table().unwrap()];
        for (key, value) in keys.into_iter().zip(values) {
            vm.raw_set(table, key, Value::Object(value)).unwrap();
        }
        let (current, _) = vm.raw_next_value(table, Value::Nil).unwrap().unwrap();
        vm.collect().unwrap();
        vm.collect_major().unwrap();
        for value in values {
            assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        }
        for key in keys {
            assert_eq!(vm.raw_get(table, key), Ok(Value::Nil));
        }
        assert_eq!(vm.raw_next_value(table, current).unwrap(), None);
        assert_eq!(
            vm.raw_next_value(table, Value::Integer(999))
                .unwrap_err()
                .kind,
            RuntimeErrorKind::InvalidNextKey
        );
    }
}

#[test]
fn capi_unpublished_table_root_failure_refunds_capacity_slot_and_gc_state() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for active in [false, true] {
            for point in [FailPoint::RootReserve, FailPoint::HostLease] {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let anchor = if active {
                    vm.set_gc_debt_threshold(usize::MAX);
                    let anchor = vm.allocate_table().unwrap();
                    let root = vm.add_root(RootKind::Host, anchor).unwrap();
                    for _ in 0..128 {
                        vm.incremental_step(1).unwrap();
                        if vm.gc_trace().phase != GcPhase::Pause {
                            break;
                        }
                    }
                    assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                    Some(root)
                } else {
                    None
                };
                let before = vm.ledger_snapshot();
                let before_gc = vm.gc_trace();
                let before_roots = vm.roots().total_count();
                vm.inject_failure_once(point);
                let result = vm.prepare_unpublished_host_table::<VmError>(3, 2, |_| Ok(()));
                assert!(matches!(result, Err(VmError::InjectedFailure(failed)) if failed == point));
                assert_eq!(vm.ledger_snapshot(), before);
                assert_eq!(vm.gc_trace(), before_gc);
                assert_eq!(vm.roots().total_count(), before_roots);
                if let Some(root) = anchor {
                    vm.remove_root(root).unwrap();
                }
            }
        }

        let mut vm = Vm::new_with_profile(profile).unwrap();
        let (_, root) = vm
            .prepare_unpublished_host_table::<VmError>(3, 2, |_| Ok(()))
            .unwrap();
        let Value::Object(table) = root.as_value(&vm).unwrap() else {
            panic!("host table root 應持有 table 物件");
        };
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        let capacities = vm
            .with_table(table, |stored| {
                (stored.array_capacity(), stored.hash_capacity())
            })
            .unwrap();
        assert!(capacities.0 >= 3 && capacities.1 >= 2);
        vm.raw_set(table, Value::Integer(1), Value::Boolean(true))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Boolean(true))
        );
        drop(root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn capi_table_raw_vm_rejects_foreign_identity_without_mutation() {
    let mut first = Vm::new().unwrap();
    let table = first.allocate_table().unwrap();
    let mut second = Vm::new().unwrap();
    let before = second.ledger_snapshot();
    assert_eq!(
        second.raw_get(table, Value::Integer(1)),
        Err(VmError::WrongVm)
    );
    assert_eq!(
        second.raw_set(table, Value::Integer(1), Value::Integer(3)),
        Err(VmError::WrongVm)
    );
    assert_eq!(second.ledger_snapshot(), before);
    assert_eq!(first.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
}

#[test]
fn capi_table_lightuserdata_keys_and_values_preserve_address_without_roots() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let before_roots = vm.roots().total_count();
        let first = Value::LightUserdata(0x1234);
        let same = Value::LightUserdata(0x1234);
        let other = Value::LightUserdata(0x1235);
        let null = Value::LightUserdata(0);
        let first_key = vm.canonical_key(first).unwrap().unwrap();
        let same_key = vm.canonical_key(same).unwrap().unwrap();
        let other_key = vm.canonical_key(other).unwrap().unwrap();
        assert_eq!(first_key, same_key);
        assert_ne!(first_key, other_key);
        assert_ne!(
            first_key,
            vm.canonical_key(Value::Integer(0x1234)).unwrap().unwrap()
        );
        vm.raw_set(table, first, null).unwrap();
        vm.raw_set(table, null, other).unwrap();
        assert_eq!(vm.raw_get(table, same), Ok(null));
        assert_eq!(vm.raw_get(table, other), Ok(Value::Nil));
        assert_eq!(vm.raw_get(table, null), Ok(other));
        assert_eq!(vm.roots().total_count(), before_roots);
        vm.collect().unwrap();
        assert_eq!(vm.raw_get(table, first), Ok(null));
        assert_eq!(vm.raw_get(table, null), Ok(other));
        drop(root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
    }
}

#[test]
fn capi_table_rawset_rejects_foreign_and_stale_object_keys_and_values_atomically() {
    let mut vm = Vm::new().unwrap();
    let table = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, table).unwrap();
    let stale = vm.allocate_byte_string(b"stale").unwrap();
    vm.collect().unwrap();
    assert_eq!(vm.object_kind(stale), Err(VmError::StaleObject));
    let mut other = Vm::new().unwrap();
    let foreign = other.allocate_byte_string(b"foreign").unwrap();
    let before = vm.ledger_snapshot();
    for (value, expected) in [(foreign, VmError::WrongVm), (stale, VmError::StaleObject)] {
        assert_eq!(
            vm.raw_set(table, Value::Integer(1), Value::Object(value)),
            Err(expected)
        );
        assert_eq!(
            vm.raw_set(table, Value::Object(value), Value::Integer(3)),
            Err(expected)
        );
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        assert_eq!(vm.ledger_snapshot(), before);
    }
}

#[test]
fn capi_raw_equal_adapter_is_pure_and_validates_object_identity() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let first = vm.allocate_byte_string(b"same").unwrap();
        let second = vm.allocate_byte_string(b"same").unwrap();
        let _first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
        let _second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
        let before = vm.ledger_snapshot();
        let gc = vm.gc_trace();
        assert_eq!(
            vm.raw_equal_value(Value::Object(first), Value::Object(second)),
            Ok(true)
        );
        assert_eq!(
            vm.raw_equal_value(Value::Integer(i64::MAX), Value::Float(i64::MAX as f64)),
            Ok(false)
        );
        assert_eq!(
            vm.raw_equal_value(Value::LightUserdata(0), Value::LightUserdata(0)),
            Ok(true)
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.gc_trace(), gc);

        let stale = vm.allocate_byte_string(b"stale").unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(stale), Err(VmError::StaleObject));
        assert_eq!(
            vm.raw_equal_value(Value::Object(stale), Value::Nil),
            Err(VmError::StaleObject.into())
        );
        let mut other = Vm::new().unwrap();
        let foreign = other.allocate_byte_string(b"foreign").unwrap();
        assert_eq!(
            vm.raw_equal_value(Value::Object(foreign), Value::Nil),
            Err(VmError::WrongVm.into())
        );
    }
}

#[test]
fn capi_raw_len_adapter_validates_objects_and_preserves_gc_accounting() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let string = vm.allocate_byte_string(b"a\0\xff7").unwrap();
        let table = vm.allocate_table().unwrap();
        let other = vm.allocate(Value::Integer(17)).unwrap();
        let _string_root = HostHandle::<Value>::new(&mut vm, string).unwrap();
        let _table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let _other_root = HostHandle::<Value>::new(&mut vm, other).unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Boolean(true))
            .unwrap();
        vm.raw_set(table, Value::Float(2.0), Value::Boolean(true))
            .unwrap();
        vm.raw_set(table, Value::Integer(4), Value::Boolean(true))
            .unwrap();
        let before = vm.ledger_snapshot();
        let trace = vm.allocation_trace();
        let gc = vm.gc_trace();
        let roots = vm.roots().total_count();
        vm.set_collect_every_allocation(true);
        assert_eq!(vm.raw_len_value(Value::Object(string)), Ok(4));
        assert_eq!(vm.raw_len_value(Value::Object(table)), Ok(2));
        for value in [
            Value::Nil,
            Value::Boolean(false),
            Value::Integer(7),
            Value::Float(2.0),
            Value::LightUserdata(0),
            Value::Object(other),
        ] {
            assert_eq!(vm.raw_len_value(value), Ok(0));
        }
        assert_eq!(vm.raw_len_value(Value::Object(string)), Ok(4));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.allocation_trace(), trace);
        assert_eq!(vm.gc_trace(), gc);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(
            vm.raw_get(table, Value::Integer(4)),
            Ok(Value::Boolean(true))
        );
        vm.collect_major().unwrap();
        assert_eq!(vm.raw_len_value(Value::Object(string)), Ok(4));
        assert_eq!(vm.raw_len_value(Value::Object(table)), Ok(2));

        let stale = vm.allocate_byte_string(b"stale").unwrap();
        let stale_table = vm.allocate_table().unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(stale), Err(VmError::StaleObject));
        assert_eq!(
            vm.raw_len_value(Value::Object(stale)),
            Err(VmError::StaleObject.into())
        );
        assert_eq!(vm.object_kind(stale_table), Err(VmError::StaleObject));
        assert_eq!(
            vm.raw_len_value(Value::Object(stale_table)),
            Err(VmError::StaleObject.into())
        );
        let mut foreign_vm = Vm::new_with_profile(profile).unwrap();
        let foreign = foreign_vm.allocate_table().unwrap();
        let foreign_string = foreign_vm.allocate_byte_string(b"foreign").unwrap();
        assert_eq!(
            vm.raw_len_value(Value::Object(foreign)),
            Err(VmError::WrongVm.into())
        );
        assert_eq!(
            vm.raw_len_value(Value::Object(foreign_string)),
            Err(VmError::WrongVm.into())
        );
    }
}
