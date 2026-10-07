use rivetlua_core::{LuaProfile, ObjectRef, Value};
use rivetlua_runtime::{HostHandle, ObjectKind, Vm, VmError};

fn version_value(vm: &mut Vm, environment: ObjectRef) -> Value {
    let key = vm.allocate_byte_string(b"_VERSION").unwrap();
    let _key_root = HostHandle::<Value>::new(vm, key).unwrap();
    vm.raw_get(environment, Value::Object(key)).unwrap()
}

fn count_builtin_value(vm: &mut Vm, environment: ObjectRef) -> Value {
    let key = vm.allocate_byte_string(b"collectgarbage").unwrap();
    let _key_root = HostHandle::<Value>::new(vm, key).unwrap();
    vm.raw_get(environment, Value::Object(key)).unwrap()
}

#[test]
fn basic_environment_version_matches_vm_profile() {
    for (profile, expected) in [
        (LuaProfile::Lua54, b"Lua 5.4".as_slice()),
        (LuaProfile::Lua55, b"Lua 5.5".as_slice()),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let Value::Object(count) = count_builtin_value(&mut vm, environment) else {
            panic!("basic environment 必須提供 collectgarbage")
        };
        assert_eq!(vm.object_kind(count), Ok(ObjectKind::Builtin));
        let Value::Object(version) = version_value(&mut vm, environment) else {
            panic!("basic environment 必須提供 _VERSION ByteString")
        };
        assert_eq!(
            vm.with_byte_string(version, |value| value.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );
    }
}

#[test]
fn basic_environment_version_is_guest_mutable_and_removed_value_collects() {
    for (profile, expected) in [
        (LuaProfile::Lua54, b"Lua 5.4".as_slice()),
        (LuaProfile::Lua55, b"Lua 5.5".as_slice()),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.set_collect_every_allocation(true);
        vm.install_basic_builtins(environment).unwrap();
        vm.collect_major().unwrap();
        let Value::Object(original) = version_value(&mut vm, environment) else {
            panic!("_VERSION 必須是 ByteString")
        };
        assert_eq!(
            vm.with_byte_string(original, |value| value.as_bytes().to_vec()),
            Ok(expected.to_vec())
        );

        let key = vm.allocate_byte_string(b"_VERSION").unwrap();
        let _key_root = HostHandle::<Value>::new(&mut vm, key).unwrap();
        let replacement = vm.allocate_byte_string(b"guest version").unwrap();
        let replacement_root = HostHandle::<Value>::new(&mut vm, replacement).unwrap();
        vm.raw_set(environment, Value::Object(key), Value::Object(replacement))
            .unwrap();
        drop(replacement_root);
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(original), Err(VmError::StaleObject));
        assert_eq!(
            version_value(&mut vm, environment),
            Value::Object(replacement)
        );

        vm.raw_set(environment, Value::Object(key), Value::Nil)
            .unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(replacement), Err(VmError::StaleObject));
        assert_eq!(version_value(&mut vm, environment), Value::Nil);
    }
}

#[test]
fn basic_environment_allocation_faults_release_roots_and_allow_retry() {
    for (profile, expected) in [
        (LuaProfile::Lua54, b"Lua 5.4".as_slice()),
        (LuaProfile::Lua55, b"Lua 5.5".as_slice()),
    ] {
        let setup = || {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
            vm.collect_major().unwrap();
            (vm, environment, environment_root)
        };
        let (mut successful, environment, _environment_root) = setup();
        let first = successful.allocation_trace().next_ordinal;
        successful.install_basic_builtins(environment).unwrap();
        let end = successful.allocation_trace().next_ordinal;
        assert!(end > first);

        for ordinal in first..end {
            let (mut vm, environment, _environment_root) = setup();
            assert_eq!(vm.allocation_trace().next_ordinal, first);
            let roots = vm.roots().total_count();
            vm.inject_allocation_failure_at(ordinal);
            assert!(
                vm.install_basic_builtins(environment).is_err(),
                "ordinal {ordinal} 應拒絕"
            );
            assert_eq!(vm.roots().total_count(), roots, "ordinal {ordinal}");
            assert_eq!(vm.ledger_snapshot().reserved, 0, "ordinal {ordinal}");
            assert_eq!(
                vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
                ordinal
            );
            vm.install_basic_builtins(environment).unwrap();
            let Value::Object(count) = count_builtin_value(&mut vm, environment) else {
                panic!("重試後須有 collectgarbage")
            };
            assert_eq!(vm.object_kind(count), Ok(ObjectKind::Builtin));
            let Value::Object(version) = version_value(&mut vm, environment) else {
                panic!("重試後須有 _VERSION")
            };
            assert_eq!(
                vm.with_byte_string(version, |value| value.as_bytes().to_vec()),
                Ok(expected.to_vec())
            );
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}
