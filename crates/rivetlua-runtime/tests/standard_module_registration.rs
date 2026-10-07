use rivetlua_core::{LuaProfile, ObjectRef, Value};
use rivetlua_runtime::{ObjectKind, RootKind, Vm};

fn field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> Value {
    let key = vm.allocate_byte_string(name).unwrap();
    vm.raw_get(table, Value::Object(key)).unwrap()
}

fn table_field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> ObjectRef {
    let Value::Object(value) = field(vm, table, name) else {
        panic!("{name:?} 應為 table")
    };
    assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
    value
}

#[test]
fn standard_modules_register_before_or_after_package_without_fabrication() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for package_first in [false, true] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, environment).unwrap();
            if package_first {
                vm.install_package_builtins(environment).unwrap();
                let package = table_field(&mut vm, environment, b"package");
                let loaded = table_field(&mut vm, package, b"loaded");
                assert_eq!(field(&mut vm, loaded, b"io"), Value::Nil);
                assert_eq!(field(&mut vm, loaded, b"os"), Value::Nil);
                assert_eq!(field(&mut vm, loaded, b"debug"), Value::Nil);
                assert_eq!(field(&mut vm, loaded, b"math"), Value::Nil);
            }
            vm.install_io_os_builtins(environment).unwrap();
            vm.install_debug_builtins(environment).unwrap();
            if !package_first {
                vm.install_package_builtins(environment).unwrap();
            }
            let package = table_field(&mut vm, environment, b"package");
            let loaded = table_field(&mut vm, package, b"loaded");
            for name in [b"io".as_slice(), b"os", b"debug"] {
                let global = table_field(&mut vm, environment, name);
                assert_eq!(field(&mut vm, loaded, name), Value::Object(global));
            }
            for name in [
                b"_G".as_slice(),
                b"string",
                b"table",
                b"math",
                b"utf8",
                b"coroutine",
            ] {
                assert_eq!(field(&mut vm, loaded, name), Value::Nil);
            }
            assert_eq!(field(&mut vm, loaded, b"package"), Value::Object(package));
            assert_eq!(vm.roots().total_count(), 4);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}

#[test]
fn package_reinstall_keeps_registry_cache_and_preload_but_updates_package_entry() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        let first_package = table_field(&mut vm, environment, b"package");
        let loaded = table_field(&mut vm, first_package, b"loaded");
        let preload = table_field(&mut vm, first_package, b"preload");
        let custom = vm.allocate_table().unwrap();
        let custom_key = vm.allocate_byte_string(b"custom").unwrap();
        vm.raw_set(loaded, Value::Object(custom_key), Value::Object(custom))
            .unwrap();
        let math_key = vm.allocate_byte_string(b"math").unwrap();
        vm.raw_set(loaded, Value::Object(math_key), Value::Boolean(false))
            .unwrap();
        vm.raw_set(preload, Value::Object(custom_key), Value::Object(custom))
            .unwrap();

        vm.install_package_builtins(environment).unwrap();
        let second_package = table_field(&mut vm, environment, b"package");
        assert_ne!(first_package, second_package);
        assert_eq!(table_field(&mut vm, second_package, b"loaded"), loaded);
        assert_eq!(table_field(&mut vm, second_package, b"preload"), preload);
        assert_eq!(
            field(&mut vm, loaded, b"package"),
            Value::Object(second_package)
        );
        assert_eq!(field(&mut vm, loaded, b"custom"), Value::Object(custom));
        assert_eq!(field(&mut vm, preload, b"custom"), Value::Object(custom));
        assert_eq!(field(&mut vm, loaded, b"math"), Value::Boolean(false));
        assert_eq!(vm.roots().total_count(), 3);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
