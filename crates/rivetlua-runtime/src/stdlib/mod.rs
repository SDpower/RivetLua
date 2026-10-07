pub(crate) mod basic;
pub(crate) mod debug;
pub(crate) mod format;
pub(crate) mod gsub;
pub(crate) mod io;
pub(crate) mod math;
pub(crate) mod os;
pub(crate) mod pack;
pub(crate) mod package;
pub(crate) mod pattern;
pub(crate) mod string;
pub mod table;
pub(crate) mod utf8;

#[cfg(test)]
mod standard_module_tests {
    use rivetlua_core::{LuaProfile, ObjectRef, Value};

    use crate::{AllocationFailureKind, ObjectKind, RootKind, Vm, VmError};

    fn field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> Value {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.raw_get(table, Value::Object(key)).unwrap()
    }

    fn table_field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> ObjectRef {
        let Value::Object(table) = field(vm, table, name) else {
            panic!("{name:?} 應為 table")
        };
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        table
    }

    #[test]
    fn weak_value_environment_registration_retains_modules_only_through_loaded() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, environment).unwrap();
            let metatable = vm.allocate_table().unwrap();
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode = vm.allocate_byte_string(b"v").unwrap();
            vm.raw_set(metatable, Value::Object(mode_key), Value::Object(mode))
                .unwrap();
            vm.set_metatable(environment, Some(metatable)).unwrap();
            vm.collect().unwrap();

            let mut modules = Vec::new();
            for name in [b"math".as_slice(), b"string", b"debug"] {
                let table = vm.allocate_table().unwrap();
                let root = vm.add_root(RootKind::Host, table).unwrap();
                let key = vm.allocate_byte_string(name).unwrap();
                vm.raw_set(environment, Value::Object(key), Value::Object(table))
                    .unwrap();
                modules.push((name, table, root));
            }
            vm.set_collect_every_allocation(true);
            vm.install_package_builtins(environment).unwrap();
            for (_, _, root) in &modules {
                vm.remove_root(*root).unwrap();
            }
            vm.collect().unwrap();

            let package = table_field(&mut vm, environment, b"package");
            let loaded = table_field(&mut vm, package, b"loaded");
            for (name, table, _) in modules {
                assert_eq!(field(&mut vm, loaded, name), Value::Object(table));
                assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
            }
            assert_eq!(vm.roots().total_count(), 3);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn registered_debug_reinstall_limit_failure_restores_both_tables_and_retries() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_package_builtins(environment).unwrap();
            vm.install_debug_builtins(environment).unwrap();
            let package = table_field(&mut vm, environment, b"package");
            let loaded = table_field(&mut vm, package, b"loaded");
            let old = table_field(&mut vm, environment, b"debug");
            let before_roots = vm.roots().total_count();
            let before = vm.ledger_snapshot();
            vm.set_allocation_limit(before.committed);
            assert_eq!(
                vm.install_debug_builtins(environment),
                Err(VmError::AllocationFailed)
            );
            vm.set_allocation_limit(usize::MAX);
            assert_eq!(field(&mut vm, environment, b"debug"), Value::Object(old));
            assert_eq!(field(&mut vm, loaded, b"debug"), Value::Object(old));
            assert_eq!(vm.roots().total_count(), before_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            vm.install_debug_builtins(environment).unwrap();
            let new = table_field(&mut vm, environment, b"debug");
            assert_ne!(new, old);
            assert_eq!(field(&mut vm, loaded, b"debug"), Value::Object(new));
            assert_eq!(vm.roots().total_count(), before_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Publisher {
        Package,
        IoOs,
        Debug,
    }

    #[derive(Clone, Copy)]
    struct FieldSnapshot {
        table: ObjectRef,
        key: ObjectRef,
        value: Value,
    }

    struct PublisherFixture {
        vm: Vm,
        environment: ObjectRef,
        loaded: Option<ObjectRef>,
        preload: Option<ObjectRef>,
        fields: Vec<FieldSnapshot>,
    }

    fn install(vm: &mut Vm, environment: ObjectRef, publisher: Publisher) -> Result<(), VmError> {
        match publisher {
            Publisher::Package => vm.install_package_builtins(environment),
            Publisher::IoOs => vm.install_io_os_builtins(environment),
            Publisher::Debug => vm.install_debug_builtins(environment),
        }
    }

    fn snapshot_field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> FieldSnapshot {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.add_root(RootKind::Host, key).unwrap();
        FieldSnapshot {
            table,
            key,
            value: vm.raw_get(table, Value::Object(key)).unwrap(),
        }
    }

    fn setup_publisher(
        publisher: Publisher,
        registry_before: bool,
        reinstall: bool,
        active_gc: bool,
    ) -> PublisherFixture {
        let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
        let environment = vm.allocate_table().unwrap();
        vm.add_root(RootKind::Host, environment).unwrap();
        if registry_before {
            vm.install_package_builtins(environment).unwrap();
        }
        if reinstall && !matches!(publisher, Publisher::Package) {
            install(&mut vm, environment, publisher).unwrap();
        }
        let loaded = vm.package_loaded();
        let preload = vm.package_preload();
        let names: &[&[u8]] = match publisher {
            Publisher::Package => &[b"package", b"require"],
            Publisher::IoOs => &[b"io", b"os"],
            Publisher::Debug => &[b"debug"],
        };
        let mut fields = Vec::new();
        for &name in names {
            let old = vm.allocate_table().unwrap();
            vm.set_string_field(environment, name, Value::Object(old))
                .unwrap();
            fields.push(snapshot_field(&mut vm, environment, name));
        }
        if let Some(loaded) = loaded {
            for &name in names {
                if name == b"require" {
                    continue;
                }
                let old = vm.allocate_table().unwrap();
                vm.set_string_field(loaded, name, Value::Object(old))
                    .unwrap();
                fields.push(snapshot_field(&mut vm, loaded, name));
            }
            vm.set_string_field(loaded, b"custom", Value::Boolean(false))
                .unwrap();
            fields.push(snapshot_field(&mut vm, loaded, b"custom"));
            let preload = preload.unwrap();
            let old = vm.allocate_table().unwrap();
            vm.set_string_field(preload, b"custom", Value::Object(old))
                .unwrap();
            fields.push(snapshot_field(&mut vm, preload, b"custom"));
        } else if matches!(publisher, Publisher::Package) {
            let old = vm.allocate_table().unwrap();
            vm.set_string_field(environment, b"math", Value::Object(old))
                .unwrap();
            fields.push(snapshot_field(&mut vm, environment, b"math"));
        }
        vm.collect().unwrap();
        vm.collect().unwrap();
        if active_gc {
            vm.incremental_step(1).unwrap();
        }
        vm.set_collect_every_allocation(active_gc);
        PublisherFixture {
            vm,
            environment,
            loaded,
            preload,
            fields,
        }
    }

    #[test]
    fn standard_publisher_ordinal_failures_restore_env_loaded_registry_and_retry() {
        let cases = [
            (Publisher::Package, false, false),
            (Publisher::Package, true, true),
            (Publisher::IoOs, false, false),
            (Publisher::IoOs, false, true),
            (Publisher::IoOs, true, false),
            (Publisher::IoOs, true, true),
            (Publisher::Debug, false, false),
            (Publisher::Debug, false, true),
            (Publisher::Debug, true, false),
            (Publisher::Debug, true, true),
        ];
        for (publisher, registry_before, reinstall) in cases {
            for active_gc in [false, true] {
                let mut dry = setup_publisher(publisher, registry_before, reinstall, active_gc);
                let start = dry.vm.allocation_trace().next_ordinal;
                install(&mut dry.vm, dry.environment, publisher).unwrap();
                let attempts = dry.vm.allocation_trace().next_ordinal - start;
                assert!(
                    attempts > 10,
                    "{publisher:?} {registry_before} {reinstall} {active_gc}"
                );

                let mut failures = 0;
                for offset in 0..attempts {
                    let mut fixture =
                        setup_publisher(publisher, registry_before, reinstall, active_gc);
                    assert_eq!(fixture.vm.allocation_trace().next_ordinal, start);
                    let before_roots = fixture.vm.roots().total_count();
                    fixture.vm.inject_allocation_failure_at(start + offset);
                    let error = install(&mut fixture.vm, fixture.environment, publisher).err();
                    let Some(error) = error else {
                        continue;
                    };
                    assert!(
                        matches!(error, VmError::InjectedAllocation(_)),
                        "{publisher:?} {registry_before} {reinstall} {active_gc} {offset}: {error:?}"
                    );
                    failures += 1;
                    let trace = fixture.vm.allocation_trace();
                    let failure = trace.last_failure.expect("失敗應記錄配置點");
                    assert_eq!(failure.kind, AllocationFailureKind::Injection);
                    assert_eq!(failure.attempt.ordinal, start + offset);
                    assert_eq!(
                        fixture.vm.roots().total_count(),
                        before_roots,
                        "{publisher:?} {registry_before} {reinstall} {active_gc} {offset}"
                    );
                    assert_eq!(fixture.vm.package_loaded(), fixture.loaded);
                    assert_eq!(fixture.vm.package_preload(), fixture.preload);
                    for field in &fixture.fields {
                        assert_eq!(
                            fixture
                                .vm
                                .raw_get(field.table, Value::Object(field.key))
                                .unwrap(),
                            field.value,
                            "{publisher:?} {registry_before} {reinstall} {active_gc} {offset}"
                        );
                    }
                    assert_eq!(fixture.vm.ledger_snapshot().reserved, 0);
                    fixture.vm.collect().unwrap();
                    fixture.vm.collect().unwrap();
                    for field in &fixture.fields {
                        if let Value::Object(object) = field.value {
                            assert_eq!(fixture.vm.object_kind(object), Ok(ObjectKind::Table));
                        }
                    }
                    install(&mut fixture.vm, fixture.environment, publisher).unwrap();
                    let root_gain = usize::from(matches!(publisher, Publisher::IoOs) && !reinstall)
                        + 2 * usize::from(
                            matches!(publisher, Publisher::Package) && !registry_before,
                        );
                    assert_eq!(fixture.vm.roots().total_count(), before_roots + root_gain);
                    assert_eq!(fixture.vm.ledger_snapshot().reserved, 0);
                    if let Some(loaded) = fixture.vm.package_loaded() {
                        match publisher {
                            Publisher::Package => {
                                let package =
                                    table_field(&mut fixture.vm, fixture.environment, b"package");
                                assert_eq!(
                                    field(&mut fixture.vm, loaded, b"package"),
                                    Value::Object(package)
                                );
                            }
                            Publisher::IoOs => {
                                for name in [b"io".as_slice(), b"os"] {
                                    let global =
                                        table_field(&mut fixture.vm, fixture.environment, name);
                                    assert_eq!(
                                        field(&mut fixture.vm, loaded, name),
                                        Value::Object(global)
                                    );
                                }
                            }
                            Publisher::Debug => {
                                let global =
                                    table_field(&mut fixture.vm, fixture.environment, b"debug");
                                assert_eq!(
                                    field(&mut fixture.vm, loaded, b"debug"),
                                    Value::Object(global)
                                );
                            }
                        }
                    }
                }
                assert!(
                    failures > 10,
                    "{publisher:?} {registry_before} {reinstall} {active_gc}"
                );
                eprintln!(
                    "標準庫發布 {publisher:?} registry={registry_before} reinstall={reinstall} active_gc={active_gc} 配置點={attempts} 回滾={failures}"
                );
            }
        }
    }
}

#[cfg(test)]
mod p13_h_tests {
    use rivetlua_core::{LuaProfile, ObjectRef, Value};

    use crate::stdlib::basic::BasicBuiltin;
    use crate::stdlib::debug::DebugHook;
    use crate::{AllocationFailureKind, FailPoint, GcPhase, ObjectKind, RootKind, Vm, VmError};

    #[test]
    fn p13_h_debug_table_publishes_policy_gated_functions() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_debug_builtins(environment).unwrap();
        let key = vm.allocate_byte_string(b"debug").unwrap();
        let Value::Object(library) = vm.raw_get(environment, Value::Object(key)).unwrap() else {
            panic!("debug 函式庫應發布到環境")
        };
        assert_eq!(vm.object_kind(library), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p13_h_setcstacklimit_is_only_published_for_lua54() {
        for (profile, present) in [(LuaProfile::Lua54, true), (LuaProfile::Lua55, false)] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_debug_builtins(environment).unwrap();
            let debug_key = vm.allocate_byte_string(b"debug").unwrap();
            let Value::Object(library) = vm.raw_get(environment, Value::Object(debug_key)).unwrap()
            else {
                panic!("debug 函式庫應存在")
            };
            let key = vm.allocate_byte_string(b"setcstacklimit").unwrap();
            assert_eq!(
                vm.raw_get(library, Value::Object(key)).unwrap() != Value::Nil,
                present
            );
            vm.remove_root(root).unwrap();
        }
    }

    #[test]
    fn p13_h_main_hook_root_swap_failure_keeps_old_and_retries() {
        let mut vm = Vm::new().unwrap();
        let old = vm.allocate_basic_builtin(BasicBuiltin::Type).unwrap();
        let new = vm.allocate_basic_builtin(BasicBuiltin::ToString).unwrap();
        vm.set_debug_hook(None, Some(DebugHook::new(old, 3)))
            .unwrap();
        let new_root = vm.add_root(RootKind::Host, new).unwrap();
        let before = vm.roots().total_count();
        vm.incremental_step(1).unwrap();
        vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            vm.set_debug_hook(None, Some(DebugHook::new(new, 5))),
            Err(VmError::InjectedFailure(FailPoint::RootReserve)),
        );
        assert_eq!(vm.debug_hook_for(None).unwrap().unwrap().function, old);
        assert_eq!(vm.roots().total_count(), before);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(old), Ok(ObjectKind::Builtin));
        vm.set_debug_hook(None, Some(DebugHook::new(new, 5)))
            .unwrap();
        assert_eq!(vm.debug_hook_for(None).unwrap().unwrap().function, new);
        assert_eq!(vm.roots().total_count(), before);
        vm.remove_root(new_root).unwrap();
        vm.set_debug_hook(None, None).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(old), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(new), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p13_h_debug_installer_ordinal_failures_restore_old_value_under_active_gc() {
        fn setup(reinstall: bool, active_gc: bool) -> (Vm, ObjectRef, ObjectRef, ObjectRef) {
            let mut vm = Vm::new().unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, environment).unwrap();
            let key = vm.allocate_byte_string(b"debug").unwrap();
            vm.add_root(RootKind::Host, key).unwrap();
            if reinstall {
                vm.install_debug_builtins(environment).unwrap();
            }
            let old = vm.allocate_table().unwrap();
            vm.raw_set(environment, Value::Object(key), Value::Object(old))
                .unwrap();
            vm.collect().unwrap();
            if active_gc {
                vm.incremental_step(1).unwrap();
            }
            assert_eq!(vm.gc_trace().phase == GcPhase::Pause, !active_gc);
            (vm, environment, key, old)
        }
        for (reinstall, active_gc) in [(false, false), (false, true), (true, false), (true, true)] {
            let (mut dry, environment, _, _) = setup(reinstall, active_gc);
            let start = dry.allocation_trace().next_ordinal;
            dry.install_debug_builtins(environment).unwrap();
            let attempts = dry.allocation_trace().next_ordinal - start;
            assert!(attempts > 10);
            let mut failures = 0;
            for offset in 0..attempts {
                let (mut vm, environment, key, old) = setup(reinstall, active_gc);
                let before = vm.roots().total_count();
                let before_trace = vm.gc_trace();
                let before_live = before_trace.young + before_trace.survivor + before_trace.old;
                assert_eq!(vm.allocation_trace().next_ordinal, start);
                vm.inject_allocation_failure_at(start + offset);
                let error = vm
                    .install_debug_builtins(environment)
                    .err()
                    .unwrap_or_else(|| {
                        panic!(
                            "reinstall={reinstall} active={active_gc} offset={offset} 注入不得成功"
                        )
                    });
                let VmError::InjectedAllocation(attempt) = error else {
                    panic!(
                        "reinstall={reinstall} active={active_gc} offset={offset} 意外錯誤: {error:?}"
                    )
                };
                let failure = vm.allocation_trace().last_failure.expect("須記錄注入位置");
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt, attempt);
                assert_eq!(attempt.ordinal, start + offset);
                assert!(!attempt.site.file.is_empty());
                assert!(attempt.site.line > 0);
                failures += 1;
                assert_eq!(
                    vm.roots().total_count(),
                    before,
                    "reinstall={reinstall} active={active_gc} offset={offset}"
                );
                assert_eq!(
                    vm.raw_get(environment, Value::Object(key)).unwrap(),
                    Value::Object(old),
                    "reinstall={reinstall} active={active_gc} offset={offset}"
                );
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.collect().unwrap_or_else(|error| panic!("reinstall={reinstall} active={active_gc} offset={offset} collect={error:?} trace={:?}", vm.allocation_trace()));
                let after_trace = vm.gc_trace();
                assert_eq!(
                    after_trace.young + after_trace.survivor + after_trace.old,
                    before_live,
                    "reinstall={reinstall} active={active_gc} offset={offset}"
                );
                assert_eq!(vm.object_kind(old), Ok(ObjectKind::Table));
                vm.install_debug_builtins(environment).unwrap();
                assert_eq!(vm.roots().total_count(), before);
            }
            assert_eq!(
                failures, attempts,
                "reinstall={reinstall} active={active_gc}"
            );
            eprintln!(
                "H installer reinstall={reinstall} active_gc={active_gc} attempts={attempts} failures={failures}"
            );
        }
    }
}

#[cfg(test)]
mod p13_g_tests {
    use rivetlua_core::Value;

    use crate::{ObjectKind, RootKind, Vm};

    #[test]
    fn p13_g_installer_exposes_io_and_os_tables() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_io_os_builtins(environment).unwrap();
        for name in [b"io".as_slice(), b"os"] {
            let key = vm.allocate_byte_string(name).unwrap();
            let Value::Object(library) = vm.raw_get(environment, Value::Object(key)).unwrap()
            else {
                panic!("io/os 函式庫應存在: {name:?}");
            };
            assert_eq!(vm.object_kind(library), Ok(ObjectKind::Table));
        }
        vm.remove_root(root).unwrap();
    }
}

#[cfg(test)]
mod p13_f_tests {
    use rivetlua_core::{ObjectRef, Value};

    use crate::{GcPhase, ObjectKind, RootKind, Vm};

    #[test]
    fn p13_f_basic_installer_exposes_load_entrypoints() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        for name in [b"load".as_slice(), b"loadfile", b"dofile"] {
            let key = vm.allocate_byte_string(name).unwrap();
            let Value::Object(function) = vm.raw_get(environment, Value::Object(key)).unwrap()
            else {
                panic!("基本載入入口應存在: {name:?}");
            };
            assert_eq!(vm.object_kind(function), Ok(ObjectKind::Builtin));
        }
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p13_f_package_installer_keeps_two_registry_roots_on_reinstall() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_package_builtins(environment).unwrap();
        assert_eq!(vm.roots().total_count(), 3);
        let loaded = vm.package_loaded().unwrap();
        let preload = vm.package_preload().unwrap();
        vm.install_package_builtins(environment).unwrap();
        assert_eq!(vm.roots().total_count(), 3);
        assert_eq!(vm.package_loaded(), Some(loaded));
        assert_eq!(vm.package_preload(), Some(preload));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.roots().total_count(), 2);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p13_f_package_installer_ordinal_failures_restore_old_values_and_roots() {
        fn setup(
            reinstall: bool,
            active_gc: bool,
        ) -> (Vm, ObjectRef, ObjectRef, ObjectRef, ObjectRef, ObjectRef) {
            let mut vm = Vm::new().unwrap();
            let environment = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, environment).unwrap();
            let package_key = vm.allocate_byte_string(b"package").unwrap();
            vm.add_root(RootKind::Host, package_key).unwrap();
            let require_key = vm.allocate_byte_string(b"require").unwrap();
            vm.add_root(RootKind::Host, require_key).unwrap();
            if reinstall {
                vm.install_package_builtins(environment).unwrap();
            }
            let old_package = vm.allocate_table().unwrap();
            let old_require = vm.allocate_table().unwrap();
            vm.raw_set(
                environment,
                Value::Object(package_key),
                Value::Object(old_package),
            )
            .unwrap();
            vm.raw_set(
                environment,
                Value::Object(require_key),
                Value::Object(old_require),
            )
            .unwrap();
            vm.collect().unwrap();
            if active_gc {
                vm.incremental_step(1).unwrap();
            }
            assert_eq!(vm.gc_trace().phase == GcPhase::Pause, !active_gc);
            (
                vm,
                environment,
                package_key,
                require_key,
                old_package,
                old_require,
            )
        }

        for (reinstall, active_gc) in [(false, false), (false, true), (true, false), (true, true)] {
            let (mut dry, environment, _, _, _, _) = setup(reinstall, active_gc);
            let start = dry.allocation_trace().next_ordinal;
            dry.install_package_builtins(environment).unwrap();
            let attempts = dry.allocation_trace().next_ordinal - start;
            assert!(attempts > 10, "installer 應有可注入階段");
            let mut failures = 0;
            for offset in 0..attempts {
                let (mut vm, environment, package_key, require_key, old_package, old_require) =
                    setup(reinstall, active_gc);
                let before = vm.roots().total_count();
                let before_trace = vm.gc_trace();
                let before_live = before_trace.young + before_trace.survivor + before_trace.old;
                let loaded_before = vm.package_loaded();
                let preload_before = vm.package_preload();
                assert_eq!(vm.allocation_trace().next_ordinal, start);
                vm.inject_allocation_failure_at(start + offset);
                let result = vm.install_package_builtins(environment);
                if result.is_ok() {
                    continue;
                }
                failures += 1;
                assert_eq!(
                    vm.roots().total_count(),
                    before,
                    "reinstall={reinstall} offset={offset}"
                );
                assert_eq!(vm.package_loaded(), loaded_before);
                assert_eq!(vm.package_preload(), preload_before);
                assert_eq!(
                    vm.raw_get(environment, Value::Object(package_key)).unwrap(),
                    Value::Object(old_package),
                    "reinstall={reinstall} offset={offset}"
                );
                assert_eq!(
                    vm.raw_get(environment, Value::Object(require_key)).unwrap(),
                    Value::Object(old_require),
                    "reinstall={reinstall} offset={offset}"
                );
                vm.collect().unwrap_or_else(|error| {
                    panic!(
                        "reinstall={reinstall} offset={offset} collect={error:?} trace={:?}",
                        vm.allocation_trace()
                    )
                });
                let after_trace = vm.gc_trace();
                assert_eq!(
                    after_trace.young + after_trace.survivor + after_trace.old,
                    before_live,
                    "reinstall={reinstall} active_gc={active_gc} offset={offset} transient objects must be collected"
                );
                assert_eq!(vm.object_kind(old_package), Ok(ObjectKind::Table));
                assert_eq!(vm.object_kind(old_require), Ok(ObjectKind::Table));
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.install_package_builtins(environment).unwrap();
                assert_eq!(
                    vm.roots().total_count(),
                    before + if reinstall { 0 } else { 2 }
                );
            }
            assert!(failures > 10, "reinstall={reinstall} failures={failures}");
        }
    }
}

#[cfg(test)]
mod p13_e_tests {
    use rivetlua_core::Value;

    use crate::errors::Builtin;
    use crate::stdlib::utf8::Utf8Builtin;
    use crate::{ObjectKind, RootKind, Vm, VmError};

    #[test]
    fn p13_e_utf8_library_installs_pattern_as_bytes() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_utf8_builtins(environment).unwrap();
        let name = vm.allocate_byte_string(b"utf8").unwrap();
        let Value::Object(library) = vm.raw_get(environment, Value::Object(name)).unwrap() else {
            panic!("utf8 應安裝為 library table")
        };
        let pattern = vm.allocate_byte_string(b"charpattern").unwrap();
        let Value::Object(bytes) = vm.raw_get(library, Value::Object(pattern)).unwrap() else {
            panic!("charpattern 應為原始 bytes")
        };
        assert_eq!(
            vm.with_byte_string(bytes, |value| value.as_bytes().to_vec())
                .unwrap(),
            b"[\0-\x7f\xc2-\xfd][\x80-\xbf]*"
        );
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p13_e_codes_function_traces_both_iterators_without_registry_retention() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_utf8_builtins(environment).unwrap();
        let utf8_key = vm.allocate_byte_string(b"utf8").unwrap();
        let Value::Object(library) = vm.raw_get(environment, Value::Object(utf8_key)).unwrap()
        else {
            panic!("utf8 table")
        };
        let codes_key = vm.allocate_byte_string(b"codes").unwrap();
        let Value::Object(codes) = vm.raw_get(library, Value::Object(codes_key)).unwrap() else {
            panic!("codes function")
        };
        let Builtin::Utf8(Utf8Builtin::Codes { strict, lax }) = vm.builtin(codes).unwrap() else {
            panic!("codes refs")
        };
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(strict), Ok(ObjectKind::Builtin));
        assert_eq!(vm.object_kind(lax), Ok(ObjectKind::Builtin));
        assert_eq!(vm.roots().total_count(), 1);
        let iterator_root = vm.add_root(RootKind::Host, strict).unwrap();
        vm.remove_root(environment_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(strict), Ok(ObjectKind::Builtin));
        assert_eq!(vm.object_kind(lax), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(codes), Err(VmError::StaleObject));
        vm.remove_root(iterator_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(strict), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let other = Vm::new().unwrap();
        assert_eq!(other.object_kind(strict), Err(VmError::WrongVm));
    }
}

#[cfg(test)]
mod p13_d_tests {
    use rivetlua_core::Value;

    use crate::{ObjectKind, RootKind, Vm};

    #[test]
    fn p13_d_math_library_is_vm_value() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_math_builtins(environment).unwrap();
        let key = vm.allocate_byte_string(b"math").unwrap();
        let Value::Object(library) = vm.raw_get(environment, Value::Object(key)).unwrap() else {
            panic!("math 函式庫應安裝為 Lua table");
        };
        assert_eq!(vm.object_kind(library), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
    }
}

#[cfg(test)]
mod p13_c_tests {
    use rivetlua_core::Value;

    use crate::{FailPoint, ObjectKind, RootKind, Vm, VmError};

    #[test]
    fn p13_c_string_entrypoints_are_vm_values() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_string_builtins(environment).unwrap();
        let name = vm.allocate_byte_string(b"string").unwrap();
        let Value::Object(library) = vm.raw_get(environment, Value::Object(name)).unwrap() else {
            panic!("string 函式庫應作為 Lua table 安裝");
        };
        assert_eq!(vm.object_kind(library), Ok(ObjectKind::Table));
        for name in [b"byte".as_slice(), b"match", b"pack"] {
            let key = vm.allocate_byte_string(name).unwrap();
            let Value::Object(function) = vm.raw_get(library, Value::Object(key)).unwrap() else {
                panic!("string 入口應存在: {name:?}");
            };
            assert_eq!(vm.object_kind(function), Ok(ObjectKind::Builtin));
        }
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p13_c_string_metatable_root_survives_gc_and_reinstall() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        let registry_count = |vm: &Vm| {
            let mut count = 0;
            vm.visit_roots(|kind, _, _| {
                if kind == RootKind::Registry {
                    count += 1;
                }
            });
            count
        };
        assert_eq!(registry_count(&vm), 0);
        vm.install_string_builtins(environment).unwrap();
        assert_eq!(registry_count(&vm), 1);
        let first = vm.string_metatable().unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
        vm.install_string_builtins(environment).unwrap();
        assert_eq!(registry_count(&vm), 1);
        assert_ne!(vm.string_metatable(), Some(first));
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        vm.remove_root(environment_root).unwrap();
        vm.collect().unwrap();
        let second = vm.string_metatable().unwrap();
        assert_eq!(vm.object_kind(second), Ok(ObjectKind::Table));
        let other = Vm::new().unwrap();
        assert_eq!(other.string_metatable(), None);
    }

    #[test]
    fn p13_c_gmatch_iterator_traces_captures_and_reclaims_after_drop() {
        let mut vm = Vm::new().unwrap();
        let source = vm.allocate_byte_string(b"abc").unwrap();
        let source_root = vm.add_root(RootKind::Temporary, source).unwrap();
        let pattern = vm.allocate_byte_string(b".").unwrap();
        let pattern_root = vm.add_root(RootKind::Temporary, pattern).unwrap();
        let iterator = vm
            .allocate_string_iterator(Value::Object(source), Value::Object(pattern), 0)
            .unwrap();
        let iterator_root = vm.add_root(RootKind::Host, iterator).unwrap();
        vm.remove_root(source_root).unwrap();
        vm.remove_root(pattern_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(source), Ok(ObjectKind::ByteString));
        assert_eq!(vm.object_kind(pattern), Ok(ObjectKind::ByteString));
        let other = Vm::new().unwrap();
        assert_eq!(other.object_kind(iterator), Err(VmError::WrongVm));
        vm.remove_root(iterator_root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(iterator), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(source), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(pattern), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p13_c_string_buffer_growth_is_bounded_and_retryable() {
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot().committed;
        let mut buffer = super::string::Buffer::empty(&vm);
        for _ in 0..257 {
            buffer.append(b"a").unwrap();
        }
        assert_eq!(buffer.bytes.len(), 257);
        assert!(buffer.bytes.capacity() >= buffer.bytes.len());
        assert!(vm.ledger_snapshot().committed - baseline < 1024);
        let before_failure = vm.ledger_snapshot().committed;
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(matches!(
            buffer.reserve_extra(2048),
            Err(crate::vm::RuntimeError {
                kind: crate::vm::RuntimeErrorKind::Heap(VmError::InjectedFailure(
                    FailPoint::WorkReserve
                )),
                ..
            })
        ));
        assert_eq!(buffer.bytes.len(), 257);
        assert_eq!(vm.ledger_snapshot().committed, before_failure);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        buffer.reserve_extra(2048).unwrap();
        assert!(buffer.bytes.capacity() >= 2305);
        drop(buffer);
        assert_eq!(vm.ledger_snapshot().committed, baseline);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
