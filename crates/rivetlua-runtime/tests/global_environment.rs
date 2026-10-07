use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, ObjectRef, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostHandle, RunOutcome, Vm, VmError};

struct Unlimited;

impl CompileBudgetSink for Unlimited {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn compile(source: &[u8], profile: LanguageProfile) -> VerifiedModule {
    compile_with_budget(
        source,
        b"=global-environment",
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn field(vm: &mut Vm, table: ObjectRef, name: &[u8]) -> Value {
    let key = vm.allocate_byte_string(name).unwrap();
    let _key_root = HostHandle::<Value>::new(vm, key).unwrap();
    vm.raw_get(table, Value::Object(key)).unwrap()
}

fn run(vm: &mut Vm, environment: ObjectRef, source: &[u8], profile: LanguageProfile) -> Vec<Value> {
    match vm
        .load_with_environment(compile(source, profile), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap()
    {
        RunOutcome::Returned(values) => values,
        other => panic!("預期正常返回：{other:?}"),
    }
}

#[test]
fn basic_environment_global_alias_writes_arg_field_in_both_profiles() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        let arg = vm.allocate_table().unwrap();
        let _arg_root = HostHandle::<Value>::new(&mut vm, arg).unwrap();
        vm.set_collect_every_allocation(true);
        vm.install_basic_builtins(environment).unwrap();
        let arg_key = vm.allocate_byte_string(b"arg").unwrap();
        let _arg_key_root = HostHandle::<Value>::new(&mut vm, arg_key).unwrap();
        vm.raw_set(environment, Value::Object(arg_key), Value::Object(arg))
            .unwrap();
        let alias = field(&mut vm, environment, b"_G");
        let source = b"_G.ARG = arg; return _G == _ENV, _G.ARG == arg";
        let outcome = vm
            .load_with_environment(compile(source, language), Value::Object(environment))
            .and_then(|mut execution| execution.run());
        let control = vm
            .load_with_environment(
                compile(b"local t={}; t.ARG=arg; return t.ARG == arg", language),
                Value::Object(environment),
            )
            .and_then(|mut execution| execution.run());
        assert_eq!(
            control,
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)])),
            "{language:?} local table control"
        );
        assert_eq!(alias, Value::Object(environment), "{language:?}");
        assert_eq!(
            outcome,
            Ok(RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(true),
            ])),
            "{language:?}"
        );
        assert_eq!(field(&mut vm, environment, b"ARG"), Value::Object(arg));
    }
}

#[test]
fn global_alias_mutation_does_not_redirect_environment_or_cross_vm_boundaries() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let first = vm.allocate_table().unwrap();
        let _first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
        let second = vm.allocate_table().unwrap();
        let _second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
        vm.install_basic_builtins(first).unwrap();
        vm.install_basic_builtins(second).unwrap();
        assert_eq!(field(&mut vm, first, b"_G"), Value::Object(first));
        assert_eq!(field(&mut vm, second, b"_G"), Value::Object(second));

        assert_eq!(
            run(
                &mut vm,
                first,
                b"_G.marker=11; return _G == _ENV, marker",
                language,
            ),
            [Value::Boolean(true), Value::Integer(11)]
        );
        assert_eq!(
            run(&mut vm, second, b"return marker", language),
            [Value::Nil]
        );
        assert_eq!(
            run(
                &mut vm,
                first,
                b"_G={marker=22}; marker=33; return _G.marker, marker",
                language,
            ),
            [Value::Integer(22), Value::Integer(33)]
        );
        assert_eq!(field(&mut vm, second, b"_G"), Value::Object(second));
        assert_eq!(
            run(
                &mut vm,
                first,
                b"_G=nil; marker=44; return marker",
                language
            ),
            [Value::Integer(44)]
        );
        assert_eq!(field(&mut vm, first, b"_G"), Value::Nil);
        assert_eq!(field(&mut vm, second, b"_G"), Value::Object(second));

        let mut other_vm = Vm::new_with_profile(runtime).unwrap();
        let other = other_vm.allocate_table().unwrap();
        let _other_root = HostHandle::<Value>::new(&mut other_vm, other).unwrap();
        other_vm.install_basic_builtins(other).unwrap();
        assert_eq!(field(&mut other_vm, other, b"_G"), Value::Object(other));
        assert_eq!(other_vm.object_kind(first), Err(VmError::WrongVm));
        assert_eq!(
            run(&mut other_vm, other, b"return marker", language),
            [Value::Nil]
        );
    }
}

#[test]
fn global_alias_self_cycle_survives_roots_and_is_collectible_after_root_drop() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        vm.set_collect_every_allocation(true);
        let initial_roots = vm.roots().total_count();
        let environment = vm.allocate_table().unwrap();
        let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        let rooted_count = vm.roots().total_count();
        assert_eq!(rooted_count, initial_roots + 1);
        vm.install_basic_builtins(environment).unwrap();
        assert_eq!(vm.roots().total_count(), rooted_count);
        vm.collect_major().unwrap();
        assert_eq!(
            field(&mut vm, environment, b"_G"),
            Value::Object(environment)
        );
        assert_eq!(vm.roots().total_count(), rooted_count);
        drop(environment_root);
        assert_eq!(vm.roots().total_count(), initial_roots);
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(environment), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn global_alias_allocation_faults_leave_no_temporary_roots_and_retry_on_same_vm() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let setup = || {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
            vm.set_collect_every_allocation(true);
            vm.collect_major().unwrap();
            (vm, environment, root)
        };
        let (mut successful, environment, _root) = setup();
        let first = successful.allocation_trace().next_ordinal;
        successful.install_basic_builtins(environment).unwrap();
        let end = successful.allocation_trace().next_ordinal;
        assert!(end > first);
        assert_eq!(
            field(&mut successful, environment, b"_G"),
            Value::Object(environment)
        );

        for ordinal in first..end {
            let (mut vm, environment, _root) = setup();
            assert_eq!(vm.allocation_trace().next_ordinal, first);
            let roots = vm.roots().total_count();
            vm.inject_allocation_failure_at(ordinal);
            assert!(
                vm.install_basic_builtins(environment).is_err(),
                "{profile:?} ordinal={ordinal}"
            );
            assert_eq!(
                vm.roots().total_count(),
                roots,
                "{profile:?} ordinal={ordinal}"
            );
            assert_eq!(
                vm.ledger_snapshot().reserved,
                0,
                "{profile:?} ordinal={ordinal}"
            );
            assert_eq!(
                vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
                ordinal
            );
            vm.install_basic_builtins(environment).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(
                field(&mut vm, environment, b"_G"),
                Value::Object(environment)
            );
            assert_eq!(
                vm.roots().total_count(),
                roots,
                "{profile:?} ordinal={ordinal}"
            );
            assert_eq!(
                vm.ledger_snapshot().reserved,
                0,
                "{profile:?} ordinal={ordinal}"
            );
        }
    }
}
