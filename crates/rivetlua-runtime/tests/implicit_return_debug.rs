use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{HostHandle, RunOutcome, Vm};

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
        b"=implicit-return-runtime",
        profile,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut Unlimited,
    )
    .unwrap()
}

fn run(vm: &mut Vm, environment: Value, source: &[u8], profile: LanguageProfile) -> Vec<Value> {
    match vm
        .load_with_environment(compile(source, profile), environment)
        .unwrap()
        .run()
        .unwrap()
    {
        RunOutcome::Returned(values) => values,
        other => panic!("預期正常返回：{other:?}"),
    }
}

#[test]
fn root_and_child_implicit_returns_preserve_saved_captures_after_gc_and_reload() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.set_collect_every_allocation(true);
        let environment = environment_root.as_value(&vm).unwrap();

        assert_eq!(
            run(
                &mut vm,
                environment,
                b"local unused=1; local x=7; saved=function() return x end",
                language,
            ),
            []
        );
        vm.collect_major().unwrap();
        assert_eq!(
            run(&mut vm, environment, b"return saved()", language),
            [Value::Integer(7)]
        );

        assert_eq!(
            run(
                &mut vm,
                environment,
                b"local function make() local unused=1; local a=7; local b=8; saved=function() return a+b end end; make()",
                language,
            ),
            []
        );
        vm.collect_major().unwrap();
        assert_eq!(
            run(&mut vm, environment, b"return saved()", language),
            [Value::Integer(15)]
        );
        assert_eq!(
            run(
                &mut vm,
                environment,
                b"local a,b; local f=function() b=1 end; f(); observed=b",
                language,
            ),
            []
        );
        vm.collect_major().unwrap();
        assert_eq!(
            run(&mut vm, environment, b"return observed", language),
            [Value::Integer(1)]
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn implicit_return_with_tbc_and_error_close_runs_once_per_exit() {
    let source = b"local log=0; local saved; local mt={__close=function() log=log+1 end}; local function outer(fail) local unused=3; local x=7; local c <close> = setmetatable({},mt); saved=function() return x end; if fail then error('boom') end end; outer(false); local first=saved(); local ok=pcall(outer,true); return log,first,ok,saved()";
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(runtime).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.set_collect_every_allocation(true);
        assert_eq!(
            run(&mut vm, Value::Object(environment), source, language),
            [
                Value::Integer(2),
                Value::Integer(7),
                Value::Boolean(false),
                Value::Integer(7),
            ],
            "{language:?}"
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
