use std::error::Error;

use rivetlua::{
    CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits, CompileError, Engine, FromValue,
    HostServices, LuaProfile, Root, RunOutcome, SdkError, Value, Vm,
};

const SOURCE: &[u8] = b"local config={enabled=true,retries=3,read_retries=function(self) return self.retries end}; return config";

fn profile() -> Result<(LuaProfile, &'static str), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (None, None) | (Some("lua55"), None) => Ok((LuaProfile::Lua55, "lua55")),
        (Some("lua54"), None) => Ok((LuaProfile::Lua54, "lua54")),
        _ => Err("用法：down-001 [lua54|lua55]".into()),
    }
}

fn field(vm: &mut Vm, table: &Root, name: &[u8]) -> Result<Value, SdkError> {
    let key = vm.new_string(name)?;
    let key_value = key.value(vm)?;
    vm.table_raw_get(table, key_value)
}

fn main() -> Result<(), Box<dyn Error>> {
    let (profile, label) = profile()?;
    let engine = Engine::new(profile);
    let module = engine.compile_named(SOURCE, b"down-001")?;

    let mut vm = engine.new_vm_with_services(HostServices::deny_all())?;
    let outcome = vm
        .load_module(&module)?
        .run()
        .map_err(SdkError::Runtime)?;
    let RunOutcome::Returned(mut values) = outcome else {
        return Err("設定 module 應回傳 table".into());
    };
    if values.len() != 1 {
        return Err("設定 module 應只回傳一個 table".into());
    }
    let config = vm.root(values.remove(0))?;

    assert_eq!(bool::from_value(field(&mut vm, &config, b"enabled")?), Some(true));
    assert_eq!(i64::from_value(field(&mut vm, &config, b"retries")?), Some(3));

    let reader_value = field(&mut vm, &config, b"read_retries")?;
    let reader = vm.root(reader_value)?;
    let config_value = config.value(&vm)?;
    assert_eq!(
        vm.call(&reader, &[config_value])?
            .run()
            .map_err(SdkError::Runtime)?,
        RunOutcome::Returned(vec![Value::Integer(3)])
    );

    assert!(engine.compile(b"local = 1").is_err());
    let budget = CompileBudget::new(CompileBudgetLimits {
        max_work: 0,
        max_allocation_bytes: 1024,
    });
    assert!(matches!(
        engine.compile_named_with_budget(b"return 1 + 2", b"down-001-limit", &budget),
        Err(CompileError::Budget(
            CompileBudgetErrorKind::WorkLimitExceeded
        ))
    ));

    println!("DOWN-001 {label} enabled=true retries=3 call=3");
    Ok(())
}
