use rivetlua::{ContainerLimits, Engine, LuaProfile, RunOutcome, TransportBudget, Value};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let (profile, label) = match (args.next().as_deref(), args.next()) {
        (None | Some("lua55"), None) => (LuaProfile::Lua55, "lua55"),
        (Some("lua54"), None) => (LuaProfile::Lua54, "lua54"),
        _ => return Err("用法：embed [lua55|lua54]".into()),
    };
    let engine = Engine::new(profile);
    let budget = TransportBudget::new(ContainerLimits::default());
    let module = engine.compile_named(b"return function() return {} end", b"example.lua")?;
    let container = engine.save_module(&module, &budget)?;
    let module = engine.load_module(&container, &budget)?;
    let mut vm = engine.new_vm()?;

    // Execution 結束後立即 root 回傳的 closure，避免後續配置或 GC 回收它。
    let function = match vm
        .load_module(&module)?
        .run()
        .map_err(rivetlua::SdkError::Runtime)?
    {
        RunOutcome::Returned(values) => values[0],
        other => return Err(format!("預期回傳函式，得到 {other:?}").into()),
    };
    let function = vm.root(function)?;

    // closure 呼叫回傳新表格；Execution 暫存值需先離開借用，再立刻建立 Root。
    let table = match vm
        .call(&function, &[])?
        .run()
        .map_err(rivetlua::SdkError::Runtime)?
    {
        RunOutcome::Returned(values) => values[0],
        other => return Err(format!("預期回傳表格，得到 {other:?}").into()),
    };
    let table = vm.root(table)?;
    vm.collect()?;
    assert!(matches!(table.value(&vm)?, Value::Object(_)));
    println!("P14_EXAMPLE:{label}:PASS");
    Ok(())
}
