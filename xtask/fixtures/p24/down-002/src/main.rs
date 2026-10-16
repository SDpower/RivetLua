use std::cell::{Cell, RefCell};
use std::error::Error;
use std::rc::Rc;

use rivetlua::{
    CallbackResult, Engine, HostServices, LuaProfile, RunOutcome, RuntimeErrorKind, SdkError,
    Value, VmPolicy,
};

fn profile() -> Result<(LuaProfile, &'static str), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (None, None) | (Some("lua55"), None) => Ok((LuaProfile::Lua55, "lua55")),
        (Some("lua54"), None) => Ok((LuaProfile::Lua54, "lua54")),
        _ => Err("用法：down-002 [lua54|lua55]".into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let (profile, label) = profile()?;
    let engine = Engine::new(profile);
    let source: &[u8] = if profile == LuaProfile::Lua55 {
        b"global host_log, compute, explode; return host_log(compute(20,22))"
    } else {
        b"return host_log(compute(20,22))"
    };
    let module = engine.compile_named(source, b"down-002")?;

    let services = HostServices::deny_all().and_policy(VmPolicy::Sandbox);
    let mut vm = engine.new_vm_with_services(services)?;
    let compute_calls = Rc::new(Cell::new(0));
    let compute_calls_for_callback = Rc::clone(&compute_calls);
    let compute = vm.register_callback(
        &[],
        Rc::new(move |_, args| {
            let [Value::Integer(left), Value::Integer(right)] = args else {
                return CallbackResult::Throw(Value::Integer(-1));
            };
            compute_calls_for_callback.set(compute_calls_for_callback.get() + 1);
            CallbackResult::Return(vec![Value::Integer(*left + *right)])
        }),
    )?;
    let compute_value = compute.value(&vm)?;
    vm.set_global(b"compute", compute_value)?;

    let logged = Rc::new(RefCell::new(Vec::<i64>::new()));
    let logged_for_callback = Rc::clone(&logged);
    let host_log = vm.register_callback(
        &[],
        Rc::new(move |_, args| {
            let [Value::Integer(value)] = args else {
                return CallbackResult::Throw(Value::Integer(-2));
            };
            logged_for_callback.borrow_mut().push(*value);
            CallbackResult::Return(vec![Value::Nil])
        }),
    )?;
    let host_log_value = host_log.value(&vm)?;
    vm.set_global(b"host_log", host_log_value)?;

    let explode = vm.register_callback(
        &[],
        Rc::new(|_, _| CallbackResult::Throw(Value::Integer(77))),
    )?;
    let explode_value = explode.value(&vm)?;
    vm.set_global(b"explode", explode_value)?;

    assert_eq!(
        vm.load_module(&module)?
            .run()
            .map_err(SdkError::Runtime)?,
        RunOutcome::Returned(vec![Value::Nil])
    );
    assert_eq!(compute_calls.get(), 1);
    assert_eq!(logged.borrow().as_slice(), &[42]);

    let throw_source: &[u8] = if profile == LuaProfile::Lua55 {
        b"global explode; return explode()"
    } else {
        b"return explode()"
    };
    let throw_module = engine.compile_named(throw_source, b"down-002-throw")?;
    let RunOutcome::LuaError(error) = vm
        .load_module(&throw_module)?
        .run()
        .map_err(SdkError::Runtime)?
    else {
        return Err("Throw callback 應回報 LuaError".into());
    };
    assert_eq!(error.kind, RuntimeErrorKind::Thrown);
    assert_eq!(error.value, Value::Integer(77));

    println!("DOWN-002 {label} compute=42 log=42 throw=77");
    Ok(())
}
