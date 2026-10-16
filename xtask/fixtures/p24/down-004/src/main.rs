use std::cell::{Cell, RefCell};
use std::error::Error;
use std::rc::Rc;

use rivetlua::{
    CallbackResult, Engine, HostOutput, HostOutputError, HostServices, LuaProfile, Root,
    RunOutcome, SdkError, Value, Vm, VmPolicy,
};

struct CapturedOutput(Rc<RefCell<Vec<u8>>>);

impl HostOutput for CapturedOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
}

fn profile() -> Result<(LuaProfile, &'static str), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    match (args.next().as_deref(), args.next()) {
        (None, None) | (Some("lua55"), None) => Ok((LuaProfile::Lua55, "lua55")),
        (Some("lua54"), None) => Ok((LuaProfile::Lua54, "lua54")),
        _ => Err("用法：down-004 [lua54|lua55]".into()),
    }
}

fn install_tenant(
    vm: &mut Vm,
    tenant: i64,
    initial_count: i64,
    handle_value: i64,
    calls: Rc<Cell<usize>>,
) -> Result<(Root, Root), SdkError> {
    vm.set_global(b"tenant", Value::Integer(tenant))?;

    let state = vm.new_table()?;
    let count_key = vm.new_string(b"count")?;
    let count_key_value = count_key.value(vm)?;
    vm.table_raw_set(&state, count_key_value, Value::Integer(initial_count))?;
    let state_value = state.value(vm)?;
    vm.set_global(b"state", state_value)?;

    let callback = vm.register_callback(
        &[],
        Rc::new(move |_, _| {
            calls.set(calls.get() + 1);
            CallbackResult::Return(vec![Value::Integer(handle_value)])
        }),
    )?;
    let callback_value = callback.value(vm)?;
    vm.set_global(b"tenant_handle", callback_value)?;

    Ok((state, callback))
}

fn state_count(vm: &mut Vm, state: &Root) -> Result<Value, SdkError> {
    let key = vm.new_string(b"count")?;
    let key_value = key.value(vm)?;
    vm.table_raw_get(state, key_value)
}

fn main() -> Result<(), Box<dyn Error>> {
    let (profile, label) = profile()?;
    let engine = Engine::new(profile);
    let source: &[u8] = if profile == LuaProfile::Lua55 {
        b"global tenant, state, tenant_handle, print; state.count = state.count + 1; print(tenant); return tenant, state.count, tenant_handle()"
    } else {
        b"state.count = state.count + 1; print(tenant); return tenant, state.count, tenant_handle()"
    };
    let module = engine.compile_named(source, b"down-004")?;

    let output_a = Rc::new(RefCell::new(Vec::new()));
    let output_b = Rc::new(RefCell::new(Vec::new()));
    let services_a = HostServices::deny_all()
        .and_policy(VmPolicy::Sandbox)
        .and_output(CapturedOutput(Rc::clone(&output_a)));
    let services_b = HostServices::deny_all()
        .and_policy(VmPolicy::Sandbox)
        .and_output(CapturedOutput(Rc::clone(&output_b)));
    let mut vm_a = engine.new_vm_with_services(services_a)?;
    let mut vm_b = engine.new_vm_with_services(services_b)?;

    let calls_a = Rc::new(Cell::new(0));
    let calls_b = Rc::new(Cell::new(0));
    let (state_a, capability_a) =
        install_tenant(&mut vm_a, 11, 3, 101, Rc::clone(&calls_a))?;
    let (state_b, capability_b) =
        install_tenant(&mut vm_b, 22, 8, 202, Rc::clone(&calls_b))?;

    assert!(state_a.value(&vm_b).is_err());
    assert!(capability_a.value(&vm_b).is_err());
    assert!(state_b.value(&vm_a).is_err());
    assert!(capability_b.value(&vm_a).is_err());

    let RunOutcome::Returned(values_a) = vm_a
        .load_module(&module)?
        .run()
        .map_err(SdkError::Runtime)?
    else {
        return Err("VM A 應正常回傳 tenant 狀態".into());
    };
    let RunOutcome::Returned(values_b) = vm_b
        .load_module(&module)?
        .run()
        .map_err(SdkError::Runtime)?
    else {
        return Err("VM B 應正常回傳 tenant 狀態".into());
    };
    assert_eq!(
        values_a,
        vec![Value::Integer(11), Value::Integer(4), Value::Integer(101)]
    );
    assert_eq!(
        values_b,
        vec![Value::Integer(22), Value::Integer(9), Value::Integer(202)]
    );
    assert_eq!(vm_a.get_global(b"tenant")?, Value::Integer(11));
    assert_eq!(vm_b.get_global(b"tenant")?, Value::Integer(22));
    assert_eq!(state_count(&mut vm_a, &state_a)?, Value::Integer(4));
    assert_eq!(state_count(&mut vm_b, &state_b)?, Value::Integer(9));
    assert_eq!(calls_a.get(), 1);
    assert_eq!(calls_b.get(), 1);
    assert_eq!(output_a.borrow().as_slice(), b"11\n");
    assert_eq!(output_b.borrow().as_slice(), b"22\n");

    println!("DOWN-004 {label} A=11/4/101 B=22/9/202");
    Ok(())
}
