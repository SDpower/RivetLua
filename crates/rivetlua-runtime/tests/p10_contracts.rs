use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{ObjectRef, Value, VerifyLimits};
use rivetlua_runtime::{
    FailPoint, HostHandle, LuaError, MetamethodEvent, RunOutcome, Table, Vm, VmError,
};

fn release_implicit_error(vm: &mut Vm, error: LuaError, baseline_roots: usize) {
    let Value::Object(message) = error.value else {
        panic!("隱含 LuaError 須保留 byte string 值")
    };
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(error.diagnostic_id.as_bytes().to_vec())
    );
    assert_eq!(vm.roots().total_count(), baseline_roots + 1);
    drop(error);
    assert_eq!(vm.roots().total_count(), baseline_roots);
    assert!(vm.collect().unwrap() >= 1);
    assert_eq!(vm.object_kind(message), Err(VmError::StaleObject));
    let stable = vm.ledger_snapshot();
    assert_eq!(stable.reserved, 0);
    assert_eq!(vm.collect().unwrap(), 0);
    assert_eq!(vm.ledger_snapshot(), stable);
}

#[test]
fn p10_1_event_lookup() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let source = b"local t={x=false}; return t";
    let limits = CompileLimits::default();
    let chunk = lex(source, profile, &limits).unwrap();
    let parsed = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let verified = emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone();
    let mut vm = Vm::new().unwrap();
    let owner = {
        let mut execution = vm.load(verified).unwrap();
        let Ok(RunOutcome::Returned(values)) = execution.run() else {
            panic!("compiler → VerifiedModule → VM 須回傳 table")
        };
        assert_eq!(values.len(), 1);
        let Value::Object(owner) = values[0] else {
            panic!("結果須為 table")
        };
        owner
    };
    let owner_handle = HostHandle::<Table>::new(&mut vm, owner).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let metatable_handle = HostHandle::<Table>::new(&mut vm, metatable).unwrap();
    vm.set_metatable(owner, Some(metatable)).unwrap();
    assert_eq!(vm.get_metatable(owner), Ok(Some(metatable)));
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Index),
        Ok(Value::Nil)
    );
    let metatable_of_metatable = vm.allocate_table().unwrap();
    let outer_handle = HostHandle::<Table>::new(&mut vm, metatable_of_metatable).unwrap();
    let fallback_key = vm.allocate_byte_string(b"__index").unwrap();
    let fallback_handle = HostHandle::<Value>::new(&mut vm, fallback_key).unwrap();
    vm.raw_set(
        metatable_of_metatable,
        Value::Object(fallback_key),
        Value::Boolean(true),
    )
    .unwrap();
    vm.set_metatable(metatable, Some(metatable_of_metatable))
        .unwrap();
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Call),
        Ok(Value::Nil)
    );
    let key = vm.allocate_byte_string(b"__index").unwrap();
    let key_handle = HostHandle::<Value>::new(&mut vm, key).unwrap();
    vm.raw_set(metatable, Value::Object(key), Value::Boolean(false))
        .unwrap();
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Index),
        Ok(Value::Boolean(false))
    );
    let event_value = vm.allocate_table().unwrap();
    let event_handle = HostHandle::<Table>::new(&mut vm, event_value).unwrap();
    vm.raw_set(metatable, Value::Object(key), Value::Object(event_value))
        .unwrap();
    drop(event_handle);
    drop(key_handle);
    drop(fallback_handle);
    drop(outer_handle);
    drop(metatable_handle);
    vm.set_collect_every_allocation(true);
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Index),
        Ok(Value::Object(event_value))
    );
    assert_eq!(vm.collect().unwrap(), 0);
    assert_eq!(
        vm.object_kind(event_value),
        Ok(rivetlua_runtime::ObjectKind::Table)
    );
    let before = vm.ledger_snapshot();
    let roots_before = vm.roots().total_count();
    vm.inject_failure_once(FailPoint::StringBytesReserve);
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Index),
        Err(VmError::InjectedFailure(FailPoint::StringBytesReserve))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), roots_before);
    vm.set_metatable(owner, None).unwrap();
    assert_eq!(
        vm.lookup_metamethod(owner, MetamethodEvent::Index),
        Ok(Value::Nil)
    );
    drop(owner_handle);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P10_STAGE\tp10_1_event_lookup\t{selected}\tstatus=PASS;event=__index;false=present;object_id=preserved;gc=traced"
    );
}

fn compile_p10(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, profile, &limits).unwrap();
    let parsed = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_p10(vm: &mut Vm, env: ObjectRef, source: &[u8], profile: LanguageProfile) -> RunOutcome {
    let mut execution = vm
        .load_with_environment(compile_p10(source, profile), Value::Object(env))
        .unwrap();
    execution.run().unwrap()
}

#[test]
fn review_builtin_metamethod_error_preserves_event_receiver() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    vm.install_error_builtins(env).unwrap();
    let table = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();
    let key_error = vm.allocate_byte_string(b"error").unwrap();
    let builtin = vm.raw_get(env, Value::Object(key_error)).unwrap();
    for (event, source) in [
        (b"__call".as_slice(), b"return t(9)".as_slice()),
        (b"__index".as_slice(), b"return t.missing".as_slice()),
    ] {
        meta_set_event(&mut vm, metatable, event, builtin);
        let RunOutcome::LuaError(error) = run_p10(&mut vm, env, source, profile) else {
            panic!("Builtin metamethod 應傳遞原始事件接收者")
        };
        assert_eq!(error.value, Value::Object(table));
        drop(error);
    }
    meta_set_event(&mut vm, metatable, b"__call", builtin);
    meta_set_event(&mut vm, metatable, b"__index", builtin);
    assert_eq!(
        run_p10(
            &mut vm,
            env,
            b"local a,x=pcall(function() return t(9) end); local b,y=pcall(function() return t.missing end); return a,x==t,b,y==t",
            profile,
        ),
        RunOutcome::Returned(vec![
            Value::Boolean(false),
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Boolean(true),
        ])
    );
    let proxy = vm.allocate_table().unwrap();
    let proxy_metatable = vm.allocate_table().unwrap();
    vm.set_metatable(proxy, Some(proxy_metatable)).unwrap();
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(proxy));
    meta_set_event(&mut vm, proxy_metatable, b"__index", builtin);
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.missing", profile) else {
        panic!("__index 事件鏈末端 Builtin 須被呼叫")
    };
    assert_eq!(error.value, Value::Object(proxy));
    drop(error);
    meta_set_event(&mut vm, metatable, b"__call", Value::Object(proxy));
    meta_set_event(&mut vm, proxy_metatable, b"__call", builtin);
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t(9)", profile) else {
        panic!("__call 事件鏈末端 Builtin 須被呼叫")
    };
    assert_eq!(error.value, Value::Object(proxy));
    drop(error);
}

#[test]
fn review_builtin_metamethod_yield_resumes_table_and_call_events() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    vm.install_coroutine_builtins(env).unwrap();
    let table = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();
    let key_coroutine = vm.allocate_byte_string(b"coroutine").unwrap();
    let Value::Object(coroutine) = vm.raw_get(env, Value::Object(key_coroutine)).unwrap() else {
        panic!("coroutine table 必須存在")
    };
    let key_yield = vm.allocate_byte_string(b"yield").unwrap();
    let builtin = vm.raw_get(coroutine, Value::Object(key_yield)).unwrap();
    meta_set_event(&mut vm, metatable, b"__call", builtin);
    meta_set_event(&mut vm, metatable, b"__index", builtin);
    vm.set_collect_every_allocation(true);
    let source = b"local c=coroutine.create(function() local a=t(9); local b=t.x; return a,b end); local ok1,v1,v2=coroutine.resume(c); local ok2,w1,w2=coroutine.resume(c,7); local ok3,r1,r2=coroutine.resume(c,8); return ok1,v1==t,v2,ok2,w1==t,w2=='x',ok3,r1,r2";
    assert_eq!(
        run_p10(&mut vm, env, source, profile),
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(9),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(7),
            Value::Integer(8),
        ])
    );
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn review_builtin_metamethod_protected_result_and_tail_yield() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    vm.install_error_builtins(env).unwrap();
    vm.install_coroutine_builtins(env).unwrap();
    let table = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();
    let (call, call_root) = closure_p10(&mut vm, b"return function() return 9 end", profile);
    meta_set_event(&mut vm, metatable, b"__call", Value::Object(call));
    drop(call_root);
    let key_pcall = vm.allocate_byte_string(b"pcall").unwrap();
    let pcall = vm.raw_get(env, Value::Object(key_pcall)).unwrap();
    meta_set_event(&mut vm, metatable, b"__index", pcall);
    vm.set_collect_every_allocation(true);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.missing", profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    let (throwing, throwing_root) =
        closure_p10(&mut vm, b"return function() error(9) end", profile);
    meta_set_event(&mut vm, metatable, b"__call", Value::Object(throwing));
    drop(throwing_root);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.missing", profile),
        RunOutcome::Returned(vec![Value::Boolean(false)])
    );
    let key_coroutine = vm.allocate_byte_string(b"coroutine").unwrap();
    let Value::Object(coroutine) = vm.raw_get(env, Value::Object(key_coroutine)).unwrap() else {
        panic!("coroutine table 必須存在")
    };
    let key_yield = vm.allocate_byte_string(b"yield").unwrap();
    let builtin = vm.raw_get(coroutine, Value::Object(key_yield)).unwrap();
    meta_set_event(&mut vm, metatable, b"__call", builtin);
    assert_eq!(
        run_p10(
            &mut vm,
            env,
            b"local c=coroutine.create(function() return t(9) end); local ok,x,y=coroutine.resume(c); local done,z=coroutine.resume(c,7); return ok,x==t,y,done,z",
            profile,
        ),
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(9),
            Value::Boolean(true),
            Value::Integer(7),
        ])
    );
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

fn closure_p10(
    vm: &mut Vm,
    source: &[u8],
    profile: LanguageProfile,
) -> (ObjectRef, HostHandle<Value>) {
    let closure = {
        let mut execution = vm.load(compile_p10(source, profile)).unwrap();
        let Ok(RunOutcome::Returned(values)) = execution.run() else {
            panic!("須由 VM 建立 closure")
        };
        assert_eq!(values.len(), 1);
        let Value::Object(closure) = values[0] else {
            panic!("須回傳 closure")
        };
        closure
    };
    let handle = HostHandle::<Value>::new(vm, closure).unwrap();
    (closure, handle)
}

#[test]
fn p10_2_regular_access() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let table = vm.allocate_table().unwrap();
    let table_root = HostHandle::<Table>::new(&mut vm, table).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let metatable_root = HostHandle::<Table>::new(&mut vm, metatable).unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    let key_x = vm.allocate_byte_string(b"x").unwrap();
    let key_x_root = HostHandle::<Value>::new(&mut vm, key_x).unwrap();
    let key_index = vm.allocate_byte_string(b"__index").unwrap();
    let key_newindex = vm.allocate_byte_string(b"__newindex").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();

    let (error_function, error_root) = closure_p10(
        &mut vm,
        b"return function() local x=nil; return x.any end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_index),
        Value::Object(error_function),
    )
    .unwrap();
    vm.raw_set(
        metatable,
        Value::Object(key_newindex),
        Value::Object(error_function),
    )
    .unwrap();
    drop(error_root);
    vm.raw_set(table, Value::Object(key_x), Value::Boolean(false))
        .unwrap();
    vm.set_collect_every_allocation(true);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Boolean(false)])
    );
    assert_eq!(
        run_p10(&mut vm, env, b"t.x=9; return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(9)])
    );
    vm.raw_set(table, Value::Object(key_x), Value::Integer(4))
        .unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(4)])
    );
    vm.raw_set(table, Value::Object(key_x), Value::Nil).unwrap();
    let roots_before_set_error = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"t.x=9; return 1", profile) else {
        panic!("__newindex 函式錯誤須受控傳回")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));
    release_implicit_error(&mut vm, error, roots_before_set_error);

    let proxy = vm.allocate_table().unwrap();
    let proxy_root = HostHandle::<Table>::new(&mut vm, proxy).unwrap();
    vm.raw_set(proxy, Value::Object(key_x), Value::Integer(7))
        .unwrap();
    vm.raw_set(metatable, Value::Object(key_index), Value::Object(proxy))
        .unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );
    assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));

    let key_marker = vm.allocate_byte_string(b"marker").unwrap();
    vm.raw_set(table, Value::Object(key_marker), Value::Integer(7))
        .unwrap();
    let (index_function, index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) return self.marker+#key end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_index),
        Value::Object(index_function),
    )
    .unwrap();
    drop(index_root);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(8)])
    );

    let (tail_index, tail_index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local g=function() return 6 end; return g() end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_index),
        Value::Object(tail_index),
    )
    .unwrap();
    drop(tail_index_root);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(6)])
    );

    vm.raw_set(metatable, Value::Object(key_newindex), Value::Object(proxy))
        .unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"t.x=11; return 1", profile),
        RunOutcome::Returned(vec![Value::Integer(1)])
    );
    assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));
    assert_eq!(
        vm.raw_get(proxy, Value::Object(key_x)),
        Ok(Value::Integer(11))
    );

    let (setter_function, setter_root) = closure_p10(
        &mut vm,
        b"return function(self,key,value) self.marker=value+#key end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_newindex),
        Value::Object(setter_function),
    )
    .unwrap();
    drop(setter_root);
    assert_eq!(
        run_p10(&mut vm, env, b"t.x=12; return 1", profile),
        RunOutcome::Returned(vec![Value::Integer(1)])
    );
    assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));
    assert_eq!(
        vm.raw_get(table, Value::Object(key_marker)),
        Ok(Value::Integer(13))
    );
    vm.raw_set(table, Value::Object(key_x), Value::Integer(13))
        .unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(13)])
    );
    vm.raw_set(table, Value::Object(key_x), Value::Nil).unwrap();

    let (throwing_function, throwing_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local x=nil; return x.any end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_index),
        Value::Object(throwing_function),
    )
    .unwrap();
    drop(throwing_root);
    let roots_before_error = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("Lua event 錯誤須傳至既有 boundary")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    release_implicit_error(&mut vm, error, roots_before_error);

    let (looping_function, looping_root) = closure_p10(
        &mut vm,
        b"return function(self,key) while true do end end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_index),
        Value::Object(looping_function),
    )
    .unwrap();
    drop(looping_root);
    let roots_before_abort = vm.roots().total_count();
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t.x", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(30).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), roots_before_abort);

    vm.raw_set(proxy, Value::Object(key_x), Value::Nil).unwrap();
    let proxy_metatable = vm.allocate_table().unwrap();
    vm.set_metatable(proxy, Some(proxy_metatable)).unwrap();
    vm.raw_set(
        proxy_metatable,
        Value::Object(key_index),
        Value::Object(table),
    )
    .unwrap();
    vm.raw_set(metatable, Value::Object(key_index), Value::Object(proxy))
        .unwrap();
    let roots_before_mutual = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("互指 __index 須受控終止")
    };
    assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    release_implicit_error(&mut vm, error, roots_before_mutual);

    vm.raw_set(metatable, Value::Object(key_index), Value::Object(table))
        .unwrap();
    let roots_before = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("自指 __index 須受控終止")
    };
    assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    release_implicit_error(&mut vm, error, roots_before);
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t.x", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(8).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), roots_before);
    drop(key_x_root);
    drop(proxy_root);
    drop(metatable_root);
    drop(table_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P10_STAGE\tp10_2_regular_access\t{selected}\tstatus=PASS;false=fast;index=table+call;newindex=table+call;raw=bypass;cycle=error;fuel=aborted"
    );
}

#[test]
fn p10_3_pending_op_resume() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let table = vm.allocate_table().unwrap();
    let table_root = HostHandle::<Table>::new(&mut vm, table).unwrap();
    let bridge = vm.allocate_table().unwrap();
    let outer_mt = vm.allocate_table().unwrap();
    let inner_mt = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    let key_bridge = vm.allocate_byte_string(b"bridge").unwrap();
    let key_index = vm.allocate_byte_string(b"__index").unwrap();
    let key_newindex = vm.allocate_byte_string(b"__newindex").unwrap();
    let key_newindex_root = HostHandle::<Value>::new(&mut vm, key_newindex).unwrap();
    let key_x = vm.allocate_byte_string(b"x").unwrap();
    let key_x_root = HostHandle::<Value>::new(&mut vm, key_x).unwrap();
    let key_marker = vm.allocate_byte_string(b"marker").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.raw_set(table, Value::Object(key_bridge), Value::Object(bridge))
        .unwrap();
    vm.raw_set(table, Value::Object(key_marker), Value::Integer(0))
        .unwrap();
    vm.set_metatable(table, Some(outer_mt)).unwrap();
    vm.set_metatable(bridge, Some(inner_mt)).unwrap();
    let (outer, outer_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local g=function() return self.bridge[key] end; return g()+1 end",
        profile,
    );
    let (inner, inner_root) = closure_p10(
        &mut vm,
        b"return function(self,key) return 4,99 end",
        profile,
    );
    vm.raw_set(outer_mt, Value::Object(key_index), Value::Object(outer))
        .unwrap();
    vm.raw_set(inner_mt, Value::Object(key_index), Value::Object(inner))
        .unwrap();
    drop(outer_root);
    drop(inner_root);
    vm.set_collect_every_allocation(true);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(5)])
    );
    let (setter, setter_root) = closure_p10(
        &mut vm,
        b"return function(self,key,value) self.marker=value+self.bridge[key]; return 999 end",
        profile,
    );
    vm.raw_set(outer_mt, Value::Object(key_newindex), Value::Object(setter))
        .unwrap();
    drop(setter_root);
    assert_eq!(
        run_p10(&mut vm, env, b"t.x=7; return t.marker", profile),
        RunOutcome::Returned(vec![Value::Integer(11)])
    );
    assert_eq!(vm.raw_get(table, Value::Object(key_x)), Ok(Value::Nil));

    let (throwing, throwing_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local x=nil; return x.bad end",
        profile,
    );
    vm.raw_set(inner_mt, Value::Object(key_index), Value::Object(throwing))
        .unwrap();
    drop(throwing_root);
    let roots_before_error = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("內層事件錯誤須到現有 LuaError 邊界")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    release_implicit_error(&mut vm, error, roots_before_error);

    let (looping, looping_root) = closure_p10(
        &mut vm,
        b"return function(self,key) while true do end end",
        profile,
    );
    vm.raw_set(inner_mt, Value::Object(key_index), Value::Object(looping))
        .unwrap();
    drop(looping_root);
    let roots_before_abort = vm.roots().total_count();
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t.x", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(40).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), roots_before_abort);
    vm.raw_set(inner_mt, Value::Object(key_index), Value::Object(bridge))
        .unwrap();
    let roots_before_chain = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("內層事件鏈循環須受控終止")
    };
    assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    release_implicit_error(&mut vm, error, roots_before_chain);
    drop(key_newindex_root);
    drop(key_x_root);
    drop(table_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P10_STAGE\tp10_3_pending_op_resume\t{selected}\tstatus=PASS;nested=index+newindex;result=5,11;error=lua+chain;fuel=aborted;gc=traced"
    );
}

#[test]
fn p10_4_metamethod_events() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    let key_x = vm.allocate_byte_string(b"x").unwrap();
    let key_call = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(target))
        .unwrap();
    vm.raw_set(target, Value::Object(key_x), Value::Integer(7))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (closure, closure_root) = closure_p10(
        &mut vm,
        b"return function(self,a,b) return a+b,self.x end",
        profile,
    );
    vm.raw_set(metatable, Value::Object(key_call), Value::Object(closure))
        .unwrap();
    drop(closure_root);
    assert_eq!(
        run_p10(&mut vm, env, b"local a,b=t(3,4); return a,b", profile),
        RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(7)])
    );
    assert_eq!(
        run_p10(&mut vm, env, b"return t(3,4)", profile),
        RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(7)])
    );
    assert_eq!(
        run_p10(&mut vm, env, b"return (t(3,4))", profile),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );
    let proxy = vm.allocate_table().unwrap();
    let proxy_mt = vm.allocate_table().unwrap();
    vm.set_metatable(proxy, Some(proxy_mt)).unwrap();
    let (chain_call, chain_root) = closure_p10(
        &mut vm,
        b"return function(proxy,self,a,b) return a+b,self.x end",
        profile,
    );
    let proxy_call_key = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(
        proxy_mt,
        Value::Object(proxy_call_key),
        Value::Object(chain_call),
    )
    .unwrap();
    vm.raw_set(metatable, Value::Object(key_call), Value::Object(proxy))
        .unwrap();
    drop(chain_root);
    vm.set_collect_every_allocation(true);
    assert_eq!(
        run_p10(&mut vm, env, b"return t(3,4)", profile),
        RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(7)])
    );
    vm.raw_set(
        proxy_mt,
        Value::Object(proxy_call_key),
        Value::Object(proxy),
    )
    .unwrap();
    let roots_before_abort = vm.roots().total_count();
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t(3,4)", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(40).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), roots_before_abort);
    drop(target_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P10_STAGE\tp10_4_metamethod_events\t{selected}\tstatus=PASS;call=7,7");
}

#[test]
fn p10_4_event_matrix() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let t = vm.allocate_table().unwrap();
    let t_root = HostHandle::<Table>::new(&mut vm, t).unwrap();
    let u = vm.allocate_table().unwrap();
    let u_root = HostHandle::<Table>::new(&mut vm, u).unwrap();
    let mt = vm.allocate_table().unwrap();
    vm.set_metatable(t, Some(mt)).unwrap();
    vm.set_metatable(u, Some(mt)).unwrap();
    for (name, value) in [(b"t".as_slice(), t), (b"u".as_slice(), u)] {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.raw_set(env, Value::Object(key), Value::Object(value))
            .unwrap();
    }
    let (event, root) = closure_p10(&mut vm, b"return function(a,b) return 41 end", profile);
    for name in [
        b"__add".as_slice(),
        b"__band",
        b"__len",
        b"__concat",
        b"__lt",
        b"__le",
        b"__eq",
    ] {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.raw_set(mt, Value::Object(key), Value::Object(event))
            .unwrap();
    }
    drop(root);
    vm.set_collect_every_allocation(true);
    for (source, expected) in [
        (b"return t+u".as_slice(), Value::Integer(41)),
        (b"return t&u", Value::Integer(41)),
        (b"return #t", Value::Integer(41)),
        (b"return t..u", Value::Integer(41)),
        (b"return t<u", Value::Boolean(true)),
        (b"return t<=u", Value::Boolean(true)),
        (b"return t==u", Value::Boolean(true)),
    ] {
        assert_eq!(
            run_p10(&mut vm, env, source, profile),
            RunOutcome::Returned(vec![expected]),
            "{source:?}"
        );
    }
    let len_key = vm.allocate_byte_string(b"__len").unwrap();
    let len_key_root = HostHandle::<rivetlua_core::Value>::new(&mut vm, len_key).unwrap();
    let (len_second_arg, len_root) =
        closure_p10(&mut vm, b"return function(a,b) return b end", profile);
    vm.raw_set(mt, Value::Object(len_key), Value::Object(len_second_arg))
        .unwrap();
    drop(len_root);
    assert_eq!(
        run_p10(&mut vm, env, b"return #t", profile),
        RunOutcome::Returned(vec![Value::Object(t)])
    );
    drop(len_key_root);
    let le_key = vm.allocate_byte_string(b"__le").unwrap();
    vm.raw_set(mt, Value::Object(le_key), Value::Nil).unwrap();
    let (false_lt, false_lt_root) =
        closure_p10(&mut vm, b"return function(a,b) return false end", profile);
    let lt_key = vm.allocate_byte_string(b"__lt").unwrap();
    vm.raw_set(mt, Value::Object(lt_key), Value::Object(false_lt))
        .unwrap();
    drop(false_lt_root);
    let le = run_p10(&mut vm, env, b"return t<=u", profile);
    if profile == LanguageProfile::Lua54 {
        assert_eq!(le, RunOutcome::Returned(vec![Value::Boolean(true)]));
    } else {
        let RunOutcome::LuaError(error) = le else {
            panic!("Lua55 不提供 Le fallback")
        };
        assert_eq!(error.diagnostic_id, "E_METAMETHOD_ABSENT");
    }
    let concat = run_p10(&mut vm, env, b"return 'A'..'B'..7", profile);
    let RunOutcome::Returned(values) = concat else {
        panic!("raw concat")
    };
    let Value::Object(concat) = values[0] else {
        panic!("raw concat byte string")
    };
    assert_eq!(
        vm.with_byte_string(concat, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"AB7"
    );
    let RunOutcome::Returned(values) =
        run_p10(&mut vm, env, b"return \"\\0A\"..\"\\255\"", profile)
    else {
        panic!("raw bytes concat")
    };
    let Value::Object(bytes) = values[0] else {
        panic!("raw bytes concat")
    };
    assert_eq!(
        vm.with_byte_string(bytes, |s| s.as_bytes().to_vec())
            .unwrap(),
        [0, b'A', 255]
    );
    let RunOutcome::Returned(values) = run_p10(&mut vm, env, b"return 1.0 .. 'x'", profile) else {
        panic!("raw float concat")
    };
    let Value::Object(float_concat) = values[0] else {
        panic!("raw float concat")
    };
    assert_eq!(
        vm.with_byte_string(float_concat, |s| s.as_bytes().to_vec())
            .unwrap(),
        b"1.0x"
    );
    assert_eq!(
        run_p10(&mut vm, env, b"return 1+2", profile),
        RunOutcome::Returned(vec![Value::Integer(3)])
    );
    let right_mt = vm.allocate_table().unwrap();
    vm.set_metatable(u, Some(right_mt)).unwrap();
    let eq_key = vm.allocate_byte_string(b"__eq").unwrap();
    let eq_key_root = HostHandle::<rivetlua_core::Value>::new(&mut vm, eq_key).unwrap();
    vm.raw_set(right_mt, Value::Object(eq_key), Value::Object(false_lt))
        .unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"return t==u", profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    vm.raw_set(mt, Value::Object(eq_key), Value::Nil).unwrap();
    assert_eq!(
        run_p10(&mut vm, env, b"return t==u", profile),
        RunOutcome::Returned(vec![Value::Boolean(false)])
    );
    assert_eq!(
        run_p10(&mut vm, env, b"return t~=u", profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    assert_eq!(
        run_p10(&mut vm, env, b"return t==t", profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    let add_key = vm.allocate_byte_string(b"__add").unwrap();
    let add_key_root = HostHandle::<rivetlua_core::Value>::new(&mut vm, add_key).unwrap();
    vm.raw_set(mt, Value::Object(add_key), Value::Boolean(false))
        .unwrap();
    let roots_before_noncall = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t+u", profile) else {
        panic!("不可呼叫事件應受控失敗")
    };
    assert_eq!(error.diagnostic_id, "E_CALL_NON_FUNCTION");
    release_implicit_error(&mut vm, error, roots_before_noncall);
    vm.raw_set(mt, Value::Object(add_key), Value::Nil).unwrap();
    let roots_before_absent = vm.roots().total_count();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t+u", profile) else {
        panic!("無事件應是 LuaError")
    };
    assert_eq!(error.diagnostic_id, "E_NOT_NUMERIC");
    release_implicit_error(&mut vm, error, roots_before_absent);
    drop(add_key_root);
    drop(eq_key_root);
    drop(u_root);
    drop(t_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    assert_raw_concat_float_profile(profile);
    println!("P10_STAGE\tp10_4_event_matrix\t{selected}\tstatus=PASS;events=7");
}

fn assert_raw_concat_float_profile(profile: LanguageProfile) {
    let expected: [&[u8]; 6] = if profile == LanguageProfile::Lua55 {
        [
            b"1.2345678901234567x",
            b"1e+20x",
            b"1e-05x",
            b"0.0001x",
            b"100000000000000.0x",
            b"1e+15x",
        ]
    } else {
        [
            b"1.2345678901235x",
            b"1e+20x",
            b"1e-05x",
            b"0.0001x",
            b"1e+14x",
            b"1e+15x",
        ]
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    for (source, expected) in [
        b"return 1.2345678901234567 .. 'x'".as_slice(),
        b"return 1e20 .. 'x'",
        b"return 1e-5 .. 'x'",
        b"return 1e-4 .. 'x'",
        b"return 1e14 .. 'x'",
        b"return 1e15 .. 'x'",
    ]
    .into_iter()
    .zip(expected)
    {
        let RunOutcome::Returned(values) = run_p10(&mut vm, env, source, profile) else {
            panic!("raw concat 須回傳 byte string")
        };
        let Value::Object(object) = values[0] else {
            panic!("raw concat 須回傳 byte string")
        };
        assert_eq!(
            vm.with_byte_string(object, |s| s.as_bytes().to_vec())
                .unwrap(),
            expected
        );
    }
    drop(env_root);
}

fn meta_profile() -> (String, LanguageProfile) {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    (selected, profile)
}

fn meta_set_global(vm: &mut Vm, env: ObjectRef, name: &[u8], value: Value) {
    let key = vm.allocate_byte_string(name).unwrap();
    vm.raw_set(env, Value::Object(key), value).unwrap();
}

fn meta_set_event(vm: &mut Vm, metatable: ObjectRef, name: &[u8], value: Value) {
    let key = vm.allocate_byte_string(name).unwrap();
    vm.raw_set(metatable, Value::Object(key), value).unwrap();
}

fn meta_marker(
    id: &str,
    profile: &str,
    actual: &str,
    event: &str,
    operands: &str,
    pending: &str,
    frame_pc: &str,
    resume: &str,
    fuel: &str,
    roots: &str,
    error: &str,
    aborted: &str,
    protected_boundary: &str,
    internal_unit: &str,
) {
    let diagnostic = format!(
        "event={event};operands={operands};pending={pending};frame_pc={frame_pc};resume={resume};fuel={fuel};roots={roots};error={error};aborted={aborted};protected_boundary={protected_boundary};internal_unit={internal_unit}"
    );
    println!("P10_CASE\t{id}\t{profile}\tactual={actual}\tdiagnostic={diagnostic}");
}

#[test]
fn meta_case_001_raw_false_bypasses_index() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    let key = vm.allocate_byte_string(b"x").unwrap();
    vm.raw_set(target, Value::Object(key), Value::Boolean(false))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (index, index_root) = closure_p10(&mut vm, b"return function() return 9 end", profile);
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(index));
    drop(index_root);
    let outcome = run_p10(&mut vm, env, b"return t.x", profile);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(false)]));
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, 2);
    meta_marker(
        "META-001",
        &selected,
        &format!("{outcome:?}"),
        "__index(raw-fast-path)",
        "target=t,key=x,raw=false",
        "none",
        "no-call",
        "no-resume",
        "default",
        &format!("{roots_after}"),
        "none",
        "false",
        "run",
        "vm::tests::p10_2_regular_access(asserts raw false fast path)",
    );
}

#[test]
fn meta_case_002_missing_index_resumes_with_value() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (index, index_root) =
        closure_p10(&mut vm, b"return function(self,key) return 7 end", profile);
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(index));
    drop(index_root);
    let outcome = run_p10(&mut vm, env, b"return t.x", profile);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, 2);
    meta_marker(
        "META-002",
        &selected,
        &format!("{outcome:?}"),
        "__index",
        "target=t,key=x",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-result=7",
        "default",
        &format!("{roots_after}"),
        "none",
        "false",
        "run",
        "vm::tests::p10_3_pending_op_resume(asserts caller-depth and resume-pc)",
    );
}

#[test]
fn meta_case_003_raw_write_bypasses_newindex() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (newindex, newindex_root) = closure_p10(
        &mut vm,
        b"return function() error('raw write called __newindex') end",
        profile,
    );
    meta_set_event(&mut vm, metatable, b"__newindex", Value::Object(newindex));
    drop(newindex_root);
    let key = vm.allocate_byte_string(b"x").unwrap();
    vm.raw_set(target, Value::Object(key), Value::Integer(7))
        .unwrap();
    let outcome = run_p10(&mut vm, env, b"return t.x", profile);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
    meta_marker(
        "META-003",
        &selected,
        &format!("{outcome:?}"),
        "raw_set(bypass-__newindex)",
        "target=t,key=x,value=7",
        "none",
        "no-call",
        "no-resume",
        "default",
        &format!("{}", vm.roots().total_count()),
        "none",
        "false",
        "host-raw-boundary",
        "vm::tests::p10_2_regular_access(asserts raw table access)",
    );
}

#[test]
fn meta_case_004_call_receives_original_table_first() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_x = vm.allocate_byte_string(b"x").unwrap();
    vm.raw_set(target, Value::Object(key_x), Value::Integer(7))
        .unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (call, call_root) = closure_p10(
        &mut vm,
        b"return function(self,a,b) return a+b,self.x end",
        profile,
    );
    meta_set_event(&mut vm, metatable, b"__call", Value::Object(call));
    drop(call_root);
    let outcome = run_p10(&mut vm, env, b"return t(3,4)", profile);
    assert_eq!(
        outcome,
        RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(7)])
    );
    meta_marker(
        "META-004",
        &selected,
        &format!("{outcome:?}"),
        "__call",
        "original=t,args=[3,4]",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-results=[7,7]",
        "default",
        &format!("{}", vm.roots().total_count()),
        "none",
        "false",
        "run",
        "vm::tests::p10_4_metamethod_events(asserts __call arguments and results)",
    );
}

#[test]
fn meta_case_005_index_chain_cycle_is_controlled() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(target));
    let roots_before = vm.roots().total_count();
    let outcome = run_p10(&mut vm, env, b"return t.missing", profile);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("self-referential __index chain must fail in a controlled way")
    };
    assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    let diagnostic_id = error.diagnostic_id;
    let actual = format!("LuaError({diagnostic_id})");
    release_implicit_error(&mut vm, error, roots_before);
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, roots_before);
    meta_marker(
        "META-005",
        &selected,
        &actual,
        "__index",
        "target=t,key=missing,chain=self",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-LuaError(E_METATABLE_CHAIN_LIMIT)",
        "default",
        &format!("before:{roots_before},after:{roots_after}"),
        diagnostic_id,
        "false",
        "run",
        "vm::tests::p10_5_reentry_gc_cleanup(asserts chain-limit cleanup)",
    );
}

#[test]
fn meta_case_006_pending_roots_survive_allocation_collection() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (index, index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local created={}; created.value=8; return created.value end",
        profile,
    );
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(index));
    drop(index_root);
    vm.set_collect_every_allocation(true);
    let roots_before = vm.roots().total_count();
    let outcome = run_p10(&mut vm, env, b"return t.missing", profile);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(8)]));
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, roots_before);
    meta_marker(
        "META-006",
        &selected,
        &format!("{outcome:?}"),
        "__index",
        "target=t,key=missing,created.value=8",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-result=8",
        "collect-every-allocation",
        &format!("before:{roots_before},after:{roots_after}"),
        "none",
        "false",
        "run",
        "vm::tests::p10_4_event_matrix(asserts GC-safe event completion)",
    );
}

#[test]
fn meta_case_007_lua_error_cleans_pending_at_boundary() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let (index, index_root) = closure_p10(
        &mut vm,
        b"return function() local z=nil; return z.bad end",
        profile,
    );
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(index));
    drop(index_root);
    let roots_before = vm.roots().total_count();
    let outcome = run_p10(&mut vm, env, b"return t.missing", profile);
    let RunOutcome::LuaError(error) = outcome else {
        panic!("metamethod error must propagate to the execution boundary")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    let diagnostic_id = error.diagnostic_id;
    release_implicit_error(&mut vm, error, roots_before);
    assert_eq!(vm.roots().total_count(), roots_before);
    meta_marker(
        "META-007",
        &selected,
        &format!("LuaError({diagnostic_id})"),
        "__index",
        "target=t,key=missing,error-value-preserved",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "LuaError(E_WRONG_OBJECT_TYPE)",
        "default",
        &format!("before:{roots_before},after:{}", vm.roots().total_count()),
        diagnostic_id,
        "false",
        "run-boundary",
        "vm::tests::p10_5_reentry_gc_cleanup(asserts LuaError root cleanup)",
    );
}

#[test]
fn meta_case_008_operator_events_return_expected_values() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let left = vm.allocate_table().unwrap();
    let _left_root = HostHandle::<Table>::new(&mut vm, left).unwrap();
    let right = vm.allocate_table().unwrap();
    let _right_root = HostHandle::<Table>::new(&mut vm, right).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(left));
    meta_set_global(&mut vm, env, b"u", Value::Object(right));
    vm.set_metatable(left, Some(metatable)).unwrap();
    vm.set_metatable(right, Some(metatable)).unwrap();
    let (event, event_root) = closure_p10(&mut vm, b"return function(a,b) return 41 end", profile);
    for name in [
        b"__add".as_slice(),
        b"__band",
        b"__len",
        b"__concat",
        b"__lt",
        b"__le",
        b"__eq",
    ] {
        meta_set_event(&mut vm, metatable, name, Value::Object(event));
    }
    drop(event_root);
    vm.set_collect_every_allocation(true);
    let roots_before = vm.roots().total_count();
    let mut actuals = Vec::new();
    for (source, expected) in [
        (b"return t+u".as_slice(), Value::Integer(41)),
        (b"return t&u", Value::Integer(41)),
        (b"return #t", Value::Integer(41)),
        (b"return t..u", Value::Integer(41)),
        (b"return t<u", Value::Boolean(true)),
        (b"return t<=u", Value::Boolean(true)),
        (b"return t==u", Value::Boolean(true)),
    ] {
        let outcome = run_p10(&mut vm, env, source, profile);
        assert_eq!(outcome, RunOutcome::Returned(vec![expected]), "{source:?}");
        let RunOutcome::Returned(values) = outcome else {
            unreachable!()
        };
        actuals.push(format!("{:?}", values[0]));
    }
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, roots_before);
    let actual = format!("Returned([{}])", actuals.join(","));
    meta_marker(
        "META-008",
        &selected,
        &actual,
        "__add,__band,__len,__concat,__lt,__le,__eq",
        "left=t,right=u,len=(t,t),comparison=boolean",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-results-checked-per-event",
        "collect-every-allocation",
        &format!("before:{roots_before},after:{roots_after}"),
        "none",
        "false",
        "run",
        "vm::tests::p10_4_event_matrix(asserts all operator event results)",
    );
}

#[test]
fn meta_case_009_nested_function_reads_and_writes_metatable_table() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let target_mt = vm.allocate_table().unwrap();
    let other = vm.allocate_table().unwrap();
    let _other_root = HostHandle::<Table>::new(&mut vm, other).unwrap();
    let other_mt = vm.allocate_table().unwrap();
    let backing = vm.allocate_table().unwrap();
    let backing_key = vm.allocate_byte_string(b"_backing").unwrap();
    vm.raw_set(other, Value::Object(backing_key), Value::Object(backing))
        .unwrap();
    let value_key = vm.allocate_byte_string(b"value").unwrap();
    vm.raw_set(backing, Value::Object(value_key), Value::Integer(5))
        .unwrap();
    vm.set_metatable(other, Some(other_mt)).unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    let other_key = vm.allocate_byte_string(b"other").unwrap();
    vm.raw_set(target, Value::Object(other_key), Value::Object(other))
        .unwrap();
    vm.set_metatable(target, Some(target_mt)).unwrap();
    let (other_index, other_index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) return self._backing[key] end",
        profile,
    );
    meta_set_event(&mut vm, other_mt, b"__index", Value::Object(other_index));
    drop(other_index_root);
    let (other_newindex, other_newindex_root) = closure_p10(
        &mut vm,
        b"return function(self,key,value) self._backing[key]=value end",
        profile,
    );
    meta_set_event(
        &mut vm,
        other_mt,
        b"__newindex",
        Value::Object(other_newindex),
    );
    drop(other_newindex_root);
    let (outer_index, outer_index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) local f=function() local value=self.other.value; self.other.saved=value; return self.other.saved end; return f() end",
        profile,
    );
    meta_set_event(&mut vm, target_mt, b"__index", Value::Object(outer_index));
    drop(outer_index_root);
    vm.set_collect_every_allocation(true);
    let roots_before = vm.roots().total_count();
    let outcome = run_p10(&mut vm, env, b"return t.missing", profile);
    assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(5)]));
    let roots_after = vm.roots().total_count();
    assert_eq!(roots_after, roots_before);
    meta_marker(
        "META-009",
        &selected,
        &format!("{outcome:?}"),
        "__index->Lua-call->__index->__newindex->__index",
        "target=t,other=metatable-table,read=value,write=saved",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external-result=5",
        "collect-every-allocation",
        &format!("before:{roots_before},after:{roots_after}"),
        "none",
        "false",
        "run",
        "vm::tests::p10_3_pending_op_resume(asserts nested frame depth and resume-pc)",
    );
}

#[test]
fn meta_case_010_terminal_paths_release_pending_roots_once() {
    let (selected, profile) = meta_profile();
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let _env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let target = vm.allocate_table().unwrap();
    let _target_root = HostHandle::<Table>::new(&mut vm, target).unwrap();
    let metatable = vm.allocate_table().unwrap();
    meta_set_global(&mut vm, env, b"t", Value::Object(target));
    vm.set_metatable(target, Some(metatable)).unwrap();
    let baseline = vm.roots().total_count();
    let (normal, normal_root) = closure_p10(&mut vm, b"return function() return 7 end", profile);
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(normal));
    drop(normal_root);
    assert_eq!(
        run_p10(&mut vm, env, b"return t.x", profile),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );
    let after_return = vm.roots().total_count();
    assert_eq!(after_return, baseline);

    let (throwing, throwing_root) = closure_p10(
        &mut vm,
        b"return function() local z=nil; return z.bad end",
        profile,
    );
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(throwing));
    drop(throwing_root);
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("LuaError path must terminate")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    release_implicit_error(&mut vm, error, baseline);
    let after_error = vm.roots().total_count();
    assert_eq!(after_error, baseline);

    let (looping, looping_root) =
        closure_p10(&mut vm, b"return function() while true do end end", profile);
    meta_set_event(&mut vm, metatable, b"__index", Value::Object(looping));
    drop(looping_root);
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t.x", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(40).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    let after_abort = vm.roots().total_count();
    assert_eq!(after_abort, baseline);

    meta_set_event(&mut vm, metatable, b"__index", Value::Object(target));
    let RunOutcome::LuaError(chain_error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("chain-limit path must terminate")
    };
    assert_eq!(chain_error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    release_implicit_error(&mut vm, chain_error, baseline);
    let after_chain = vm.roots().total_count();
    assert_eq!(after_chain, baseline);
    let actual = format!("Terminated(return=clean;error=clean;aborted=clean;chain=clean)");
    meta_marker(
        "META-010",
        &selected,
        &actual,
        "__index:return,LuaError,Aborted,chain-limit",
        "target=t,key=x",
        "not-exposed-by-crate-external-test",
        "not-exposed-by-crate-external-test",
        "external terminal outcomes and root counts asserted",
        "40-on-abort",
        &format!(
            "baseline:{baseline},return:{after_return},error:{after_error},abort:{after_abort},chain:{after_chain}"
        ),
        "E_WRONG_OBJECT_TYPE,E_METATABLE_CHAIN_LIMIT",
        "true-on-abort-only",
        "run-boundary",
        "vm::tests::p10_5_reentry_gc_cleanup(asserts error, abort, chain cleanup)",
    );
}

#[test]
fn p10_5_reentry_gc_cleanup() {
    let selected =
        std::env::var("RIVETLUA_P10_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P10 profile 無效"),
    };
    let mut vm = Vm::new().unwrap();
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Table>::new(&mut vm, env).unwrap();
    let table = vm.allocate_table().unwrap();
    let table_root = HostHandle::<Table>::new(&mut vm, table).unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key_t = vm.allocate_byte_string(b"t").unwrap();
    let key_call = vm.allocate_byte_string(b"__call").unwrap();
    vm.raw_set(env, Value::Object(key_t), Value::Object(table))
        .unwrap();
    vm.set_metatable(table, Some(metatable)).unwrap();
    let (event, event_root) = closure_p10(
        &mut vm,
        b"return function(self,n) if n==0 then return 7 end return self(n-1) end",
        profile,
    );
    vm.raw_set(metatable, Value::Object(key_call), Value::Object(event))
        .unwrap();
    drop(event_root);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t(1500)", profile), Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    assert!(execution.peak_frame_count() <= 3);
    drop(execution);
    vm.set_collect_every_allocation(false);
    let key_index = vm.allocate_byte_string(b"__index").unwrap();
    let key_newindex = vm.allocate_byte_string(b"__newindex").unwrap();
    let key_side = vm.allocate_byte_string(b"side").unwrap();
    vm.raw_set(table, Value::Object(key_side), Value::Integer(0))
        .unwrap();
    let (index, index_root) = closure_p10(
        &mut vm,
        b"return function(self,key) return self(2) end",
        profile,
    );
    vm.raw_set(metatable, Value::Object(key_index), Value::Object(index))
        .unwrap();
    drop(index_root);
    let (newindex, newindex_root) = closure_p10(
        &mut vm,
        b"return function(self,key,value) local f=function() self.side=value; return self.x end; return f() end",
        profile,
    );
    vm.raw_set(
        metatable,
        Value::Object(key_newindex),
        Value::Object(newindex),
    )
    .unwrap();
    drop(newindex_root);
    vm.set_collect_every_allocation(true);
    let baseline_roots = vm.roots().total_count();
    let mut execution = vm
        .load_with_environment(
            compile_p10(b"t.missing=9; return t.side,t.x", profile),
            Value::Object(env),
        )
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(9),
            Value::Integer(7)
        ]))
    );
    assert!(execution.peak_frame_count() <= 4);
    drop(execution);
    assert_eq!(vm.roots().total_count(), baseline_roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    vm.set_collect_every_allocation(false);
    let (throwing, throwing_root) = closure_p10(
        &mut vm,
        b"return function(self,n) local z=nil; return z.bad end",
        profile,
    );
    vm.raw_set(metatable, Value::Object(key_call), Value::Object(throwing))
        .unwrap();
    drop(throwing_root);
    vm.set_collect_every_allocation(true);
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("巢狀事件錯誤須傳至現有 LuaError 邊界")
    };
    assert_eq!(error.diagnostic_id, "E_WRONG_OBJECT_TYPE");
    release_implicit_error(&mut vm, error, baseline_roots);

    vm.set_collect_every_allocation(false);
    let (looping, looping_root) = closure_p10(
        &mut vm,
        b"return function(self,n) while true do end end",
        profile,
    );
    vm.raw_set(metatable, Value::Object(key_call), Value::Object(looping))
        .unwrap();
    drop(looping_root);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(compile_p10(b"return t.x", profile), Value::Object(env))
        .unwrap();
    execution.set_fuel(80).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(
            rivetlua_runtime::AbortReason::FuelExhausted
        ))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), baseline_roots);

    vm.raw_set(metatable, Value::Object(key_call), Value::Object(table))
        .unwrap();
    let RunOutcome::LuaError(error) = run_p10(&mut vm, env, b"return t.x", profile) else {
        panic!("__call 事件鏈須受控終止")
    };
    assert_eq!(error.diagnostic_id, "E_METATABLE_CHAIN_LIMIT");
    release_implicit_error(&mut vm, error, baseline_roots);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    drop(table_root);
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P10_STAGE\tp10_5_reentry_gc_cleanup\t{selected}\tstatus=PASS;tail=1500");
}
