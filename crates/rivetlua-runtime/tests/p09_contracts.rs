use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    BytecodeConstant, BytecodeInstruction, ConstId, Instruction, ObjectRef, Register, ResultMode,
    Value, VerifyLimits, verify_module,
};
use rivetlua_runtime::{
    AbortReason, HostHandle, LuaError, RunOutcome, RuntimeErrorKind, Vm, VmError,
};

fn release_implicit_error(vm: &mut Vm, error: LuaError) {
    let Value::Object(message) = error.value else {
        panic!("隱含 LuaError 須保留 byte string 值")
    };
    assert_eq!(
        vm.with_byte_string(message, |string| string.as_bytes().to_vec()),
        Ok(error.diagnostic_id.as_bytes().to_vec())
    );
    assert_eq!(vm.roots().total_count(), 1);
    drop(error);
    assert_eq!(vm.roots().total_count(), 0);
    assert!(vm.collect().unwrap() >= 1);
    assert_eq!(vm.object_kind(message), Err(VmError::StaleObject));
    let stable = vm.ledger_snapshot();
    assert_eq!(stable.reserved, 0);
    assert_eq!(vm.collect().unwrap(), 0);
    assert_eq!(vm.ledger_snapshot(), stable);
}

fn compile(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
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

fn close_environment(
    vm: &mut Vm,
    profile: LanguageProfile,
) -> (
    ObjectRef,
    HostHandle<Value>,
    ObjectRef,
    ObjectRef,
    ObjectRef,
) {
    let env = vm.allocate_table().unwrap();
    let env_root = HostHandle::<Value>::new(vm, env).unwrap();
    let log = vm.allocate_table().unwrap();
    let log_key = vm.allocate_byte_string(b"close_log").unwrap();
    vm.raw_set(env, Value::Object(log_key), Value::Object(log))
        .unwrap();
    let outcome = vm
        .load_with_environment(
            compile(b"return function(v) close_log[#close_log+1]=v end", profile),
            Value::Object(env),
        )
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("__close handler 須為 Lua closure")
    };
    let Value::Object(handler) = values[0] else {
        panic!("__close handler 須為 Lua closure")
    };
    let metatable = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"__close").unwrap();
    vm.raw_set(metatable, Value::Object(key), Value::Object(handler))
        .unwrap();
    let first = vm.allocate_table().unwrap();
    let second = vm.allocate_table().unwrap();
    vm.set_metatable(first, Some(metatable)).unwrap();
    vm.set_metatable(second, Some(metatable)).unwrap();
    for (name, value) in [(b"closer_a".as_slice(), first), (b"closer_b", second)] {
        let key = vm.allocate_byte_string(name).unwrap();
        vm.raw_set(env, Value::Object(key), Value::Object(value))
            .unwrap();
    }
    (env, env_root, log, first, second)
}

fn verified_active_callee_case(profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let source = b"local f; local t={v=7}; f=function() f=nil; local x={}; return t.v end; local z=f(); return z";
    let mut candidate = compile(source, profile).module().clone();
    let child = candidate.prototypes[1].id;
    let child_code = &candidate.prototypes[1].instructions;
    let set = child_code
        .iter()
        .position(|entry| matches!(entry.instruction, Instruction::SetUpvalue { .. }))
        .unwrap();
    let allocation = child_code
        .iter()
        .position(|entry| matches!(entry.instruction, Instruction::NewTable { .. }))
        .unwrap();
    let get = child_code
        .iter()
        .position(|entry| matches!(entry.instruction, Instruction::GetUpvalue { .. }))
        .unwrap();
    assert!(set < allocation && allocation < get);
    let root = &mut candidate.prototypes[0];
    let f = root.binding_registers[1].1;
    let table = root.binding_registers[2].1;
    let key = Register(root.register_count - 2);
    let value = Register(root.register_count - 1);
    root.constants = vec![
        BytecodeConstant::Name(b"v".to_vec()),
        BytecodeConstant::Integer(7),
    ];
    root.instructions = vec![
        Instruction::NewTable { dest: table },
        Instruction::LoadConst {
            dest: key,
            constant: ConstId(0),
        },
        Instruction::LoadConst {
            dest: value,
            constant: ConstId(1),
        },
        Instruction::SetTable { table, key, value },
        Instruction::Closure {
            dest: f,
            proto: child,
        },
        Instruction::Call {
            base: f,
            arg_count: 0,
            result_mode: ResultMode::Fixed(1),
        },
        Instruction::Return {
            base: f,
            result_mode: ResultMode::Fixed(1),
        },
    ]
    .into_iter()
    .map(|instruction| BytecodeInstruction {
        instruction,
        span: candidate.span,
        close_path: None,
    })
    .collect();
    verify_module(
        candidate.clone(),
        candidate.profile,
        &VerifyLimits::default(),
    )
    .unwrap()
}

#[test]
fn p09_1_frame_entry_return() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let source = b"local f=function() return 7 end; local x=f(); return x";
    let verified = compile(source, profile);
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(verified).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    println!("P09_CASE\tCALL-ENTRY\t{selected}\tactual=Returned([Integer(7)])");

    let nested = b"local f=function() local g=function() return 8 end; local x=g(); return x end; local y=f(); return y";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let verified = compile(nested, profile);
    let mut execution = vm.load(verified.clone()).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(8)]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.collect().unwrap(), 3);

    let mut execution = vm.load(verified).unwrap();
    execution.set_fuel(2).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let mut vm = Vm::new().unwrap();
    let mut execution = vm
        .load(compile(b"local f=nil; local x=f(); return x", profile))
        .unwrap();
    let RunOutcome::LuaError(error) = execution.run().unwrap() else {
        panic!("nil call 須回 LuaError")
    };
    assert_eq!(error.kind, RuntimeErrorKind::NotCallable);
    drop(execution);
    release_implicit_error(&mut vm, error);

    let pending = b"local f=function() return nil,1,nil end; do local a <close> = closer_a; do local b <close> = closer_b; return f() end end";
    let verified = compile(pending, profile);
    let root = &verified.module().prototypes[0];
    let call = root
        .instructions
        .iter()
        .position(|entry| {
            matches!(
                entry.instruction,
                rivetlua_core::Instruction::Call {
                    result_mode: rivetlua_core::ResultMode::All,
                    ..
                }
            )
        })
        .unwrap();
    let path = root.instructions[call + 1].close_path.as_ref().unwrap();
    assert_eq!(path.registers.len(), 2);
    assert_eq!(root.instructions[call + 2].close_path.as_ref(), Some(path));
    assert!(matches!(
        root.instructions[call + 3].instruction,
        rivetlua_core::Instruction::Return {
            result_mode: rivetlua_core::ResultMode::All,
            ..
        }
    ));
    let path = path.clone();
    assert_eq!(path.kind, rivetlua_core::BytecodeExitKind::Return);
    let prototype = root.id;
    let rivetlua_core::Instruction::Return {
        base: return_base, ..
    } = root.instructions[call + 3].instruction
    else {
        panic!("ClosePath 後須有 Return(All)")
    };
    assert_eq!(prototype, root.id);
    assert_eq!(path.bindings.len(), 2);
    assert_eq!(path.registers.len(), 2);
    assert_eq!(root.instructions[call + 1].close_path.as_ref(), Some(&path));
    assert_eq!(root.instructions[call + 2].close_path.as_ref(), Some(&path));
    assert!(usize::from(return_base.0) < usize::from(root.register_count));
    let mut vm = Vm::new().unwrap();
    let (env, env_root, log, first, second) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(verified, Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Nil,
            Value::Integer(1),
            Value::Nil
        ]))
    );
    assert_eq!(execution.peak_frame_count(), 2);
    drop(execution);
    assert_eq!(
        vm.raw_get(log, Value::Integer(1)),
        Ok(Value::Object(second))
    );
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert!(vm.collect().unwrap() >= 1);
    println!(
        "P09_CASE\tCALL-PENDING\t{selected}\tpath_pc={};result_count=3;actual=Returned;close_order=LIFO",
        call + 1
    );
}

#[test]
fn p09_2_closure_upvalue() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let counter = b"local function counter() local n=0; return function() n=n+1; return n end end; local a=counter(); local b=counter(); local x=a(); local y=a(); local z=b(); return x,y,z";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(counter, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(1),
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-001\t{selected}\tactual=Returned([1,2,1])");

    let shared = b"local function pair() local x=3; local t={}; t.get=function() return x end; t.set=function() x=9 end; return t end; local p=pair(); local a=p.get(); p.set(); local b=p.get(); return a,b";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(shared, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(9)
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    println!("P09_CASE\tCALL-006\t{selected}\tactual=Returned([3,9])");

    let reused = b"local function make() local x={v=7}; local t={}; t.get=function() return x.v end; t.set=function() x.v=9 end; return t end; local a=make(); local b=make(); a.set(); local x=a.get(); local y=b.get(); local z=a.get(); return x,y,z";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(reused, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(9),
            Value::Integer(7),
            Value::Integer(9),
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-009\t{selected}\tactual=Returned([9,7,9])");

    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(verified_active_callee_case(profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-UPVALUE-ACTIVE\t{selected}\tactual=Returned([7])");
}

#[test]
fn p09_2_scope_close() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let source = b"local f; do local x={v=7}; f=function() return x.v end end; local y={}; local z=f(); return z";
    let verified = compile(source, profile);
    let root = &verified.module().prototypes[0];
    assert!(root.instructions.iter().any(|entry| {
        matches!(entry.instruction, Instruction::Close { count: 0, .. })
            && entry.close_path.is_none()
    }));
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(verified).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-SCOPE-CLOSE\t{selected}\tactual=Returned([7])");

    for (exit, source) in [
        (
            "break",
            b"local f; while true do local x=7; f=function() return x end; break end; local z=f(); return z"
                .as_slice(),
        ),
        (
            "goto",
            b"local f; do local x=7; f=function() return x end; goto L end ::L:: local z=f(); return z"
                .as_slice(),
        ),
        (
            "return",
            b"do local x=7; local f=function() return x end; return f end".as_slice(),
        ),
        (
            "shadow",
            b"local f; do local x=1; local x=7; f=function() return x end end; local z=f(); return z"
                .as_slice(),
        ),
    ] {
        let verified = compile(source, profile);
        assert!(verified.module().prototypes[0].instructions.iter().any(|entry| {
            matches!(entry.instruction, Instruction::Close { count: 0, .. })
                && entry.close_path.is_none()
        }));
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        let actual = execution.run();
        if exit == "return" {
            assert!(matches!(actual, Ok(RunOutcome::Returned(values)) if values.len() == 1 && matches!(values[0], Value::Object(_))));
        } else {
            assert_eq!(actual, Ok(RunOutcome::Returned(vec![Value::Integer(7)])));
        }
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tCALL-SCOPE-{exit}\t{selected}\tstatus=PASS");
    }

    let shared = b"local t={}; do local x=3; t.get=function() return x end; t.set=function() x=9 end end; local a=t.get(); t.set(); local b=t.get(); return a,b";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(shared, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(9)
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-SCOPE-SHARED\t{selected}\tactual=Returned([3,9])");

    let reused = b"local t={}; local i=1; while i<=2 do local x={v=i}; t[i]=function() return x.v end; i=i+1 end; local a=t[1](); local b=t[2](); return a,b";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(reused, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(1),
            Value::Integer(2)
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-SCOPE-REUSED\t{selected}\tactual=Returned([1,2])");

    let unopened =
        b"local f; do local x=7; if false then f=function() return x end end end; return 7";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compile(unopened, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    println!("P09_CASE\tCALL-SCOPE-UNOPENED\t{selected}\tactual=Returned([7])");

    let verified = compile(
        b"local f; do local x=7; local c <close> = closer_a; f=function() return x end end; return f",
        profile,
    );
    let root = &verified.module().prototypes[0];
    assert!(root.instructions.windows(2).any(|window| {
        matches!(window[0].instruction, Instruction::Close { count: 0, .. })
            && window[0].close_path.is_none()
            && matches!(window[1].instruction, Instruction::Close { count: 1, .. })
            && window[1].close_path.is_some()
    }));
    let mut vm = Vm::new().unwrap();
    let (env, env_root, log, first, _) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(verified, Value::Object(env))
        .unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("scope close 後須回傳捕捉 closure")
    };
    let Value::Object(closure) = values[0] else {
        panic!("捕捉 closure 須保留身分")
    };
    drop(execution);
    let closure_root = HostHandle::<Value>::new(&mut vm, closure).unwrap();
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    drop(env_root);
    vm.collect().unwrap();
    assert_eq!(
        vm.object_kind(closure),
        Ok(rivetlua_runtime::ObjectKind::Closure)
    );
    drop(closure_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-SCOPE-TBC\t{selected}\tstatus=Returned;close=executed");
}

#[test]
fn p09_3_result_adjustment() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    for (case, source, expected) in [
        (
            "CALL-002",
            b"local f=function() return 1,2,3 end; return (f())".as_slice(),
            vec![Value::Integer(1)],
        ),
        (
            "CALL-003",
            b"local f=function() return 1,2,3 end; return f(),9".as_slice(),
            vec![Value::Integer(1), Value::Integer(9)],
        ),
        (
            "CALL-004",
            b"local f=function() return 1,2,3 end; return 9,f()".as_slice(),
            vec![Value::Integer(9), Value::Integer(1), Value::Integer(2), Value::Integer(3)],
        ),
        (
            "CALL-004-zero",
            b"local f=function() return end; return 9,f()".as_slice(),
            vec![Value::Integer(9)],
        ),
        (
            "CALL-004-one",
            b"local f=function() return 1 end; return 9,f()".as_slice(),
            vec![Value::Integer(9), Value::Integer(1)],
        ),
        (
            "CALL-004-two-prefix",
            b"local f=function() return 1,2,3 end; return 9,8,f()".as_slice(),
            vec![Value::Integer(9), Value::Integer(8), Value::Integer(1), Value::Integer(2), Value::Integer(3)],
        ),
        (
            "CALL-005",
            b"return nil,1,nil".as_slice(),
            vec![Value::Nil, Value::Integer(1), Value::Nil],
        ),
        (
            "CALL-010-fixed-fewer",
            b"local f=function(a,b) return a,b end; local x,y=f(7); return x,y".as_slice(),
            vec![Value::Integer(7), Value::Nil],
        ),
        (
            "CALL-010-vararg-tail-nil",
            b"local f=function(a,...) return a,... end; local w,x,y,z=f(7,nil,9,nil); return w,x,y,z".as_slice(),
            vec![Value::Integer(7), Value::Nil, Value::Integer(9), Value::Nil],
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(compile(source, profile)).unwrap();
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)), "{case}");
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0, "{case}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
        println!("P09_CASE\t{case}\t{selected}\tstatus=PASS");
    }
}

#[test]
fn p09_3_vararg_runtime_subset() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    for (case, source, expected) in [
        (
            "CALL-010-fixed-zero",
            b"local f=function(a,b) return a,b end; local x,y=f(); return x,y".as_slice(),
            vec![Value::Nil, Value::Nil],
        ),
        (
            "CALL-010-fixed-exact",
            b"local f=function(a,b) return a,b end; local x,y=f(7,8); return x,y".as_slice(),
            vec![Value::Integer(7), Value::Integer(8)],
        ),
        (
            "CALL-010-fixed-excess",
            b"local f=function(a,b) return a,b end; local x,y=f(7,8,9); return x,y".as_slice(),
            vec![Value::Integer(7), Value::Integer(8)],
        ),
        (
            "CALL-010-vararg-fixed",
            b"local f=function(a,...) local x,y,z=...; return a,x,y,z end; local w,x,y,z=f(7,nil,9,nil); return w,x,y,z".as_slice(),
            vec![Value::Integer(7), Value::Nil, Value::Integer(9), Value::Nil],
        ),
        (
            "CALL-010-setter-argument",
            b"local x=1; local set=function(v) x=v end; set(9); return x".as_slice(),
            vec![Value::Integer(9)],
        ),
        (
            "CALL-010-vararg-GC",
            b"local f; local o={v=7}; f=function(...) o=nil; local x={}; local y=...; return y.v end; local z=f(o); return z".as_slice(),
            vec![Value::Integer(7)],
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(compile(source, profile)).unwrap();
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)), "{case}");
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0, "{case}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
        println!("P09_CASE\t{case}\t{selected}\tstatus=PASS");
    }
}

#[test]
fn p09_3_prefix_open_pending_close() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let source = b"local f=function() return 1,2,3 end; local c <close> = closer_a; return 9,f()";
    let verified = compile(source, profile);
    let root = &verified.module().prototypes[0];
    let path = root
        .instructions
        .iter()
        .find_map(|entry| {
            matches!(entry.instruction, Instruction::Close { count: 1, .. })
                .then_some(entry.close_path.as_ref())
                .flatten()
        })
        .unwrap();
    assert_eq!(path.registers.len(), 1);
    assert!(root.instructions.iter().any(|entry| matches!(
        entry.instruction,
        Instruction::Return {
            result_mode: ResultMode::All,
            ..
        }
    )));
    let mut vm = Vm::new().unwrap();
    let (env, env_root, log, first, _) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(verified, Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(9),
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3)
        ]))
    );
    drop(execution);
    assert_eq!(vm.raw_get(log, Value::Integer(1)), Ok(Value::Object(first)));
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P09_CASE\tPREFIX-OPEN-PENDING-CLOSE\t{selected}\tcount=4;actual=Returned;close=executed"
    );
}

#[test]
fn p09_3_prefix_open_scope_close() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let source = b"local f=function() return 1,2,3 end; do local x=9; local g=function() return x end; return x,f() end";
    let verified = compile(source, profile);
    assert!(
        verified.module().prototypes[0]
            .instructions
            .iter()
            .any(|entry| matches!(entry.instruction, Instruction::Close { count: 0, .. }))
    );
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(verified).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(9),
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tPREFIX-OPEN-SCOPE-CLOSE\t{selected}\tcount=4");
}

#[test]
fn p09_3_dynamic_call_arguments_cases() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    for (case, source, expected) in [
        (
            "prefix",
            b"local f=function(...) return ... end; local g=function() return 1,2 end; local a,b,c=f(9,g()); return a,b,c".as_slice(),
            vec![Value::Integer(9), Value::Integer(1), Value::Integer(2)],
        ),
        (
            "zero",
            b"local f=function(...) return ... end; local g=function() return end; return 9,f(g())".as_slice(),
            vec![Value::Integer(9)],
        ),
        (
            "tail-nil",
            b"local f=function(...) return ... end; local g=function() return nil,1,nil end; return 9,f(g())".as_slice(),
            vec![Value::Integer(9), Value::Nil, Value::Integer(1), Value::Nil],
        ),
        (
            "fixed-callee",
            b"local f=function(a,b) return a,b end; local g=function() return 1,2,3 end; local x,y=f(g()); return x,y".as_slice(),
            vec![Value::Integer(1), Value::Integer(2)],
        ),
        (
            "vararg-final",
            b"local f=function(...) return ... end; local wrap=function(...) local a,b,c=f(9,...); return a,b,c end; local x,y,z=wrap(1,nil); return x,y,z".as_slice(),
            vec![Value::Integer(9), Value::Integer(1), Value::Nil],
        ),
        (
            "nested",
            b"local f=function(...) return ... end; local g=function(...) return ... end; local h=function() return 1,2 end; local x,y=f(g(h())); return x,y".as_slice(),
            vec![Value::Integer(1), Value::Integer(2)],
        ),
        (
            "nested-return-prefix",
            b"local f=function(...) return ... end; local g=function(...) return ... end; local h=function() return 1,2 end; return 0,f(g(h()))".as_slice(),
            vec![Value::Integer(0), Value::Integer(1), Value::Integer(2)],
        ),
        (
            "method",
            b"local t={m=function(self,...) return ... end}; local g=function() return 1,2 end; local a,b=t:m(g()); return a,b".as_slice(),
            vec![Value::Integer(1), Value::Integer(2)],
        ),
        (
            "nonlast",
            b"local f=function(a,b) return a,b end; local g=function() return 1,2 end; local a,b=f(g(),9); return a,b".as_slice(),
            vec![Value::Integer(1), Value::Integer(9)],
        ),
        (
            "paren",
            b"local f=function(a,b) return a,b end; local g=function() return 1,2 end; local a,b=f((g())); return a,b".as_slice(),
            vec![Value::Integer(1), Value::Nil],
        ),
        (
            "statement",
            b"local out=0; local f=function(a,b) out=a+b end; local g=function() return 1,2 end; f(g()); return out".as_slice(),
            vec![Value::Integer(3)],
        ),
        (
            "object-root",
            b"local f=function(v) local x={}; return v.k end; local g=function() return {k=7} end; local z=f(g()); return z".as_slice(),
            vec![Value::Integer(7)],
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(compile(source, profile)).unwrap();
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)), "{case}");
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0, "{case}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
        println!("P09_CASE\tDYNAMIC-CALL-ARGS-{case}\t{selected}\tstatus=PASS");
    }
}

#[test]
fn p09_4_named_vararg_profiles_and_table_mutation() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    if profile == LanguageProfile::Lua55 {
        let exact = b"function f(...va) va[1]=9; va.n=1; return ... end; return f(1,2)";
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_handle = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm
            .load_with_environment(compile(exact, profile), Value::Object(environment))
            .unwrap();
        drop(environment_handle);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(9)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tCALL-011\t{selected}\tcount=1;value=9");

        let source =
            b"local f=function(...va) va[1]=9; va.n=1; return ... end; local r=f(1,2); return r";
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(compile(source, profile)).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(9)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tCALL-011-BODY\t{selected}\tcount=1;value=9");

        let tail_local = b"local function f(...va) va[1]=9; va.n=1; return ... end; return f(1,2)";
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(compile(tail_local, profile)).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(9)]))
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tCALL-011-TAIL-LOCAL\t{selected}\tcount=1;value=9");

        for (case, source, expected) in [
            (
                "tail-nested-nil",
                b"local function f(...va) return ... end; local function g() return f(1,nil) end; return g()".as_slice(),
                vec![Value::Integer(1), Value::Nil],
            ),
            (
                "tail-object-root",
                b"local function f(...va) local a=...; return a.k end; return f({k=7})".as_slice(),
                vec![Value::Integer(7)],
            ),
        ] {
            let mut vm = Vm::new().unwrap();
            vm.set_collect_every_allocation(true);
            let mut execution = vm.load(compile(source, profile)).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)), "{case}");
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0, "{case}");
            assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
            println!("P09_CASE\tNAMED-VARARG-{case}\t{selected}\tstatus=PASS");
        }

        let tail_error = b"local function f(...va) va.n=nil; return ... end; return f(1)";
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(compile(tail_error, profile)).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("尾呼叫內刪除 n 欄位須得到受控 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNamedVarargCount);
        drop(execution);
        release_implicit_error(&mut vm, error);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tNAMED-VARARG-tail-error\t{selected}\tstatus=LUA_ERROR");

        for (case, source, expected) in [
            (
                "n-grow-with-nil",
                b"local f=function(...va) va[1]=9; va.n=2; return ... end; local a,b=f(1); return a,b".as_slice(),
                vec![Value::Integer(9), Value::Nil],
            ),
            (
                "object-root",
                b"local f=function(...va) va[1]={k=7}; va.n=1; local a=...; return a.k end; local r=f(nil); return r".as_slice(),
                vec![Value::Integer(7)],
            ),
        ] {
            let mut vm = Vm::new().unwrap();
            vm.set_collect_every_allocation(true);
            let mut execution = vm.load(compile(source, profile)).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(expected)), "{case}");
            drop(execution);
            assert_eq!(vm.roots().total_count(), 0, "{case}");
            assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
            println!("P09_CASE\tNAMED-VARARG-{case}\t{selected}\tstatus=PASS");
        }

        let invalid_n = b"local f=function(...va) va.n=nil; return ... end; local r=f(1); return r";
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(compile(invalid_n, profile)).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("刪除 n 欄位須得到受控 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNamedVarargCount);
        assert_eq!(error.diagnostic_id, "E_VARARG_TABLE_COUNT");
        drop(execution);
        release_implicit_error(&mut vm, error);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        println!("P09_CASE\tNAMED-VARARG-INVALID-N\t{selected}\tstatus=LUA_ERROR");

        let readonly = b"local f=function(...va) va={}; return ... end";
        let limits = CompileLimits::default();
        let chunk = lex(readonly, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let error = resolve(&parsed, &chunk, profile, &limits).unwrap_err();
        assert_eq!(error.code, rivetlua_compiler::DiagnosticCode::Resolve);
        assert!(error.message.contains("readonly"));
        println!("P09_CASE\tNAMED-VARARG-READONLY\t{selected}\tstatus=REJECTED");
    } else {
        let named = b"local f=function(...va) return ... end";
        let limits = CompileLimits::default();
        let chunk = lex(named, profile, &limits).unwrap();
        let error = parse(&chunk, profile, &limits).unwrap_err();
        assert_eq!(error.code, rivetlua_compiler::DiagnosticCode::Parse);
        assert!(error.message.contains("具名 vararg table 僅支援 lua55"));
        let mut candidate = compile(named, LanguageProfile::Lua55).module().clone();
        candidate.profile = rivetlua_core::LuaProfile::Lua54;
        let error = verify_module(
            candidate,
            rivetlua_core::LuaProfile::Lua54,
            &VerifyLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code, rivetlua_core::BytecodeErrorCode::Verify);
        assert!(
            error
                .message
                .contains("lua54 不可攜帶 named vararg metadata")
        );
        println!("P09_CASE\tCALL-012\t{selected}\tstatus=REJECTED");
    }

    let anonymous = b"local function f(...) return ... end; return f(1,nil)";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compile(anonymous, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(1), Value::Nil]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tNAMED-VARARG-ANONYMOUS-REGRESSION\t{selected}\tcount=2;tail=nil");

    let dynamic_tail = b"local function f(...) return ... end; local function g() return 1,nil end; return f(9,g())";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compile(dynamic_tail, profile)).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(9),
            Value::Integer(1),
            Value::Nil,
        ]))
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tNAMED-VARARG-TAIL-DYNAMIC\t{selected}\tcount=3;tail=nil");
}

#[test]
fn p09_5_tail_call_depth_close_path() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    let source = b"local function f(n) if n==0 then return 7 end return f(n-1) end; return f(1500)";
    let verified = compile(source, profile);
    assert!(verified.module().prototypes.iter().any(|prototype| {
        prototype
            .instructions
            .iter()
            .any(|entry| matches!(entry.instruction, Instruction::TailCall { .. }))
    }));
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(verified).unwrap();
    execution.set_fuel(100_000).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![Value::Integer(7)]))
    );
    assert_eq!(execution.peak_frame_count(), 1);
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-007\t{selected}\tpeak=1;value=7");

    let non_tail = b"local function f(n) if n==0 then return 0 end local x=f(n-1); return x+1 end; return f(1100)";
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(compile(non_tail, profile)).unwrap();
    let Ok(RunOutcome::LuaError(error)) = execution.run() else {
        panic!("非尾遞迴須為受控 stack limit")
    };
    assert_eq!(error.diagnostic_id, "E_STACK_LIMIT");
    assert_eq!(execution.peak_frame_count(), 1025);
    drop(execution);
    release_implicit_error(&mut vm, error);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tCALL-008\t{selected}\tpeak=1025;error=E_STACK_LIMIT");

    for (case, source, expected) in [
        (
            "parenthesized",
            b"local f=function() return 1,2 end; return (f())".as_slice(),
            vec![Value::Integer(1)],
        ),
        (
            "prefix",
            b"local f=function() return 1,2 end; return 9,f()".as_slice(),
            vec![Value::Integer(9), Value::Integer(1), Value::Integer(2)],
        ),
        (
            "arithmetic",
            b"local f=function() return 1,2 end; return f()+1".as_slice(),
            vec![Value::Integer(2)],
        ),
        (
            "call-then-return",
            b"local f=function() return 1,2 end; local x=f(); return x".as_slice(),
            vec![Value::Integer(1)],
        ),
    ] {
        let verified = compile(source, profile);
        assert!(
            verified.module().prototypes[0]
                .instructions
                .iter()
                .all(|entry| !matches!(entry.instruction, Instruction::TailCall { .. })),
            "{case}"
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(expected)),
            "{case}"
        );
        assert_eq!(execution.peak_frame_count(), 2, "{case}");
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0, "{case}");
    }

    let captured = b"local function f(n,out) local x=n; out[n]=function() return x end; if n==0 then return out end; return f(n-1,out) end; local t=f(3,{}); return t[3](),t[2](),t[1](),t[0]()";
    let verified = compile(captured, profile);
    assert!(verified.module().prototypes.iter().any(|prototype| {
        prototype
            .instructions
            .iter()
            .any(|entry| matches!(entry.instruction, Instruction::TailCall { .. }))
    }));
    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let mut execution = vm.load(verified).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Integer(3),
            Value::Integer(2),
            Value::Integer(1),
            Value::Integer(0),
        ]))
    );
    assert_eq!(execution.peak_frame_count(), 2);
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!("P09_CASE\tTAIL-CAPTURE-CLOSED\t{selected}\tcount=4;peak=2");

    let pending = b"local f=function() return nil,1,nil end; do local a <close> = closer_a; do local b <close> = closer_b; return f() end end";
    let verified = compile(pending, profile);
    let root = &verified.module().prototypes[0];
    let call = root
        .instructions
        .iter()
        .position(|entry| {
            matches!(
                entry.instruction,
                Instruction::Call {
                    result_mode: ResultMode::All,
                    ..
                }
            )
        })
        .unwrap();
    let path = root.instructions[call + 1].close_path.clone().unwrap();
    assert_eq!(path.bindings.len(), 2);
    assert_eq!(root.instructions[call + 2].close_path.as_ref(), Some(&path));
    assert!(matches!(
        root.instructions[call + 3].instruction,
        Instruction::Return {
            result_mode: ResultMode::All,
            ..
        }
    ));
    let mut vm = Vm::new().unwrap();
    let (env, env_root, log, first, second) = close_environment(&mut vm, profile);
    vm.set_collect_every_allocation(true);
    let mut execution = vm
        .load_with_environment(verified, Value::Object(env))
        .unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Returned(vec![
            Value::Nil,
            Value::Integer(1),
            Value::Nil
        ]))
    );
    assert_eq!(execution.peak_frame_count(), 2);
    assert_eq!(path.bindings.len(), 2);
    assert_eq!(path.registers.len(), 2);
    drop(execution);
    assert_eq!(
        vm.raw_get(log, Value::Integer(1)),
        Ok(Value::Object(second))
    );
    assert_eq!(vm.raw_get(log, Value::Integer(2)), Ok(Value::Object(first)));
    drop(env_root);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P09_CASE\tCALL-013\t{selected}\tpeak=2;path_pc={};count=3;actual=Returned;close_order=LIFO",
        call + 1
    );

    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compile(source, profile)).unwrap();
    execution.set_fuel(8).unwrap();
    assert_eq!(
        execution.run(),
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    );
    assert_eq!(execution.peak_frame_count(), 1);
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn review_tail_dynamic_arguments_close_after_producer() {
    let selected =
        std::env::var("RIVETLUA_P09_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match selected.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P09 profile 無效"),
    };
    for (case, source, first) in [
        ("call", b"local function outer() local x=1; local h=function() return x end; local function g() x=9; return 2,nil end; local function f(...) return h(),... end; return f(g()) end; return outer()".as_slice(), 9),
        ("vararg", b"local function outer(...) local x=1; local h=function() return x end; local function f(...) return h(),... end; return f(...) end; return outer(2,nil)".as_slice(), 1),
        ("method", b"local function outer() local x=1; local h=function() return x end; local t={f=function(self,...) return h(),... end}; local function g() x=9; return 2,nil end; return t:f(g()) end; return outer()".as_slice(), 9),
    ] {
        let verified = compile(source, profile);
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(first),
                Value::Integer(2),
                Value::Nil
            ])),
            "{case}"
        );
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0, "{case}");
        assert_eq!(vm.ledger_snapshot().reserved, 0, "{case}");
    }
}
