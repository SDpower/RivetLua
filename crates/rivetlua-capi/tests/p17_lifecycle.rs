#![forbid(unsafe_code)]

use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{CoroutineState, HostHandle, ObjectKind, RunOutcome, Vm, VmError};

const SEED: u64 = 0x173003;
const ITERATIONS: usize = 128;
const WORKLOAD_PER_ITERATION: usize = 64;

fn profile() -> LuaProfile {
    #[cfg(feature = "lua54")]
    {
        LuaProfile::Lua54
    }
    #[cfg(not(feature = "lua54"))]
    {
        LuaProfile::Lua55
    }
}

fn profile_label() -> &'static str {
    #[cfg(feature = "lua54")]
    {
        "lua54-i64f64"
    }
    #[cfg(not(feature = "lua54"))]
    {
        "lua55-i64f64"
    }
}

fn compile(source: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-lifecycle",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn next_word(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

#[test]
fn p17_stress_gc_long_run() {
    let language = profile();
    let mut vm = Vm::new_with_profile(language).unwrap();
    let probe = vm.ledger_probe();
    let environment = vm.allocate_table().unwrap();
    let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let baseline_roots = vm.roots().total_count();
    let normal = compile(
        b"local function inner() return 42 end; return inner()",
        language,
    );
    let failing = compile(b"error('P17_B03_EXPECTED_ERROR')", language);
    let mut state = SEED;
    let mut completed = 0;
    let mut guest_operations = 0;
    let mut normal_operations = 0;
    let mut error_operations = 0;
    let mut gc_cycles = 0;
    let mut peak_committed = vm.ledger_snapshot().committed;

    for _ in 0..ITERATIONS {
        let length = 1 + (next_word(&mut state) % 64) as usize;
        let table = vm.allocate_table().unwrap();
        let child = vm.allocate_byte_string(&vec![b'x'; length]).unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(child))
            .unwrap();
        let table_root = HostHandle::<Value>::new(&mut vm, table).unwrap();
        let live_roots = vm.roots().total_count();
        assert_eq!(live_roots, baseline_roots + 1);
        vm.collect().unwrap();
        gc_cycles += 1;
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        assert_eq!(vm.object_kind(child), Ok(ObjectKind::ByteString));

        for operation in 0..WORKLOAD_PER_ITERATION {
            if operation % 2 == 0 {
                let returned = vm
                    .load_with_environment(normal.clone(), Value::Object(environment))
                    .unwrap()
                    .run()
                    .unwrap();
                assert_eq!(returned, RunOutcome::Returned(vec![Value::Integer(42)]));
                assert_eq!(vm.roots().total_count(), live_roots);
                normal_operations += 1;
            } else {
                let failure = vm
                    .load_with_environment(failing.clone(), Value::Object(environment))
                    .unwrap()
                    .run()
                    .unwrap();
                let RunOutcome::LuaError(error) = &failure else {
                    panic!("真實 Lua error 必須返回宿主持根的錯誤");
                };
                let Value::Object(message) = error.value else {
                    panic!("Lua error 值必須是 byte string");
                };
                assert_eq!(vm.roots().total_count(), live_roots + 1);
                if operation == WORKLOAD_PER_ITERATION - 1 {
                    vm.collect().unwrap();
                    gc_cycles += 1;
                    assert_eq!(vm.object_kind(message), Ok(ObjectKind::ByteString));
                }
                let text = vm
                    .with_byte_string(message, |bytes| bytes.as_bytes().to_vec())
                    .unwrap();
                assert!(
                    text.windows(b"P17_B03_EXPECTED_ERROR".len())
                        .any(|part| part == b"P17_B03_EXPECTED_ERROR")
                );
                drop(failure);
                assert_eq!(vm.roots().total_count(), live_roots);
                error_operations += 1;
            }
            guest_operations += 1;
        }

        drop(table_root);
        vm.collect().unwrap();
        gc_cycles += 1;
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), baseline_roots);
        let ledger = vm.ledger_snapshot();
        assert_eq!(ledger.reserved, 0);
        peak_committed = peak_committed.max(ledger.committed);
        completed += 1;
    }

    assert_eq!(completed, ITERATIONS);
    assert_eq!(guest_operations, ITERATIONS * WORKLOAD_PER_ITERATION);
    assert_eq!(normal_operations + error_operations, guest_operations);
    assert_eq!(normal_operations, error_operations);
    assert_eq!(gc_cycles, ITERATIONS * 3);
    drop(environment_root);
    let root_count = vm.roots().total_count();
    assert_eq!(root_count + 1, baseline_roots);
    drop(vm);
    let ledger = probe.snapshot();
    assert_eq!(ledger.committed, 0);
    assert_eq!(ledger.reserved, 0);
    println!(
        "P17_B03_CASE {{\"case_id\":\"p17_stress_gc_long_run\",\"profile\":\"{}\",\"seed\":{},\"iterations\":{},\"guest_operations\":{},\"normal_operations\":{},\"error_operations\":{},\"gc_cycles\":{},\"outcome\":\"PASS\",\"root_count\":{},\"ledger_committed\":{},\"ledger_reserved\":{},\"peak_committed\":{}}}",
        profile_label(),
        SEED,
        completed,
        guest_operations,
        normal_operations,
        error_operations,
        gc_cycles,
        root_count,
        ledger.committed,
        ledger.reserved,
        peak_committed
    );
}

#[test]
fn p17_stress_coroutine_debug() {
    let language = profile();
    let mut vm = Vm::new_with_profile(language).unwrap();
    let probe = vm.ledger_probe();
    let environment = vm.allocate_table().unwrap();
    let environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_coroutine_builtins(environment).unwrap();
    let baseline_roots = vm.roots().total_count();
    let coroutine_body = compile(
        b"local captured = 10\nreturn function()\n captured = captured + 1\n coroutine.yield(captured)\n captured = captured + 1\n return captured\nend",
        language,
    );
    let failing = compile(b"error('P17_B03_FRAME_ERROR')", language);
    let reusable = compile(b"return 99", language);
    let mut state = SEED;
    let mut completed = 0;
    let mut guest_operations = 0;
    let mut gc_cycles = 0;
    let mut peak_committed = vm.ledger_snapshot().committed;

    for _ in 0..ITERATIONS {
        let payload = vec![b'y'; 1 + (next_word(&mut state) % 48) as usize];
        let noise = vm.allocate_byte_string(&payload).unwrap();
        let noise_root = HostHandle::<Value>::new(&mut vm, noise).unwrap();
        let returned = vm
            .load_with_environment(coroutine_body.clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        guest_operations += 1;
        let RunOutcome::Returned(values) = returned else {
            panic!("coroutine body module 必須返回 closure");
        };
        let Value::Object(closure) = values[0] else {
            panic!("coroutine body 必須是 closure");
        };
        let closure_root = HostHandle::<Value>::new(&mut vm, closure).unwrap();
        let coroutine = vm.new_coroutine(Value::Object(closure)).unwrap();
        let coroutine_value = coroutine.as_value(&vm).unwrap();
        let Value::Object(thread) = coroutine_value else {
            panic!("coroutine 必須是 heap object");
        };
        assert_eq!(vm.coroutine_state(thread), Ok(CoroutineState::Suspended));
        drop(closure_root);
        vm.collect().unwrap();
        gc_cycles += 1;
        assert_eq!(vm.object_kind(closure), Ok(ObjectKind::Closure));
        let info = vm.debug_function_info(Value::Object(closure)).unwrap();
        assert!(info.nups >= 1);
        assert!(info.source.ends_with(b"p17-lifecycle"));
        assert!(info.linedefined >= 1);
        assert!(info.lastlinedefined > info.linedefined);
        assert!(!info.active_lines.is_empty());
        drop(info);

        let yielded = vm.resume(coroutine_value, &[]).unwrap().run().unwrap();
        guest_operations += 1;
        assert_eq!(
            yielded,
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(11)])
        );
        assert_eq!(vm.coroutine_state(thread), Ok(CoroutineState::Suspended));
        vm.collect().unwrap();
        gc_cycles += 1;
        assert_eq!(vm.object_kind(closure), Ok(ObjectKind::Closure));
        let resumed = vm.resume(coroutine_value, &[]).unwrap().run().unwrap();
        guest_operations += 1;
        assert_eq!(
            resumed,
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(12)])
        );
        assert_eq!(vm.coroutine_state(thread), Ok(CoroutineState::Dead));
        drop(coroutine);
        drop(noise_root);
        vm.collect().unwrap();
        gc_cycles += 1;
        assert_eq!(vm.object_kind(thread), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(noise), Err(VmError::StaleObject));

        let before_error = vm.roots().total_count();
        let failure = vm
            .load_with_environment(failing.clone(), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        guest_operations += 1;
        assert!(matches!(failure, RunOutcome::LuaError(_)));
        assert_eq!(vm.roots().total_count(), before_error + 1);
        drop(failure);
        assert_eq!(vm.roots().total_count(), before_error);
        assert_eq!(
            vm.load_with_environment(reusable.clone(), Value::Object(environment))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(99)])
        );
        guest_operations += 1;
        assert_eq!(vm.roots().total_count(), baseline_roots);
        let ledger = vm.ledger_snapshot();
        assert_eq!(ledger.reserved, 0);
        peak_committed = peak_committed.max(ledger.committed);
        completed += 1;
    }

    assert_eq!(completed, ITERATIONS);
    assert_eq!(guest_operations, ITERATIONS * 5);
    assert_eq!(gc_cycles, ITERATIONS * 3);
    drop(environment_root);
    let root_count = vm.roots().total_count();
    assert_eq!(root_count + 1, baseline_roots);
    drop(vm);
    let ledger = probe.snapshot();
    assert_eq!(ledger.committed, 0);
    assert_eq!(ledger.reserved, 0);
    println!(
        "P17_B03_CASE {{\"case_id\":\"p17_stress_coroutine_debug\",\"profile\":\"{}\",\"seed\":{},\"iterations\":{},\"guest_operations\":{},\"gc_cycles\":{},\"outcome\":\"PASS\",\"root_count\":{},\"ledger_committed\":{},\"ledger_reserved\":{},\"peak_committed\":{}}}",
        profile_label(),
        SEED,
        completed,
        guest_operations,
        gc_cycles,
        root_count,
        ledger.committed,
        ledger.reserved,
        peak_committed
    );
}
