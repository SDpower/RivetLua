#![cfg(feature = "aot-builder")]

use rivetlua::{
    AbortReason, AotError, Endian, Engine, ExecMemoryPolicy, JitPolicy, JitStats, LuaProfile,
    Module, NativeError, RVLU_NUMERIC_I64_F64, RunOutcome, SdkError, TargetDescriptor, Value, Vm,
};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn target_descriptor(profile: LuaProfile) -> TargetDescriptor {
    TargetDescriptor {
        target_triple: "aarch64-apple-darwin".into(),
        isa: "aarch64".into(),
        os: "macos".into(),
        abi: "apple-aarch64".into(),
        cpu_features: BTreeSet::new(),
        endian: Endian::Little,
        lua_profile: profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        flash_cap: None,
        ram_cap: 64 * 1024 * 1024,
        code_cap: 16 * 1024 * 1024,
        exec_memory_policy: ExecMemoryPolicy::MapJit,
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        compiler_version: env!("CARGO_PKG_VERSION").into(),
        build_provenance: "synthetic-fixture".into(),
    }
}

fn install_aot_or_fallback(
    vm: &mut Vm,
    module: &Module,
    target: &TargetDescriptor,
    unsupported_build_is_expected: bool,
) -> bool {
    let artifact = match module.build_aot(target, 0, 0) {
        Ok(artifact) => artifact,
        Err(AotError::Unsupported(_)) if unsupported_build_is_expected => return false,
        Err(error) => panic!("AOT 建置失敗：{error:?}"),
    };

    let trust = artifact.trusted_build();
    match vm.install_aot(module, artifact.bytes(), target, &trust) {
        Ok(()) => true,
        Err(AotError::Native(NativeError::Unsupported(_))) => false,
        Err(error) => panic!("AOT 安裝失敗：{error:?}"),
    }
}

fn run(vm: &mut Vm, module: &Module) -> RunOutcome {
    vm.load_module(module).unwrap().run().unwrap()
}

fn run_with_stats(vm: &mut Vm, module: &Module) -> (RunOutcome, JitStats) {
    let mut execution = vm.load_module(module).unwrap();
    let outcome = execution.run().unwrap();
    (outcome, execution.jit_stats())
}

fn assert_numeric_edge_values(outcome: RunOutcome) {
    let RunOutcome::Returned(values) = outcome else {
        panic!("預期數值邊界回傳值，實際為 {outcome:?}")
    };
    assert_eq!(values.len(), 6);
    assert_eq!(values[0], Value::Boolean(false));
    assert_eq!(values[1], Value::Integer(i64::MIN));
    assert!(matches!(
        values[2],
        Value::Float(value) if value.to_bits() == (-0.0_f64).to_bits()
    ));
    assert!(matches!(values[3], Value::Float(value) if value.is_nan()));
    assert!(matches!(
        values[4],
        Value::Float(value) if value == f64::INFINITY
    ));
    assert_eq!(values[5], Value::Integer(6));
}

fn assert_integer_divide_by_zero(outcome: RunOutcome) {
    let RunOutcome::LuaError(error) = outcome else {
        panic!("整數除以零應回傳 LuaError，實際為 {outcome:?}")
    };
    assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
}

fn assert_allocation_rejected(vm: &mut Vm, module: &Module) {
    vm.inject_next_allocation_failure();
    match vm.load_module(module) {
        Err(SdkError::Runtime(error)) => {
            assert_eq!(error.diagnostic_id, "E_ALLOCATION_FAILED")
        }
        Err(SdkError::Lua(error)) => assert_eq!(error.diagnostic_id, "E_ALLOCATION_FAILED"),
        Err(error) => panic!("配置失敗應保留公開配置錯誤碼：{error:?}"),
        Ok(mut execution) => match execution.run() {
            Ok(RunOutcome::LuaError(error)) => {
                assert_eq!(error.diagnostic_id, "E_ALLOCATION_FAILED")
            }
            Err(error) => assert_eq!(error.diagnostic_id, "E_ALLOCATION_FAILED"),
            Ok(outcome) => panic!("注入的配置失敗應拒絕配置，實際為 {outcome:?}"),
        },
    }
}

fn assert_recovery_and_rejections(
    vm: &mut Vm,
    loop_module: &Module,
    recovery_module: &Module,
    allocation_module: &Module,
    wrong_profile_module: &Module,
    profile: LuaProfile,
    other_profile: LuaProfile,
) {
    let mut fuel_execution = vm.load_module(loop_module).unwrap();
    fuel_execution.set_fuel(32).unwrap();
    assert_eq!(
        fuel_execution.run().unwrap(),
        RunOutcome::Aborted(AbortReason::FuelExhausted)
    );
    drop(fuel_execution);
    assert_eq!(
        run(vm, recovery_module),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );

    let interrupt_flag = Arc::new(AtomicBool::new(true));
    let mut interrupted = vm.load_module(loop_module).unwrap();
    interrupted
        .set_interrupt_flag(interrupt_flag.clone())
        .unwrap();
    let RunOutcome::LuaError(error) = interrupted.run().unwrap() else {
        panic!("host interrupt 應交付 LuaError")
    };
    assert_eq!(error.diagnostic_id, "E_VM_INTERRUPTED");
    assert!(!interrupt_flag.load(Ordering::Acquire));
    drop(interrupted);
    assert_eq!(
        run(vm, recovery_module),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );

    assert_allocation_rejected(vm, allocation_module);
    assert_eq!(
        run(vm, recovery_module),
        RunOutcome::Returned(vec![Value::Integer(7)])
    );
    assert!(matches!(
        vm.load_module(wrong_profile_module),
        Err(SdkError::ProfileMismatch { vm, module }) if vm == profile && module == other_profile
    ));
}

#[test]
fn p21_aot_enabled_matches_interpreter_and_preserves_recovery_paths() {
    let numeric_loop = br#"
        local i = 0
        local total = 0
        while i < 20 do
            total = total + i
            i = i + 1
        end
        return total
    "#;
    let numeric_edges = br#"
        return 9007199254740993 == 9007199254740992.0,
               9223372036854775807 + 1,
               -0.0,
               0.0 / 0.0,
               1.0 / 0.0,
               6
    "#;
    let integer_divide_by_zero = b"return 1 // 0";
    let table_side_effect = br#"
        local reads = 0
        local object = setmetatable({}, {
            __index = function()
                reads = reads + 1
                return 7
            end
        })
        local value = object.key
        return value, reads
    "#;
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let mut interpreter_vm = engine.new_vm().unwrap();
        interpreter_vm
            .set_jit_policy(JitPolicy::Disabled)
            .unwrap();
        let mut aot_vm = engine.new_vm().unwrap();
        aot_vm.set_jit_policy(JitPolicy::Enabled).unwrap();
        let target = target_descriptor(profile);

        let loop_module = engine.compile(numeric_loop).unwrap();
        let loop_installed = install_aot_or_fallback(&mut aot_vm, &loop_module, &target, false);
        assert_eq!(
            run(&mut interpreter_vm, &loop_module),
            RunOutcome::Returned(vec![Value::Integer(190)])
        );
        let (aot_loop, loop_stats) = run_with_stats(&mut aot_vm, &loop_module);
        assert_eq!(aot_loop, RunOutcome::Returned(vec![Value::Integer(190)]));
        if loop_installed {
            assert!(loop_stats.native_executed_instructions > 0);
        }

        let edge_module = engine.compile(numeric_edges).unwrap();
        install_aot_or_fallback(&mut aot_vm, &edge_module, &target, true);
        assert_numeric_edge_values(run(&mut interpreter_vm, &edge_module));
        assert_numeric_edge_values(run(&mut aot_vm, &edge_module));

        let division_module = engine.compile(integer_divide_by_zero).unwrap();
        install_aot_or_fallback(&mut aot_vm, &division_module, &target, true);
        assert_integer_divide_by_zero(run(&mut interpreter_vm, &division_module));
        assert_integer_divide_by_zero(run(&mut aot_vm, &division_module));

        let table_module = engine.compile(table_side_effect).unwrap();
        install_aot_or_fallback(&mut aot_vm, &table_module, &target, true);
        assert_eq!(
            run(&mut interpreter_vm, &table_module),
            RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(1)])
        );
        assert_eq!(
            run(&mut aot_vm, &table_module),
            RunOutcome::Returned(vec![Value::Integer(7), Value::Integer(1)])
        );

        let recovery_module = engine.compile(b"return 7").unwrap();
        let allocation_module = engine.compile(b"return {}").unwrap();
        let other_profile = match profile {
            LuaProfile::Lua54 => LuaProfile::Lua55,
            LuaProfile::Lua55 => LuaProfile::Lua54,
        };
        let wrong_profile_module = Engine::new(other_profile).compile(b"return 1").unwrap();
        assert_recovery_and_rejections(
            &mut interpreter_vm,
            &loop_module,
            &recovery_module,
            &allocation_module,
            &wrong_profile_module,
            profile,
            other_profile,
        );
        assert_recovery_and_rejections(
            &mut aot_vm,
            &loop_module,
            &recovery_module,
            &allocation_module,
            &wrong_profile_module,
            profile,
            other_profile,
        );
    }
}
