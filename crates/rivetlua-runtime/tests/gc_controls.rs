use rivetlua_core::LuaProfile;
use rivetlua_runtime::{
    FailPoint, GcControl, GcControlResult, GcMode, GcPhase, RootKind, Vm, VmError,
};

#[test]
fn typed_gc_control_defaults_and_running_b8() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        assert_eq!(
            vm.gc_control(GcControl::IsRunning).unwrap(),
            GcControlResult::Integer(1)
        );
        assert_eq!(
            vm.gc_control(GcControl::Stop).unwrap(),
            GcControlResult::Integer(0)
        );
        assert_eq!(
            vm.gc_control(GcControl::IsRunning).unwrap(),
            GcControlResult::Integer(0)
        );
        assert_eq!(
            vm.gc_control(GcControl::Restart).unwrap(),
            GcControlResult::Integer(0)
        );
    }
}

fn answer(vm: &mut Vm, control: GcControl) -> i32 {
    let GcControlResult::Integer(value) = vm.gc_control(control).unwrap();
    value
}

#[test]
fn profile_defaults_and_parameter_roundtrip_b8() {
    let mut lua54 = Vm::new_with_profile(LuaProfile::Lua54).unwrap();
    assert_eq!(answer(&mut lua54, GcControl::SetPause(201)), 200);
    assert_eq!(answer(&mut lua54, GcControl::SetPause(200)), 200);
    assert_eq!(answer(&mut lua54, GcControl::SetStepMultiplier(109)), 100);
    assert_eq!(answer(&mut lua54, GcControl::SetStepMultiplier(100)), 108);
    assert_eq!(
        answer(
            &mut lua54,
            GcControl::Generational {
                minor_mul: 20,
                minor_major: 100,
            },
        ),
        10
    );
    assert_eq!(
        answer(
            &mut lua54,
            GcControl::Incremental {
                pause: 0,
                step_mul: 0,
                step_size: 0,
            },
        ),
        10
    );

    let mut lua55 = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    for (index, expected) in [20, 50, 68, 250, 200, 9600].into_iter().enumerate() {
        assert_eq!(
            answer(
                &mut lua55,
                GcControl::Parameter {
                    index: index as i32,
                    value: -1,
                },
            ),
            expected,
            "parameter {index}"
        );
    }
    assert_eq!(
        answer(
            &mut lua55,
            GcControl::Parameter {
                index: 0,
                value: 32,
            },
        ),
        20
    );
    assert_eq!(
        answer(
            &mut lua55,
            GcControl::Parameter {
                index: 0,
                value: -1,
            },
        ),
        31
    );
}

#[test]
fn stopped_manual_work_and_inflight_mode_switch_b8() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        assert_eq!(answer(&mut vm, GcControl::Stop), 0);
        assert_eq!(answer(&mut vm, GcControl::IsRunning), 0);
        for _ in 0..100 {
            let held = vm.allocate_table().unwrap();
            vm.add_root(RootKind::Host, held).unwrap();
        }
        let old_mode = if profile == LuaProfile::Lua54 { 10 } else { 7 };
        assert_eq!(
            answer(
                &mut vm,
                GcControl::Incremental {
                    pause: 0,
                    step_mul: 0,
                    step_size: 0
                }
            ),
            old_mode
        );
        assert_eq!(vm.gc_trace().mode, GcMode::Incremental);
        assert_eq!(answer(&mut vm, GcControl::Step(1)), 0);
        assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(
            answer(
                &mut vm,
                GcControl::Generational {
                    minor_mul: 0,
                    minor_major: 0
                }
            ),
            if profile == LuaProfile::Lua54 { 11 } else { 8 }
        );
        assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(vm.gc_trace().mode, GcMode::Generational);
        assert_eq!(answer(&mut vm, GcControl::Collect), 0);
        assert_eq!(answer(&mut vm, GcControl::IsRunning), 0);
        assert_eq!(answer(&mut vm, GcControl::Restart), 0);
        assert_eq!(vm.gc_trace().debt_bytes, 0);
        assert_eq!(answer(&mut vm, GcControl::IsRunning), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn gc_control_allocation_failure_rolls_back_and_retries_b8() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let held = vm.allocate_table().unwrap();
        vm.add_root(RootKind::Host, held).unwrap();
        vm.inject_failure_once(FailPoint::MarkReserve);
        assert_eq!(
            vm.gc_control(GcControl::Collect),
            Err(VmError::InjectedFailure(FailPoint::MarkReserve))
        );
        assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(answer(&mut vm, GcControl::Collect), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
