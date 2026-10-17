#![cfg(feature = "jit")]

use rivetlua::{
    AbortReason, Engine, JitEligibility, JitFallbackReason, JitPolicy, LuaProfile, RunOutcome,
    Value,
};

#[test]
fn limited_jit_matches_interpreter_and_falls_back_before_table_side_effects() {
    let numeric_loop = br#"
        local i = 0
        local total = 0
        while i < 20 do
            total = total + i
            i = i + 1
        end
        return total
    "#;
    let table_side_effect = br#"
        local reads = 0
        local object = setmetatable({}, {
            __index = function()
                reads = reads + 1
                return 7
            end
        })
        local value = object.key
        return value == 7 and reads == 1
    "#;

    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let numeric_module = engine.compile(numeric_loop).unwrap();

        let mut interpreter_vm = engine.new_vm().unwrap();
        interpreter_vm.set_jit_policy(JitPolicy::Disabled).unwrap();
        let mut interpreter = interpreter_vm.load_module(&numeric_module).unwrap();
        assert!(matches!(
            interpreter.jit_eligibility(),
            JitEligibility::Unsupported {
                reason: JitFallbackReason::Disabled
            }
        ));
        let interpreted = interpreter.run().unwrap();
        assert!(matches!(&interpreted, RunOutcome::Returned(_)));

        let mut enabled_vm = engine.new_vm().unwrap();
        enabled_vm.set_jit_policy(JitPolicy::Enabled).unwrap();
        let mut enabled = enabled_vm.load_module(&numeric_module).unwrap();
        let eligibility = enabled.jit_eligibility();
        let native_result = enabled.run().unwrap();
        assert_eq!(native_result, interpreted);
        let stats = enabled.jit_stats();
        assert!(stats.total_logical_instructions > 0);
        match eligibility {
            JitEligibility::Supported => {
                assert!(stats.native_executed_instructions > 0);
            }
            JitEligibility::Rejected {
                reason: JitFallbackReason::Platform,
            } => {
                assert_eq!(stats.native_executed_instructions, 0);
                assert!(matches!(
                    stats.fallback_reason,
                    Some(JitFallbackReason::Platform)
                ));
            }
            _ => {
                panic!("numeric while loop should be supported or explicitly rejected by platform")
            }
        }

        let table_module = engine.compile(table_side_effect).unwrap();
        let mut table_vm = engine.new_vm().unwrap();
        table_vm.set_jit_policy(JitPolicy::Enabled).unwrap();
        let mut table_execution = table_vm.load_module(&table_module).unwrap();
        let table_eligibility = table_execution.jit_eligibility();
        let RunOutcome::Returned(values) = table_execution.run().unwrap() else {
            panic!("unsupported table operation should fall back and return")
        };
        assert_eq!(values.as_slice(), &[Value::Boolean(true)]);
        let table_stats = table_execution.jit_stats();
        assert_eq!(table_stats.native_executed_instructions, 0);
        match table_eligibility {
            JitEligibility::Unsupported {
                reason: JitFallbackReason::UnsupportedInstruction,
            } => {
                assert!(matches!(
                    table_stats.fallback_reason,
                    Some(JitFallbackReason::UnsupportedInstruction)
                ));
            }
            JitEligibility::Rejected {
                reason: JitFallbackReason::Platform,
            } => {
                assert!(matches!(
                    table_stats.fallback_reason,
                    Some(JitFallbackReason::Platform)
                ));
            }
            _ => panic!("table side effect should use an explicit fallback reason"),
        }

        let mut fuel_vm = engine.new_vm().unwrap();
        fuel_vm.set_jit_policy(JitPolicy::Enabled).unwrap();
        let mut fuel_execution = fuel_vm.load_module(&numeric_module).unwrap();
        fuel_execution.set_fuel(32).unwrap();
        assert_eq!(
            fuel_execution.run().unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted)
        );
        let fuel_stats = fuel_execution.jit_stats();
        assert!(fuel_stats.native_executed_instructions <= fuel_stats.total_logical_instructions);
    }
}
