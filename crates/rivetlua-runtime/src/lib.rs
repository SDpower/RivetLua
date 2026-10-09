//! RivetLua 的 VM 與 heap。

#![forbid(unsafe_code)]

mod alloc;
mod call;
mod callback;
mod closure;
mod coroutine;
mod errors;
mod gc;
mod handle;
mod heap;
mod host;
mod metamethod;
mod pending_op;
mod roots;
mod stdlib;
mod string;
mod table;
mod unwind;
mod upvalue;
mod vm;

pub use alloc::{
    AllocationAdmission, AllocationAttempt, AllocationCharge, AllocationCharges, AllocationDomain,
    AllocationFailure, AllocationFailureKind, AllocationLedger, AllocationSite, AllocationTrace,
    FailPoint, LedgerProbe, LedgerSnapshot,
};
pub use call::PendingCloseSnapshot;
pub use callback::{CallbackContext, CallbackContinuation, CallbackFn, CallbackResult};
pub use closure::Closure;
pub use coroutine::CoroutineState;
pub use errors::LuaError;
pub use gc::trace::ActiveRootKind;
pub use gc::{
    FinalizerState, GcAge, GcColor, GcControl, GcControlResult, GcCycleKind, GcMode, GcPhase,
    GcTrace, WeakMode,
};
pub use handle::HostHandle;
pub use heap::{
    HostAllocationCharge, HostAllocationReservation, ObjectKind, SlotState, Vm, VmError,
};
pub use host::{
    DebugCapability, DebugLimits, DebugPermission, DumpCapability, DumpLimits, FileOperation,
    FileReadFormat, FileSeekOrigin, HostCalendar, HostCloseResult, HostDeadline, HostEntropy,
    HostEntropyError, HostExitStatus, HostFileLease, HostIo, HostIoFailure, HostLoadCompiler,
    HostLoadError, HostLoadErrorKind, HostModuleBytes, HostModuleRepository, HostNativeLoader,
    HostNativeModule, HostOs, HostOsOperation, HostOsValue, HostOutput, HostOutputError,
    HostResourceError, HostResourceErrorKind, HostServices, HostSourceReader, LoadBudget,
    LoadCapability, LoadFormat, LoadLimits, PathEncoding, ResourceBudget, ResourceCapability,
    ResourceLimits,
};
pub use metamethod::MetamethodEvent;
pub use rivetlua_core::{Generation, ObjectId, SlotId, VmId};
pub use roots::{RootId, RootKind, RootSet};
pub use stdlib::table::{TableSortStop, TableSortTrace};
pub use string::{ByteString, ExternalStringStorage};
pub use table::{CanonicalKey, CanonicalKeyClass, Table};
pub use upvalue::{Upvalue, UpvalueState};
pub use vm::{
    AbortReason, CapiDumpBytes, DebugFrameHandle, DebugFrameInfo, DebugFrameKind, DebugHookConfig,
    DebugLocal, DebugLocalKind, DebugParameterName, Execution, ExternalCommand, ExternalEventView,
    ExternalResumeA5, ExternalToken, RunOutcome, RuntimeError, RuntimeErrorKind, ValueOperation,
};

#[cfg(test)]
mod tests {
    use super::{Generation, ObjectId, SlotId, SlotState, Vm, VmError};
    use rivetlua_core::{ObjectRef, Value};

    fn p12_4_weak_table(vm: &mut Vm, mode: &[u8]) -> (ObjectRef, ObjectRef) {
        let table = vm.allocate_table().unwrap();
        let metatable = vm.allocate_table().unwrap();
        let name = vm.allocate_byte_string(b"__mode").unwrap();
        let value = vm.allocate_byte_string(mode).unwrap();
        vm.raw_set(metatable, Value::Object(name), Value::Object(value))
            .unwrap();
        vm.set_metatable(table, Some(metatable)).unwrap();
        (table, metatable)
    }

    #[test]
    fn p12_4_weak_key_reverse_reference_cannot_self_preserve() {
        let mut vm = Vm::new().unwrap();
        let (table, _) = p12_4_weak_table(&mut vm, b"k");
        let table_root = vm.add_root(super::RootKind::Host, table).unwrap();
        let key = vm.allocate_table().unwrap();
        let value = vm.allocate_table().unwrap();
        vm.add_child(value, key).unwrap();
        vm.raw_set(table, Value::Object(key), Value::Object(value))
            .unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        assert!(vm.with_table(table, |table| table.is_empty()).unwrap());
        vm.remove_root(table_root).unwrap();
    }

    #[test]
    fn p12_4_weak_key_multihop_ephemeron_reaches_fixed_point() {
        let mut vm = Vm::new().unwrap();
        let (later, _) = p12_4_weak_table(&mut vm, b"k");
        let (first, _) = p12_4_weak_table(&mut vm, b"k");
        let later_root = vm.add_root(super::RootKind::Host, later).unwrap();
        let first_root = vm.add_root(super::RootKind::Host, first).unwrap();
        let key1 = vm.allocate_table().unwrap();
        let key1_root = vm.add_root(super::RootKind::Host, key1).unwrap();
        let key2 = vm.allocate_table().unwrap();
        let value1 = vm.allocate_table().unwrap();
        let value2 = vm.allocate_table().unwrap();
        vm.add_child(value1, key2).unwrap();
        vm.raw_set(later, Value::Object(key2), Value::Object(value2))
            .unwrap();
        vm.raw_set(first, Value::Object(key1), Value::Object(value1))
            .unwrap();
        assert_eq!(vm.collect(), Ok(0));
        assert_eq!(vm.object_kind(value2), Ok(super::ObjectKind::Table));
        assert!(vm.gc_trace().ephemeron_iterations >= 2);
        assert_eq!(vm.gc_trace().ephemeron_last_key, Some(key2));
        assert!(vm.gc_trace().ephemeron_converged);
        vm.remove_root(key1_root).unwrap();
        vm.collect().unwrap();
        assert!(vm.gc_trace().weak_cleared_pairs >= 2);
        for object in [key1, key2, value1, value2] {
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
        }
        vm.remove_root(first_root).unwrap();
        vm.remove_root(later_root).unwrap();
    }

    #[test]
    fn p12_4_weak_values_all_and_string_exceptions() {
        let mut vm = Vm::new().unwrap();
        let (values, _) = p12_4_weak_table(&mut vm, b"v");
        let (all, _) = p12_4_weak_table(&mut vm, b"kv");
        let values_root = vm.add_root(super::RootKind::Host, values).unwrap();
        let all_root = vm.add_root(super::RootKind::Host, all).unwrap();
        let key = vm.allocate_table().unwrap();
        let value = vm.allocate_table().unwrap();
        vm.raw_set(values, Value::Object(key), Value::Object(value))
            .unwrap();
        let all_key = vm.allocate_table().unwrap();
        let all_value = vm.allocate_table().unwrap();
        vm.raw_set(all, Value::Object(all_key), Value::Object(all_value))
            .unwrap();
        vm.raw_set(all, Value::Integer(2), Value::Integer(3))
            .unwrap();
        let string_key = vm.allocate_byte_string(b"key").unwrap();
        let string_value = vm.allocate_byte_string(b"value").unwrap();
        vm.raw_set(all, Value::Object(string_key), Value::Object(string_value))
            .unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(key), Ok(super::ObjectKind::Table));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        assert_eq!(vm.raw_get(values, Value::Object(key)), Ok(Value::Nil));
        assert_eq!(vm.object_kind(all_key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(all_value), Err(VmError::StaleObject));
        assert_eq!(vm.raw_get(all, Value::Integer(2)), Ok(Value::Integer(3)));
        assert_eq!(
            vm.object_kind(string_key),
            Ok(super::ObjectKind::ByteString)
        );
        assert_eq!(
            vm.object_kind(string_value),
            Ok(super::ObjectKind::ByteString)
        );
        vm.remove_root(values_root).unwrap();
        vm.remove_root(all_root).unwrap();
    }

    #[test]
    fn p12_4_weak_mode_changes_only_at_next_cycle_and_minor_clears_young() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let (table, metatable) = p12_4_weak_table(&mut vm, b"strong");
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        vm.collect_minor().unwrap();
        vm.set_gc_promotion_survivals(2).unwrap();
        let child = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(child))
            .unwrap();
        let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
        let mode_value = vm.allocate_byte_string(b"v").unwrap();
        vm.incremental_step(1).unwrap();
        vm.raw_set(
            metatable,
            Value::Object(mode_key),
            Value::Object(mode_value),
        )
        .unwrap();
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.object_kind(child), Ok(super::ObjectKind::Table));
        assert!(vm.collect_minor().unwrap() >= 1);
        assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
    }

    #[test]
    fn p12_4_long_mode_profile_and_nonstring_mode() {
        for (profile, expected_weak) in [
            (rivetlua_core::LuaProfile::Lua54, false),
            (rivetlua_core::LuaProfile::Lua55, true),
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let mut long_mode = vec![b'x'; 40];
            long_mode.push(b'v');
            let (table, mt) = p12_4_weak_table(&mut vm, &long_mode);
            let root = vm.add_root(super::RootKind::Host, table).unwrap();
            let value = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Object(value))
                .unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(value).is_err(), expected_weak);
            let mode_name = vm.allocate_byte_string(b"__mode").unwrap();
            vm.raw_set(mt, Value::Object(mode_name), Value::Integer(7))
                .unwrap();
            let second = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(2), Value::Object(second))
                .unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(second), Ok(super::ObjectKind::Table));
            vm.remove_root(root).unwrap();
        }
    }

    #[test]
    fn p12_4_cycle_reserve_failure_keeps_weak_pair_until_retry() {
        let mut vm = Vm::new().unwrap();
        let (table, _) = p12_4_weak_table(&mut vm, b"v");
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        let value = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(value))
            .unwrap();
        let ledger = vm.ledger_snapshot();
        vm.inject_failure_once(super::FailPoint::WorkReserve);
        assert_eq!(
            vm.collect(),
            Err(VmError::InjectedFailure(super::FailPoint::WorkReserve))
        );
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Pause);
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(value))
        );
        assert_eq!(vm.ledger_snapshot(), ledger);
        vm.collect().unwrap();
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p12_4_atomic_remembered_failure_keeps_live_ephemeron_pair() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(2).unwrap();
        let (table, _) = p12_4_weak_table(&mut vm, b"k");
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        vm.collect_minor().unwrap();
        vm.collect_minor().unwrap();
        assert_eq!(vm.gc_age(table), Ok(super::GcAge::Old));
        let value = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(value))
            .unwrap();
        vm.inject_failure_once(super::FailPoint::RememberedReserve);
        assert_eq!(
            vm.collect_minor(),
            Err(VmError::InjectedFailure(
                super::FailPoint::RememberedReserve
            ))
        );
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Atomic);
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(value))
        );
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.object_kind(value), Ok(super::ObjectKind::Table));
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(value))
        );
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
    }

    #[test]
    fn p12_4_minor_keeps_old_weak_pair_until_major_discovers_dead_key() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let (table, _) = p12_4_weak_table(&mut vm, b"k");
        let table_root = vm.add_root(super::RootKind::Host, table).unwrap();
        let key = vm.allocate_table().unwrap();
        let key_root = vm.add_root(super::RootKind::Host, key).unwrap();
        let value = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Object(key), Value::Object(value))
            .unwrap();
        vm.collect_minor().unwrap();
        for object in [table, key, value] {
            assert_eq!(vm.gc_age(object), Ok(super::GcAge::Old));
        }
        vm.remove_root(key_root).unwrap();
        vm.collect_minor().unwrap();
        assert_eq!(vm.object_kind(value), Ok(super::ObjectKind::Table));
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        assert!(vm.with_table(table, |table| table.is_empty()).unwrap());
        vm.remove_root(table_root).unwrap();
    }

    #[test]
    fn p12_4_dead_weak_key_does_not_keep_string_value() {
        let mut vm = Vm::new().unwrap();
        let (table, _) = p12_4_weak_table(&mut vm, b"k");
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        let key = vm.allocate_table().unwrap();
        let value = vm.allocate_byte_string(b"value").unwrap();
        vm.raw_set(table, Value::Object(key), Value::Object(value))
            .unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p12_3_old_black_table_remembers_young_until_major() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        assert_eq!(vm.collect_minor(), Ok(0));
        assert_eq!(vm.gc_age(table), Ok(super::GcAge::Old));
        vm.incremental_step(1).unwrap();
        assert_eq!(vm.gc_color(table), Ok(super::GcColor::Black));
        let child = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(child))
            .unwrap();
        assert_eq!(vm.gc_trace().remembered_len, 1);
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.collect_minor(), Ok(0));
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(child))
        );
        assert_eq!(vm.gc_age(child), Ok(super::GcAge::Old));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect_major(), Ok(2));
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
    }

    #[test]
    fn p12_3_mode_boundary_promotion_and_major_threshold() {
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.set_gc_promotion_survivals(0),
            Err(VmError::InvalidGcConfig)
        );
        assert_eq!(vm.set_gc_major_threshold(0), Err(VmError::InvalidGcConfig));
        vm.set_gc_promotion_survivals(2).unwrap();
        vm.set_gc_major_threshold(1).unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        let object = vm.allocate(Value::Integer(1)).unwrap();
        let root = vm.add_root(super::RootKind::Host, object).unwrap();
        let trace = vm.incremental_step(1).unwrap();
        assert_eq!(trace.cycle, super::GcCycleKind::Major);
        assert_eq!(trace.major_threshold_bytes, 1);
        assert_eq!(trace.promotion_survivals, 2);
        assert_eq!(
            vm.set_gc_mode(super::GcMode::Incremental),
            Err(VmError::WrongGcPhase)
        );
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.gc_age(object), Ok(super::GcAge::Survivor));
        vm.set_gc_mode(super::GcMode::Incremental).unwrap();
        assert_eq!(vm.gc_age(object), Ok(super::GcAge::Young));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect(), Ok(1));
    }

    #[test]
    fn p12_3_remembered_reserve_failure_does_not_write_edge() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        vm.collect_minor().unwrap();
        let child = vm.allocate_table().unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(super::FailPoint::RememberedReserve);
        assert_eq!(
            vm.raw_set(table, Value::Integer(1), Value::Object(child)),
            Err(VmError::InjectedFailure(
                super::FailPoint::RememberedReserve
            ))
        );
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        assert_eq!(vm.gc_trace().remembered_len, 0);
        assert_eq!(vm.ledger_snapshot(), before);
        vm.raw_set(table, Value::Integer(1), Value::Object(child))
            .unwrap();
        assert_eq!(vm.gc_trace().remembered_len, 1);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect_major(), Ok(2));
    }

    #[test]
    fn p12_3_atomic_remembered_rebuild_failure_retries_without_promotion() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(2).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        vm.collect_minor().unwrap();
        vm.collect_minor().unwrap();
        assert_eq!(vm.gc_age(table), Ok(super::GcAge::Old));
        let child = vm.allocate_table().unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(child))
            .unwrap();
        let before = vm.gc_trace();
        vm.inject_failure_once(super::FailPoint::RememberedReserve);
        assert_eq!(
            vm.collect_minor(),
            Err(VmError::InjectedFailure(
                super::FailPoint::RememberedReserve
            ))
        );
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Atomic);
        assert_eq!(vm.gc_age(child), Ok(super::GcAge::Young));
        assert_eq!(vm.gc_trace().remembered_len, before.remembered_len);
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.gc_age(child), Ok(super::GcAge::Survivor));
        assert_eq!(vm.gc_trace().remembered_len, 1);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect_major(), Ok(2));
        assert_eq!(vm.gc_trace().remembered_len, 0);
    }

    #[test]
    fn p12_3_minor_reclaims_young_but_major_reclaims_unrooted_old() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let old = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, old).unwrap();
        vm.collect_minor().unwrap();
        vm.remove_root(root).unwrap();
        let young = vm.allocate_table().unwrap();
        assert_eq!(vm.collect_minor(), Ok(1));
        assert_eq!(vm.object_kind(young), Err(VmError::StaleObject));
        assert_eq!(vm.gc_age(old), Ok(super::GcAge::Old));
        assert_eq!(vm.collect_major(), Ok(1));
        assert_eq!(vm.object_kind(old), Err(VmError::StaleObject));
    }

    #[test]
    fn p12_3_mode_change_clears_remembered_without_losing_edges() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_mode(super::GcMode::Generational).unwrap();
        vm.set_gc_promotion_survivals(1).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, table).unwrap();
        vm.collect_minor().unwrap();
        let child = vm.allocate_table().unwrap();
        vm.add_child(table, child).unwrap();
        assert_eq!(vm.gc_trace().remembered_len, 1);
        vm.set_gc_mode(super::GcMode::Incremental).unwrap();
        assert_eq!(vm.gc_trace().remembered_len, 0);
        assert_eq!(vm.gc_age(table), Ok(super::GcAge::Young));
        assert_eq!(vm.gc_age(child), Ok(super::GcAge::Young));
        assert_eq!(vm.collect(), Ok(0));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect(), Ok(2));
    }

    #[test]
    fn p12_2_limited_steps_expose_all_phases_and_reclaim() {
        let mut vm = Vm::new().unwrap();
        let live = vm.allocate_table().unwrap();
        let dead = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, live).unwrap();
        let mut phases = Vec::new();
        for _ in 0..32 {
            let trace = vm.incremental_step(1).unwrap();
            phases.push(trace.phase);
            if phases.len() > 1 && trace.phase == super::GcPhase::Pause {
                break;
            }
        }
        for phase in [
            super::GcPhase::RootMark,
            super::GcPhase::Propagate,
            super::GcPhase::Atomic,
            super::GcPhase::Sweep,
            super::GcPhase::Pause,
        ] {
            assert!(phases.contains(&phase), "缺少 {phase:?}: {phases:?}");
        }
        assert_eq!(vm.object_kind(dead), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(live), Ok(super::ObjectKind::Table));
        assert!(vm.gc_trace().reclaimed_bytes > 0);
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn p12_2_worklist_failure_and_invalid_budget_keep_collector_recoverable() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(1)).unwrap();
        let before = vm.ledger_snapshot();
        assert_eq!(vm.incremental_step(0), Err(VmError::InvalidGcStepBudget));
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Pause);
        vm.inject_failure_once(super::FailPoint::WorkReserve);
        assert_eq!(
            vm.incremental_step(1),
            Err(VmError::InjectedFailure(super::FailPoint::WorkReserve))
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Pause);
        assert_eq!(vm.collect(), Ok(1));
        assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
    }

    #[test]
    fn p12_2_cycle_start_rejects_active_phase() {
        let mut vm = Vm::new().unwrap();
        vm.allocate(Value::Integer(1)).unwrap();
        vm.incremental_step(1).unwrap();
        let before = vm.gc_trace();
        let ledger = vm.ledger_snapshot();
        assert_eq!(vm.begin_gc_cycle(), Err(VmError::WrongGcPhase));
        assert_eq!(vm.gc_trace(), before);
        assert_eq!(vm.ledger_snapshot(), ledger);
    }

    #[test]
    fn p12_2_allocation_debt_starts_bounded_work() {
        let mut vm = Vm::new().unwrap();
        vm.set_gc_debt_threshold(1);
        let first = vm.allocate(Value::Integer(1)).unwrap();
        let root = vm.add_root(super::RootKind::Host, first).unwrap();
        assert!(vm.gc_trace().debt_bytes > 0);
        let _second = vm.allocate(Value::Integer(2)).unwrap();
        assert_eq!(vm.gc_trace().phase, super::GcPhase::RootMark);
        vm.remove_root(root).unwrap();

        let mut strings = Vm::new().unwrap();
        strings.allocate_byte_string(&[b'x'; 256]).unwrap();
        assert!(strings.gc_trace().debt_bytes >= 256);
    }

    #[test]
    fn p12_2_sweep_root_barrier_and_coroutine_field_barrier() {
        let mut vm = Vm::new().unwrap();
        let late = vm.allocate(Value::Integer(1)).unwrap();
        for _ in 0..16 {
            if vm.incremental_step(1).unwrap().phase == super::GcPhase::Sweep {
                break;
            }
        }
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Sweep);
        let late_root = vm.add_root(super::RootKind::Host, late).unwrap();
        assert_eq!(vm.gc_color(late), Ok(super::GcColor::Gray));
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Propagate);
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.read(late), Ok(Value::Integer(1)));

        let coroutine = vm.allocate_coroutine(Value::Nil).unwrap();
        let coroutine_root = vm.add_root(super::RootKind::Host, coroutine).unwrap();
        for _ in 0..32 {
            vm.incremental_step(1).unwrap();
            if vm.gc_color(coroutine) == Ok(super::GcColor::Black) {
                break;
            }
        }
        assert_eq!(vm.gc_color(coroutine), Ok(super::GcColor::Black));
        let error = vm.allocate(Value::Integer(9)).unwrap();
        let before = vm.gc_trace().barrier_count;
        vm.with_coroutine_mut(coroutine, &[error], |co| {
            co.error = Some(Value::Object(error));
        })
        .unwrap();
        assert_eq!(vm.gc_color(error), Ok(super::GcColor::Gray));
        assert_eq!(vm.gc_trace().barrier_count, before + 1);
        while vm.gc_trace().phase != super::GcPhase::Pause {
            vm.incremental_step(1).unwrap();
        }
        assert_eq!(vm.read(error), Ok(Value::Integer(9)));
        vm.remove_root(coroutine_root).unwrap();
        vm.remove_root(late_root).unwrap();
        assert_eq!(vm.collect(), Ok(3));
    }

    #[test]
    fn p12_2_active_worklist_growth_failure_keeps_slots_and_ledger() {
        let mut vm = Vm::new().unwrap();
        let owner = vm.allocate_table().unwrap();
        let root = vm.add_root(super::RootKind::Host, owner).unwrap();
        vm.incremental_step(1).unwrap();
        let trace = vm.gc_trace();
        let ledger = vm.ledger_snapshot();
        vm.inject_failure_once(super::FailPoint::WorkReserve);
        assert_eq!(
            vm.allocate_table(),
            Err(VmError::InjectedFailure(super::FailPoint::WorkReserve))
        );
        assert_eq!(vm.gc_trace(), trace);
        assert_eq!(vm.ledger_snapshot(), ledger);
        let child = vm.allocate_table().unwrap();
        vm.add_child(owner, child).unwrap();
        assert_eq!(vm.collect(), Ok(0));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect(), Ok(2));
    }

    #[test]
    fn p12_2_forced_collection_preserves_candidate_edge_during_active_cycle() {
        let mut vm = Vm::new().unwrap();
        let child = vm.allocate(Value::Integer(17)).unwrap();
        vm.incremental_step(1).unwrap();
        vm.set_collect_every_allocation(true);
        let parent = vm.allocate(Value::Object(child)).unwrap();
        assert_eq!(vm.read(parent), Ok(Value::Object(child)));
        assert_eq!(vm.read(child), Ok(Value::Integer(17)));
        assert_eq!(vm.gc_trace().phase, super::GcPhase::Pause);
        assert_eq!(vm.collect(), Ok(2));
    }

    #[test]
    fn p12_1_native_resume_payload_traces_outer_parent_and_handler() {
        let mut vm = Vm::new().unwrap();
        let outer = vm.allocate(Value::Integer(1)).unwrap();
        let parent = vm.allocate(Value::Integer(2)).unwrap();
        let handler = vm.allocate(Value::Integer(3)).unwrap();
        let coroutine = vm.allocate_coroutine(Value::Nil).unwrap();
        vm.with_coroutine_mut(coroutine, &[outer, parent, handler], |co| {
            co.native = Some(super::vm::NativeCompletion::Resume {
                outer,
                parent: Some(parent),
                parent_root: None,
                protected: Some(super::vm::NativeProtected::XPCall {
                    handler: Value::Object(handler),
                }),
            });
        })
        .unwrap();
        let root = vm.add_root(super::RootKind::Host, coroutine).unwrap();
        assert_eq!(vm.collect(), Ok(0));
        for (object, expected) in [(outer, 1), (parent, 2), (handler, 3)] {
            assert_eq!(vm.read(object), Ok(Value::Integer(expected)));
        }
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect(), Ok(4));
    }

    #[test]
    fn p12_1_new_payload_rejects_foreign_and_stale_edges_before_commit() {
        let mut vm = Vm::new().unwrap();
        let mut other = Vm::new().unwrap();
        let foreign = other.allocate(Value::Integer(1)).unwrap();
        let before = vm.ledger_snapshot();
        assert_eq!(
            vm.allocate_upvalue(super::Upvalue::open(vm.id(), Some(foreign), 0)),
            Err(VmError::WrongVm)
        );
        assert_eq!(vm.ledger_snapshot(), before);

        let stale = vm.allocate(Value::Integer(2)).unwrap();
        assert_eq!(vm.collect(), Ok(1));
        let before = vm.ledger_snapshot();
        let mut upvalue = super::Upvalue::open(vm.id(), None, 0);
        upvalue.close(Value::Object(stale));
        assert_eq!(vm.allocate_upvalue(upvalue), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p12_1_coroutine_write_preflight_and_reserve_failure_leave_payload_unchanged() {
        let mut vm = Vm::new().unwrap();
        let coroutine = vm.allocate_coroutine(Value::Nil).unwrap();
        let root = vm.add_root(super::RootKind::Host, coroutine).unwrap();
        let mut other = Vm::new().unwrap();
        let foreign = other.allocate(Value::Integer(1)).unwrap();
        let before = vm.ledger_snapshot();
        assert_eq!(
            vm.with_coroutine_mut(coroutine, &[foreign], |co| {
                co.state = super::CoroutineState::Dead;
                co.error = Some(Value::Object(foreign));
            }),
            Err(VmError::WrongVm)
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(
            vm.with_coroutine(coroutine, |co| (co.state, co.error)),
            Ok((super::CoroutineState::Suspended, None))
        );

        let stale = vm.allocate(Value::Integer(2)).unwrap();
        assert_eq!(vm.collect(), Ok(1));
        let before = vm.ledger_snapshot();
        assert_eq!(
            vm.with_coroutine_mut(coroutine, &[stale], |co| {
                co.error = Some(Value::Object(stale));
            }),
            Err(VmError::StaleObject)
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.with_coroutine(coroutine, |co| co.error), Ok(None));

        let child = vm.allocate(Value::Integer(3)).unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(super::FailPoint::ChildReserve);
        assert_eq!(
            vm.add_child(coroutine, child),
            Err(VmError::InjectedFailure(super::FailPoint::ChildReserve))
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.collect(), Ok(1));
        assert_eq!(vm.read(child), Err(VmError::StaleObject));
        assert_eq!(
            vm.with_coroutine(coroutine, |co| (co.state, co.error)),
            Ok((super::CoroutineState::Suspended, None))
        );
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect(), Ok(1));
    }

    #[test]
    fn p11_2_coroutine_installer_provides_traceable_table() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let key = vm.allocate_byte_string(b"coroutine").unwrap();
        let Value::Object(table) = vm.raw_get(env, Value::Object(key)).unwrap() else {
            panic!("coroutine table 應安裝到環境")
        };
        assert_eq!(vm.object_kind(table), Ok(super::ObjectKind::Table));
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
    }

    #[test]
    fn p11_2_native_builtin_body_executes_without_lua_frame() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local co=coroutine.create(coroutine.status); local ok,s=coroutine.resume(co,co); return ok,s,coroutine.status(co)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let _root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let super::RunOutcome::Returned(values) = outcome else {
            panic!("native builtin 應執行")
        };
        assert_eq!(values[0], Value::Boolean(true));
        for (index, expected) in [(1, b"running".as_slice()), (2, b"dead")] {
            let Value::Object(object) = values[index] else {
                panic!("狀態須是 byte string")
            };
            assert_eq!(
                vm.with_byte_string(object, |s| s.as_bytes().to_vec()),
                Ok(expected.to_vec())
            );
        }
    }

    #[test]
    fn p11_2_native_protected_body_preserves_multiple_results() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local co=coroutine.create(pcall); return coroutine.resume(co,function() return 2,3 end)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let _root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            super::RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Integer(2),
                Value::Integer(3)
            ])
        );
    }

    #[test]
    fn p11_2_native_resume_missing_target_is_lua_failure() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local co=coroutine.create(coroutine.resume); local ok,message=coroutine.resume(co); return ok,coroutine.status(co)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let _root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let super::RunOutcome::Returned(values) = outcome else {
            panic!("invalid native resume 應是 Lua 結果")
        };
        assert_eq!(values[0], Value::Boolean(false));
        let Value::Object(status) = values[1] else {
            panic!("狀態須是字串")
        };
        assert_eq!(
            vm.with_byte_string(status, |s| s.as_bytes().to_vec()),
            Ok(b"dead".to_vec())
        );
    }

    #[test]
    fn p11_2_native_pcall_builtin_error_preserves_original_value() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local co=coroutine.create(pcall); return coroutine.resume(co,error,9)";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let _root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            super::RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(false),
                Value::Integer(9)
            ])
        );
    }

    #[test]
    fn p11_2_native_xpcall_invalid_target_runs_handler() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local t={}; local co=coroutine.create(xpcall); local a,b,c=coroutine.resume(co,nil,function(v) return t end); return a,b,c==t";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let _root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            super::RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(false),
                Value::Boolean(true)
            ])
        );
    }

    #[test]
    fn p11_2_coroutine_installer_failure_keeps_environment_atomic() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        let roots_before = vm.roots().total_count();
        vm.inject_failure_once(super::FailPoint::ObjectInitialize);
        assert_eq!(
            vm.install_coroutine_builtins(env),
            Err(VmError::InjectedFailure(super::FailPoint::ObjectInitialize))
        );
        assert_eq!(vm.roots().total_count(), roots_before);
        let key = vm.allocate_byte_string(b"coroutine").unwrap();
        assert_eq!(vm.raw_get(env, Value::Object(key)), Ok(Value::Nil));
        vm.collect().unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.install_coroutine_builtins(env).unwrap();
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p11_2_coroutine_installer_partial_private_table_is_reclaimed() {
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        let roots_before = vm.roots().total_count();
        vm.inject_failure_once(super::FailPoint::TableInsert);
        assert_eq!(
            vm.install_coroutine_builtins(env),
            Err(VmError::InjectedFailure(super::FailPoint::TableInsert))
        );
        assert_eq!(vm.roots().total_count(), roots_before);
        let key = vm.allocate_byte_string(b"coroutine").unwrap();
        assert_eq!(vm.raw_get(env, Value::Object(key)), Ok(Value::Nil));
        assert!(vm.collect().unwrap() >= 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p11_2_body_error_parks_thread_until_coroutine_reclaimed() {
        use rivetlua_compiler::{
            CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
        };
        use rivetlua_core::VerifyLimits;
        let source = b"local t={}; local co=coroutine.create(function() local x=t; error(t) end); local ok,e=coroutine.resume(co); return co,t,e,ok";
        let limits = CompileLimits::default();
        let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let module = emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        let mut vm = Vm::new().unwrap();
        let env = vm.allocate_table().unwrap();
        let env_root = super::HostHandle::<Value>::new(&mut vm, env).unwrap();
        vm.install_error_builtins(env).unwrap();
        vm.install_coroutine_builtins(env).unwrap();
        let outcome = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap()
            .run()
            .unwrap();
        let super::RunOutcome::Returned(values) = outcome else {
            panic!("body error 應回傳 resume tuple")
        };
        let (Value::Object(co), Value::Object(table)) = (values[0], values[1]) else {
            panic!("須回傳 thread 與原 table")
        };
        assert_eq!(values[2], Value::Object(table));
        assert_eq!(values[3], Value::Boolean(false));
        let co_root = super::HostHandle::<Value>::new(&mut vm, co).unwrap();
        let (state, pending, error) = vm
            .with_coroutine(co, |co| (co.state, co.context.is_some(), co.error))
            .unwrap();
        assert_eq!(state, super::CoroutineState::Dead);
        assert!(pending);
        assert_eq!(error, Some(Value::Object(table)));
        drop(env_root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(table), Ok(super::ObjectKind::Table));
        drop(co_root);
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(co), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    fn record_case(case_id: &str, input: &str, actual: &str) {
        let Ok(profile) = std::env::var("RIVETLUA_P06_PROFILE") else {
            return;
        };
        assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
        println!("P06_CASE\t{case_id}\t{profile}\t{input}\t{actual}");
    }

    #[test]
    fn complete_identity_distinguishes_vm_slot_and_generation() {
        let a = Vm::new().unwrap();
        let b = Vm::new().unwrap();
        let base = ObjectId::new(a.id(), SlotId::new(0), Generation::new(0));
        assert_ne!(
            base,
            ObjectId::new(b.id(), SlotId::new(0), Generation::new(0))
        );
        assert_ne!(
            base,
            ObjectId::new(a.id(), SlotId::new(1), Generation::new(0))
        );
        assert_ne!(
            base,
            ObjectId::new(a.id(), SlotId::new(0), Generation::new(1))
        );
    }

    #[test]
    fn occupied_free_and_retired_slots_never_alias() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(11)).unwrap();
        let first_id = first.identity().unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Occupied));
        vm.reclaim(first).unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Free));
        assert_eq!(vm.read(first), Err(VmError::StaleObject));
        assert_eq!(vm.reclaim(first), Err(VmError::StaleObject));
        let second = vm.allocate(Value::Integer(22)).unwrap();
        assert_eq!(second.identity().unwrap().slot, first_id.slot);
        assert_eq!(second.identity().unwrap().generation, Generation::new(1));
        assert!(vm.read(first).is_err());
        let last = vm.set_generation_for_test(second, Generation::new(u64::MAX));
        assert_eq!(vm.read(second), Err(VmError::StaleObject));
        vm.reclaim(last).unwrap();
        assert_eq!(vm.slot_state(first_id.slot), Some(SlotState::Retired));
        let third = vm.allocate(Value::Integer(33)).unwrap();
        assert_ne!(third.identity().unwrap().slot, first_id.slot);
        assert!(vm.read(last).is_err());
    }

    #[test]
    fn heap_007_retired_slot_never_revives_old_host_handle() {
        let mut vm = Vm::new().unwrap();
        let original = vm.allocate(Value::Integer(10)).unwrap();
        let handle = super::HostHandle::<Value>::new(&mut vm, original).unwrap();
        assert_eq!(vm.remove_root(handle.root_id()), Ok(original));
        let terminal = vm.set_generation_for_test(original, Generation::new(u64::MAX));
        vm.reclaim(terminal).unwrap();
        let replacement = vm.allocate(Value::Integer(20)).unwrap();
        assert_eq!(
            vm.slot_state(original.identity().unwrap().slot),
            Some(SlotState::Retired)
        );
        assert_ne!(
            replacement.identity().unwrap().slot,
            original.identity().unwrap().slot
        );
        assert_eq!(handle.read(&vm), Err(VmError::StaleObject));
        assert_eq!(vm.read(terminal), Err(VmError::StaleObject));
        assert_eq!(vm.read(replacement), Ok(Value::Integer(20)));
        drop(handle);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        record_case(
            "HEAP-007",
            "將 slot generation 設為 u64::MAX 後回收並配置替代物件",
            "原 slot=Retired; 替代物件使用其他 slot; 舊 HostHandle=E_STALE_HANDLE",
        );
    }

    #[test]
    fn slot_growth_keeps_live_object_address() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(7)).unwrap();
        let before = vm
            .with_value(first, |value| value as *const Value as usize)
            .unwrap();
        for n in 0..512 {
            vm.allocate(Value::Integer(n)).unwrap();
        }
        let after = vm
            .with_value(first, |value| value as *const Value as usize)
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn rejected_reclaims_leave_occupied_slot_unchanged() {
        let mut a = Vm::new().unwrap();
        let mut b = Vm::new().unwrap();
        let object = a.allocate(Value::Integer(9)).unwrap();
        let id = object.identity().unwrap();
        assert_eq!(b.reclaim(object), Err(VmError::WrongVm));
        let forged = ObjectRef::from_id(ObjectId::new(a.id(), id.slot, Generation::new(1)));
        assert_eq!(a.reclaim(forged), Err(VmError::StaleObject));
        assert_eq!(a.slot_state(id.slot), Some(SlotState::Occupied));
        assert_eq!(a.read(object), Ok(Value::Integer(9)));
    }

    #[test]
    fn every_root_kind_is_registered_scanned_and_removed() {
        for kind in super::RootKind::ALL {
            let mut vm = Vm::new().unwrap();
            let object = vm.allocate(Value::Integer(7)).unwrap();
            let root = vm.add_root(kind, object).unwrap();
            assert_eq!(vm.roots().count(kind), 1);
            let mut visited = Vec::new();
            vm.roots().visit(kind, |reference| visited.push(reference));
            assert_eq!(visited, vec![object]);
            assert_eq!(vm.collect().unwrap(), 0);
            assert_eq!(vm.remove_root(root), Ok(object));
            assert_eq!(vm.roots().count(kind), 0);
            assert_eq!(vm.collect().unwrap(), 1);
            assert_eq!(vm.read(object), Err(VmError::StaleObject));
        }
    }

    #[test]
    fn tracing_follows_object_fields_and_collects_cycles() {
        let mut vm = Vm::new().unwrap();
        let parent = vm.allocate(Value::Nil).unwrap();
        let child = vm.allocate(Value::Nil).unwrap();
        let leaf = vm.allocate(Value::Integer(3)).unwrap();
        vm.add_child(parent, child).unwrap();
        vm.add_child(child, leaf).unwrap();
        vm.add_child(leaf, parent).unwrap();
        let root = vm.add_root(super::RootKind::Stack, parent).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(leaf), Ok(Value::Integer(3)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 3);
        assert_eq!(vm.read(parent), Err(VmError::StaleObject));
        assert_eq!(vm.read(child), Err(VmError::StaleObject));
        assert_eq!(vm.read(leaf), Err(VmError::StaleObject));
    }

    #[test]
    fn tracing_follows_value_object_field_and_rejects_bad_edges() {
        let mut vm = Vm::new().unwrap();
        let child = vm.allocate(Value::Integer(21)).unwrap();
        let parent = vm.allocate(Value::Object(child)).unwrap();
        let root = vm.add_root(super::RootKind::Registry, parent).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(child), Ok(Value::Integer(21)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(vm.add_child(parent, child), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn removing_one_of_two_roots_does_not_reclaim_object() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        let stack = vm.add_root(super::RootKind::Stack, object).unwrap();
        let host = vm.add_root(super::RootKind::Host, object).unwrap();
        vm.remove_root(stack).unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.read(object), Ok(Value::Integer(8)));
        vm.remove_root(host).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn mark_error_does_not_start_sweep() {
        let mut vm = Vm::new().unwrap();
        let invalid = vm.allocate(Value::Integer(1)).unwrap();
        let unreachable = vm.allocate(Value::Integer(2)).unwrap();
        let root = vm.add_root(super::RootKind::Stack, invalid).unwrap();
        vm.reclaim(invalid).unwrap();
        assert_eq!(vm.collect(), Err(VmError::StaleObject));
        assert_eq!(vm.read(unreachable), Ok(Value::Integer(2)));
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_clone_transfer_and_drop_have_exact_root_counts() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(31)).unwrap();
        let base = vm.ledger_snapshot().committed;
        let first = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        let after_first = vm.ledger_snapshot().committed;
        assert!(after_first > base);
        assert_eq!(vm.roots().count(super::RootKind::Host), 1);
        let cloned = first.try_clone(&mut vm).unwrap();
        assert!(vm.ledger_snapshot().committed > after_first);
        assert_eq!(vm.roots().count(super::RootKind::Host), 2);
        let transferred = first;
        assert_eq!(vm.roots().count(super::RootKind::Host), 2);
        drop(transferred);
        assert_eq!(vm.ledger_snapshot().committed, after_first);
        assert_eq!(vm.roots().count(super::RootKind::Host), 1);
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(cloned.read(&vm), Ok(Value::Integer(31)));
        drop(cloned);
        assert_eq!(vm.ledger_snapshot().committed, base);
        assert_eq!(vm.roots().count(super::RootKind::Host), 0);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_drop_never_borrows_or_collects_vm() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(5)).unwrap();
        let handle = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        let roots = vm.roots();
        drop(handle);
        assert_eq!(roots.count(super::RootKind::Host), 0);
        assert_eq!(vm.read(object), Ok(Value::Integer(5)));
        let second = super::HostHandle::<Value>::new(&mut vm, object).unwrap();
        vm.with_value(object, |_| drop(second)).unwrap();
        assert_eq!(vm.roots().count(super::RootKind::Host), 0);
        assert_eq!(
            vm.slot_state(object.identity().unwrap().slot),
            Some(SlotState::Occupied)
        );
        assert_eq!(vm.read(object), Ok(Value::Integer(5)));
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn host_handle_can_outlive_vm_without_retaining_heap() {
        let handle = {
            let mut vm = Vm::new().unwrap();
            let object = vm.allocate(Value::Integer(1)).unwrap();
            super::HostHandle::<Value>::new(&mut vm, object).unwrap()
        };
        drop(handle);
    }

    #[test]
    fn injected_allocation_failures_preserve_heap_root_and_ledger_state() {
        for point in [
            super::FailPoint::SlotReserve,
            super::FailPoint::ObjectReserve,
            super::FailPoint::ObjectInitialize,
            super::FailPoint::RootReserve,
            super::FailPoint::MarkReserve,
            super::FailPoint::WorkReserve,
        ] {
            let mut vm = Vm::new().unwrap();
            if matches!(
                point,
                super::FailPoint::RootReserve
                    | super::FailPoint::MarkReserve
                    | super::FailPoint::WorkReserve
            ) {
                vm.set_collect_every_allocation(true);
            }
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate(Value::Integer(1)),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.slot_state(SlotId::new(0)), None);
            assert_eq!(vm.roots().total_count(), 0);
        }
    }

    #[test]
    fn sweep_refunds_objects_and_child_edges_but_keeps_reusable_slot_charge() {
        let mut vm = Vm::new().unwrap();
        let first = vm.allocate(Value::Integer(1)).unwrap();
        let second = vm.allocate(Value::Integer(2)).unwrap();
        let after_objects = vm.ledger_snapshot().committed;
        vm.add_child(first, second).unwrap();
        let after_edge = vm.ledger_snapshot().committed;
        assert!(after_edge > after_objects);
        let root = vm.add_root(super::RootKind::Stack, first).unwrap();
        assert!(vm.ledger_snapshot().committed > after_edge);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().committed, after_edge);
        assert_eq!(vm.collect().unwrap(), 2);
        let after_sweep = vm.ledger_snapshot();
        assert!(after_sweep.committed > 0);
        assert!(after_sweep.committed < after_objects);
        assert_eq!(after_sweep.reserved, 0);
        let replacement = vm.allocate(Value::Integer(3)).unwrap();
        assert_eq!(
            replacement.identity().unwrap().slot,
            first.identity().unwrap().slot
        );
        assert!(vm.ledger_snapshot().committed > after_sweep.committed);
    }
}

#[cfg(test)]
mod p13_a_tests {
    use rivetlua_core::{LuaProfile, Value};

    use crate::{ObjectKind, RootKind, Vm};

    #[test]
    fn p13_a_installer_exposes_basic_callables_without_losing_roots() {
        let mut vm = Vm::new().unwrap();
        let environment = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        for name in [
            b"assert".as_slice(),
            b"error",
            b"pcall",
            b"xpcall",
            b"select",
            b"type",
            b"tostring",
            b"tonumber",
            b"next",
            b"pairs",
            b"ipairs",
            b"getmetatable",
            b"setmetatable",
            b"rawget",
            b"rawset",
            b"rawequal",
            b"rawlen",
            b"print",
        ] {
            let key = vm.allocate_byte_string(name).unwrap();
            let value = vm.raw_get(environment, Value::Object(key)).unwrap();
            let Value::Object(function) = value else {
                panic!("缺少 basic function: {name:?}");
            };
            assert_eq!(vm.object_kind(function), Ok(ObjectKind::Builtin));
        }
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(environment), Ok(ObjectKind::Table));
        vm.remove_root(root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn p13_a_default_vm_constructors_deny_output() {
        assert!(!Vm::new().unwrap().host_output_allowed());
        assert!(
            !Vm::new_with_profile(LuaProfile::Lua54)
                .unwrap()
                .host_output_allowed()
        );
        assert!(
            !Vm::new_with_profile(LuaProfile::Lua55)
                .unwrap()
                .host_output_allowed()
        );
    }
}
