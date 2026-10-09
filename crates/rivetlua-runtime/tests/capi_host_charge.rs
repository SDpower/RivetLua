use rivetlua_runtime::{AllocationFailureKind, Vm, VmError};

#[test]
fn host_allocation_reservation_rolls_back_and_charge_refunds() {
    let mut vm = Vm::new().unwrap();
    let probe = vm.ledger_probe();
    let baseline = vm.ledger_snapshot();

    let pending = vm.reserve_host_allocation(37).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, baseline.reserved + 37);
    drop(pending);
    assert_eq!(vm.ledger_snapshot(), baseline);

    let too_large = vm.reserve_host_allocation(usize::MAX).unwrap();
    let mut values = Vec::<u8>::new();
    assert!(values.try_reserve_exact(usize::MAX).is_err());
    assert_eq!(too_large.rust_reserve_failure(), VmError::AllocationFailed);
    assert_eq!(
        vm.allocation_trace().last_failure.unwrap().kind,
        AllocationFailureKind::RustReserve
    );
    drop(too_large);
    assert_eq!(vm.ledger_snapshot(), baseline);

    let ordinal = vm.allocation_trace().next_ordinal;
    vm.inject_allocation_failure_at(ordinal);
    assert!(matches!(
        vm.reserve_host_allocation(1),
        Err(VmError::InjectedAllocation(_))
    ));
    assert_eq!(vm.ledger_snapshot(), baseline);

    vm.set_allocation_limit(baseline.committed + 36);
    assert!(matches!(
        vm.reserve_host_allocation(37),
        Err(VmError::AllocationFailed)
    ));
    assert_eq!(vm.ledger_snapshot().reserved, baseline.reserved);
    vm.set_allocation_limit(baseline.limit);

    let charge = vm.reserve_host_allocation(37).unwrap().commit().unwrap();
    assert_eq!(charge.bytes(), 37);
    assert_eq!(vm.ledger_snapshot().host_allocation_bytes, 37);
    assert_eq!(vm.ledger_snapshot().reserved, baseline.reserved);
    drop(vm);
    assert_eq!(probe.snapshot().host_allocation_bytes, 37);
    drop(charge);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}
