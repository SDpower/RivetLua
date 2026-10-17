use super::harness::{CaseOutcome, HarnessLimits};
use rivetlua::{
    Engine, FromValue, HostServices, IntoValue, LuaProfile, SdkError, Value, VmError, VmPolicy,
};

const BASE_WORK: u64 = 32;
const WORK_PER_DEPTH: u64 = 4;
const BASE_HEAP_BYTES: usize = 16 * 1024;
const TABLE_HEAP_BYTES: usize = 4096;

pub(super) fn sdk_values(profile: LuaProfile, input: &[u8], limits: &HarnessLimits) -> CaseOutcome {
    if limits.max_input_bytes == 0
        || limits.max_depth == 0
        || limits.fuel < BASE_WORK
        || input.len() > limits.max_input_bytes
    {
        return CaseOutcome::Limit;
    }

    let string_charge = match input.len().checked_mul(2) {
        Some(bytes) => bytes,
        None => return CaseOutcome::Limit,
    };
    let base_charge = match string_charge.checked_add(BASE_HEAP_BYTES) {
        Some(bytes) => bytes,
        None => return CaseOutcome::Limit,
    };
    if base_charge > limits.heap_bytes {
        return CaseOutcome::Limit;
    }

    let fuel_depth =
        usize::try_from((limits.fuel - BASE_WORK) / WORK_PER_DEPTH).unwrap_or(usize::MAX);
    let heap_depth = (limits.heap_bytes - base_charge) / TABLE_HEAP_BYTES;
    let depth = limits.max_depth.min(fuel_depth).min(heap_depth);

    let engine = Engine::new(profile);
    let mut vm =
        match engine.new_vm_with_services(HostServices::deny_all().and_policy(VmPolicy::Sandbox)) {
            Ok(vm) => vm,
            Err(_) => return CaseOutcome::Limit,
        };
    vm.set_allocation_limit(limits.heap_bytes);
    if vm.policy() != VmPolicy::Sandbox {
        return CaseOutcome::Finding("SDK_POLICY_CONFIGURATION");
    }

    let marker = match i64::try_from(input.len()) {
        Ok(marker) => marker,
        Err(_) => return CaseOutcome::Limit,
    };
    if i64::from_value(marker.into_value()) != Some(marker)
        || bool::from_value(true.into_value()) != Some(true)
        || i64::from_value(Value::Nil).is_some()
    {
        return CaseOutcome::Finding("SDK_PRIMITIVE_CONVERSION");
    }

    let string = match vm.new_string(input) {
        Ok(string) => string,
        Err(_) => return CaseOutcome::Limit,
    };
    let string_value = match string.value(&vm) {
        Ok(value) => value,
        Err(_) => return CaseOutcome::Finding("SDK_ROOT_VALUE"),
    };
    if i64::from_value(string_value).is_some() {
        return CaseOutcome::Finding("SDK_OBJECT_CONVERSION");
    }
    let bytes = match vm.read_byte_string(&string) {
        Ok(bytes) => bytes,
        Err(_) => return CaseOutcome::Finding("SDK_STRING_READ"),
    };
    if bytes.as_slice() != input {
        return CaseOutcome::Finding("SDK_STRING_ROUNDTRIP");
    }

    let stale_table = match vm.new_table() {
        Ok(table) => table,
        Err(_) => return CaseOutcome::Limit,
    };
    let stale_value = match stale_table.value(&vm) {
        Ok(value) => value,
        Err(_) => return CaseOutcome::Finding("SDK_ROOT_VALUE"),
    };
    drop(stale_table);
    if vm.collect().is_err() {
        return CaseOutcome::Limit;
    }
    if !matches!(
        vm.root(stale_value),
        Err(SdkError::RuntimeVm(VmError::StaleObject))
    ) {
        return CaseOutcome::Finding("SDK_STALE_GENERATION");
    }

    let mut current = match vm.new_table() {
        Ok(table) => table,
        Err(_) => return CaseOutcome::Limit,
    };
    if vm
        .table_raw_set(&current, 0i64.into_value(), string_value)
        .is_err()
    {
        return CaseOutcome::Finding("SDK_TABLE_WRITE");
    }
    let stored_string = match vm.table_raw_get(&current, 0i64.into_value()) {
        Ok(value) => value,
        Err(_) => return CaseOutcome::Finding("SDK_TABLE_READ"),
    };
    if stored_string != string_value {
        return CaseOutcome::Finding("SDK_TABLE_VALUE");
    }

    let self_value = match current.value(&vm) {
        Ok(value) => value,
        Err(_) => return CaseOutcome::Finding("SDK_ROOT_VALUE"),
    };
    if vm
        .table_raw_set(&current, (-1i64).into_value(), self_value)
        .is_err()
    {
        return CaseOutcome::Finding("SDK_CYCLE_WRITE");
    }
    let cycle_value = match vm.table_raw_get(&current, (-1i64).into_value()) {
        Ok(value) => value,
        Err(_) => return CaseOutcome::Finding("SDK_CYCLE_READ"),
    };
    if cycle_value != self_value {
        return CaseOutcome::Finding("SDK_CYCLE_READ");
    }

    for index in 0..depth {
        let next = match vm.new_table() {
            Ok(table) => table,
            Err(_) => return CaseOutcome::Limit,
        };
        let child = match current.value(&vm) {
            Ok(value) => value,
            Err(_) => return CaseOutcome::Finding("SDK_ROOT_VALUE"),
        };
        let key = match i64::try_from(index)
            .ok()
            .and_then(|index| index.checked_add(1))
        {
            Some(key) => key,
            None => return CaseOutcome::Limit,
        };
        if vm.table_raw_set(&next, key.into_value(), child).is_err() {
            return CaseOutcome::Finding("SDK_NESTED_TABLE_WRITE");
        }
        current = next;
    }

    let mut foreign_vm =
        match engine.new_vm_with_services(HostServices::deny_all().and_policy(VmPolicy::Sandbox)) {
            Ok(vm) => vm,
            Err(_) => return CaseOutcome::Limit,
        };
    foreign_vm.set_allocation_limit(limits.heap_bytes);
    if current.value(&foreign_vm).is_ok() {
        return CaseOutcome::Finding("SDK_CROSS_VM_ROOT");
    }
    if foreign_vm.policy() != VmPolicy::Sandbox {
        return CaseOutcome::Finding("SDK_POLICY_CONFIGURATION");
    }

    CaseOutcome::Accepted
}
