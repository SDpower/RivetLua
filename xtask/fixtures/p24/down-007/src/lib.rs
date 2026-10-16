#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use rivetlua_core::{LuaProfile, Value, VerifyLimits, decode_module};
use rivetlua_runtime::{AbortReason, RunOutcome, Vm};

pub const CORTEX_M_TRIPLE: &str = "thumbv7em-none-eabi";
pub const MAX_RVLU_BYTES: usize = 1024 * 1024;
const VM_HEAP_LIMIT: usize = 8 * 1024 * 1024;
const FIRST_RUN_FUEL: u64 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContractError {
    InputTooLarge,
    InvalidRvlu,
    WrongProfileAccepted,
    WrongFormatAccepted,
    VmCreation,
    ModuleLoad,
    RuntimeResult,
    FuelConfiguration,
    FuelAbort,
}

fn opposite_profile(profile: LuaProfile) -> LuaProfile {
    match profile {
        LuaProfile::Lua54 => LuaProfile::Lua55,
        LuaProfile::Lua55 => LuaProfile::Lua54,
    }
}

pub fn verify_host_contract(bytes: &[u8], profile: LuaProfile) -> Result<(), ContractError> {
    if bytes.len() > MAX_RVLU_BYTES {
        return Err(ContractError::InputTooLarge);
    }
    let limits = VerifyLimits::default();
    let verified = decode_module(bytes, profile, &limits).map_err(|_| ContractError::InvalidRvlu)?;

    if decode_module(bytes, opposite_profile(profile), &limits).is_ok() {
        return Err(ContractError::WrongProfileAccepted);
    }
    let mut wrong_format = Vec::from(bytes);
    let Some(version) = wrong_format.get_mut(4) else {
        return Err(ContractError::InvalidRvlu);
    };
    *version ^= 0xff;
    if decode_module(&wrong_format, profile, &limits).is_ok() {
        return Err(ContractError::WrongFormatAccepted);
    }

    let mut vm = Vm::new_with_profile(profile).map_err(|_| ContractError::VmCreation)?;
    vm.set_allocation_limit(VM_HEAP_LIMIT);
    let mut execution = vm.load(verified).map_err(|_| ContractError::ModuleLoad)?;
    execution
        .set_fuel(FIRST_RUN_FUEL)
        .map_err(|_| ContractError::FuelConfiguration)?;
    let result = execution.run();
    if !matches!(result, Ok(RunOutcome::Returned(ref values)) if values.len() == 1 && values[0] == Value::Integer(41)) {
        return Err(ContractError::RuntimeResult);
    }
    drop(execution);

    let verified = decode_module(bytes, profile, &limits).map_err(|_| ContractError::InvalidRvlu)?;
    let mut execution = vm.load(verified).map_err(|_| ContractError::ModuleLoad)?;
    execution
        .set_fuel(0)
        .map_err(|_| ContractError::FuelConfiguration)?;
    if !matches!(
        execution.run(),
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
    ) {
        return Err(ContractError::FuelAbort);
    }
    Ok(())
}
