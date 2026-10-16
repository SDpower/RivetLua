use rivetlua_core::Value;

pub const TAG_NIL: u64 = 0;
pub const TAG_BOOLEAN: u64 = 1;
pub const TAG_INTEGER: u64 = 2;
pub const TAG_FLOAT: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NumericValue {
    tag: u64,
    bits: u64,
}

impl NumericValue {
    pub const fn nil() -> Self { Self { tag: TAG_NIL, bits: 0 } }

    pub fn from_value(value: Value) -> Option<Self> {
        match value {
            Value::Nil => Some(Self { tag: TAG_NIL, bits: 0 }),
            Value::Boolean(value) => Some(Self { tag: TAG_BOOLEAN, bits: u64::from(value) }),
            Value::Integer(value) => Some(Self { tag: TAG_INTEGER, bits: value as u64 }),
            Value::Float(value) => Some(Self { tag: TAG_FLOAT, bits: value.to_bits() }),
            _ => None,
        }
    }

    pub fn to_value(self) -> Option<Value> {
        match (self.tag, self.bits) {
            (TAG_NIL, 0) => Some(Value::Nil),
            (TAG_BOOLEAN, 0) => Some(Value::Boolean(false)),
            (TAG_BOOLEAN, 1) => Some(Value::Boolean(true)),
            (TAG_INTEGER, bits) => Some(Value::Integer(bits as i64)),
            (TAG_FLOAT, bits) => Some(Value::Float(f64::from_bits(bits))),
            _ => None,
        }
    }

    pub const fn tag(self) -> u64 { self.tag }
    pub const fn bits(self) -> u64 { self.bits }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeError {
    InvalidState,
    InvalidCode,
    InvalidExit,
    AllocationFailed,
    ProtectionFailed,
    Unsupported(&'static str),
}

#[repr(u64)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeExit {
    Return = 1,
    Deopt = 2,
    Safepoint = 3,
    FuelExhausted = 4,
    Cancelled = 5,
    Invalidated = 6,
}

pub struct NativeState<'a> {
    pub registers: &'a mut [NumericValue],
    pub pc: u64,
    pub dynamic_top: u64,
    pub fuel_remaining: u64,
    pub step_budget: u64,
    pub cancel_requested: bool,
    pub expected_epoch: u64,
    pub observed_epoch: u64,
    pub executed: u64,
}

#[repr(C)]
pub(crate) struct RawFrame {
    pub registers_ptr: *mut NumericValue,
    pub register_len: u64,
    pub pc: u64,
    pub dynamic_top: u64,
    pub fuel_remaining: u64,
    pub step_budget: u64,
    pub cancel_requested: u64,
    pub expected_epoch: u64,
    pub observed_epoch: u64,
    pub exit: u64,
    pub executed: u64,
}

#[cfg(feature = "compiler")]
pub(crate) const VALUE_TAG_OFFSET: i32 = core::mem::offset_of!(NumericValue, tag) as i32;
#[cfg(feature = "compiler")]
pub(crate) const VALUE_BITS_OFFSET: i32 = core::mem::offset_of!(NumericValue, bits) as i32;
#[cfg(feature = "compiler")]
pub(crate) const VALUE_SIZE: i32 = core::mem::size_of::<NumericValue>() as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_REGISTERS_OFFSET: i32 = core::mem::offset_of!(RawFrame, registers_ptr) as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_PC_OFFSET: i32 = core::mem::offset_of!(RawFrame, pc) as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_FUEL_OFFSET: i32 = core::mem::offset_of!(RawFrame, fuel_remaining) as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_STEP_BUDGET_OFFSET: i32 = core::mem::offset_of!(RawFrame, step_budget) as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_EXIT_OFFSET: i32 = core::mem::offset_of!(RawFrame, exit) as i32;
#[cfg(feature = "compiler")]
pub(crate) const FRAME_EXECUTED_OFFSET: i32 = core::mem::offset_of!(RawFrame, executed) as i32;

pub(crate) fn call_entry(
    entry: *const u8,
    state: &mut NativeState<'_>,
    entry_pc: u64,
    max_pc: u64,
    register_count: usize,
) -> Result<NativeExit, NativeError> {
    state.executed = 0;
    if state.registers.len() > 4096
        || state.registers.len() < register_count
        || state.pc != entry_pc
        || state.pc > max_pc
        || state.dynamic_top > state.registers.len() as u64
        || state.registers.iter().any(|value| value.to_value().is_none())
    {
        return Err(NativeError::InvalidState);
    }
    if state.cancel_requested {
        return Ok(NativeExit::Cancelled);
    }
    if state.expected_epoch != state.observed_epoch {
        return Ok(NativeExit::Invalidated);
    }
    if state.fuel_remaining == 0 {
        return Ok(NativeExit::FuelExhausted);
    }
    if state.step_budget == 0 {
        return Ok(NativeExit::Safepoint);
    }

    let original_ptr = state.registers.as_mut_ptr();
    let original_len = state.registers.len() as u64;
    let original_fuel = state.fuel_remaining;
    let mut frame = RawFrame {
        registers_ptr: original_ptr,
        register_len: original_len,
        pc: state.pc,
        dynamic_top: state.dynamic_top,
        fuel_remaining: original_fuel,
        step_budget: state.step_budget,
        cancel_requested: 0,
        expected_epoch: state.expected_epoch,
        observed_epoch: state.observed_epoch,
        exit: 0,
        executed: 0,
    };

    // SAFETY: entry 只由已驗證的 codegen 輸出經 execmem 發布；其 ABI 固定為此 repr(C) frame。
    // frame 與寄存器切片的唯一可變借用涵蓋整段原生呼叫，指標不會逃逸。
    let native: unsafe extern "C" fn(*mut RawFrame) = unsafe { core::mem::transmute(entry) };
    unsafe { native(&mut frame) };

    let exit = match frame.exit {
        1 => NativeExit::Return,
        2 => NativeExit::Deopt,
        3 => NativeExit::Safepoint,
        4 => NativeExit::FuelExhausted,
        5 => NativeExit::Cancelled,
        6 => NativeExit::Invalidated,
        _ => return Err(NativeError::InvalidExit),
    };
    if frame.registers_ptr != original_ptr
        || frame.register_len != original_len
        || frame.pc > max_pc
        || frame.dynamic_top > original_len
        || frame.fuel_remaining > original_fuel
        || frame.executed > state.step_budget
        || frame.step_budget != state.step_budget - frame.executed
        || frame.cancel_requested != 0
        || frame.expected_epoch != state.expected_epoch
        || frame.observed_epoch != state.observed_epoch
        || frame.executed != original_fuel - frame.fuel_remaining
        || state.registers.iter().any(|value| value.to_value().is_none())
    {
        return Err(NativeError::InvalidExit);
    }
    state.pc = frame.pc;
    state.dynamic_top = frame.dynamic_top;
    state.fuel_remaining = frame.fuel_remaining;
    state.executed = frame.executed;
    Ok(exit)
}
