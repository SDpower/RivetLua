//! RivetLua 的值與數值核心。

#![forbid(unsafe_code)]

pub mod bytecode;
pub mod error;
pub mod limits;
pub mod number;
pub mod value;

pub use bytecode::{
    BinaryOperation, BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeError,
    BytecodeErrorCode, BytecodeExitKind, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, BytecodeVersion, ConstId, ControlFlow,
    EncodedModule, EnvironmentSource, FrameLayout, Instruction, InstructionEffects,
    InstructionOffset, IrLimits, LuaProfile, Opcode, ProfileRequirement, ProtoId, RVLU_MAGIC,
    RVLU_NUMERIC_I64_F64, RVLU_V1, RVLU_V2, Register, RegisterEffects, ResultMode, UnaryOperation,
    UpvalueId, VerifiedModule, VerifyLimits, decode_module, encode_module, verify_module,
};
pub use error::{CoreError, CoreErrorKind, Operation};
pub use number::{
    Number, add, bit_and, bit_not, bit_or, bit_xor, compare, divide, equal, floor_divide, modulo,
    multiply, negate, number_from_value, power, shift_left, shift_right, subtract,
};
pub use value::{
    Generation, ObjectId, ObjectRef, SlotId, Value, ValueKind, VmId, select_and, select_or,
};

/// P00 骨架版本，不能當成 bytecode 或語言相容性版本。
pub const P00_SCAFFOLD_VERSION: &str = "0.0.0";
