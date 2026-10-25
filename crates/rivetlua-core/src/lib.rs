//! RivetLua 的值與數值核心。

#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate alloc;

#[cfg(all(not(feature = "std"), panic = "unwind"))]
compile_error!("rivetlua-core 的 no_std 組態需要 panic=abort");
#[cfg(not(target_has_atomic = "ptr"))]
compile_error!("rivetlua-core 需要指標原子操作以支援 Arc");

pub mod bytecode;
mod compatibility;
mod digest;
pub mod error;
pub mod limits;
pub mod number;
pub mod profile;
pub mod target;
pub mod value;

pub use bytecode::input::{
    InputAdmission, InputDecodeRecoveryError, InputError, InputErrorKind, InputFormat,
    InputPreflight, classify_input, decode_input_module, decode_input_module_with_recovery,
    input_scan_admission, preflight_input_module,
};

pub use bytecode::native_debug::{
    NativeDebug, NativeDebugCandidate, NativeLocal, NativePrototypeDebug, NativeTemporary,
    StateNativeDebugCandidate, verify_native_debug, verify_native_debug_with_recovery,
};
pub use bytecode::official::{
    OfficialAbsLine, OfficialChunk, OfficialChunkError, OfficialChunkErrorKind,
    OfficialChunkLimits, OfficialConstant, OfficialDebug, OfficialLocal, OfficialPrototype,
    OfficialUpvalue, OfficialChunkRecoveryError, decode_official_chunk,
    decode_official_chunk_with_recovery, encode_official_chunk,
};
pub use bytecode::official_execution::{
    OfficialExecutionPlan, OfficialPlanBuiltin, OfficialPlanCall, OfficialPlanCandidate,
    OfficialPlanFrameInput, OfficialPlanFrameInputSource, OfficialPlanRootBinding,
    OfficialPlanRootSource, OfficialPlanUpvalueMap, StateOfficialPlanCandidate,
    native_builtin_candidate_from_calls, native_builtin_candidate_from_calls_with_recovery,
    verify_native_builtin_plan, verify_native_builtin_plan_with_recovery,
    verify_official_execution_plan, verify_official_execution_plan_with_recovery,
};
pub use bytecode::official_export::{
    OfficialExportError, OfficialExportErrorKind, OfficialExportRecoveryError,
    emit_official_chunk, emit_official_chunk_with_recovery,
};
#[doc(hidden)]
pub use bytecode::official_export::{
    Dump54Cursor, Dump54Footprint, Dump54Piece, Dump54Plan, Dump54Preflight,
    Dump54PreparePolicy, Dump54Prepared, prepare_dump54_plan_with_recovery,
};
pub use bytecode::official_preflight::{OfficialChunkPreflight, preflight_official_chunk};
#[doc(hidden)]
pub use bytecode::official_preflight::{OfficialChunkCursor, OfficialChunkCursorBudget, OfficialChunkProgress};
pub use bytecode::official_translation::{
    OfficialTranslationError, OfficialTranslationErrorKind, OfficialTranslationRecoveryError,
    OfficialWorkBudget, translate_official_chunk, translate_official_chunk_with_work,
    translate_official_chunk_with_work_and_recovery,
};
pub use bytecode::transport::{
    EncodedTransportModule, TransportAdmission, TransportError, TransportErrorKind,
    TransportLimits, TransportMeasureRecoveryError, TransportScanAdmission,
    bytecode_module_allocation_bytes, bytecode_module_allocation_bytes_with_recovery,
    bytecode_wire_upper_bytes, decode_transport_module, encode_transport_module,
    preflight_transport_decode, preflight_transport_encode, transport_encode_scan_admission,
    transport_scan_admission, verified_module_allocation_bytes,
    verified_module_allocation_bytes_with_recovery, verified_module_measurement_scratch_bytes,
    verified_module_measurement_work,
};
pub use bytecode::{
    BinaryOperation, BytecodeBindingId, BytecodeBytes, BytecodeClosePath,
    BytecodeClosePathData, BytecodeConstant, BytecodeError, BytecodeRecoveryError,
    BytecodeErrorCode, BytecodeExitKind, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, BytecodeVec, BytecodeVersion, ConstId, ControlFlow,
    EncodedModule, EnvironmentSource, FrameLayout, Instruction, InstructionEffects,
    InstructionOffset, IrLimits, LuaProfile, ModuleOrigin, OfficialArtifact, OfficialRvluPc,
    Opcode, ProfileRequirement, ProtoId, RVLU_MAGIC, RVLU_NUMERIC_I64_F64, RVLU_V1, RVLU_V2,
    Register, RegisterEffects, ResultMode, UnaryOperation, UpvalueId, VerifiedModule, VerifyLimits,
    decode_module, decode_module_with_recovery, encode_module,
    encode_module_with_recovery, global_bytecode_bytes, global_bytecode_close_path,
    global_bytecode_function_prototypes,
    global_bytecode_prototypes, global_bytecode_vec, verify_module, verify_module_with_recovery,
};
pub use compatibility::{COMPATIBILITY_VERSION, CompatibilityEntry, compatibility_entries};
pub use digest::sha256_bytes;
pub use error::{CoreError, CoreErrorKind, Operation};
pub use number::{
    Number, add, bit_and, bit_not, bit_or, bit_xor, compare, divide, equal, floor_divide, modulo,
    multiply, negate, number_from_value, power, shift_left, shift_right, subtract,
};
pub use profile::ProfileRules;
pub use target::{
    BoardConfig, DeploymentStatus, Endian, ExecMemoryPolicy, TargetDescriptor, TargetError,
};
pub use value::{
    Generation, HostFunctionId, ObjectId, ObjectRef, SlotId, Value, ValueKind, VmId, select_and,
    select_or,
};

/// P00 骨架版本，不能當成 bytecode 或語言相容性版本。
pub const P00_SCAFFOLD_VERSION: &str = "0.0.0";
