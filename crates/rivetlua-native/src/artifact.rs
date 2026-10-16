//! P20 JIT 與 P21 AOT 共用的密封碼身分與白名單。

use rivetlua_core::bytecode::{BinaryOperation, BytecodeConstant, BytecodePrototype, Instruction, InstructionEffects, UnaryOperation};
use rivetlua_core::{LuaProfile, ProtoId, RVLU_V2, VerifiedModule, VmId};
use crate::abi::{NativeError, NativeExit, NativeState};
use crate::execmem::{self, ExecutableCode};

pub const BACKEND_VERSION: &str = "cranelift-0.134.2-rvlu-v2-1";
pub const CODE_VERSION: u32 = 1;

pub struct NativeCompileInput<'a> {
    pub module: &'a VerifiedModule,
    pub prototype_index: usize,
    pub entry_pc: usize,
    pub module_digest: [u8; 32],
    pub vm_id: VmId,
    pub code_limit_bytes: usize,
}

#[derive(Debug)]
pub enum NativeCompileError {
    Unsupported(&'static str),
    Rejected(&'static str),
    Backend(String),
    Native(NativeError),
}

/// 僅由 crate 內的 codegen 或可信 AOT loader 在驗證後建立。
pub(crate) struct ValidatedCode {
    pub(crate) bytes: Vec<u8>,
    pub(crate) entry_offset: usize,
    pub(crate) entry_pc: u64,
    pub(crate) max_pc: u64,
    pub(crate) register_count: usize,
    pub(crate) target: String,
    pub(crate) required_cpu_features: Vec<&'static str>,
}

impl ValidatedCode {
    pub(crate) fn bytes(&self) -> &[u8] { &self.bytes }
    pub(crate) fn entry_offset(&self) -> usize { self.entry_offset }
    pub(crate) fn entry_pc(&self) -> u64 { self.entry_pc }
    pub(crate) fn max_pc(&self) -> u64 { self.max_pc }
    pub(crate) fn register_count(&self) -> usize { self.register_count }
    pub(crate) fn target(&self) -> &str { &self.target }
    pub(crate) fn required_cpu_features(&self) -> &[&str] { &self.required_cpu_features }
}

pub struct NativeArtifact {
    pub(crate) code: ExecutableCode,
    pub(crate) module_digest: [u8; 32],
    pub(crate) vm_id: VmId,
    pub(crate) function_id: ProtoId,
    pub(crate) function: u32,
    pub(crate) format_version: rivetlua_core::BytecodeVersion,
    pub(crate) code_version: u32,
    pub(crate) profile: LuaProfile,
    pub(crate) numeric_config: u8,
    pub(crate) entry_pc: usize,
    pub(crate) register_mask: Vec<bool>,
    pub(crate) code_bytes: usize,
    pub(crate) compile_ns: u64,
    pub(crate) target: String,
    pub(crate) cpu_features: &'static [&'static str],
}

impl NativeArtifact {
    pub fn validate(module: &VerifiedModule, prototype_index: usize) -> Result<(), NativeCompileError> {
        if module.format_version() != RVLU_V2 {
            return Err(NativeCompileError::Rejected("RVLU version"));
        }
        let prototype = module.module().prototypes.get(prototype_index)
            .ok_or(NativeCompileError::Rejected("prototype index"))?;
        if prototype.register_count == 0 || prototype.register_count > 4096
            || prototype.instructions.is_empty() || prototype.instructions.len() > 100_000
            || !prototype.close_paths.is_empty()
        {
            return Err(NativeCompileError::Rejected("function limits or close path"));
        }
        check_prototype(prototype)?;
        execmem::platform_preflight().map_err(NativeCompileError::Native)
    }

    pub fn execute(&self, state: &mut NativeState<'_>) -> Result<NativeExit, NativeError> {
        self.code.execute(state)
    }
    pub fn module_digest(&self) -> [u8; 32] { self.module_digest }
    pub fn vm_id(&self) -> VmId { self.vm_id }
    pub fn function_id(&self) -> ProtoId { self.function_id }
    pub fn function(&self) -> u32 { self.function }
    pub fn format_version(&self) -> rivetlua_core::BytecodeVersion { self.format_version }
    pub fn code_version(&self) -> u32 { self.code_version }
    pub fn profile(&self) -> LuaProfile { self.profile }
    pub fn numeric_config(&self) -> u8 { self.numeric_config }
    pub fn entry_pc(&self) -> usize { self.entry_pc }
    pub fn register_mask(&self) -> &[bool] { &self.register_mask }
    pub fn code_bytes(&self) -> usize { self.code_bytes }
    pub fn allocated_bytes(&self) -> usize { self.code.allocated_bytes() }
    pub fn metadata_bytes(&self) -> usize {
        self.code.metadata_bytes()
            .saturating_add(self.register_mask.capacity())
            .saturating_add(self.target.capacity())
    }
    pub fn compile_ns(&self) -> u64 { self.compile_ns }
    pub fn target(&self) -> &str { &self.target }
    pub fn cpu_features(&self) -> &'static [&'static str] { self.cpu_features }
    pub fn backend_version(&self) -> &'static str { BACKEND_VERSION }
    pub fn matches_identity(
        &self,
        module: &VerifiedModule,
        module_digest: [u8; 32],
        prototype_index: usize,
        entry_pc: usize,
        vm_id: VmId,
    ) -> bool {
        let Some(prototype) = module.module().prototypes.get(prototype_index) else {
            return false;
        };
        self.module_digest == module_digest
            && self.vm_id == vm_id
            && self.function_id == prototype.id
            && self.function == prototype.function
            && self.format_version == module.format_version()
            && self.format_version == RVLU_V2
            && self.code_version == CODE_VERSION
            && self.profile == module.profile()
            && self.numeric_config == module.module().numeric_config
            && self.entry_pc == entry_pc
            && self.target == execmem::host_target()
            && self.cpu_features.is_empty()
            && self.backend_version() == BACKEND_VERSION
    }
}

pub(crate) fn check_prototype(prototype: &BytecodePrototype) -> Result<Vec<bool>, NativeCompileError> {
    let mut mask = vec![false; usize::from(prototype.register_count)];
    let count = prototype.instructions.len();
    for (pc, entry) in prototype.instructions.iter().enumerate() {
        if entry.close_path.is_some() {
            return Err(NativeCompileError::Unsupported("close path"));
        }
        let instruction = &entry.instruction;
        let flags = instruction.effects().encoded_flags();
        let allowed = match instruction {
            Instruction::LoadConst { constant, .. } => {
                matches!(prototype.constants.get(constant.0 as usize),
                    Some(BytecodeConstant::Integer(_) | BytecodeConstant::FloatBits(_)
                        | BytecodeConstant::Boolean(_))) && flags == 0
            }
            Instruction::LoadNil { .. } | Instruction::Move { .. }
            | Instruction::Jump { .. } | Instruction::JumpIfFalse { .. }
            | Instruction::Return { .. } => flags == 0,
            Instruction::UnaryOp { op: UnaryOperation::Negate | UnaryOperation::Not, .. }
            | Instruction::BinaryOp { op: BinaryOperation::Add | BinaryOperation::Subtract
                | BinaryOperation::Multiply | BinaryOperation::Equal
                | BinaryOperation::NotEqual | BinaryOperation::Less
                | BinaryOperation::LessEqual | BinaryOperation::Greater
                | BinaryOperation::GreaterEqual, .. } => {
                    flags == (InstructionEffects::MAY_CALL | InstructionEffects::MAY_YIELD
                        | InstructionEffects::MAY_ERROR | InstructionEffects::SAFE_POINT)
                }
            _ => false,
        };
        if !allowed {
            return Err(NativeCompileError::Unsupported("instruction or effect"));
        }
        if let Instruction::LoadNil { start, count } = instruction {
            if usize::from(start.0).checked_add(usize::from(*count))
                .is_none_or(|end| end > mask.len())
            {
                return Err(NativeCompileError::Rejected("nil register range"));
            }
        }
        let effects = instruction.effects();
        for register in effects.reads.iter().chain(effects.writes.iter()) {
            let slot = mask.get_mut(usize::from(register.0))
                .ok_or(NativeCompileError::Rejected("register effect"))?;
            *slot = true;
        }
        match instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. }
                if target.0 as usize >= count =>
                    return Err(NativeCompileError::Rejected("jump target")),
            Instruction::Return { .. } => {}
            _ if pc + 1 == count && !matches!(instruction, Instruction::Jump { .. }) =>
                return Err(NativeCompileError::Rejected("fallthrough")),
            _ => {}
        }
    }
    Ok(mask)
}
