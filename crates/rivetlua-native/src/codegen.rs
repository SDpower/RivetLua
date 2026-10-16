//! 僅編譯已驗證、無 heap 效果的 RVLU 數值函式。

use std::time::Instant;

use cranelift_codegen::ir::condcodes::IntCC;
use cranelift_codegen::ir::{self, AbiParam, InstBuilder, MemFlagsData, Value as ClifValue, types};
use cranelift_codegen::isa::{self, TargetIsa};
use cranelift_codegen::settings;
use cranelift_codegen::{Context, control::ControlPlane};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use rivetlua_core::bytecode::{
    BinaryOperation, BytecodeConstant, BytecodePrototype, Instruction, InstructionEffects,
    Register, UnaryOperation,
};
use rivetlua_core::{LuaProfile, ProtoId, RVLU_V2, VerifiedModule, VmId};
use target_lexicon::Triple;

use crate::abi::{
    FRAME_EXECUTED_OFFSET, FRAME_EXIT_OFFSET, FRAME_FUEL_OFFSET, FRAME_PC_OFFSET,
    FRAME_REGISTERS_OFFSET, FRAME_STEP_BUDGET_OFFSET, TAG_BOOLEAN, TAG_FLOAT, TAG_INTEGER,
    TAG_NIL, VALUE_BITS_OFFSET, VALUE_SIZE, VALUE_TAG_OFFSET, NativeError, NativeExit, NativeState,
};
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

/// 只有本模組在完整靜態檢查及 relocation 檢查後才可建立的機器碼權杖。
pub(crate) struct ValidatedCode {
    bytes: Vec<u8>,
    entry_offset: usize,
    entry_pc: u64,
    max_pc: u64,
    register_count: usize,
    target: String,
    required_cpu_features: Vec<&'static str>,
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
    code: ExecutableCode,
    module_digest: [u8; 32],
    vm_id: VmId,
    function_id: ProtoId,
    function: u32,
    format_version: rivetlua_core::BytecodeVersion,
    code_version: u32,
    profile: LuaProfile,
    numeric_config: u8,
    entry_pc: usize,
    register_mask: Vec<bool>,
    code_bytes: usize,
    compile_ns: u64,
    target: String,
    cpu_features: &'static [&'static str],
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

    pub fn compile(input: NativeCompileInput<'_>) -> Result<Self, NativeCompileError> {
        let started = Instant::now();
        if input.module.format_version() != RVLU_V2 {
            return Err(NativeCompileError::Rejected("RVLU version"));
        }
        let module = input.module.module();
        let prototype = module.prototypes.get(input.prototype_index)
            .ok_or(NativeCompileError::Rejected("prototype index"))?;
        if prototype.register_count == 0 || prototype.register_count > 4096
            || prototype.instructions.is_empty() || prototype.instructions.len() > 100_000
            || input.entry_pc >= prototype.instructions.len()
            || !prototype.close_paths.is_empty()
        {
            return Err(NativeCompileError::Rejected("function limits or close path"));
        }
        if !matches!(module.profile, LuaProfile::Lua54 | LuaProfile::Lua55) {
            return Err(NativeCompileError::Rejected("Lua profile"));
        }
        let mask = check_prototype(prototype)?;
        execmem::platform_preflight().map_err(NativeCompileError::Native)?;
        let target = Triple::host().to_string();
        let isa_builder = isa::lookup(Triple::host())
            .map_err(|_| NativeCompileError::Rejected("host ISA"))?;
        let flags = settings::Flags::new(settings::builder());
        let isa = isa_builder.finish(flags)
            .map_err(|error| NativeCompileError::Backend(format!("{error:?}")))?;
        let code = lower(prototype, input.entry_pc, isa.as_ref(), target.clone())?;
        if code.bytes().len() > input.code_limit_bytes || code.bytes().len() > 16 * 1024 * 1024 {
            return Err(NativeCompileError::Rejected("code quota"));
        }
        execmem::preflight(&code, input.code_limit_bytes).map_err(NativeCompileError::Native)?;
        let code_bytes = code.bytes().len();
        let executable = ExecutableCode::publish(&code, input.code_limit_bytes)
            .map_err(NativeCompileError::Native)?;
        Ok(Self {
            code: executable,
            module_digest: input.module_digest,
            vm_id: input.vm_id,
            function_id: prototype.id,
            function: prototype.function,
            format_version: module.format_version,
            code_version: CODE_VERSION,
            profile: module.profile,
            numeric_config: module.numeric_config,
            entry_pc: input.entry_pc,
            register_mask: mask,
            code_bytes,
            compile_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            target,
            cpu_features: &[],
        })
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
            && self.target == Triple::host().to_string()
            && self.cpu_features.is_empty()
            && self.backend_version() == BACKEND_VERSION
    }
}

fn check_prototype(prototype: &BytecodePrototype) -> Result<Vec<bool>, NativeCompileError> {
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

fn field(builder: &mut FunctionBuilder<'_>, frame: ClifValue, offset: i32) -> ClifValue {
    builder.ins().load(types::I64, MemFlagsData::trusted(), frame, offset)
}

fn store_field(builder: &mut FunctionBuilder<'_>, frame: ClifValue, offset: i32, value: ClifValue) {
    builder.ins().store(MemFlagsData::trusted(), value, frame, offset);
}

fn slot(builder: &mut FunctionBuilder<'_>, frame: ClifValue, register: Register) -> ClifValue {
    let ptr = field(builder, frame, FRAME_REGISTERS_OFFSET);
    builder.ins().iadd_imm_s(ptr, i64::from(register.0) * i64::from(VALUE_SIZE))
}

fn exit(builder: &mut FunctionBuilder<'_>, frame: ClifValue, pc: usize, reason: NativeExit) {
    let at = builder.ins().iconst(types::I64, pc as i64);
    let code = builder.ins().iconst(types::I64, reason as i64);
    store_field(builder, frame, FRAME_PC_OFFSET, at);
    store_field(builder, frame, FRAME_EXIT_OFFSET, code);
    builder.ins().return_(&[]);
}

fn commit(builder: &mut FunctionBuilder<'_>, frame: ClifValue, pc: usize, target: ir::Block) {
    let fuel = field(builder, frame, FRAME_FUEL_OFFSET);
    let budget = field(builder, frame, FRAME_STEP_BUDGET_OFFSET);
    let executed = field(builder, frame, FRAME_EXECUTED_OFFSET);
    let fuel = builder.ins().iadd_imm_s(fuel, -1);
    let budget = builder.ins().iadd_imm_s(budget, -1);
    let executed = builder.ins().iadd_imm_s(executed, 1);
    let next = builder.ins().iconst(types::I64, pc as i64);
    store_field(builder, frame, FRAME_FUEL_OFFSET, fuel);
    store_field(builder, frame, FRAME_STEP_BUDGET_OFFSET, budget);
    store_field(builder, frame, FRAME_EXECUTED_OFFSET, executed);
    store_field(builder, frame, FRAME_PC_OFFSET, next);
    builder.ins().jump(target, &[]);
}

fn lower(
    prototype: &BytecodePrototype,
    entry_pc: usize,
    isa: &dyn TargetIsa,
    target: String,
) -> Result<ValidatedCode, NativeCompileError> {
    let mut context = Context::new();
    context.func.signature = ir::Signature::new(isa.default_call_conv());
    context.func.signature.params.push(AbiParam::new(types::I64));
    let mut frontend = FunctionBuilderContext::new();
    {
        let mut builder = FunctionBuilder::new(&mut context.func, &mut frontend);
        let entry = builder.create_block();
        let blocks: Vec<_> = prototype.instructions.iter().map(|_| builder.create_block()).collect();
        let safepoint = builder.create_block();
        let exhausted = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        let frame = builder.block_params(entry)[0];
        builder.ins().jump(blocks[entry_pc], &[]);

        for (pc, instruction) in prototype.instructions.iter().enumerate() {
            builder.switch_to_block(blocks[pc]);
            if matches!(instruction.instruction, Instruction::Return { .. }) {
                exit(&mut builder, frame, pc, NativeExit::Return);
                continue;
            }
            let active = builder.create_block();
            let fuel = field(&mut builder, frame, FRAME_FUEL_OFFSET);
            let no_fuel = builder.ins().icmp_imm_s(IntCC::Equal, fuel, 0);
            builder.ins().brif(no_fuel, exhausted, &[], active, &[]);
            builder.switch_to_block(active);
            let ready = builder.create_block();
            let budget = field(&mut builder, frame, FRAME_STEP_BUDGET_OFFSET);
            let no_budget = builder.ins().icmp_imm_s(IntCC::Equal, budget, 0);
            builder.ins().brif(no_budget, safepoint, &[], ready, &[]);
            builder.switch_to_block(ready);
            let next = (pc + 1).min(blocks.len() - 1);
            match &instruction.instruction {
                Instruction::LoadConst { dest, constant } => {
                    let (tag, bits) = match &prototype.constants[constant.0 as usize] {
                        BytecodeConstant::Integer(number) => (TAG_INTEGER, *number as u64),
                        BytecodeConstant::FloatBits(bits) => (TAG_FLOAT, *bits),
                        BytecodeConstant::Boolean(value) => (TAG_BOOLEAN, u64::from(*value)),
                        _ => return Err(NativeCompileError::Unsupported("constant")),
                    };
                    let ptr = slot(&mut builder, frame, *dest);
                    let tag = builder.ins().iconst(types::I64, tag as i64);
                    let bits = builder.ins().iconst(types::I64, bits as i64);
                    builder.ins().store(MemFlagsData::trusted(), tag, ptr, VALUE_TAG_OFFSET);
                    builder.ins().store(MemFlagsData::trusted(), bits, ptr, VALUE_BITS_OFFSET);
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::LoadNil { start, count } => {
                    for index in 0..*count {
                        let register = Register(start.0.checked_add(index)
                            .ok_or(NativeCompileError::Rejected("nil register range"))?);
                        let ptr = slot(&mut builder, frame, register);
                        let zero = builder.ins().iconst(types::I64, TAG_NIL as i64);
                        builder.ins().store(MemFlagsData::trusted(), zero, ptr, VALUE_TAG_OFFSET);
                        builder.ins().store(MemFlagsData::trusted(), zero, ptr, VALUE_BITS_OFFSET);
                    }
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::Move { dest, src } => {
                    let from = slot(&mut builder, frame, *src);
                    let to = slot(&mut builder, frame, *dest);
                    let tag = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_TAG_OFFSET);
                    let bits = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_BITS_OFFSET);
                    builder.ins().store(MemFlagsData::trusted(), tag, to, VALUE_TAG_OFFSET);
                    builder.ins().store(MemFlagsData::trusted(), bits, to, VALUE_BITS_OFFSET);
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::Jump { target } => {
                    commit(&mut builder, frame, target.0 as usize, blocks[target.0 as usize]);
                }
                Instruction::JumpIfFalse { condition, target } => {
                    let from = slot(&mut builder, frame, *condition);
                    let tag = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_TAG_OFFSET);
                    let bits = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_BITS_OFFSET);
                    let nil = builder.ins().icmp_imm_s(IntCC::Equal, tag, TAG_NIL as i64);
                    let boolean = builder.ins().icmp_imm_s(IntCC::Equal, tag, TAG_BOOLEAN as i64);
                    let zero = builder.ins().icmp_imm_s(IntCC::Equal, bits, 0);
                    let false_bool = builder.ins().band(boolean, zero);
                    let false_value = builder.ins().bor(nil, false_bool);
                    let false_block = builder.create_block();
                    let true_block = builder.create_block();
                    builder.ins().brif(false_value, false_block, &[], true_block, &[]);
                    builder.switch_to_block(false_block);
                    commit(&mut builder, frame, target.0 as usize, blocks[target.0 as usize]);
                    builder.switch_to_block(true_block);
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::UnaryOp { dest, op, src } => {
                    let from = slot(&mut builder, frame, *src);
                    let to = slot(&mut builder, frame, *dest);
                    let tag = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_TAG_OFFSET);
                    let bits = builder.ins().load(types::I64, MemFlagsData::trusted(), from, VALUE_BITS_OFFSET);
                    match op {
                        UnaryOperation::Not => {
                            let nil = builder.ins().icmp_imm_s(IntCC::Equal, tag, TAG_NIL as i64);
                            let boolean = builder.ins().icmp_imm_s(IntCC::Equal, tag, TAG_BOOLEAN as i64);
                            let zero = builder.ins().icmp_imm_s(IntCC::Equal, bits, 0);
                            let false_bool = builder.ins().band(boolean, zero);
                            let result = builder.ins().bor(nil, false_bool);
                            let result = builder.ins().uextend(types::I64, result);
                            let bool_tag = builder.ins().iconst(types::I64, TAG_BOOLEAN as i64);
                            builder.ins().store(MemFlagsData::trusted(), bool_tag, to, VALUE_TAG_OFFSET);
                            builder.ins().store(MemFlagsData::trusted(), result, to, VALUE_BITS_OFFSET);
                        }
                        UnaryOperation::Negate => {
                            let valid = builder.ins().icmp_imm_s(IntCC::Equal, tag, TAG_INTEGER as i64);
                            let work = builder.create_block();
                            let deopt = builder.create_block();
                            builder.ins().brif(valid, work, &[], deopt, &[]);
                            builder.switch_to_block(deopt);
                            exit(&mut builder, frame, pc, NativeExit::Deopt);
                            builder.switch_to_block(work);
                            let result = builder.ins().ineg(bits);
                            let int_tag = builder.ins().iconst(types::I64, TAG_INTEGER as i64);
                            builder.ins().store(MemFlagsData::trusted(), int_tag, to, VALUE_TAG_OFFSET);
                            builder.ins().store(MemFlagsData::trusted(), result, to, VALUE_BITS_OFFSET);
                        }
                        _ => return Err(NativeCompileError::Unsupported("unary")),
                    }
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::BinaryOp { dest, op, left, right } => {
                    let left = slot(&mut builder, frame, *left);
                    let right = slot(&mut builder, frame, *right);
                    let dest = slot(&mut builder, frame, *dest);
                    let left_tag = builder.ins().load(types::I64, MemFlagsData::trusted(), left, VALUE_TAG_OFFSET);
                    let right_tag = builder.ins().load(types::I64, MemFlagsData::trusted(), right, VALUE_TAG_OFFSET);
                    let l_int = builder.ins().icmp_imm_s(IntCC::Equal, left_tag, TAG_INTEGER as i64);
                    let r_int = builder.ins().icmp_imm_s(IntCC::Equal, right_tag, TAG_INTEGER as i64);
                    let both_int = builder.ins().band(l_int, r_int);
                    let work = builder.create_block();
                    let deopt = builder.create_block();
                    builder.ins().brif(both_int, work, &[], deopt, &[]);
                    builder.switch_to_block(deopt);
                    exit(&mut builder, frame, pc, NativeExit::Deopt);
                    builder.switch_to_block(work);
                    let l = builder.ins().load(types::I64, MemFlagsData::trusted(), left, VALUE_BITS_OFFSET);
                    let r = builder.ins().load(types::I64, MemFlagsData::trusted(), right, VALUE_BITS_OFFSET);
                    let (tag, result) = match op {
                        BinaryOperation::Add => (TAG_INTEGER, builder.ins().iadd(l, r)),
                        BinaryOperation::Subtract => (TAG_INTEGER, builder.ins().isub(l, r)),
                        BinaryOperation::Multiply => (TAG_INTEGER, builder.ins().imul(l, r)),
                        BinaryOperation::Equal | BinaryOperation::NotEqual
                        | BinaryOperation::Less | BinaryOperation::LessEqual
                        | BinaryOperation::Greater | BinaryOperation::GreaterEqual => {
                            let condition = match op {
                                BinaryOperation::Equal => IntCC::Equal,
                                BinaryOperation::NotEqual => IntCC::NotEqual,
                                BinaryOperation::Less => IntCC::SignedLessThan,
                                BinaryOperation::LessEqual => IntCC::SignedLessThanOrEqual,
                                BinaryOperation::Greater => IntCC::SignedGreaterThan,
                                BinaryOperation::GreaterEqual => IntCC::SignedGreaterThanOrEqual,
                                _ => return Err(NativeCompileError::Unsupported("compare")),
                            };
                            let value = builder.ins().icmp(condition, l, r);
                            (TAG_BOOLEAN, builder.ins().uextend(types::I64, value))
                        }
                        _ => return Err(NativeCompileError::Unsupported("binary")),
                    };
                    let tag = builder.ins().iconst(types::I64, tag as i64);
                    builder.ins().store(MemFlagsData::trusted(), tag, dest, VALUE_TAG_OFFSET);
                    builder.ins().store(MemFlagsData::trusted(), result, dest, VALUE_BITS_OFFSET);
                    commit(&mut builder, frame, pc + 1, blocks[next]);
                }
                Instruction::Return { .. } => return Err(NativeCompileError::Rejected("return control flow")),
                _ => return Err(NativeCompileError::Unsupported("instruction")),
            }
        }
        builder.switch_to_block(safepoint);
        let pc = field(&mut builder, frame, FRAME_PC_OFFSET);
        let reason = builder.ins().iconst(types::I64, NativeExit::Safepoint as i64);
        store_field(&mut builder, frame, FRAME_PC_OFFSET, pc);
        store_field(&mut builder, frame, FRAME_EXIT_OFFSET, reason);
        builder.ins().return_(&[]);
        builder.switch_to_block(exhausted);
        let reason = builder.ins().iconst(types::I64, NativeExit::FuelExhausted as i64);
        store_field(&mut builder, frame, FRAME_EXIT_OFFSET, reason);
        builder.ins().return_(&[]);
        builder.seal_all_blocks();
        builder.finalize(isa.frontend_config());
    }
    let compiled = context.compile(isa, &mut ControlPlane::default())
        .map_err(|error| NativeCompileError::Backend(format!("{error:?}")))?;
    if !compiled.buffer.relocs().is_empty() || !compiled.buffer.traps().is_empty() {
        return Err(NativeCompileError::Rejected("relocation or trap"));
    }
    let bytes = compiled.code_buffer().to_vec();
    if bytes.is_empty() {
        return Err(NativeCompileError::Rejected("empty code"));
    }
    Ok(ValidatedCode {
        bytes,
        entry_offset: 0,
        entry_pc: entry_pc as u64,
        max_pc: (prototype.instructions.len() - 1) as u64,
        register_count: usize::from(prototype.register_count),
        target,
        required_cpu_features: Vec::new(),
    })
}
