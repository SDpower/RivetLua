//! P05 對官方 chunk 轉譯所得私有執行描述的驗證；描述不屬於 RVLU_V2 wire。

use super::codec::{BytecodeError, BytecodeErrorCode, VerifiedModule, VerifyLimits};
use super::official_translation::{BoundedVecReserve, ReserveFailure};
use super::{
    BytecodeBindingId, BytecodeUpvalueSource, Instruction, InstructionOffset, ProtoId, Register,
    ResultMode, UpvalueId,
};

#[cfg(test)]
thread_local! {
    static NATIVE_RESERVE_HOOK: std::cell::Cell<(usize, Option<usize>)> = const {
        std::cell::Cell::new((0, None))
    };
}

#[cfg(test)]
pub(crate) fn native_reserve_fail_at(index: Option<usize>) {
    NATIVE_RESERVE_HOOK.with(|hook| hook.set((0, index)));
}

#[cfg(test)]
pub(crate) fn native_reserve_attempts() -> usize {
    NATIVE_RESERVE_HOOK.with(|hook| hook.get().0)
}

pub(super) fn native_reserve_exact<T>(
    vec: &mut Vec<T>,
    additional: usize,
) -> Result<(), ReserveFailure> {
    #[cfg(test)]
    if NATIVE_RESERVE_HOOK.with(|hook| {
        let (attempts, failure) = hook.get();
        hook.set((attempts + 1, failure));
        failure == Some(attempts)
    }) {
        return Err(ReserveFailure::Allocation);
    }
    vec.try_reserve_bounded_exact(additional)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OfficialPlanBuiltin {
    RawListWrite,
    RawVarargGet,
    PackUnpack,
    GlobalNilCheck,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialPlanRootSource {
    ExternalEnvironment,
    InitialNil,
    FixedBuiltin(OfficialPlanBuiltin),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialPlanRootBinding {
    pub upvalue: UpvalueId,
    pub source: OfficialPlanRootSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialPlanUpvalueMap {
    pub prototype: ProtoId,
    pub guest_count: u16,
    pub guest_start: Register,
    pub guest_register_count: u16,
    pub hidden: Vec<(OfficialPlanBuiltin, UpvalueId)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialPlanFrameInputSource {
    OriginalVarargs,
    GuestNamedVarargTable,
    ActiveVarargs,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialPlanFrameInput {
    pub prototype: ProtoId,
    pub register: Register,
    pub source: OfficialPlanFrameInputSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialPlanCall {
    pub prototype: ProtoId,
    pub call_pc: InstructionOffset,
    pub function_register: Register,
    pub source_upvalue: UpvalueId,
    pub inputs: Vec<Register>,
    pub open_tail: Option<Register>,
    pub builtin: OfficialPlanBuiltin,
}

/// 公開候選描述不可信；P05 必須核對其與已驗證 IR 的一致性。
pub struct OfficialPlanCandidate {
    pub root_bindings: Vec<OfficialPlanRootBinding>,
    pub upvalue_maps: Vec<OfficialPlanUpvalueMap>,
    pub frame_inputs: Vec<OfficialPlanFrameInput>,
    pub calls: Vec<OfficialPlanCall>,
}

impl OfficialPlanCandidate {
    fn allocated_bytes(&self) -> Option<usize> {
        let mut bytes = self
            .root_bindings
            .capacity()
            .checked_mul(core::mem::size_of::<OfficialPlanRootBinding>())?
            .checked_add(
                self.upvalue_maps
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanUpvalueMap>())?,
            )?
            .checked_add(
                self.frame_inputs
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanFrameInput>())?,
            )?
            .checked_add(
                self.calls
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanCall>())?,
            )?;
        for mapping in &self.upvalue_maps {
            bytes = bytes.checked_add(
                mapping
                    .hidden
                    .capacity()
                    .checked_mul(core::mem::size_of::<(OfficialPlanBuiltin, UpvalueId)>())?,
            )?;
        }
        for call in &self.calls {
            bytes = bytes.checked_add(
                call.inputs
                    .capacity()
                    .checked_mul(core::mem::size_of::<Register>())?,
            )?;
        }
        Some(bytes)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialExecutionPlan {
    native_builtin: bool,
    root_bindings: Vec<OfficialPlanRootBinding>,
    upvalue_maps: Vec<OfficialPlanUpvalueMap>,
    frame_inputs: Vec<OfficialPlanFrameInput>,
    calls: Vec<OfficialPlanCall>,
}

impl OfficialExecutionPlan {
    pub fn is_native_builtin(&self) -> bool {
        self.native_builtin
    }
    pub fn root_bindings(&self) -> &[OfficialPlanRootBinding] {
        &self.root_bindings
    }

    pub fn upvalue_map(&self, prototype: ProtoId) -> Option<&OfficialPlanUpvalueMap> {
        self.upvalue_maps
            .iter()
            .find(|mapping| mapping.prototype == prototype)
    }

    pub fn frame_inputs(
        &self,
        prototype: ProtoId,
    ) -> impl Iterator<Item = &OfficialPlanFrameInput> {
        self.frame_inputs
            .iter()
            .filter(move |input| input.prototype == prototype)
    }

    pub fn call(
        &self,
        prototype: ProtoId,
        call_pc: InstructionOffset,
    ) -> Option<&OfficialPlanCall> {
        self.calls
            .iter()
            .find(|call| call.prototype == prototype && call.call_pc == call_pc)
    }

    pub fn calls(&self) -> &[OfficialPlanCall] {
        &self.calls
    }

    /// `allocated_bytes` 逐項檢查的容器數，供呼叫者先支付量測工作。
    pub(crate) fn allocation_measurement_items(&self) -> Option<usize> {
        self.upvalue_maps
            .len()
            .checked_add(self.calls.len())?
            .checked_add(1)
    }

    pub fn allocated_bytes(&self) -> Option<usize> {
        let mut bytes = self
            .root_bindings
            .capacity()
            .checked_mul(core::mem::size_of::<OfficialPlanRootBinding>())?
            .checked_add(
                self.upvalue_maps
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanUpvalueMap>())?,
            )?
            .checked_add(
                self.frame_inputs
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanFrameInput>())?,
            )?;
        for mapping in &self.upvalue_maps {
            bytes = bytes.checked_add(
                mapping
                    .hidden
                    .capacity()
                    .checked_mul(core::mem::size_of::<(OfficialPlanBuiltin, UpvalueId)>())?,
            )?;
        }
        bytes = bytes.checked_add(
            self.calls
                .capacity()
                .checked_mul(core::mem::size_of::<OfficialPlanCall>())?,
        )?;
        for call in &self.calls {
            bytes = bytes.checked_add(
                call.inputs
                    .capacity()
                    .checked_mul(core::mem::size_of::<Register>())?,
            )?;
        }
        Some(bytes)
    }
}

fn invalid(message: &'static str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::Verify,
        offset: 0,
        message: message.into(),
    }
}

fn limited(message: &'static str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::CompileLimit,
        offset: 0,
        message: message.into(),
    }
}

fn reserve_error(error: ReserveFailure, message: &'static str) -> BytecodeError {
    BytecodeError {
        code: match error {
            ReserveFailure::Allocation => BytecodeErrorCode::AllocationFailed,
            ReserveFailure::ExcessCapacity => BytecodeErrorCode::CompileLimit,
        },
        offset: 0,
        message: message.into(),
    }
}

fn push_allowed_read(
    reads: &mut Vec<(usize, usize, u16)>,
    bound: usize,
    item: (usize, usize, u16),
) -> Result<(), BytecodeError> {
    if reads.len() >= bound {
        return Err(limited("官方讀取索引超過預留容量"));
    }
    reads.push(item);
    Ok(())
}

fn in_range(register: Register, start: Register, count: u16) -> bool {
    register.0 >= start.0 && u32::from(register.0) < u32::from(start.0) + u32::from(count)
}

fn reads_register(instruction: &Instruction, register: Register) -> bool {
    match instruction {
        Instruction::Move { src, .. }
        | Instruction::SetUpvalue { src, .. }
        | Instruction::UnaryOp { src, .. } => *src == register,
        Instruction::GetTable { table, key, .. } => *table == register || *key == register,
        Instruction::SetTable { table, key, value } => {
            *table == register || *key == register || *value == register
        }
        Instruction::BinaryOp { left, right, .. } => *left == register || *right == register,
        Instruction::JumpIfFalse { condition, .. } => *condition == register,
        Instruction::Call {
            base, arg_count, ..
        }
        | Instruction::TailCall {
            base, arg_count, ..
        } => {
            if *arg_count == u16::MAX {
                register.0 >= base.0
            } else {
                in_range(register, *base, arg_count.saturating_add(1))
            }
        }
        Instruction::Return { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => in_range(register, *base, *count),
            ResultMode::All => register.0 >= base.0,
        },
        Instruction::Close { base, count } => in_range(register, *base, *count),
        Instruction::NumericForPrepare {
            control,
            limit,
            step,
            ..
        }
        | Instruction::NumericForNext {
            control,
            limit,
            step,
            ..
        } => *control == register || *limit == register || *step == register,
        _ => false,
    }
}

fn writes_register(instruction: &Instruction, register: Register) -> bool {
    match instruction {
        Instruction::LoadConst { dest, .. }
        | Instruction::Move { dest, .. }
        | Instruction::GetUpvalue { dest, .. }
        | Instruction::NewTable { dest }
        | Instruction::GetTable { dest, .. }
        | Instruction::UnaryOp { dest, .. }
        | Instruction::BinaryOp { dest, .. }
        | Instruction::Closure { dest, .. } => *dest == register,
        Instruction::LoadNil { start, count } => in_range(register, *start, *count),
        Instruction::Call {
            base, result_mode, ..
        }
        | Instruction::TailCall {
            base, result_mode, ..
        }
        | Instruction::Vararg { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => in_range(register, *base, *count),
            ResultMode::All => register.0 >= base.0,
        },
        Instruction::NumericForPrepare {
            control, visible, ..
        }
        | Instruction::NumericForNext {
            control, visible, ..
        } => *control == register || *visible == register,
        _ => false,
    }
}

/// 附加的描述不由 RVLU decode 推導；裸 RVLU 永遠不會產生固定 VM binding。
pub fn verify_official_execution_plan(
    mut verified: VerifiedModule,
    candidate: OfficialPlanCandidate,
    limits: &VerifyLimits,
) -> Result<VerifiedModule, BytecodeError> {
    let module = verified.module();
    if verified.official_execution().is_some() {
        return Err(invalid("官方執行描述不可重複附加"));
    }
    if candidate.upvalue_maps.len() != module.prototypes.len()
        || candidate.frame_inputs.len() > module.prototypes.len().saturating_mul(3)
        || candidate.calls.len() > limits.max_instructions
    {
        return Err(invalid("官方執行描述數量無效"));
    }
    let root = module
        .prototypes
        .first()
        .ok_or_else(|| invalid("官方 root prototype 缺失"))?;
    if root.parent.is_some() || candidate.root_bindings.len() != root.upvalues.len() {
        return Err(invalid("官方 root binding 數量無效"));
    }
    for (index, mapping) in candidate.upvalue_maps.iter().enumerate() {
        let proto = &module.prototypes[index];
        if mapping.prototype != proto.id
            || usize::from(mapping.guest_count) + mapping.hidden.len() != proto.upvalues.len()
            || proto.upvalues.len() > limits.max_upvalues_per_prototype
            || mapping.guest_register_count == 0
            || usize::from(mapping.guest_start.0)
                .checked_add(usize::from(mapping.guest_register_count))
                .is_none_or(|end| end != usize::from(proto.register_count))
        {
            return Err(invalid("官方 upvalue mapping 無效"));
        }
        for offset in 0..mapping.guest_register_count {
            let binding = BytecodeBindingId {
                function: proto.function,
                ordinal: u32::from(offset) + 1,
            };
            let register = Register(mapping.guest_start.0 + offset);
            if !proto.binding_registers.contains(&(binding, register)) {
                return Err(invalid("官方 guest register binding 無效"));
            }
        }
        for (offset, &(kind, upvalue)) in mapping.hidden.iter().enumerate() {
            if usize::from(upvalue.0) != usize::from(mapping.guest_count) + offset
                || mapping.hidden[..offset]
                    .iter()
                    .any(|(other, _)| *other == kind)
            {
                return Err(invalid("官方 hidden upvalue 順序無效"));
            }
            if let Some(parent) = proto.parent {
                let parent_map = candidate
                    .upvalue_maps
                    .iter()
                    .find(|entry| entry.prototype == parent)
                    .ok_or_else(|| invalid("官方 parent upvalue mapping 缺失"))?;
                let parent_id = parent_map
                    .hidden
                    .iter()
                    .find_map(|(other, id)| (*other == kind).then_some(*id))
                    .ok_or_else(|| invalid("官方 hidden upvalue 未由 parent 傳遞"))?;
                if proto.upvalues[usize::from(upvalue.0)].source
                    != BytecodeUpvalueSource::ParentUpvalue(parent_id)
                {
                    return Err(invalid("官方 hidden upvalue capture 來源無效"));
                }
            }
        }
        if let Some(parent) = proto.parent {
            let parent_map = candidate
                .upvalue_maps
                .iter()
                .find(|entry| entry.prototype == parent)
                .ok_or_else(|| invalid("官方 parent upvalue mapping 缺失"))?;
            for guest in proto.upvalues.iter().take(usize::from(mapping.guest_count)) {
                match guest.source {
                    BytecodeUpvalueSource::ParentUpvalue(id) if id.0 >= parent_map.guest_count => {
                        return Err(invalid("guest 不可捕獲 hidden upvalue"));
                    }
                    BytecodeUpvalueSource::ParentLocal(binding) => {
                        let parent_proto = module
                            .prototypes
                            .iter()
                            .find(|candidate| candidate.id == parent)
                            .ok_or_else(|| invalid("官方 parent prototype 缺失"))?;
                        let parent_register = parent_proto
                            .binding_registers
                            .iter()
                            .find_map(|(id, register)| (*id == binding).then_some(*register))
                            .ok_or_else(|| invalid("guest ParentLocal binding 缺失"))?;
                        if binding.function != parent_proto.function
                            || parent_register.0 < parent_map.guest_start.0
                            || parent_register.0 >= parent_proto.register_count
                        {
                            return Err(invalid("guest ParentLocal 不可捕獲 private register"));
                        }
                    }
                    _ => {}
                }
            }
        }
        for entry in &proto.instructions {
            if let Instruction::SetUpvalue { upvalue, .. } = entry.instruction {
                if upvalue.0 >= mapping.guest_count {
                    return Err(invalid("guest 不可改寫 hidden upvalue"));
                }
            }
        }
    }
    let root_map = &candidate.upvalue_maps[0];
    for (index, binding) in candidate.root_bindings.iter().enumerate() {
        if usize::from(binding.upvalue.0) != index {
            return Err(invalid("官方 root binding 索引無效"));
        }
        let expected = if index == 0 && root_map.guest_count != 0 {
            OfficialPlanRootSource::ExternalEnvironment
        } else if index < usize::from(root_map.guest_count) {
            OfficialPlanRootSource::InitialNil
        } else {
            OfficialPlanRootSource::FixedBuiltin(
                root_map.hidden[index - usize::from(root_map.guest_count)].0,
            )
        };
        if binding.source != expected {
            return Err(invalid("官方 root binding 來源無效"));
        }
    }
    for (index, input) in candidate.frame_inputs.iter().enumerate() {
        let proto = module
            .prototypes
            .iter()
            .find(|proto| proto.id == input.prototype)
            .ok_or_else(|| invalid("官方 frame input prototype 無效"))?;
        if input.register.0 >= proto.register_count
            || candidate.frame_inputs[..index].iter().any(|earlier| {
                earlier.prototype == input.prototype
                    && (earlier.source == input.source || earlier.register == input.register)
            })
        {
            return Err(invalid("官方 frame input 重複或 register 無效"));
        }
        let mapping = candidate
            .upvalue_maps
            .iter()
            .find(|entry| entry.prototype == input.prototype)
            .ok_or_else(|| invalid("官方 frame input mapping 缺失"))?;
        match input.source {
            OfficialPlanFrameInputSource::OriginalVarargs
            | OfficialPlanFrameInputSource::ActiveVarargs => {
                if input.register.0 >= mapping.guest_start.0
                    || proto.binding_registers.iter().any(|(binding, register)| {
                        *register == input.register
                            && (input.source != OfficialPlanFrameInputSource::ActiveVarargs
                                || proto.named_vararg.map(|(id, _)| id) != Some(*binding))
                    })
                {
                    return Err(invalid("官方 private frame input 與 guest binding 重疊"));
                }
            }
            OfficialPlanFrameInputSource::GuestNamedVarargTable => {
                if input.register.0
                    != mapping
                        .guest_start
                        .0
                        .checked_add(proto.parameter_count)
                        .ok_or_else(|| invalid("官方 named vararg register 溢位"))?
                    || !proto
                        .binding_registers
                        .iter()
                        .any(|(_, register)| *register == input.register)
                {
                    return Err(invalid("官方 named vararg guest input 無效"));
                }
            }
        }
        if input.source == OfficialPlanFrameInputSource::ActiveVarargs
            && proto.named_vararg.map(|(_, register)| register) != Some(input.register)
        {
            return Err(invalid("官方 active vararg binding 無效"));
        }
    }
    for proto in &module.prototypes {
        let active = candidate.frame_inputs.iter().any(|input| {
            input.prototype == proto.id
                && input.source == OfficialPlanFrameInputSource::ActiveVarargs
        });
        if active != proto.named_vararg.is_some() {
            return Err(invalid("官方 named vararg frame input 不符"));
        }
    }
    let persistent_bytes = candidate
        .root_bindings
        .capacity()
        .checked_mul(core::mem::size_of::<OfficialPlanRootBinding>())
        .and_then(|bytes| {
            bytes.checked_add(
                candidate
                    .upvalue_maps
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanUpvalueMap>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(
                candidate
                    .frame_inputs
                    .capacity()
                    .checked_mul(core::mem::size_of::<OfficialPlanFrameInput>())?,
            )
        })
        .and_then(|bytes| {
            candidate.upvalue_maps.iter().try_fold(bytes, |sum, map| {
                sum.checked_add(
                    map.hidden
                        .capacity()
                        .checked_mul(core::mem::size_of::<(OfficialPlanBuiltin, UpvalueId)>())?,
                )
            })
        })
        .ok_or_else(|| limited("官方描述 bytes 溢位"))?;
    let calls_bytes = candidate
        .calls
        .capacity()
        .checked_mul(core::mem::size_of::<OfficialPlanCall>())
        .and_then(|bytes| {
            candidate.calls.iter().try_fold(bytes, |sum, call| {
                sum.checked_add(
                    call.inputs
                        .capacity()
                        .checked_mul(core::mem::size_of::<Register>())?,
                )
            })
        })
        .ok_or_else(|| limited("官方 Call 描述 bytes 溢位"))?;
    let instruction_count = module
        .prototypes
        .iter()
        .try_fold(0usize, |sum, proto| {
            sum.checked_add(proto.instructions.len())
        })
        .ok_or_else(|| limited("官方工作索引 bytes 溢位"))?;
    let call_inputs = candidate
        .calls
        .iter()
        .try_fold(0usize, |sum, call| sum.checked_add(call.inputs.len()))
        .ok_or_else(|| limited("官方輸入索引 bytes 溢位"))?;
    let access_capacity = instruction_count
        .checked_add(call_inputs)
        .and_then(|count| count.checked_add(candidate.calls.len().checked_mul(4)?))
        .ok_or_else(|| limited("官方讀取索引數溢位"))?;
    let register_slots = module
        .prototypes
        .iter()
        .try_fold(0usize, |sum, proto| {
            sum.checked_add(usize::from(proto.register_count))
        })
        .ok_or_else(|| limited("官方 register 索引數溢位"))?;
    let work_bytes = instruction_count
        .checked_mul(core::mem::size_of::<bool>() + core::mem::size_of::<i32>())
        .and_then(|bytes| {
            bytes.checked_add(access_capacity.checked_mul(core::mem::size_of::<(
                usize,
                usize,
                u16,
            )>())?)
        })
        .and_then(|bytes| {
            bytes.checked_add(register_slots.checked_mul(core::mem::size_of::<Register>())?)
        })
        .and_then(|bytes| {
            bytes.checked_add(
                module
                    .prototypes
                    .len()
                    .checked_mul(core::mem::size_of::<i32>())?,
            )
        })
        .and_then(|bytes| {
            bytes.checked_add(module.prototypes.len().checked_mul(
                core::mem::size_of::<Vec<bool>>()
                    + core::mem::size_of::<Vec<i32>>()
                    + core::mem::size_of::<Vec<Register>>(),
            )?)
        })
        .ok_or_else(|| limited("官方工作索引 bytes 溢位"))?;
    if persistent_bytes
        .checked_add(calls_bytes)
        .and_then(|bytes| bytes.checked_add(work_bytes))
        .is_none_or(|bytes| bytes > limits.max_module_bytes)
    {
        return Err(limited("官方描述與工作索引 bytes 超過限制"));
    }
    let mut covered = Vec::new();
    covered
        .try_reserve_bounded_exact(module.prototypes.len())
        .map_err(|error| reserve_error(error, "官方 Call 覆蓋索引配置失敗"))?;
    for proto in &module.prototypes {
        let mut flags = Vec::new();
        flags
            .try_reserve_bounded_exact(proto.instructions.len())
            .map_err(|error| reserve_error(error, "官方 Call 覆蓋索引配置失敗"))?;
        flags.resize(proto.instructions.len(), false);
        covered.push(flags);
    }
    let mut protected = Vec::new();
    protected
        .try_reserve_bounded_exact(module.prototypes.len())
        .map_err(|error| reserve_error(error, "官方 CFG 索引配置失敗"))?;
    let mut sensitive = Vec::new();
    sensitive
        .try_reserve_bounded_exact(module.prototypes.len())
        .map_err(|error| reserve_error(error, "官方私有 register 索引配置失敗"))?;
    for proto in &module.prototypes {
        let mut differences = Vec::new();
        differences
            .try_reserve_bounded_exact(proto.instructions.len() + 1)
            .map_err(|error| reserve_error(error, "官方 CFG 索引配置失敗"))?;
        differences.resize(proto.instructions.len() + 1, 0_i32);
        protected.push(differences);
        let mut registers = Vec::new();
        registers
            .try_reserve_bounded_exact(proto.register_count as usize)
            .map_err(|error| reserve_error(error, "官方私有 register 索引配置失敗"))?;
        for input in candidate
            .frame_inputs
            .iter()
            .filter(|input| input.prototype == proto.id)
        {
            if input.source != OfficialPlanFrameInputSource::GuestNamedVarargTable {
                registers.push(input.register);
            }
        }
        sensitive.push(registers);
    }
    let mut allowed_reads = Vec::<(usize, usize, u16)>::new();
    allowed_reads
        .try_reserve_bounded_exact(access_capacity)
        .map_err(|error| reserve_error(error, "官方讀取索引配置失敗"))?;
    for call in &candidate.calls {
        let index = module
            .prototypes
            .iter()
            .position(|proto| proto.id == call.prototype)
            .ok_or_else(|| invalid("官方內部 Call prototype 無效"))?;
        let proto = &module.prototypes[index];
        let mapping = &candidate.upvalue_maps[index];
        let pc = call.call_pc.0 as usize;
        let expected_args = if call.open_tail.is_some() {
            u16::MAX
        } else {
            u16::try_from(call.inputs.len()).map_err(|_| invalid("官方內部 Call 引數過多"))?
        };
        let expected_mode = match call.builtin {
            OfficialPlanBuiltin::RawListWrite | OfficialPlanBuiltin::GlobalNilCheck => {
                ResultMode::Fixed(0)
            }
            OfficialPlanBuiltin::RawVarargGet | OfficialPlanBuiltin::PackUnpack => {
                ResultMode::Fixed(1)
            }
        };
        if !mapping
            .hidden
            .contains(&(call.builtin, call.source_upvalue))
            || !matches!(proto.instructions.get(pc).map(|entry| &entry.instruction), Some(Instruction::Call { base, arg_count, result_mode })
                if *base == call.function_register && *arg_count == expected_args && *result_mode == expected_mode)
            || call.inputs.iter().enumerate().any(|(offset, input)| {
                usize::from(input.0) != usize::from(call.function_register.0) + offset + 1
            })
            || call.open_tail.is_some_and(|tail| {
                usize::from(tail.0) != usize::from(call.function_register.0) + call.inputs.len() + 1
            })
            || covered[index][pc]
        {
            return Err(invalid("官方內部 Call ABI 無效"));
        }
        if call.function_register.0 >= mapping.guest_start.0
            || candidate.frame_inputs.iter().any(|input| {
                input.prototype == call.prototype && input.register == call.function_register
            })
            || proto
                .binding_registers
                .iter()
                .any(|(_, register)| *register == call.function_register)
        {
            return Err(invalid(
                "官方固定 builtin function slot 與 guest/frame input 重疊",
            ));
        }
        let fixed_input_count = match call.builtin {
            OfficialPlanBuiltin::RawListWrite => 3,
            OfficialPlanBuiltin::RawVarargGet
            | OfficialPlanBuiltin::PackUnpack
            | OfficialPlanBuiltin::GlobalNilCheck => 2,
        };
        if call.inputs.len() < fixed_input_count
            || (call.builtin != OfficialPlanBuiltin::RawListWrite
                && (call.inputs.len() != fixed_input_count || call.open_tail.is_some()))
        {
            return Err(invalid("官方固定 builtin ABI 輸入數無效"));
        }
        for (position, input) in call.inputs.iter().enumerate() {
            let private = position < fixed_input_count || call.open_tail.is_none();
            if private {
                if input.0 >= mapping.guest_start.0
                    || candidate.frame_inputs.iter().any(|frame_input| {
                        frame_input.prototype == call.prototype && frame_input.register == *input
                    })
                    || candidate.calls.iter().any(|other| {
                        other.prototype == call.prototype && other.function_register == *input
                    })
                {
                    return Err(invalid(
                        "官方固定 builtin private 輸入與 guest/frame/builtin 重疊",
                    ));
                }
            } else if input.0 < mapping.guest_start.0 {
                return Err(invalid(
                    "官方開放 RawListWrite values 必須來自 guest register",
                ));
            }
        }
        let load_pc = (0..pc)
            .rev()
            .find(|&candidate_pc| {
                writes_register(
                    &proto.instructions[candidate_pc].instruction,
                    call.function_register,
                )
            })
            .ok_or_else(|| invalid("官方內部 Call 缺少私有 binding 載入"))?;
        if !matches!(proto.instructions[load_pc].instruction, Instruction::GetUpvalue { dest, upvalue }
            if dest == call.function_register && upvalue == call.source_upvalue)
            || (load_pc + 1..pc).any(|between| {
                reads_register(
                    &proto.instructions[between].instruction,
                    call.function_register,
                )
            })
        {
            return Err(invalid("官方內部 Call binding 被改寫或外洩"));
        }
        let last_writer = |register: Register| {
            (load_pc + 1..pc).rev().find_map(|writer| {
                writes_register(&proto.instructions[writer].instruction, register)
                    .then_some((writer, &proto.instructions[writer].instruction))
            })
        };
        for input in &call.inputs {
            if input.0 >= proto.register_count {
                return Err(invalid("官方固定 builtin 輸入 register 無效"));
            }
            if input.0 < mapping.guest_start.0 {
                let Some((_, instruction)) = last_writer(*input) else {
                    return Err(invalid("官方固定 builtin private 輸入未初始化"));
                };
                if !matches!(
                    instruction,
                    Instruction::Move { .. }
                        | Instruction::LoadConst { .. }
                        | Instruction::LoadNil { .. }
                ) {
                    return Err(invalid("官方固定 builtin private 輸入來源無效"));
                }
                if !sensitive[index].contains(input) {
                    sensitive[index].push(*input);
                }
                push_allowed_read(&mut allowed_reads, access_capacity, (index, pc, input.0))?;
            }
        }
        let guest_move_source = |register: Register| match last_writer(register) {
            Some((_, Instruction::Move { dest, src }))
                if *dest == register
                    && src.0 >= mapping.guest_start.0
                    && src.0 < proto.register_count =>
            {
                Some(*src)
            }
            _ => None,
        };
        let integer_constant = |register: Register| match last_writer(register) {
            Some((_, Instruction::LoadConst { dest, constant })) if *dest == register => {
                match proto.constants.get(constant.0 as usize) {
                    Some(super::BytecodeConstant::Integer(value)) => Some(*value),
                    _ => None,
                }
            }
            _ => None,
        };
        match call.builtin {
            OfficialPlanBuiltin::RawListWrite => {
                let table = guest_move_source(call.inputs[0])
                    .ok_or_else(|| invalid("RawListWrite table 必須由 guest Move 載入"))?;
                let first = integer_constant(call.inputs[1])
                    .filter(|value| *value >= 1)
                    .ok_or_else(|| invalid("RawListWrite index 常數無效"))?;
                let skip = integer_constant(call.inputs[2])
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| invalid("RawListWrite skip 常數無效"))?;
                let _ = first;
                if let Some(tail) = call.open_tail {
                    if skip == 0
                        || usize::from(table.0) != usize::from(mapping.guest_start.0) + skip - 1
                        || call.inputs.get(3).copied() != Some(mapping.guest_start)
                        || usize::from(tail.0) < usize::from(mapping.guest_start.0) + skip
                        || !matches!(proto.instructions.get(pc.wrapping_sub(1)).map(|entry| &entry.instruction),
                            Some(Instruction::Vararg { base, result_mode: ResultMode::All })
                                | Some(Instruction::Call { base, result_mode: ResultMode::All, .. })
                                    if *base == tail)
                    {
                        return Err(invalid("開放 RawListWrite producer/skip 來源無效"));
                    }
                } else {
                    if skip != 0 {
                        return Err(invalid("固定 RawListWrite skip 必須為零"));
                    }
                    for (offset, &input) in call.inputs[3..].iter().enumerate() {
                        let expected = usize::from(table.0) + offset + 1;
                        if guest_move_source(input)
                            .is_none_or(|source| usize::from(source.0) != expected)
                        {
                            return Err(invalid("固定 RawListWrite value 來源無效"));
                        }
                    }
                }
            }
            OfficialPlanBuiltin::RawVarargGet => {
                let raw = candidate
                    .frame_inputs
                    .iter()
                    .find(|input| {
                        input.prototype == call.prototype
                            && input.source == OfficialPlanFrameInputSource::OriginalVarargs
                    })
                    .ok_or_else(|| invalid("官方 RawVarargGet 缺少原始 pack"))?;
                if !matches!(last_writer(call.inputs[0]),
                    Some((_, Instruction::Move { dest, src }))
                        if *dest == call.inputs[0] && *src == raw.register)
                    || guest_move_source(call.inputs[1]).is_none()
                {
                    return Err(invalid("RawVarargGet pack/key 最後來源無效"));
                }
            }
            OfficialPlanBuiltin::PackUnpack => {
                let wanted = integer_constant(call.inputs[1]);
                if guest_move_source(call.inputs[0]).is_none()
                    || wanted.is_none_or(|value| !(-1..=254).contains(&value))
                    || !matches!(proto.instructions.get(pc + 2).map(|entry| &entry.instruction),
                    Some(Instruction::Vararg { result_mode, .. })
                        if *result_mode == if wanted == Some(-1) {
                            ResultMode::All
                        } else {
                            ResultMode::Fixed(wanted.unwrap_or_default() as u16)
                        })
                {
                    return Err(invalid("PackUnpack table/wanted 來源無效"));
                }
            }
            OfficialPlanBuiltin::GlobalNilCheck => {
                let valid_name = match last_writer(call.inputs[1]) {
                    Some((_, Instruction::LoadNil { start, count: 1 })) => *start == call.inputs[1],
                    Some((_, Instruction::LoadConst { dest, constant }))
                        if *dest == call.inputs[1] =>
                    {
                        matches!(
                            proto.constants.get(constant.0 as usize),
                            Some(
                                super::BytecodeConstant::Name(_)
                                    | super::BytecodeConstant::String(_)
                            )
                        )
                    }
                    _ => false,
                };
                if guest_move_source(call.inputs[0]).is_none() || !valid_name {
                    return Err(invalid("GlobalNilCheck value/name 來源無效"));
                }
            }
        }
        let end_pc = match call.builtin {
            OfficialPlanBuiltin::RawListWrite | OfficialPlanBuiltin::GlobalNilCheck => {
                if !matches!(proto.instructions.get(pc + 1).map(|entry| &entry.instruction),
                    Some(Instruction::LoadNil { start, count: 1 }) if *start == call.function_register)
                {
                    return Err(invalid("官方 Fixed0 builtin Call 後未清除 private slot"));
                }
                pc + 1
            }
            OfficialPlanBuiltin::RawVarargGet => {
                if !matches!(proto.instructions.get(pc + 1).map(|entry| &entry.instruction),
                    Some(Instruction::Move { dest, src })
                        if *src == call.function_register
                            && dest.0 >= mapping.guest_start.0
                            && dest.0 < proto.register_count)
                {
                    return Err(invalid("官方 RawVarargGet 結果用途無效"));
                }
                push_allowed_read(
                    &mut allowed_reads,
                    access_capacity,
                    (index, pc + 1, call.function_register.0),
                )?;
                let raw = candidate.frame_inputs.iter().find(|input| {
                    input.prototype == call.prototype
                        && input.source == OfficialPlanFrameInputSource::OriginalVarargs
                });
                let Some(raw) = raw else {
                    return Err(invalid("官方 RawVarargGet 缺少原始 pack"));
                };
                let pack_writer = last_writer(call.inputs[0])
                    .ok_or_else(|| invalid("官方 RawVarargGet pack 來源無效"))?
                    .0;
                push_allowed_read(
                    &mut allowed_reads,
                    access_capacity,
                    (index, pack_writer, raw.register.0),
                )?;
                pc + 1
            }
            OfficialPlanBuiltin::PackUnpack => {
                let active = candidate.frame_inputs.iter().find(|input| {
                    input.prototype == call.prototype
                        && input.source == OfficialPlanFrameInputSource::ActiveVarargs
                });
                let Some(active) = active else {
                    return Err(invalid("官方 PackUnpack 缺少 active vararg slot"));
                };
                if !matches!(proto.instructions.get(pc + 1).map(|entry| &entry.instruction),
                    Some(Instruction::Move { dest, src })
                        if *dest == active.register && *src == call.function_register)
                    || !matches!(
                        proto
                            .instructions
                            .get(pc + 2)
                            .map(|entry| &entry.instruction),
                        Some(Instruction::Vararg { .. })
                    )
                {
                    return Err(invalid("官方 PackUnpack snapshot 用途無效"));
                }
                push_allowed_read(
                    &mut allowed_reads,
                    access_capacity,
                    (index, pc + 1, call.function_register.0),
                )?;
                pc + 2
            }
        };
        protected[index][load_pc + 1] += 1;
        protected[index][end_pc + 1] -= 1;
        if !sensitive[index].contains(&call.function_register) {
            sensitive[index].push(call.function_register);
        }
        push_allowed_read(
            &mut allowed_reads,
            access_capacity,
            (index, pc, call.function_register.0),
        )?;
        covered[index][load_pc] = true;
        covered[index][pc] = true;
    }
    for (index, proto) in module.prototypes.iter().enumerate() {
        let mapping = &candidate.upvalue_maps[index];
        let raw = candidate.frame_inputs.iter().find(|input| {
            input.prototype == proto.id
                && input.source == OfficialPlanFrameInputSource::OriginalVarargs
        });
        let active = candidate.frame_inputs.iter().find(|input| {
            input.prototype == proto.id
                && input.source == OfficialPlanFrameInputSource::ActiveVarargs
        });
        for (pc, entry) in proto.instructions.iter().enumerate() {
            if matches!(entry.instruction, Instruction::GetUpvalue { upvalue, .. }
                if upvalue.0 >= mapping.guest_count)
                && !covered[index][pc]
            {
                return Err(invalid("官方 hidden binding 未對應內部 Call"));
            }
            if let Some(raw) = raw {
                if writes_register(&entry.instruction, raw.register) {
                    return Err(invalid("官方原始 varargs pack 不可被指令改寫"));
                }
            }
            if let Instruction::Vararg { .. } = entry.instruction {
                if let Some(active) = active {
                    let Some(previous) =
                        pc.checked_sub(1).and_then(|pc| proto.instructions.get(pc))
                    else {
                        return Err(invalid("官方 active vararg 缺少快照切換"));
                    };
                    let Instruction::Move { dest, src } = previous.instruction else {
                        return Err(invalid("官方 active vararg 缺少快照切換"));
                    };
                    if dest != active.register {
                        return Err(invalid("官方 active vararg 切換 slot 無效"));
                    }
                    if raw.is_some_and(|raw| raw.register == src) {
                        push_allowed_read(
                            &mut allowed_reads,
                            access_capacity,
                            (index, pc - 1, src.0),
                        )?;
                        protected[index][pc] += 1;
                        protected[index][pc + 1] -= 1;
                    } else if pc < 2
                        || !covered[index][pc - 2]
                        || !matches!(proto.instructions[pc - 2].instruction,
                            Instruction::Call { base, result_mode: ResultMode::Fixed(1), .. }
                                if base == src)
                    {
                        return Err(invalid("官方 active vararg 快照來源無效"));
                    }
                }
            }
            if let Some(active) = active {
                if writes_register(&entry.instruction, active.register)
                    && !matches!(entry.instruction, Instruction::Move { dest, .. }
                    if dest == active.register
                        && proto.instructions.get(pc + 1).is_some_and(|next| {
                            matches!(next.instruction, Instruction::Vararg { .. })
                        }))
                {
                    return Err(invalid("官方 active vararg slot 被非預期指令改寫"));
                }
            }
        }
        let mut depth = 0_i32;
        for pc in 0..proto.instructions.len() {
            depth += protected[index][pc];
            protected[index][pc] = depth;
        }
        for (pc, entry) in proto.instructions.iter().enumerate() {
            let depth = protected[index][pc];
            if depth > 0
                && matches!(
                    entry.instruction,
                    Instruction::Jump { .. }
                        | Instruction::JumpIfFalse { .. }
                        | Instruction::NumericForPrepare { .. }
                        | Instruction::NumericForNext { .. }
                        | Instruction::TailCall { .. }
                        | Instruction::Return { .. }
                )
            {
                return Err(invalid("官方私有值受保護區段含控制轉移"));
            }
            let target_is_private = |target: InstructionOffset| {
                protected[index]
                    .get(target.0 as usize)
                    .is_some_and(|depth| *depth > 0)
            };
            let forbidden = match entry.instruction {
                Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                    target_is_private(target)
                }
                Instruction::NumericForPrepare { exit, .. } => target_is_private(exit),
                Instruction::NumericForNext { target, exit, .. } => {
                    target_is_private(target) || target_is_private(exit)
                }
                _ => false,
            };
            if forbidden {
                return Err(invalid("官方 CFG 不可跳入 private 指令區段"));
            }
        }
        sensitive[index].sort_unstable();
        sensitive[index].dedup();
    }
    allowed_reads.sort_unstable();
    allowed_reads.dedup();
    for (index, proto) in module.prototypes.iter().enumerate() {
        let raw = candidate.frame_inputs.iter().find(|input| {
            input.prototype == proto.id
                && input.source == OfficialPlanFrameInputSource::OriginalVarargs
        });
        let active = candidate.frame_inputs.iter().find(|input| {
            input.prototype == proto.id
                && input.source == OfficialPlanFrameInputSource::ActiveVarargs
        });
        for (pc, entry) in proto.instructions.iter().enumerate() {
            for register in &sensitive[index] {
                if reads_register(&entry.instruction, *register)
                    && allowed_reads
                        .binary_search(&(index, pc, register.0))
                        .is_err()
                {
                    return Err(invalid("官方 private pack/builtin register 被 guest 讀取"));
                }
            }
            if let Some(active) = active {
                if matches!(entry.instruction, Instruction::Vararg { .. })
                    && proto.named_vararg.map(|(_, register)| register) != Some(active.register)
                {
                    return Err(invalid("官方 active vararg binding 無效"));
                }
            }
            if let Some(raw) = raw {
                if raw.register.0 >= proto.register_count {
                    return Err(invalid("官方原始 pack register 越界"));
                }
            }
        }
    }
    let plan = OfficialExecutionPlan {
        native_builtin: false,
        root_bindings: candidate.root_bindings,
        upvalue_maps: candidate.upvalue_maps,
        frame_inputs: candidate.frame_inputs,
        calls: candidate.calls,
    };
    if plan
        .allocated_bytes()
        .is_none_or(|bytes| bytes > limits.max_module_bytes)
    {
        return Err(limited("官方執行描述 bytes 超過限制"));
    }
    verified.set_official_execution(plan);
    Ok(verified)
}

/// Native 編譯器的 RawListWrite 候選只授權 table constructor 的末尾開放欄位。
/// 候選可來自編譯器或 sidecar；每次均須與已驗證的 RVLU 重新核對。
pub fn verify_native_builtin_plan(
    verified: VerifiedModule,
    candidate: OfficialPlanCandidate,
    limits: &VerifyLimits,
) -> Result<VerifiedModule, BytecodeError> {
    verify_native_builtin_plan_metered(verified, candidate, limits, usize::MAX)
}

pub(crate) fn verify_native_builtin_plan_metered(
    mut verified: VerifiedModule,
    candidate: OfficialPlanCandidate,
    limits: &VerifyLimits,
    max_scratch_bytes: usize,
) -> Result<VerifiedModule, BytecodeError> {
    if verified.official_execution().is_some() || verified.official_artifact().is_some() {
        return Err(invalid("native helper 不可附加官方來源或其他計畫"));
    }
    let module = verified.module();
    if candidate.calls.is_empty()
        || candidate.calls.len() > limits.max_instructions
        || candidate.upvalue_maps.len() != module.prototypes.len()
        || !candidate.frame_inputs.is_empty()
        || candidate.root_bindings.len() != 1
        || candidate.root_bindings[0]
            != (OfficialPlanRootBinding {
                upvalue: UpvalueId(0),
                source: OfficialPlanRootSource::FixedBuiltin(OfficialPlanBuiltin::RawListWrite),
            })
    {
        return Err(invalid("native RawListWrite 宣告形狀無效"));
    }
    let mut needed = Vec::new();
    let needed_requested = module
        .prototypes
        .len()
        .checked_mul(core::mem::size_of::<bool>())
        .ok_or_else(|| limited("native helper needed 容量溢位"))?;
    if needed_requested > max_scratch_bytes {
        return Err(limited("native helper needed 超出預准入"));
    }
    native_reserve_exact(&mut needed, module.prototypes.len())
        .map_err(|error| reserve_error(error, "native helper needed 索引配置失敗"))?;
    let needed_bytes = needed
        .capacity()
        .checked_mul(core::mem::size_of::<bool>())
        .ok_or_else(|| limited("native helper needed 容量溢位"))?;
    if needed_bytes > max_scratch_bytes {
        return Err(limited("native helper needed 超出預准入"));
    }
    needed.resize(module.prototypes.len(), false);
    for (index, call) in candidate.calls.iter().enumerate() {
        if call.builtin != OfficialPlanBuiltin::RawListWrite
            || index > 0
                && (
                    candidate.calls[index - 1].prototype,
                    candidate.calls[index - 1].call_pc,
                ) >= (call.prototype, call.call_pc)
        {
            return Err(invalid("native helper 種類或宣告順序無效"));
        }
        let mut current = Some(call.prototype);
        let declared = module
            .prototypes
            .iter()
            .find(|proto| proto.id == call.prototype)
            .ok_or_else(|| invalid("native helper call prototype 無效"))?;
        if call.call_pc.0 as usize >= declared.instructions.len() {
            return Err(invalid("native helper call PC 越界"));
        }
        while let Some(id) = current {
            let position = module
                .prototypes
                .iter()
                .position(|proto| proto.id == id)
                .ok_or_else(|| invalid("native helper prototype 無效"))?;
            if needed[position] {
                break;
            }
            needed[position] = true;
            current = module.prototypes[position].parent;
        }
    }
    for (index, (proto, map)) in module
        .prototypes
        .iter()
        .zip(&candidate.upvalue_maps)
        .enumerate()
    {
        if map.prototype != proto.id
            || map.guest_start != Register(0)
            || map.guest_register_count != proto.register_count
            || map.hidden.len() != usize::from(needed[index])
            || usize::from(map.guest_count) + map.hidden.len() != proto.upvalues.len()
        {
            return Err(invalid("native helper upvalue/register mapping 無效"));
        }
        if needed[index] {
            let hidden = UpvalueId(map.guest_count);
            if map.hidden != [(OfficialPlanBuiltin::RawListWrite, hidden)] {
                return Err(invalid("native helper hidden binding 無效"));
            }
            let expected = match proto.parent {
                Some(parent) => {
                    let parent_map = candidate
                        .upvalue_maps
                        .iter()
                        .find(|entry| entry.prototype == parent)
                        .ok_or_else(|| invalid("native helper parent mapping 缺失"))?;
                    BytecodeUpvalueSource::ParentUpvalue(UpvalueId(parent_map.guest_count))
                }
                None => BytecodeUpvalueSource::ParentLocal(proto.global_environment_binding),
            };
            if proto.upvalues[usize::from(hidden.0)].source != expected {
                return Err(invalid("native helper hidden capture 來源無效"));
            }
        }
        if let Some(parent) = proto.parent {
            let parent_map = candidate
                .upvalue_maps
                .iter()
                .find(|entry| entry.prototype == parent)
                .ok_or_else(|| invalid("native helper parent mapping 缺失"))?;
            if proto.upvalues[..usize::from(map.guest_count)]
                .iter()
                .any(|upvalue| matches!(upvalue.source, BytecodeUpvalueSource::ParentUpvalue(id) if id.0 >= parent_map.guest_count))
            {
                return Err(invalid("native guest 不可捕獲 hidden helper"));
            }
        }
        if proto.instructions.iter().any(|entry| {
            matches!(entry.instruction, Instruction::SetUpvalue { upvalue, .. } if upvalue.0 >= map.guest_count)
        }) {
            return Err(invalid("native guest 不可改寫 hidden helper"));
        }
    }
    let root = module
        .prototypes
        .first()
        .ok_or_else(|| invalid("native root prototype 缺失"))?;
    if root.parent.is_some()
        || candidate.upvalue_maps[0].guest_count != 0
        || !needed[0]
        || root.upvalues.len() != 1
    {
        return Err(invalid("native root helper binding 無效"));
    }
    let mut allowed_hidden_reads = Vec::new();
    let allowed_requested = candidate
        .calls
        .len()
        .checked_mul(core::mem::size_of::<(ProtoId, usize)>())
        .and_then(|bytes| bytes.checked_add(needed_bytes))
        .ok_or_else(|| limited("native helper read index 容量溢位"))?;
    if allowed_requested > max_scratch_bytes {
        return Err(limited("native helper read index 超出預准入"));
    }
    native_reserve_exact(&mut allowed_hidden_reads, candidate.calls.len())
        .map_err(|error| reserve_error(error, "native helper read index 配置失敗"))?;
    let scratch_bytes = needed_bytes
        .checked_add(
            allowed_hidden_reads
                .capacity()
                .checked_mul(core::mem::size_of::<(ProtoId, usize)>())
                .ok_or_else(|| limited("native helper read index 容量溢位"))?,
        )
        .ok_or_else(|| limited("native helper scratch 容量溢位"))?;
    if scratch_bytes > max_scratch_bytes {
        return Err(limited("native helper scratch 超出預准入"));
    }
    for call in &candidate.calls {
        let proto_index = module
            .prototypes
            .iter()
            .position(|proto| proto.id == call.prototype)
            .ok_or_else(|| invalid("native helper call prototype 無效"))?;
        let proto = &module.prototypes[proto_index];
        let map = &candidate.upvalue_maps[proto_index];
        let pc = call.call_pc.0 as usize;
        let base = call.function_register;
        let slots = [
            base.0,
            base.0
                .checked_add(1)
                .ok_or_else(|| invalid("native helper register 溢位"))?,
            base.0
                .checked_add(2)
                .ok_or_else(|| invalid("native helper register 溢位"))?,
            base.0
                .checked_add(3)
                .ok_or_else(|| invalid("native helper register 溢位"))?,
            base.0
                .checked_add(4)
                .ok_or_else(|| invalid("native helper register 溢位"))?,
        ];
        if slots[4] >= proto.register_count
            || call.source_upvalue != UpvalueId(map.guest_count)
            || call.inputs
                != [Register(slots[1]), Register(slots[2]), Register(slots[3])]
            || call.open_tail != Some(Register(slots[4]))
            || base.0 < proto.frame.initial_top.0
            || proto.binding_registers.iter().any(|(_, register)| {
                slots[..4].contains(&register.0)
            })
            || matches!(proto.named_vararg, Some((_, register)) if slots[..4].contains(&register.0))
            || slots[..4].contains(&proto.frame.environment.0)
            || module.prototypes.iter().any(|child| {
                child.parent == Some(proto.id)
                    && child.upvalues.iter().any(|upvalue| {
                        matches!(upvalue.source, BytecodeUpvalueSource::ParentLocal(binding)
                            if proto.binding_registers.iter().any(|(id, register)| *id == binding && slots[..4].contains(&register.0)))
                    })
            })
        {
            return Err(invalid("native helper private register/capture 無效"));
        }
        if !matches!(proto.instructions.get(pc).map(|entry| &entry.instruction),
            Some(Instruction::Call { base: actual, arg_count: u16::MAX, result_mode: ResultMode::Fixed(0) }) if *actual == base)
            || !matches!(proto.instructions.get(pc.checked_sub(1).ok_or_else(|| invalid("native helper producer 缺失"))?).map(|entry| &entry.instruction),
                Some(Instruction::Call { base: actual, result_mode: ResultMode::All, .. })
                | Some(Instruction::Vararg { base: actual, result_mode: ResultMode::All })
                    if actual.0 == slots[4])
            || !matches!(proto.instructions.get(pc + 1).map(|entry| &entry.instruction),
                Some(Instruction::LoadNil { start, count: 1 }) if *start == base)
        {
            return Err(invalid(
                "native RawListWrite call/producer/cleanup ABI 無效",
            ));
        }
        let load_pc = (0..pc)
            .rev()
            .find(|&position| writes_register(&proto.instructions[position].instruction, base))
            .ok_or_else(|| invalid("native helper binding 載入缺失"))?;
        let setup = &proto.instructions;
        if !matches!(setup[load_pc].instruction, Instruction::GetUpvalue { dest, upvalue }
            if dest == base && upvalue == call.source_upvalue)
            || !matches!(setup.get(load_pc + 1).map(|entry| &entry.instruction),
                Some(Instruction::Move { dest, src }) if dest.0 == slots[1]
                    && src.0 < proto.register_count
                    && (0..load_pc).rev().find(|&position| writes_register(&setup[position].instruction, *src))
                        .is_some_and(|position| matches!(setup[position].instruction, Instruction::NewTable { dest } if dest == *src)))
            || !matches!(setup.get(load_pc + 2).map(|entry| &entry.instruction),
                Some(Instruction::LoadConst { dest, constant }) if dest.0 == slots[2]
                    && matches!(proto.constants.get(constant.0 as usize), Some(super::BytecodeConstant::Integer(first)) if *first >= 1))
            || !matches!(setup.get(load_pc + 3).map(|entry| &entry.instruction),
                Some(Instruction::LoadConst { dest, constant }) if dest.0 == slots[3]
                    && matches!(proto.constants.get(constant.0 as usize), Some(super::BytecodeConstant::Integer(0))))
            || load_pc + 4 >= pc
        {
            return Err(invalid("native RawListWrite private setup 無效"));
        }
        allowed_hidden_reads.push((proto.id, load_pc));
        for (position, entry) in proto.instructions.iter().enumerate() {
            for &private in &slots[..4] {
                let private = Register(private);
                let permitted_read = position == pc;
                let permitted_write = position == load_pc && private == base
                    || position == load_pc + 1 && private.0 == slots[1]
                    || position == load_pc + 2 && private.0 == slots[2]
                    || position == load_pc + 3 && private.0 == slots[3]
                    || position == pc && private == base
                    || position == pc + 1 && private == base;
                if position >= load_pc
                    && (reads_register(&entry.instruction, private) && !permitted_read
                        || writes_register(&entry.instruction, private) && !permitted_write)
                {
                    return Err(invalid("native helper private register 被 guest 讀寫"));
                }
            }
            let targets = match entry.instruction {
                Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                    [Some(target), None]
                }
                Instruction::NumericForPrepare { exit, .. } => [Some(exit), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            for target in targets.into_iter().flatten() {
                let inside_from = (load_pc + 1..=pc + 1).contains(&position);
                let inside_to = (load_pc + 1..=pc + 1).contains(&(target.0 as usize));
                if inside_from != inside_to || inside_to && target.0 as usize >= pc - 1 {
                    return Err(invalid("native helper CFG 跨越 private 區段"));
                }
            }
            if (load_pc..=pc).contains(&position)
                && matches!(
                    entry.instruction,
                    Instruction::Return { .. } | Instruction::TailCall { .. }
                )
            {
                return Err(invalid("native helper private 區段提前離開"));
            }
        }
    }
    for (proto, map) in module.prototypes.iter().zip(&candidate.upvalue_maps) {
        for (pc, entry) in proto.instructions.iter().enumerate() {
            if matches!(entry.instruction, Instruction::GetUpvalue { upvalue, .. }
                if upvalue.0 >= map.guest_count)
                && !allowed_hidden_reads.contains(&(proto.id, pc))
            {
                return Err(invalid("native helper hidden binding 外洩"));
            }
        }
    }
    let plan = OfficialExecutionPlan {
        native_builtin: true,
        root_bindings: candidate.root_bindings,
        upvalue_maps: candidate.upvalue_maps,
        frame_inputs: candidate.frame_inputs,
        calls: candidate.calls,
    };
    if plan
        .allocated_bytes()
        .is_none_or(|bytes| bytes > limits.max_module_bytes)
    {
        return Err(limited("native helper plan 容量超限"));
    }
    verified.set_official_execution(plan);
    Ok(verified)
}

/// sidecar 只保存靜態 call 宣告；mapping 從 RVLU 的實際 prototype/capture 重建。
pub fn native_builtin_candidate_from_calls(
    verified: &VerifiedModule,
    calls: Vec<OfficialPlanCall>,
) -> Result<OfficialPlanCandidate, BytecodeError> {
    native_builtin_candidate_from_calls_metered(verified, calls, usize::MAX)
        .map(|(candidate, _, _)| candidate)
}

/// 回傳建立 mapping 時相對於傳入 calls 的峰值額外容量；needed 索引在返回前釋放。
pub(crate) fn native_builtin_candidate_from_calls_metered(
    verified: &VerifiedModule,
    calls: Vec<OfficialPlanCall>,
    max_additional_bytes: usize,
) -> Result<(OfficialPlanCandidate, usize, usize), BytecodeError> {
    let protos = &verified.module().prototypes;
    let calls_bytes = calls
        .capacity()
        .checked_mul(core::mem::size_of::<OfficialPlanCall>())
        .and_then(|mut bytes| {
            for call in &calls {
                bytes = bytes.checked_add(
                    call.inputs
                        .capacity()
                        .checked_mul(core::mem::size_of::<Register>())?,
                )?;
            }
            Some(bytes)
        })
        .ok_or_else(|| limited("native helper calls 容量溢位"))?;
    let mut needed = Vec::new();
    if protos.len() > max_additional_bytes {
        return Err(limited("native helper needed 超出預准入"));
    }
    native_reserve_exact(&mut needed, protos.len())
        .map_err(|error| reserve_error(error, "native helper needed 配置失敗"))?;
    let needed_bytes = needed
        .capacity()
        .checked_mul(core::mem::size_of::<bool>())
        .ok_or_else(|| limited("native helper needed 容量溢位"))?;
    if needed_bytes > max_additional_bytes {
        return Err(limited("native helper needed 超出預准入"));
    }
    needed.resize(protos.len(), false);
    for call in &calls {
        let mut current = Some(call.prototype);
        while let Some(id) = current {
            let index = protos
                .iter()
                .position(|proto| proto.id == id)
                .ok_or_else(|| invalid("native helper call prototype 無效"))?;
            if needed[index] {
                break;
            }
            needed[index] = true;
            current = protos[index].parent;
        }
    }
    let mut upvalue_maps = Vec::new();
    let maps_requested = protos
        .len()
        .checked_mul(core::mem::size_of::<OfficialPlanUpvalueMap>())
        .and_then(|bytes| bytes.checked_add(needed_bytes))
        .ok_or_else(|| limited("native helper mapping 容量溢位"))?;
    if maps_requested > max_additional_bytes {
        return Err(limited("native helper mapping 超出預准入"));
    }
    native_reserve_exact(&mut upvalue_maps, protos.len())
        .map_err(|error| reserve_error(error, "native helper mapping 配置失敗"))?;
    let mut additional_used = needed_bytes
        .checked_add(
            upvalue_maps
                .capacity()
                .checked_mul(core::mem::size_of::<OfficialPlanUpvalueMap>())
                .ok_or_else(|| limited("native helper mapping 容量溢位"))?,
        )
        .ok_or_else(|| limited("native helper mapping 容量溢位"))?;
    if additional_used > max_additional_bytes {
        return Err(limited("native helper mapping 超出預准入"));
    }
    for (proto, hidden) in protos.iter().zip(needed) {
        let count = proto
            .upvalues
            .len()
            .checked_sub(usize::from(hidden))
            .ok_or_else(|| invalid("native helper upvalue 缺失"))?;
        let guest_count = u16::try_from(count).map_err(|_| limited("native guest upvalue 超限"))?;
        let mut hidden_bindings = Vec::new();
        if hidden {
            let requested = core::mem::size_of::<(OfficialPlanBuiltin, UpvalueId)>();
            if additional_used
                .checked_add(requested)
                .is_none_or(|bytes| bytes > max_additional_bytes)
            {
                return Err(limited("native helper hidden binding 超出預准入"));
            }
            native_reserve_exact(&mut hidden_bindings, 1)
                .map_err(|error| reserve_error(error, "native helper hidden binding 配置失敗"))?;
            additional_used = additional_used
                .checked_add(
                    hidden_bindings
                        .capacity()
                        .checked_mul(requested)
                        .ok_or_else(|| limited("native helper hidden binding 容量溢位"))?,
                )
                .ok_or_else(|| limited("native helper hidden binding 容量溢位"))?;
            if additional_used > max_additional_bytes {
                return Err(limited("native helper hidden binding 超出預准入"));
            }
            hidden_bindings.push((OfficialPlanBuiltin::RawListWrite, UpvalueId(guest_count)));
        }
        upvalue_maps.push(OfficialPlanUpvalueMap {
            prototype: proto.id,
            guest_count,
            guest_start: Register(0),
            guest_register_count: proto.register_count,
            hidden: hidden_bindings,
        });
    }
    let mut root_bindings = Vec::new();
    let root_requested = core::mem::size_of::<OfficialPlanRootBinding>();
    if additional_used
        .checked_add(root_requested)
        .is_none_or(|bytes| bytes > max_additional_bytes)
    {
        return Err(limited("native helper root binding 超出預准入"));
    }
    native_reserve_exact(&mut root_bindings, 1)
        .map_err(|error| reserve_error(error, "native helper root binding 配置失敗"))?;
    root_bindings.push(OfficialPlanRootBinding {
        upvalue: UpvalueId(0),
        source: OfficialPlanRootSource::FixedBuiltin(OfficialPlanBuiltin::RawListWrite),
    });
    let candidate = OfficialPlanCandidate {
        root_bindings,
        upvalue_maps,
        frame_inputs: Vec::new(),
        calls,
    };
    let resident_extra_bytes = candidate
        .allocated_bytes()
        .and_then(|bytes| bytes.checked_sub(calls_bytes))
        .ok_or_else(|| limited("native helper mapping 容量溢位"))?;
    let extra_bytes = resident_extra_bytes
        .checked_add(needed_bytes)
        .ok_or_else(|| limited("native helper mapping 容量溢位"))?;
    if extra_bytes > max_additional_bytes {
        return Err(limited("native helper mapping 超出預准入"));
    }
    Ok((candidate, extra_bytes, resident_extra_bytes))
}
