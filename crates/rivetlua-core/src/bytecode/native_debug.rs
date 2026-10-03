//! P05 驗證的一般 RVLU 來源除錯資料；不屬於 RVLU_V2 wire。

use core::mem::size_of;

use super::codec::{
    BytecodeBindingId, BytecodeClosePath, BytecodeError, BytecodeErrorCode, BytecodeInstruction,
    BytecodePrototype, VerifyLimits,
};
use super::official_translation::OfficialWorkBudget;
use super::{Instruction, ProtoId, Register, ResultMode, VerifiedModule};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLocal {
    pub binding: BytecodeBindingId,
    pub register: Register,
    pub slot: u8,
    pub initialized_pc: u32,
    pub start_pc: u32,
    pub end_pc: u32,
    pub name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativePrototypeDebug {
    pub prototype: ProtoId,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub lines: Vec<u32>,
    pub locals: Vec<NativeLocal>,
    pub upvalue_names: Vec<Option<Vec<u8>>>,
    pub max_active_locals: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDebugCandidate {
    pub source_name: Vec<u8>,
    pub prototypes: Vec<NativePrototypeDebug>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDebug {
    source_name: Vec<u8>,
    prototypes: Vec<NativePrototypeDebug>,
    storage: Vec<Vec<NativeStorageInterval>>,
    close_groups: Vec<Vec<NativeCloseGroup>>,
    allocated_bytes: usize,
}

/// P05 證明可作為單一官方 OP_CLOSE 的連續 RVLU 退出序列。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeCloseGroup {
    pub start_pc: u32,
    pub end_pc: u32,
    pub emit_pc: u32,
    operands: Vec<(Register, u16)>,
}

impl NativeCloseGroup {
    pub fn operands(&self) -> &[(Register, u16)] {
        &self.operands
    }
}

/// 僅由 P05 對已驗證指令推導；候選 debug 資料不能直接指定此區間。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeStorageInterval {
    pub binding: BytecodeBindingId,
    pub register: Register,
    pub slot: u8,
    pub start_pc: u32,
    pub end_pc: u32,
    captured: bool,
}

impl NativeDebug {
    pub fn source_name(&self) -> &[u8] {
        &self.source_name
    }

    pub fn prototypes(&self) -> &[NativePrototypeDebug] {
        &self.prototypes
    }

    pub fn prototype(&self, id: ProtoId) -> Option<&NativePrototypeDebug> {
        self.prototypes.iter().find(|entry| entry.prototype == id)
    }

    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    pub fn storage_for(&self, id: ProtoId) -> Option<&[NativeStorageInterval]> {
        self.prototypes
            .iter()
            .position(|entry| entry.prototype == id)
            .and_then(|index| self.storage.get(index).map(Vec::as_slice))
    }

    pub fn close_groups_for(&self, id: ProtoId) -> Option<&[NativeCloseGroup]> {
        self.prototypes
            .iter()
            .position(|entry| entry.prototype == id)
            .and_then(|index| self.close_groups.get(index).map(Vec::as_slice))
    }
}

fn invalid(message: &'static str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::Verify,
        offset: 0,
        message: message.into(),
    }
}

fn limit(message: &'static str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::CompileLimit,
        offset: 0,
        message: message.into(),
    }
}

fn charge(work: &mut OfficialWorkBudget, count: usize) -> Result<(), BytecodeError> {
    work.charge(count, ProtoId(0), 0)
        .map_err(|_| limit("native debug work 額度耗盡"))
}

fn add_bytes(
    total: &mut usize,
    count: usize,
    size: usize,
    maximum: usize,
) -> Result<(), BytecodeError> {
    let amount = count
        .checked_mul(size)
        .ok_or_else(|| limit("native debug 配置大小溢位"))?;
    *total = total
        .checked_add(amount)
        .filter(|bytes| *bytes <= maximum)
        .ok_or_else(|| limit("native debug 配置額度超限"))?;
    Ok(())
}

fn in_range(register: Register, start: Register, count: u16) -> bool {
    register.0 >= start.0 && register.0 - start.0 < count
}

/// 單一 register 的靜態讀、確定寫、可能寫與 close；不配置暫存 Vec。
pub(super) fn register_access(
    instruction: &Instruction,
    register: Register,
    register_count: u16,
) -> (bool, bool, bool, bool) {
    match instruction {
        Instruction::LoadConst { dest, .. }
        | Instruction::GetUpvalue { dest, .. }
        | Instruction::NewTable { dest }
        | Instruction::Closure { dest, .. } => (false, *dest == register, false, false),
        Instruction::LoadNil { start, count } => {
            (false, in_range(register, *start, *count), false, false)
        }
        Instruction::Move { dest, src } => (*src == register, *dest == register, false, false),
        Instruction::SetUpvalue { src, .. } => (*src == register, false, false, false),
        Instruction::GetTable { dest, table, key } => (
            *table == register || *key == register,
            *dest == register,
            false,
            false,
        ),
        Instruction::SetTable { table, key, value } => (
            *table == register || *key == register || *value == register,
            false,
            false,
            false,
        ),
        Instruction::UnaryOp { dest, src, .. } => {
            (*src == register, *dest == register, false, false)
        }
        Instruction::BinaryOp {
            dest, left, right, ..
        } => (
            *left == register || *right == register,
            *dest == register,
            false,
            false,
        ),
        Instruction::Jump { .. } => (false, false, false, false),
        Instruction::JumpIfFalse { condition, .. } => (*condition == register, false, false, false),
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            let reads = in_range(register, *base, arg_count.saturating_add(1));
            match result_mode {
                ResultMode::Fixed(count) => {
                    (reads, in_range(register, *base, *count), false, false)
                }
                ResultMode::All => (
                    reads,
                    false,
                    in_range(register, *base, register_count.saturating_sub(base.0)),
                    false,
                ),
            }
        }
        Instruction::TailCall {
            base, arg_count, ..
        } => (
            in_range(register, *base, arg_count.saturating_add(1)),
            false,
            false,
            false,
        ),
        Instruction::Vararg { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => (false, in_range(register, *base, *count), false, false),
            ResultMode::All => (
                false,
                false,
                in_range(register, *base, register_count.saturating_sub(base.0)),
                false,
            ),
        },
        Instruction::Return { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => (in_range(register, *base, *count), false, false, false),
            ResultMode::All => (
                in_range(register, *base, register_count.saturating_sub(base.0)),
                false,
                false,
                false,
            ),
        },
        Instruction::Close { base, count } => {
            let close = (*count == 0 && *base == register) || in_range(register, *base, *count);
            (close, false, false, close)
        }
        Instruction::NumericForPrepare {
            control,
            limit,
            step,
            visible,
            ..
        }
        | Instruction::NumericForNext {
            control,
            limit,
            step,
            visible,
            ..
        } => (
            *control == register || *limit == register || *step == register,
            *control == register || *visible == register,
            false,
            false,
        ),
    }
}

fn prototype_register_access(
    proto: &BytecodePrototype,
    instruction: &Instruction,
    register: Register,
) -> (bool, bool, bool, bool) {
    let (read, write, possible_write, close) =
        register_access(instruction, register, proto.register_count);
    let named_read = matches!(instruction, Instruction::Vararg { .. })
        && proto
            .named_vararg
            .is_some_and(|(_, named)| named == register);
    (read || named_read, write, possible_write, close)
}

pub(super) fn capture_at(
    module: &VerifiedModule,
    instruction: &Instruction,
    binding: BytecodeBindingId,
    work: &mut OfficialWorkBudget,
) -> Result<bool, BytecodeError> {
    let Instruction::Closure { proto: child, .. } = instruction else {
        return Ok(false);
    };
    charge(work, module.module().prototypes.len())?;
    let Some(child) = module
        .module()
        .prototypes
        .iter()
        .find(|proto| proto.id == *child)
    else {
        return Err(invalid("native debug closure child 不存在"));
    };
    charge(work, child.upvalues.len())?;
    Ok(child.upvalues.iter().any(|upvalue| {
        matches!(upvalue.source, super::codec::BytecodeUpvalueSource::ParentLocal(source)
            if source == binding)
    }))
}

fn close_run_end(
    instructions: &[BytecodeInstruction],
    start: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<(usize, usize)>, BytecodeError> {
    if !matches!(
        instructions.get(start).map(|entry| &entry.instruction),
        Some(Instruction::Close { .. })
    ) {
        return Ok(None);
    }
    let mut pc = start;
    let mut first_tbc = None;
    let mut path: Option<&BytecodeClosePath> = None;
    while let Some(entry) = instructions.get(pc) {
        match &entry.instruction {
            Instruction::Close { count: 0, .. } if first_tbc.is_none() => {}
            Instruction::Close { count: 1, .. } => {
                let Some(current) = entry.close_path.as_ref() else {
                    return Err(invalid("native debug TBC Close 缺少 P04 path"));
                };
                if let Some(previous) = path {
                    charge(
                        work,
                        previous
                            .bindings
                            .len()
                            .checked_add(previous.registers.len())
                            .and_then(|sum| sum.checked_add(current.bindings.len()))
                            .and_then(|sum| sum.checked_add(current.registers.len()))
                            .ok_or_else(|| limit("native debug close path work 溢位"))?,
                    )?;
                    if previous != current {
                        break;
                    }
                } else {
                    path = Some(current);
                }
                first_tbc.get_or_insert(pc);
            }
            _ => break,
        }
        pc += 1;
    }
    Ok(Some((pc, first_tbc.unwrap_or(start))))
}

pub(super) fn close_group_counts(
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
) -> Result<(usize, usize), BytecodeError> {
    charge(work, proto.instructions.len())?;
    let mut groups = 0usize;
    let mut closes = 0usize;
    let mut pc = 0usize;
    while pc < proto.instructions.len() {
        if let Some((end, _)) = close_run_end(&proto.instructions, pc, work)? {
            groups = groups
                .checked_add(1)
                .ok_or_else(|| limit("native debug close group 數溢位"))?;
            closes = closes
                .checked_add(end - pc)
                .ok_or_else(|| limit("native debug close operand 數溢位"))?;
            pc = end;
        } else {
            pc += 1;
        }
    }
    Ok((groups, closes))
}

pub(super) fn build_close_groups(
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<Vec<NativeCloseGroup>, BytecodeError> {
    let (group_count, _) = close_group_counts(proto, work)?;
    let count = proto.instructions.len();
    if count > max_temporary_bytes {
        return Err(limit("native debug close branch bitmap 額度超限"));
    }
    charge(
        work,
        count
            .checked_mul(3)
            .ok_or_else(|| limit("native debug close branch work 溢位"))?,
    )?;
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(count)
        .map_err(|_| limit("native debug close branch bitmap 配置失敗"))?;
    targets.resize(count, 0u8);
    for entry in &proto.instructions {
        let mut mark = |pc: u32| -> Result<(), BytecodeError> {
            let Some(slot) = targets.get_mut(pc as usize) else {
                return Err(invalid("native debug close branch target 超出範圍"));
            };
            *slot = 1;
            Ok(())
        };
        match &entry.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                mark(target.0)?
            }
            Instruction::NumericForPrepare { exit, .. } => mark(exit.0)?,
            Instruction::NumericForNext { target, exit, .. } => {
                mark(target.0)?;
                mark(exit.0)?;
            }
            _ => {}
        }
    }
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(group_count)
        .map_err(|_| limit("native debug close group 配置失敗"))?;
    charge(
        work,
        count
            .checked_mul(2)
            .ok_or_else(|| limit("native debug close group build work 溢位"))?,
    )?;
    let mut pc = 0usize;
    while pc < count {
        let Some((end, emit)) = close_run_end(&proto.instructions, pc, work)? else {
            pc += 1;
            continue;
        };
        if targets[pc + 1..end].contains(&1) {
            return Err(invalid("native debug branch 進入 close group 中段"));
        }
        let mut operands = Vec::new();
        operands
            .try_reserve_exact(end - pc)
            .map_err(|_| limit("native debug close operand 配置失敗"))?;
        for entry in &proto.instructions[pc..end] {
            let Instruction::Close { base, count } = entry.instruction else {
                return Err(invalid("native debug close group 含非 Close 指令"));
            };
            operands.push((base, count));
        }
        groups.push(NativeCloseGroup {
            start_pc: u32::try_from(pc).map_err(|_| limit("native debug close PC 溢位"))?,
            end_pc: u32::try_from(end).map_err(|_| limit("native debug close PC 溢位"))?,
            emit_pc: u32::try_from(emit).map_err(|_| limit("native debug close PC 溢位"))?,
            operands,
        });
        pc = end;
    }
    Ok(groups)
}

fn close_group_at<'a>(
    groups: &'a [NativeCloseGroup],
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<&'a NativeCloseGroup>, BytecodeError> {
    charge(work, usize::BITS as usize)?;
    let index = groups.partition_point(|group| group.start_pc as usize <= pc);
    Ok(index
        .checked_sub(1)
        .and_then(|index| groups.get(index))
        .filter(|group| pc < group.end_pc as usize))
}

fn check_storage_cfg(
    module: &VerifiedModule,
    proto: &super::codec::BytecodePrototype,
    local: &NativeLocal,
    interval: &NativeStorageInterval,
    storage: &[NativeStorageInterval],
    groups: &[NativeCloseGroup],
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<(), BytecodeError> {
    let count = proto.instructions.len();
    let queue_count = count
        .checked_mul(8)
        .ok_or_else(|| limit("native debug CFG state 數溢位"))?;
    let scratch_bytes = count
        .checked_mul(2)
        .and_then(|bytes| {
            queue_count
                .checked_mul(size_of::<usize>())
                .and_then(|queue| bytes.checked_add(queue))
        })
        .ok_or_else(|| limit("native debug CFG 暫存大小溢位"))?;
    if scratch_bytes > max_temporary_bytes {
        return Err(limit("native debug CFG 暫存配置額度超限"));
    }
    charge(
        work,
        count
            .checked_mul(32)
            .ok_or_else(|| limit("native debug CFG work 溢位"))?,
    )?;
    let mut captures = Vec::new();
    captures
        .try_reserve_exact(count)
        .map_err(|_| limit("native debug capture bitmap 配置失敗"))?;
    for instruction in &proto.instructions {
        captures.push(u8::from(capture_at(
            module,
            &instruction.instruction,
            local.binding,
            work,
        )?));
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(count)
        .map_err(|_| limit("native debug CFG state 配置失敗"))?;
    seen.resize(count, 0u8);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(queue_count)
        .map_err(|_| limit("native debug CFG worklist 配置失敗"))?;
    if count == 0 {
        return Ok(());
    }
    let preinitialized = local.initialized_pc == 0
        && local.start_pc == 0
        && (usize::from(local.slot) < usize::from(proto.parameter_count)
            || proto
                .named_vararg
                .is_some_and(|(binding, _)| binding == local.binding));
    let initial_state = usize::from(preinitialized);
    pending.push(initial_state);
    seen[0] = 1u8 << initial_state;
    let start = interval.start_pc as usize;
    let end = interval.end_pc as usize;
    while let Some(encoded) = pending.pop() {
        let pc = encoded / 8;
        let state = encoded % 8;
        let initialized = state & 1 != 0;
        let open = state & 2 != 0;
        let pending_close = state & 4 != 0;
        if (open || pending_close) && (pc < start || pc >= end) {
            return Err(invalid(
                "native debug captured/TBC local 離開 storage 前未 Close",
            ));
        }
        let instruction = &proto.instructions[pc].instruction;
        let (read, write, _, _) = prototype_register_access(proto, instruction, local.register);
        if pc >= start
            && pc < end
            && read
            && !initialized
            && !matches!(instruction, Instruction::Close { base, count: 0 }
                if *base == local.register)
        {
            return Err(invalid("native debug local 讀取未經 CFG 初始化"));
        }
        let next_initialized = initialized || write;
        let group = if matches!(instruction, Instruction::Close { .. }) {
            close_group_at(groups, pc, work)?
        } else {
            None
        };
        let emitting = group.is_some_and(|group| group.emit_pc as usize == pc);
        let mut close_open = false;
        let mut close_tbc = false;
        let mut lowest_slot = None;
        if let Some(group) = group.filter(|_| emitting) {
            charge(
                work,
                storage
                    .len()
                    .checked_add(2)
                    .and_then(|scans| group.operands.len().checked_mul(scans))
                    .ok_or_else(|| limit("native debug close group mapping work 溢位"))?,
            )?;
            close_open = group
                .operands
                .iter()
                .any(|(source, count)| *source == local.register && *count == 0);
            close_tbc = group
                .operands
                .iter()
                .any(|(source, count)| *source == local.register && *count == 1);
            for (source, _) in &group.operands {
                if let Some(mapped) = storage.iter().find(|candidate| {
                    candidate.register == *source
                        && candidate.start_pc as usize <= pc
                        && pc < candidate.end_pc as usize
                }) {
                    lowest_slot =
                        Some(lowest_slot.map_or(mapped.slot, |slot: u8| slot.min(mapped.slot)));
                }
            }
        }
        if emitting
            && lowest_slot.is_some_and(|slot| slot <= interval.slot)
            && ((open && !close_open) || (pending_close && !close_tbc))
        {
            return Err(invalid("native debug OP_CLOSE 提前關閉較高 local slot"));
        }
        let marker = matches!(instruction, Instruction::Move { dest, .. }
            if *dest == local.register)
            && proto.instructions[pc].close_path.is_some();
        let next_pending_close = if marker {
            true
        } else if emitting && close_tbc {
            false
        } else {
            pending_close
        };
        let next_open = if captures[pc] != 0 {
            true
        } else if emitting && close_open {
            false
        } else {
            open
        };
        let mut successors = [None; 3];
        match instruction {
            Instruction::Jump { target } => successors[0] = Some(target.0 as usize),
            Instruction::JumpIfFalse { target, .. }
            | Instruction::NumericForPrepare { exit: target, .. } => {
                successors[0] = Some(target.0 as usize);
                successors[1] = pc.checked_add(1).filter(|next| *next < count);
            }
            Instruction::NumericForNext { target, exit, .. } => {
                successors[0] = Some(target.0 as usize);
                successors[1] = Some(exit.0 as usize);
            }
            Instruction::Return { .. } | Instruction::TailCall { .. } => {}
            _ => successors[0] = pc.checked_add(1).filter(|next| *next < count),
        }
        for successor in successors.into_iter().flatten() {
            if successor >= count {
                return Err(invalid("native debug CFG successor 超出 prototype"));
            }
            if (next_open || next_pending_close) && (successor < start || successor >= end) {
                return Err(invalid(
                    "native debug captured/TBC local 分支離開 storage 前未 Close",
                ));
            }
            let entering = (pc < start || pc >= end) && successor >= start && successor < end;
            if entering
                && !preinitialized
                && successor != start
                && successor != local.initialized_pc as usize
            {
                return Err(invalid("native debug local CFG 跳過 storage 初始化"));
            }
            let successor_initialized = if entering {
                preinitialized
            } else {
                next_initialized
            };
            let next_state = usize::from(successor_initialized)
                | (usize::from(next_open) << 1)
                | (usize::from(next_pending_close) << 2);
            let bit = 1u8 << next_state;
            if seen[successor] & bit == 0 {
                seen[successor] |= bit;
                pending.push(successor * 8 + next_state);
            }
        }
    }
    Ok(())
}

fn validate_required_local_coverage(
    entry: &NativePrototypeDebug,
    proto: &super::codec::BytecodePrototype,
    module: &VerifiedModule,
    work: &mut OfficialWorkBudget,
) -> Result<(), BytecodeError> {
    charge(work, module.module().prototypes.len())?;
    for child in &module.module().prototypes {
        if child.parent != Some(proto.id) {
            continue;
        }
        charge(work, child.upvalues.len())?;
        for upvalue in &child.upvalues {
            let super::codec::BytecodeUpvalueSource::ParentLocal(binding) = upvalue.source else {
                continue;
            };
            if binding == proto.global_environment_binding {
                continue;
            }
            charge(work, entry.locals.len())?;
            if !entry.locals.iter().any(|local| local.binding == binding) {
                return Err(invalid("native debug captured binding 缺少 local storage"));
            }
        }
    }
    charge(work, proto.instructions.len())?;
    for instruction in &proto.instructions {
        let Instruction::Close { base, count: 0 } = instruction.instruction else {
            continue;
        };
        charge(
            work,
            proto
                .binding_registers
                .len()
                .checked_add(entry.locals.len())
                .ok_or_else(|| limit("native debug Close coverage work 溢位"))?,
        )?;
        let Some((binding, _)) = proto
            .binding_registers
            .iter()
            .find(|(_, register)| *register == base)
        else {
            return Err(invalid("native debug Close register 缺少 binding"));
        };
        if *binding != proto.global_environment_binding
            && !entry.locals.iter().any(|local| local.binding == *binding)
        {
            return Err(invalid("native debug Close binding 缺少 local storage"));
        }
    }
    Ok(())
}

fn validate_locals(
    entry: &NativePrototypeDebug,
    proto: &super::codec::BytecodePrototype,
    module: &VerifiedModule,
    groups: &[NativeCloseGroup],
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<Vec<NativeStorageInterval>, BytecodeError> {
    if entry.max_active_locals as usize > proto.register_count as usize
        || proto.parameter_count > u16::from(u8::MAX)
    {
        return Err(invalid("native debug local slot 數無效"));
    }
    let event_count = entry
        .locals
        .len()
        .checked_mul(2)
        .ok_or_else(|| limit("native debug local event 數溢位"))?;
    let event_bytes = event_count
        .checked_mul(size_of::<(u32, bool, u8)>())
        .ok_or_else(|| limit("native debug local event 大小溢位"))?;
    if event_bytes > max_temporary_bytes {
        return Err(limit("native debug local 暫存配置額度超限"));
    }
    charge(
        work,
        event_count
            .checked_add(entry.locals.len())
            .ok_or_else(|| limit("native debug local work 溢位"))?,
    )?;
    let mut events = Vec::new();
    events
        .try_reserve_exact(event_count)
        .map_err(|_| limit("native debug local event 配置失敗"))?;
    let mut storage: Vec<NativeStorageInterval> = Vec::new();
    storage
        .try_reserve_exact(entry.locals.len())
        .map_err(|_| limit("native debug storage 配置失敗"))?;
    for (index, local) in entry.locals.iter().enumerate() {
        charge(
            work,
            proto
                .binding_registers
                .len()
                .checked_add(index)
                .ok_or_else(|| limit("native debug local work 溢位"))?,
        )?;
        if local.binding.function != proto.function
            || proto
                .binding_registers
                .iter()
                .find(|(binding, _)| *binding == local.binding)
                .is_none_or(|(_, register)| *register != local.register)
            || local.slot >= entry.max_active_locals
            || local.initialized_pc > local.start_pc
            || local.start_pc > local.end_pc
            || local.end_pc as usize > proto.instructions.len()
            || entry.locals[..index]
                .iter()
                .any(|prior| prior.binding == local.binding || prior.register == local.register)
        {
            return Err(invalid("native debug local/binding/PC 對應無效"));
        }
        let preinitialized_parameter = usize::from(local.slot) < usize::from(proto.parameter_count)
            && local.register.0 == u16::from(local.slot) + 1
            && local.start_pc == 0
            && local.initialized_pc == 0;
        let preinitialized_named = proto.named_vararg.is_some_and(|(binding, register)| {
            binding == local.binding
                && register == local.register
                && usize::from(local.slot) == usize::from(proto.parameter_count)
                && local.start_pc == 0
                && local.initialized_pc == 0
        });
        let preinitialized = preinitialized_parameter || preinitialized_named;
        charge(work, proto.instructions.len())?;
        let mut first_write = None;
        let mut first_access = None;
        let mut first_read_after_init = None;
        let mut possible_write_before_init = false;
        let mut capture_before_init = false;
        let mut captured = false;
        for (pc, instruction) in proto.instructions.iter().enumerate() {
            let (read, write, maybe_write, close) =
                prototype_register_access(proto, &instruction.instruction, local.register);
            let capture = capture_at(module, &instruction.instruction, local.binding, work)?;
            captured |= capture;
            if pc < local.initialized_pc as usize {
                possible_write_before_init |= maybe_write;
                capture_before_init |= capture;
            }
            if write && first_write.is_none() {
                first_write = Some(pc);
            }
            if read && pc >= local.initialized_pc as usize {
                first_read_after_init.get_or_insert(pc);
            }
            let active_possible_write =
                maybe_write && pc >= local.initialized_pc as usize && pc < local.end_pc as usize;
            if read || write || active_possible_write || close || capture {
                first_access.get_or_insert(pc);
                if pc < local.initialized_pc as usize && !capture {
                    return Err(invalid("native debug local 初始化前有 register 存取"));
                }
                if pc >= local.end_pc as usize {
                    return Err(invalid("native debug local storage lifetime 遺漏存取"));
                }
            }
        }
        if possible_write_before_init && capture_before_init {
            return Err(invalid("native debug 捕獲前動態結果可能改寫 local"));
        }
        if !preinitialized && first_write != Some(local.initialized_pc as usize) {
            return Err(invalid("native debug local 初始化 PC 與指令寫入不符"));
        }
        if first_read_after_init.is_some_and(|pc| pc < local.start_pc as usize) {
            return Err(invalid("native debug local debug start 晚於首次讀取"));
        }
        let start_pc = u32::try_from(
            first_access
                .unwrap_or(local.initialized_pc as usize)
                .min(local.initialized_pc as usize),
        )
        .map_err(|_| limit("native debug storage 起始 PC 溢位"))?;
        charge(work, storage.len())?;
        if entry.locals[..index]
            .iter()
            .zip(&storage)
            .any(|(prior_local, prior)| {
                if !(start_pc < prior.end_pc && prior.start_pc < local.end_pc) {
                    return false;
                }
                prior.slot == local.slot
                    || (prior_local.initialized_pc < local.initialized_pc
                        && prior.slot >= local.slot)
                    || (prior_local.initialized_pc > local.initialized_pc
                        && prior.slot <= local.slot)
                    || (prior_local.initialized_pc == local.initialized_pc
                        && ((prior.register.0 < local.register.0 && prior.slot >= local.slot)
                            || (prior.register.0 > local.register.0 && prior.slot <= local.slot)))
            })
        {
            return Err(invalid("native debug local storage slot 重疊或順序錯誤"));
        }
        storage.push(NativeStorageInterval {
            binding: local.binding,
            register: local.register,
            slot: local.slot,
            start_pc,
            end_pc: local.end_pc,
            captured,
        });
        if local.start_pc < local.end_pc {
            events.push((local.start_pc, true, local.slot));
            events.push((local.end_pc, false, local.slot));
        }
    }
    let sort_units = events
        .len()
        .checked_mul(usize::BITS as usize)
        .ok_or_else(|| limit("native debug local sort work 溢位"))?;
    charge(work, sort_units)?;
    events.sort_unstable_by_key(|(pc, start, slot)| {
        (*pc, *start, if *start { *slot } else { u8::MAX - *slot })
    });
    let mut active = 0u8;
    for (_, start, slot) in events {
        if start {
            if slot != active {
                return Err(invalid("native debug local 起始 slot 非連續"));
            }
            active = active
                .checked_add(1)
                .ok_or_else(|| invalid("native debug active local 溢位"))?;
        } else {
            if active == 0 || slot != active - 1 {
                return Err(invalid("native debug local 結束順序無效"));
            }
            active -= 1;
        }
    }
    if active != 0 {
        return Err(invalid("native debug local 未結束"));
    }
    for (local, interval) in entry.locals.iter().zip(&storage) {
        check_storage_cfg(
            module,
            proto,
            local,
            interval,
            &storage,
            groups,
            work,
            max_temporary_bytes,
        )?;
    }
    charge(
        work,
        usize::from(proto.parameter_count)
            .checked_mul(entry.locals.len())
            .ok_or_else(|| limit("native debug 參數 work 溢位"))?,
    )?;
    for slot in 0..proto.parameter_count {
        let found = entry.locals.iter().any(|local| {
            local.slot == slot as u8
                && local.register.0 == slot + 1
                && local.start_pc == 0
                && local.initialized_pc == 0
        });
        if !found {
            return Err(invalid("native debug 參數 slot 缺失"));
        }
    }
    if let Some((binding, register)) = proto.named_vararg {
        charge(work, entry.locals.len())?;
        if !entry.locals.iter().any(|local| {
            local.binding == binding
                && local.register == register
                && usize::from(local.slot) == proto.parameter_count as usize
                && local.start_pc == 0
        }) {
            return Err(invalid("native debug 具名 vararg slot 缺失"));
        }
    }
    Ok(storage)
}

fn preflight_native_debug_bytes(
    module: &VerifiedModule,
    candidate: &NativeDebugCandidate,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<usize, BytecodeError> {
    let arc_header = size_of::<usize>()
        .checked_mul(2)
        .and_then(|bytes| bytes.checked_add(core::mem::align_of::<NativeDebug>()))
        .ok_or_else(|| limit("native debug Arc header 大小溢位"))?;
    let mut bytes = size_of::<NativeDebug>()
        .checked_add(arc_header)
        .ok_or_else(|| limit("native debug header 大小溢位"))?;
    if bytes > limits.max_artifact_bytes {
        return Err(limit("native debug header 超過配置額度"));
    }
    add_bytes(
        &mut bytes,
        candidate.source_name.capacity(),
        1,
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.prototypes.capacity(),
        size_of::<NativePrototypeDebug>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.prototypes.len(),
        size_of::<Vec<NativeStorageInterval>>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.prototypes.len(),
        size_of::<Vec<NativeCloseGroup>>(),
        limits.max_artifact_bytes,
    )?;
    charge(
        work,
        candidate
            .source_name
            .len()
            .checked_add(candidate.prototypes.len())
            .ok_or_else(|| limit("native debug preflight work 溢位"))?,
    )?;
    for (entry, proto) in candidate.prototypes.iter().zip(&module.module().prototypes) {
        let (group_count, close_count) = close_group_counts(proto, work)?;
        add_bytes(
            &mut bytes,
            group_count,
            size_of::<NativeCloseGroup>(),
            limits.max_artifact_bytes,
        )?;
        add_bytes(
            &mut bytes,
            close_count,
            size_of::<(Register, u16)>(),
            limits.max_artifact_bytes,
        )?;
        charge(
            work,
            entry
                .lines
                .len()
                .checked_add(entry.locals.len())
                .and_then(|sum| sum.checked_add(entry.upvalue_names.len()))
                .ok_or_else(|| limit("native debug preflight work 溢位"))?,
        )?;
        add_bytes(
            &mut bytes,
            entry.lines.capacity(),
            size_of::<u32>(),
            limits.max_artifact_bytes,
        )?;
        add_bytes(
            &mut bytes,
            entry.locals.capacity(),
            size_of::<NativeLocal>(),
            limits.max_artifact_bytes,
        )?;
        add_bytes(
            &mut bytes,
            entry.locals.len(),
            size_of::<NativeStorageInterval>(),
            limits.max_artifact_bytes,
        )?;
        add_bytes(
            &mut bytes,
            entry.upvalue_names.capacity(),
            size_of::<Option<Vec<u8>>>(),
            limits.max_artifact_bytes,
        )?;
        for local in &entry.locals {
            add_bytes(
                &mut bytes,
                local.name.capacity(),
                1,
                limits.max_artifact_bytes,
            )?;
            charge(work, local.name.len())?;
        }
        for name in &entry.upvalue_names {
            if let Some(name) = name {
                add_bytes(&mut bytes, name.capacity(), 1, limits.max_artifact_bytes)?;
                charge(work, name.len())?;
            }
        }
    }
    Ok(bytes)
}

/// 驗證候選資料的身分、範圍、活躍槽與資源額度；成功後才保留於 VerifiedModule。
pub fn verify_native_debug(
    module: &VerifiedModule,
    candidate: NativeDebugCandidate,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<NativeDebug, BytecodeError> {
    if module.official_artifact().is_some()
        || module
            .official_execution()
            .is_some_and(|plan| !plan.is_native_builtin())
    {
        return Err(invalid("官方匯入／plan 不可附加 native debug"));
    }
    charge(work, 1)?;
    if candidate.prototypes.len() != module.module().prototypes.len()
        || candidate.prototypes.len() > limits.max_prototypes
    {
        return Err(invalid("native debug prototype 數不符"));
    }
    let mut bytes = preflight_native_debug_bytes(module, &candidate, limits, work)?;
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug storage 清單配置失敗"))?;
    let mut close_groups = Vec::new();
    close_groups
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug close group 清單配置失敗"))?;
    for (entry, proto) in candidate.prototypes.iter().zip(&module.module().prototypes) {
        if entry.prototype != proto.id
            || entry.lines.len() != proto.instructions.len()
            || entry.upvalue_names.len() != proto.upvalues.len()
            || entry.line_defined > entry.last_line_defined
        {
            return Err(invalid("native debug prototype/line/upvalue 對應無效"));
        }
        if let Some(map) = module
            .official_execution()
            .filter(|plan| plan.is_native_builtin())
            .and_then(|plan| plan.upvalue_map(proto.id))
        {
            if entry.upvalue_names[usize::from(map.guest_count)..]
                .iter()
                .any(Option::is_some)
            {
                return Err(invalid("native debug 不可命名 hidden helper upvalue"));
            }
        }
        if entry
            .lines
            .iter()
            .any(|line| *line == 0 || *line > entry.last_line_defined.max(1))
        {
            return Err(invalid("native debug 行號無效"));
        }
        validate_required_local_coverage(entry, proto, module, work)?;
        let groups =
            build_close_groups(proto, work, limits.max_artifact_bytes.saturating_sub(bytes))?;
        let local_storage = validate_locals(
            entry,
            proto,
            module,
            &groups,
            work,
            limits.max_artifact_bytes.saturating_sub(bytes),
        )?;
        add_bytes(
            &mut bytes,
            local_storage.capacity().saturating_sub(entry.locals.len()),
            size_of::<NativeStorageInterval>(),
            limits.max_artifact_bytes,
        )?;
        storage.push(local_storage);
        let (expected_groups, expected_closes) = close_group_counts(proto, work)?;
        add_bytes(
            &mut bytes,
            groups.capacity().saturating_sub(expected_groups),
            size_of::<NativeCloseGroup>(),
            limits.max_artifact_bytes,
        )?;
        let actual_closes = groups
            .iter()
            .try_fold(0usize, |sum, group| {
                sum.checked_add(group.operands.capacity())
            })
            .ok_or_else(|| limit("native debug close group capacity 溢位"))?;
        add_bytes(
            &mut bytes,
            actual_closes.saturating_sub(expected_closes),
            size_of::<(Register, u16)>(),
            limits.max_artifact_bytes,
        )?;
        close_groups.push(groups);
    }
    add_bytes(
        &mut bytes,
        storage
            .capacity()
            .saturating_sub(candidate.prototypes.len()),
        size_of::<Vec<NativeStorageInterval>>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        close_groups
            .capacity()
            .saturating_sub(candidate.prototypes.len()),
        size_of::<Vec<NativeCloseGroup>>(),
        limits.max_artifact_bytes,
    )?;
    Ok(NativeDebug {
        source_name: candidate.source_name,
        prototypes: candidate.prototypes,
        storage,
        close_groups,
        allocated_bytes: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{
        BytecodeClosePath, BytecodeConstant, BytecodeExitKind, BytecodeInstruction, BytecodeModule,
        BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, ConstId, EnvironmentSource,
        FrameLayout, Instruction, LuaProfile, RVLU_NUMERIC_I64_F64, RVLU_V2, ResultMode, UpvalueId,
        verify_module,
    };

    fn binding(ordinal: u32) -> BytecodeBindingId {
        BytecodeBindingId {
            function: 0,
            ordinal,
        }
    }

    fn fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        let instructions = [
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::Move {
                dest: Register(0),
                src: Register(2),
            },
            Instruction::LoadConst {
                dest: Register(3),
                constant: ConstId(1),
            },
            Instruction::Move {
                dest: Register(0),
                src: Register(2),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span,
            close_path: None,
        })
        .collect();
        let module = BytecodeModule {
            format_version: RVLU_V2,
            profile: LuaProfile::Lua55,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![super::super::codec::BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 4,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 4,
                    initial_top: Register(4),
                    dynamic_top: Register(4),
                    return_base: Register(0),
                    environment: Register(1),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(1),
                global_environment_binding: binding(0),
                binding_registers: vec![
                    (binding(0), Register(1)),
                    (binding(1), Register(2)),
                    (binding(2), Register(3)),
                ],
                constants: vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(2)],
                upvalues: vec![],
                instructions,
                close_paths: vec![],
            }],
        };
        let candidate = NativeDebugCandidate {
            source_name: b"@forged.lua".to_vec(),
            prototypes: vec![NativePrototypeDebug {
                prototype: ProtoId(0),
                line_defined: 1,
                last_line_defined: 1,
                lines: vec![1; 5],
                upvalue_names: vec![],
                max_active_locals: 1,
                locals: vec![
                    NativeLocal {
                        binding: binding(1),
                        register: Register(2),
                        slot: 0,
                        initialized_pc: 0,
                        start_pc: 1,
                        end_pc: 2,
                        name: b"a".to_vec(),
                    },
                    NativeLocal {
                        binding: binding(2),
                        register: Register(3),
                        slot: 0,
                        initialized_pc: 2,
                        start_pc: 3,
                        end_pc: 5,
                        name: b"b".to_vec(),
                    },
                ],
            }],
        };
        (
            verify_module(module, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    fn check(
        candidate: NativeDebugCandidate,
        module: &VerifiedModule,
    ) -> Result<NativeDebug, BytecodeError> {
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        verify_native_debug(module, candidate, &VerifyLimits::default(), &mut work)
    }

    fn valid_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, candidate) = fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::Move {
            dest: Register(0),
            src: Register(3),
        };
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    fn named_vararg_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = fixture();
        let mut raw = verified.module().clone();
        let proto = &mut raw.prototypes[0];
        proto.is_variadic = true;
        proto.named_vararg = Some((binding(1), Register(2)));
        proto.instructions = [
            Instruction::LoadConst {
                dest: Register(0),
                constant: ConstId(0),
            },
            Instruction::Vararg {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span: raw.span,
            close_path: None,
        })
        .collect();
        candidate.prototypes[0].lines = vec![1; 3];
        candidate.prototypes[0].locals = vec![NativeLocal {
            binding: binding(1),
            register: Register(2),
            slot: 0,
            initialized_pc: 0,
            start_pc: 0,
            end_pc: 3,
            name: b"arg".to_vec(),
        }];
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn accepts_named_vararg_table_alive_through_implicit_vararg_read() {
        let (module, candidate) = named_vararg_fixture();
        check(candidate, &module).unwrap();
    }

    #[test]
    fn rejects_named_vararg_table_lifetime_ending_before_implicit_read() {
        let (module, mut candidate) = named_vararg_fixture();
        candidate.prototypes[0].locals[0].end_pc = 1;
        assert_eq!(
            check(candidate, &module).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_forged_short_storage_lifetime() {
        let (module, candidate) = fixture();
        assert_eq!(
            check(candidate, &module).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_forged_initialization_before_actual_write() {
        let (module, mut candidate) = fixture();
        candidate.prototypes[0].locals[1].initialized_pc = 1;
        assert_eq!(
            check(candidate, &module).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    fn captured_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (module, mut candidate) = fixture();
        let mut raw = module.module().clone();
        raw.prototypes[0].instructions[1].instruction = Instruction::Closure {
            dest: Register(0),
            proto: ProtoId(1),
        };
        raw.prototypes[0].instructions[3].instruction = Instruction::Move {
            dest: Register(0),
            src: Register(3),
        };
        let mut child = raw.prototypes[0].clone();
        child.id = ProtoId(1);
        child.function = 1;
        child.parent = Some(ProtoId(0));
        child.frame.environment_source = EnvironmentSource::ParentFrame {
            parent: ProtoId(0),
            register: Register(1),
        };
        child.upvalues = vec![BytecodeUpvalue {
            id: UpvalueId(0),
            source: BytecodeUpvalueSource::ParentLocal(binding(1)),
        }];
        child.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                span: raw.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span: raw.span,
                close_path: None,
            },
        ];
        raw.function_prototypes.push((1, ProtoId(1)));
        raw.prototypes.push(child);
        candidate.prototypes.push(NativePrototypeDebug {
            prototype: ProtoId(1),
            line_defined: 1,
            last_line_defined: 1,
            lines: vec![1; 2],
            locals: vec![],
            upvalue_names: vec![Some(b"a".to_vec())],
            max_active_locals: 0,
        });
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        (verified, candidate)
    }

    #[test]
    fn rejects_captured_local_reuse_without_close() {
        let (verified, candidate) = captured_fixture();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn accepts_close_on_all_paths_before_reuse() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions.insert(
            2,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span: raw.span,
                close_path: None,
            },
        );
        candidate.prototypes[0].lines.push(1);
        candidate.prototypes[0].locals[0].end_pc = 3;
        candidate.prototypes[0].locals[1].initialized_pc = 3;
        candidate.prototypes[0].locals[1].start_pc = 4;
        candidate.prototypes[0].locals[1].end_pc = 6;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        check(candidate, &verified).unwrap();
    }

    #[test]
    fn rejects_omitted_captured_binding_even_when_closed() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions.insert(
            2,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span: raw.span,
                close_path: None,
            },
        );
        candidate.prototypes[0].lines.push(1);
        candidate.prototypes[0].locals.remove(0);
        candidate.prototypes[0].locals[0].initialized_pc = 3;
        candidate.prototypes[0].locals[0].start_pc = 4;
        candidate.prototypes[0].locals[0].end_pc = 6;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_branch_that_skips_capture_close() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions.insert(
            2,
            BytecodeInstruction {
                instruction: Instruction::JumpIfFalse {
                    condition: Register(1),
                    target: super::super::InstructionOffset(4),
                },
                span: raw.span,
                close_path: None,
            },
        );
        raw.prototypes[0].instructions.insert(
            3,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span: raw.span,
                close_path: None,
            },
        );
        candidate.prototypes[0].lines.extend([1, 1]);
        candidate.prototypes[0].locals[0].end_pc = 4;
        candidate.prototypes[0].locals[1].initialized_pc = 4;
        candidate.prototypes[0].locals[1].start_pc = 5;
        candidate.prototypes[0].locals[1].end_pc = 7;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_branch_that_skips_local_initialization() {
        let (verified, mut candidate) = fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[1].instruction = Instruction::JumpIfFalse {
            condition: Register(1),
            target: super::super::InstructionOffset(3),
        };
        raw.prototypes[0].instructions[3].instruction = Instruction::Move {
            dest: Register(0),
            src: Register(3),
        };
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        candidate.prototypes[0].locals[0].end_pc = 2;
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_debug_start_after_first_local_read() {
        let (verified, mut candidate) = valid_fixture();
        candidate.prototypes[0].locals[1].start_pc = 4;
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_capacity_and_temporary_allocation_beyond_budget() {
        let (verified, candidate) = valid_fixture();
        let accepted = check(candidate.clone(), &verified).unwrap();
        let mut oversized = candidate.clone();
        oversized.source_name.reserve(1024);
        let tight = VerifyLimits {
            max_artifact_bytes: accepted.allocated_bytes() + 32,
            ..VerifyLimits::default()
        };
        let mut work = OfficialWorkBudget::for_limits(&tight).unwrap();
        assert_eq!(
            verify_native_debug(&verified, oversized, &tight, &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
        let tighter = VerifyLimits {
            max_artifact_bytes: accepted.allocated_bytes(),
            ..VerifyLimits::default()
        };
        let mut work = OfficialWorkBudget::for_limits(&tighter).unwrap();
        assert_eq!(
            verify_native_debug(&verified, candidate, &tighter, &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn rejects_close_of_outer_slot_while_inner_upvalue_is_open() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        raw.prototypes[0].instructions = [
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: Register(3),
                constant: ConstId(1),
            },
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Move {
                dest: Register(0),
                src: Register(3),
            },
            Instruction::Close {
                base: Register(3),
                count: 0,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span,
            close_path: None,
        })
        .collect();
        raw.prototypes[1].upvalues.push(BytecodeUpvalue {
            id: UpvalueId(1),
            source: BytecodeUpvalueSource::ParentLocal(binding(2)),
        });
        candidate.prototypes[0].lines = vec![1; 7];
        candidate.prototypes[0].max_active_locals = 2;
        candidate.prototypes[0].locals[0].end_pc = 7;
        candidate.prototypes[0].locals[1].initialized_pc = 1;
        candidate.prototypes[0].locals[1].start_pc = 2;
        candidate.prototypes[0].locals[1].end_pc = 6;
        candidate.prototypes[0].locals[1].slot = 1;
        candidate.prototypes[1]
            .upvalue_names
            .push(Some(b"b".to_vec()));
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_close_of_outer_slot_while_inner_tbc_is_pending() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        let marker = BytecodeClosePath {
            kind: BytecodeExitKind::Normal,
            span,
            from_scope: 1,
            target_scope: Some(1),
            bindings: vec![binding(2)],
            registers: vec![Register(3)],
        };
        let exit = BytecodeClosePath {
            target_scope: Some(0),
            ..marker.clone()
        };
        raw.prototypes[0].close_paths.push(exit.clone());
        raw.prototypes[0].instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(0),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(3),
                    src: Register(0),
                },
                span,
                close_path: Some(marker),
            },
            BytecodeInstruction {
                instruction: Instruction::Closure {
                    dest: Register(0),
                    proto: ProtoId(1),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(0),
                    src: Register(3),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(3),
                    count: 1,
                },
                span,
                close_path: Some(exit),
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span,
                close_path: None,
            },
        ];
        candidate.prototypes[0].lines = vec![1; 7];
        candidate.prototypes[0].max_active_locals = 2;
        candidate.prototypes[0].locals[0].end_pc = 7;
        candidate.prototypes[0].locals[1].initialized_pc = 1;
        candidate.prototypes[0].locals[1].start_pc = 2;
        candidate.prototypes[0].locals[1].end_pc = 6;
        candidate.prototypes[0].locals[1].slot = 1;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn rejects_upvalue_close_that_would_run_tbc_callback_early() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        let marker = BytecodeClosePath {
            kind: BytecodeExitKind::Normal,
            span,
            from_scope: 1,
            target_scope: Some(1),
            bindings: vec![binding(1)],
            registers: vec![Register(2)],
        };
        let exit = BytecodeClosePath {
            target_scope: Some(0),
            ..marker.clone()
        };
        raw.prototypes[0].close_paths.push(exit.clone());
        raw.prototypes[0].instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(0),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                span,
                close_path: Some(marker),
            },
            BytecodeInstruction {
                instruction: Instruction::Closure {
                    dest: Register(0),
                    proto: ProtoId(1),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(0),
                    src: Register(2),
                },
                span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 1,
                },
                span,
                close_path: Some(exit),
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span,
                close_path: None,
            },
        ];
        candidate.prototypes[0].lines = vec![1; 7];
        candidate.prototypes[0].locals.truncate(1);
        candidate.prototypes[0].locals[0].end_pc = 7;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn accepts_two_captured_locals_closed_in_one_group() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        raw.prototypes[0].instructions = [
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: Register(3),
                constant: ConstId(1),
            },
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Close {
                base: Register(3),
                count: 0,
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span,
            close_path: None,
        })
        .collect();
        raw.prototypes[1].upvalues.push(BytecodeUpvalue {
            id: UpvalueId(1),
            source: BytecodeUpvalueSource::ParentLocal(binding(2)),
        });
        candidate.prototypes[0].lines = vec![1; 6];
        candidate.prototypes[0].max_active_locals = 2;
        candidate.prototypes[0].locals[0].end_pc = 5;
        candidate.prototypes[0].locals[1].initialized_pc = 1;
        candidate.prototypes[0].locals[1].start_pc = 2;
        candidate.prototypes[0].locals[1].end_pc = 5;
        candidate.prototypes[0].locals[1].slot = 1;
        candidate.prototypes[1]
            .upvalue_names
            .push(Some(b"b".to_vec()));
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let validated = check(candidate, &verified).unwrap();
        let group = &validated.close_groups_for(ProtoId(0)).unwrap()[0];
        assert_eq!(group.emit_pc, 3);
        assert_eq!(group.operands(), &[(Register(3), 0), (Register(2), 0)]);
    }

    #[test]
    fn rejects_branch_into_middle_of_close_group() {
        let (verified, mut candidate) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        raw.prototypes[0].instructions = [
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::JumpIfFalse {
                condition: Register(1),
                target: super::super::InstructionOffset(4),
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span,
            close_path: None,
        })
        .collect();
        candidate.prototypes[0].lines = vec![1; 6];
        candidate.prototypes[0].locals.truncate(1);
        candidate.prototypes[0].locals[0].end_pc = 6;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let error = check(candidate, &verified).unwrap_err();
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("branch 進入 close group 中段"));
    }

    #[test]
    fn rejects_swapped_slots_for_simultaneously_visible_locals() {
        let (verified, mut candidate) = valid_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[1].instruction = Instruction::LoadConst {
            dest: Register(3),
            constant: ConstId(1),
        };
        raw.prototypes[0].instructions[2].instruction = Instruction::Move {
            dest: Register(0),
            src: Register(2),
        };
        candidate.prototypes[0].max_active_locals = 2;
        candidate.prototypes[0].locals[0].start_pc = 2;
        candidate.prototypes[0].locals[0].end_pc = 5;
        candidate.prototypes[0].locals[0].slot = 1;
        candidate.prototypes[0].locals[1].initialized_pc = 1;
        candidate.prototypes[0].locals[1].start_pc = 2;
        candidate.prototypes[0].locals[1].end_pc = 5;
        candidate.prototypes[0].locals[1].slot = 0;
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn exhausted_work_is_not_rolled_back() {
        let (verified, candidate) = valid_fixture();
        let mut work = OfficialWorkBudget::new(2);
        assert_eq!(
            verify_native_debug(&verified, candidate, &VerifyLimits::default(), &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
        assert!(work.consumed() > 0);
        assert_eq!(work.remaining() + work.consumed(), 2);
    }

    #[test]
    fn bare_export_rejects_branch_into_close_group_middle() {
        let (verified, _) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        raw.prototypes[0].instructions = [
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(0),
            },
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::JumpIfFalse {
                condition: Register(1),
                target: super::super::InstructionOffset(4),
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Close {
                base: Register(2),
                count: 0,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ]
        .into_iter()
        .map(|instruction| BytecodeInstruction {
            instruction,
            span,
            close_path: None,
        })
        .collect();
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let error = super::super::official_export::emit_official_chunk(
            &verified,
            ProtoId(0),
            LuaProfile::Lua55,
            false,
            &super::super::official::OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            super::super::official_export::OfficialExportErrorKind::InvalidPrototype
        );
        assert!(
            error.detail.contains("bare native close group"),
            "{error:?}"
        );
    }

    #[test]
    fn bare_export_rejects_reversed_tbc_physical_slot_order() {
        let (verified, _) = fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        let declare = |binding, register| BytecodeClosePath {
            kind: BytecodeExitKind::Normal,
            span,
            from_scope: 1,
            target_scope: Some(1),
            bindings: vec![binding],
            registers: vec![register],
        };
        let exit = BytecodeClosePath {
            kind: BytecodeExitKind::Normal,
            span,
            from_scope: 1,
            target_scope: Some(0),
            bindings: vec![binding(1), binding(2)],
            registers: vec![Register(2), Register(3)],
        };
        raw.prototypes[0].close_paths.push(exit.clone());
        raw.prototypes[0].instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                span,
                close_path: Some(declare(binding(1), Register(2))),
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(3),
                    src: Register(0),
                },
                span,
                close_path: Some(declare(binding(2), Register(3))),
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 1,
                },
                span,
                close_path: Some(exit.clone()),
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(3),
                    count: 1,
                },
                span,
                close_path: Some(exit),
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span,
                close_path: None,
            },
        ];
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
        let error = super::super::official_export::emit_official_chunk(
            &verified,
            ProtoId(0),
            LuaProfile::Lua55,
            false,
            &super::super::official::OfficialChunkLimits::default(),
            &mut work,
        )
        .unwrap_err();
        assert_eq!(
            error.kind,
            super::super::official_export::OfficialExportErrorKind::InvalidPrototype
        );
        assert!(error.detail.contains("TBC Close 物理槽順序無效"));
    }

    #[test]
    fn bare_export_reports_exhausted_close_group_work() {
        let (verified, _) = captured_fixture();
        let mut raw = verified.module().clone();
        let span = raw.span;
        raw.prototypes[0].instructions.insert(
            2,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 0,
                },
                span,
                close_path: None,
            },
        );
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut stage_error = None;
        for units in 1..=4_096 {
            let mut work = OfficialWorkBudget::new(units);
            let error = super::super::official_export::emit_official_chunk(
                &verified,
                ProtoId(0),
                LuaProfile::Lua55,
                false,
                &super::super::official::OfficialChunkLimits::default(),
                &mut work,
            )
            .unwrap_err();
            if error.detail.contains("bare native close group") {
                stage_error = Some((error, work.consumed()));
                break;
            }
        }
        let (error, consumed) = stage_error.expect("需能在 close group 階段耗盡 work");
        assert_eq!(
            error.kind,
            super::super::official_export::OfficialExportErrorKind::WorkExhausted
        );
        assert!(consumed > 0);
    }
}
