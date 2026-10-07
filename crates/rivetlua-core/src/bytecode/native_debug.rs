//! P05 驗證的一般 RVLU 來源除錯資料；不屬於 RVLU_V2 wire。

use core::mem::size_of;
use core::ops::Range;

use super::codec::{
    BytecodeBindingId, BytecodeClosePath, BytecodeError, BytecodeErrorCode, BytecodeInstruction,
    BytecodePrototype, VerifyLimits,
};
use super::official_translation::OfficialWorkBudget;
use super::{
    EnvironmentSource, Instruction, InstructionOffset, LuaProfile, ProtoId, Register, ResultMode,
    UpvalueId, VerifiedModule,
};

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
    pub temporaries: Vec<NativeTemporary>,
    pub initializer_temporaries: Vec<NativeInitializerTemporary>,
    pub non_counted_pcs: Vec<(ProtoId, InstructionOffset)>,
}

/// 編譯器在一般來源的 Call 暫停點宣告的父表達式 pending value。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeTemporary {
    pub prototype: ProtoId,
    pub call_pc: InstructionOffset,
    pub ordinal: u16,
    pub register: Register,
}

/// Native-only：local 初始化期間尚未具名的 guest slot；transport 不保存此資料。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeInitializerTemporary {
    pub prototype: ProtoId,
    pub binding: BytecodeBindingId,
    pub register: Register,
    pub slot: u8,
    pub start_pc: u32,
    pub end_pc: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDebug {
    source_name: Vec<u8>,
    prototypes: Vec<NativePrototypeDebug>,
    semantic_upvalues: Vec<NativeSemanticUpvalueMap>,
    storage: Vec<Vec<NativeStorageInterval>>,
    close_groups: Vec<Vec<NativeCloseGroup>>,
    temporaries: Vec<NativeTemporary>,
    temporary_ranges: Vec<Range<usize>>,
    initializer_temporaries: Vec<NativeInitializerTemporary>,
    initializer_ranges: Vec<Range<usize>>,
    non_counted_pcs: Vec<(ProtoId, InstructionOffset)>,
    allocated_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSemanticUpvalue {
    Closure(UpvalueId),
    Environment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeSemanticUpvalueMap {
    physical_guest_count: u16,
    environment: bool,
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

    pub fn semantic_upvalue_count(&self, id: ProtoId) -> Option<usize> {
        self.prototypes
            .iter()
            .position(|entry| entry.prototype == id)
            .and_then(|index| self.semantic_upvalues.get(index))
            .map(|entry| usize::from(entry.physical_guest_count) + usize::from(entry.environment))
    }

    pub fn semantic_upvalue(&self, id: ProtoId, index: usize) -> Option<NativeSemanticUpvalue> {
        let map = self
            .prototypes
            .iter()
            .position(|entry| entry.prototype == id)
            .and_then(|index| self.semantic_upvalues.get(index))?;
        if index < usize::from(map.physical_guest_count) {
            Some(NativeSemanticUpvalue::Closure(UpvalueId(index as u16)))
        } else if map.environment && index == usize::from(map.physical_guest_count) {
            Some(NativeSemanticUpvalue::Environment)
        } else {
            None
        }
    }

    pub fn semantic_upvalue_name(&self, id: ProtoId, index: usize) -> Option<Option<&[u8]>> {
        self.semantic_upvalue(id, index)?;
        self.prototype(id)
            .and_then(|entry| entry.upvalue_names.get(index))
            .map(|name| name.as_deref())
    }

    pub fn close_groups_for(&self, id: ProtoId) -> Option<&[NativeCloseGroup]> {
        self.prototypes
            .iter()
            .position(|entry| entry.prototype == id)
            .and_then(|index| self.close_groups.get(index).map(Vec::as_slice))
    }

    pub fn temporaries_for(&self, id: ProtoId) -> Option<&[NativeTemporary]> {
        let index = self
            .prototypes
            .iter()
            .position(|entry| entry.prototype == id)?;
        self.temporary_ranges
            .get(index)
            .and_then(|range| self.temporaries.get(range.clone()))
    }

    pub fn temporaries_at(
        &self,
        id: ProtoId,
        call_pc: InstructionOffset,
    ) -> Option<&[NativeTemporary]> {
        let entries = self.temporaries_for(id)?;
        let start = entries.partition_point(|entry| entry.call_pc.0 < call_pc.0);
        let end = entries.partition_point(|entry| entry.call_pc.0 <= call_pc.0);
        Some(&entries[start..end])
    }

    pub fn initializer_temporaries_for(
        &self,
        id: ProtoId,
    ) -> Option<&[NativeInitializerTemporary]> {
        let index = self
            .prototypes
            .iter()
            .position(|entry| entry.prototype == id)?;
        self.initializer_ranges
            .get(index)
            .and_then(|range| self.initializer_temporaries.get(range.clone()))
    }

    pub fn is_non_counted_pc(&self, id: ProtoId, pc: InstructionOffset) -> bool {
        self.non_counted_pcs
            .binary_search_by_key(&(id.0, pc.0), |(prototype, offset)| (prototype.0, offset.0))
            .is_ok()
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

fn temporary_successors(
    proto: &BytecodePrototype,
    pc: usize,
) -> Result<[Option<usize>; 3], BytecodeError> {
    let count = proto.instructions.len();
    let next = pc.checked_add(1).filter(|next| *next < count);
    let mut successors = [None; 3];
    match &proto.instructions[pc].instruction {
        Instruction::Jump { target } => successors[0] = Some(target.0 as usize),
        Instruction::JumpIfFalse { target, .. }
        | Instruction::NumericForPrepare { exit: target, .. } => {
            successors[0] = Some(target.0 as usize);
            successors[1] = next;
        }
        Instruction::NumericForNext { target, exit, .. } => {
            successors[0] = Some(target.0 as usize);
            successors[1] = Some(exit.0 as usize);
        }
        Instruction::Return { .. } | Instruction::TailCall { .. } => {}
        _ => successors[0] = next,
    }
    if successors
        .iter()
        .flatten()
        .any(|successor| *successor >= count)
    {
        return Err(invalid(
            "native debug temporary CFG successor 超出 prototype",
        ));
    }
    Ok(successors)
}

fn temporary_semantic_read(instruction: &Instruction, register: Register) -> bool {
    matches!(instruction,
        Instruction::BinaryOp { left, right, .. } if *left == register || *right == register
    ) || matches!(instruction,
        Instruction::GetTable { table, key, .. } if *table == register || *key == register
    ) || matches!(instruction,
        Instruction::Call { base, arg_count, .. } | Instruction::TailCall { base, arg_count, .. }
            if in_range(register, *base, arg_count.saturating_add(1))
    )
}

fn verify_initializer_interval(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    local: &NativeLocal,
    interval: &NativeInitializerTemporary,
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<(), BytecodeError> {
    let count = proto.instructions.len();
    let start = interval.start_pc as usize;
    let end = interval.end_pc as usize;
    if !proto.frame.registers_start_as_nil
        || interval.register.0 == 0
        || interval.register == proto.global_environment
        || interval.register.0 >= proto.frame.initial_top.0
        || interval.register.0 >= proto.register_count
        || start >= end
        || end >= count
        || local.binding != interval.binding
        || local.register != interval.register
        || local.slot != interval.slot
        || local.start_pc != interval.end_pc
        || local.initialized_pc < interval.start_pc
        || local.initialized_pc >= interval.end_pc
        || local.end_pc < interval.end_pc
    {
        return Err(invalid("native debug initializer slot/binding/PC 無效"));
    }
    let scratch = count
        .checked_mul(size_of::<u8>() + size_of::<usize>())
        .ok_or_else(|| limit("native debug initializer CFG 暫存大小溢位"))?;
    if scratch > max_temporary_bytes {
        return Err(limit("native debug initializer CFG 暫存配置額度超限"));
    }
    charge(
        work,
        count
            .checked_mul(16)
            .ok_or_else(|| limit("native debug initializer CFG work 溢位"))?,
    )?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(count)
        .map_err(|_| limit("native debug initializer CFG 配置失敗"))?;
    seen.resize(count, 0u8);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(count)
        .map_err(|_| limit("native debug initializer CFG worklist 配置失敗"))?;
    if seen
        .capacity()
        .checked_add(
            pending
                .capacity()
                .checked_mul(size_of::<usize>())
                .ok_or_else(|| limit("native debug initializer CFG capacity 溢位"))?,
        )
        .is_none_or(|bytes| bytes > max_temporary_bytes)
    {
        return Err(limit("native debug initializer CFG capacity 超限"));
    }
    seen[0] = 1;
    pending.push(0);
    while let Some(pc) = pending.pop() {
        for successor in temporary_successors(proto, pc)?.into_iter().flatten() {
            if seen[successor] == 0 {
                seen[successor] = 1;
                pending.push(successor);
            }
        }
    }
    if seen[start] == 0 {
        return Err(invalid("native debug initializer CFG 起點不可達"));
    }
    for (pc, entry) in proto.instructions.iter().enumerate() {
        let instruction = &entry.instruction;
        let (read, write, possible_write, close) =
            prototype_register_access(proto, instruction, interval.register);
        let early_capture = pc < end && capture_at(module, instruction, interval.binding, work)?;
        if (pc < start && (read || write || possible_write || close))
            || (start <= pc
                && pc < end
                && (read
                    || possible_write
                    || close
                    || early_capture
                    || (write != (pc == local.initialized_pc as usize))))
            || (pc < start && early_capture)
        {
            return Err(invalid("native debug initializer register 寫入契約無效"));
        }
        if start <= pc
            && pc < end
            && matches!(
                instruction,
                Instruction::Jump { .. }
                    | Instruction::JumpIfFalse { .. }
                    | Instruction::NumericForPrepare { .. }
                    | Instruction::NumericForNext { .. }
                    | Instruction::Return { .. }
                    | Instruction::TailCall { .. }
            )
        {
            return Err(invalid("native debug initializer 區間含控制轉移"));
        }
        for successor in temporary_successors(proto, pc)?.into_iter().flatten() {
            if start <= pc && pc < end {
                if successor != pc + 1 {
                    return Err(invalid("native debug initializer 提前離開區間"));
                }
            } else if start <= successor && successor < end && (successor != start || pc >= end) {
                return Err(invalid("native debug initializer CFG 跳入或重入區間"));
            } else if pc >= end && successor <= start && successor < pc {
                return Err(invalid("native debug initializer CFG 可能重入 future slot"));
            }
        }
    }
    Ok(())
}

fn verify_temporary_initialized(
    proto: &BytecodePrototype,
    call_pc: usize,
    register: Register,
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<(), BytecodeError> {
    let count = proto.instructions.len();
    let states = count
        .checked_mul(2)
        .ok_or_else(|| limit("native debug temporary CFG state 溢位"))?;
    let needed = count
        .checked_add(
            states
                .checked_mul(size_of::<(usize, bool)>())
                .ok_or_else(|| limit("native debug temporary CFG 大小溢位"))?,
        )
        .ok_or_else(|| limit("native debug temporary CFG 大小溢位"))?;
    if needed > max_temporary_bytes {
        return Err(limit("native debug temporary CFG 暫存額度超限"));
    }
    let mut seen = Vec::new();
    seen.try_reserve_exact(count)
        .map_err(|_| limit("native debug temporary CFG 配置失敗"))?;
    seen.resize(count, 0u8);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(states)
        .map_err(|_| limit("native debug temporary CFG 配置失敗"))?;
    if seen
        .capacity()
        .checked_add(
            pending
                .capacity()
                .checked_mul(size_of::<(usize, bool)>())
                .ok_or_else(|| limit("native debug temporary CFG capacity 溢位"))?,
        )
        .is_none_or(|actual| actual > max_temporary_bytes)
    {
        return Err(limit("native debug temporary CFG capacity 超限"));
    }
    if count == 0 {
        return Err(invalid("native debug temporary Call 不可達"));
    }
    pending.push((0usize, false));
    seen[0] = 1;
    let mut reached = false;
    while let Some((pc, initialized)) = pending.pop() {
        charge(work, 1)?;
        if pc == call_pc {
            if !initialized {
                return Err(invalid(
                    "native debug temporary 在 Call 前未經所有路徑初始化",
                ));
            }
            reached = true;
            continue;
        }
        let (read, write, possible_write, _) =
            prototype_register_access(proto, &proto.instructions[pc].instruction, register);
        let initialized = if write && (!read || initialized) {
            true
        } else {
            initialized && !possible_write
        };
        for successor in temporary_successors(proto, pc)?.into_iter().flatten() {
            let bit = if initialized { 2 } else { 1 };
            if seen[successor] & bit == 0 {
                seen[successor] |= bit;
                pending.push((successor, initialized));
            }
        }
    }
    if !reached {
        return Err(invalid("native debug temporary Call 不可達"));
    }
    Ok(())
}

fn verify_temporary_consumed(
    proto: &BytecodePrototype,
    call_pc: usize,
    register: Register,
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<(), BytecodeError> {
    let first = call_pc
        .checked_add(1)
        .filter(|pc| *pc < proto.instructions.len())
        .ok_or_else(|| invalid("native debug temporary Call 後缺少語意使用"))?;
    verify_temporary_consumed_from(proto, first, register, false, work, max_temporary_bytes)
}

fn verify_temporary_consumed_from(
    proto: &BytecodePrototype,
    first: usize,
    register: Register,
    moved_to_call: bool,
    work: &mut OfficialWorkBudget,
    max_temporary_bytes: usize,
) -> Result<(), BytecodeError> {
    let count = proto.instructions.len();
    let stack_slots = count
        .checked_mul(4)
        .ok_or_else(|| limit("native debug temporary CFG stack 溢位"))?;
    let needed = count
        .checked_add(
            stack_slots
                .checked_mul(size_of::<(usize, bool)>())
                .ok_or_else(|| limit("native debug temporary CFG 大小溢位"))?,
        )
        .ok_or_else(|| limit("native debug temporary CFG 大小溢位"))?;
    if needed > max_temporary_bytes {
        return Err(limit("native debug temporary CFG 暫存額度超限"));
    }
    let mut colors = Vec::new();
    colors
        .try_reserve_exact(count)
        .map_err(|_| limit("native debug temporary CFG 配置失敗"))?;
    colors.resize(count, 0u8);
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(stack_slots)
        .map_err(|_| limit("native debug temporary CFG 配置失敗"))?;
    if colors
        .capacity()
        .checked_add(
            pending
                .capacity()
                .checked_mul(size_of::<(usize, bool)>())
                .ok_or_else(|| limit("native debug temporary CFG capacity 溢位"))?,
        )
        .is_none_or(|actual| actual > max_temporary_bytes)
    {
        return Err(limit("native debug temporary CFG capacity 超限"));
    }
    pending.push((first, false));
    while let Some((pc, leaving)) = pending.pop() {
        charge(work, 1)?;
        if leaving {
            colors[pc] = 2;
            continue;
        }
        match colors[pc] {
            2 => continue,
            1 => return Err(invalid("native debug temporary 在語意使用前形成 CFG 循環")),
            _ => {}
        }
        let instruction = &proto.instructions[pc].instruction;
        let (read, write, possible_write, _) =
            prototype_register_access(proto, instruction, register);
        if read {
            if let Instruction::Move { dest, src } = instruction {
                if !moved_to_call && *src == register && *dest != register {
                    let allocated = colors
                        .capacity()
                        .checked_add(
                            pending
                                .capacity()
                                .checked_mul(size_of::<(usize, bool)>())
                                .ok_or_else(|| limit("native debug temporary CFG capacity 溢位"))?,
                        )
                        .ok_or_else(|| limit("native debug temporary CFG capacity 溢位"))?;
                    let remaining = max_temporary_bytes
                        .checked_sub(allocated)
                        .ok_or_else(|| limit("native debug temporary CFG capacity 超限"))?;
                    let next = pc
                        .checked_add(1)
                        .filter(|next| *next < count)
                        .ok_or_else(|| invalid("native debug temporary Move 後缺少外層 Call"))?;
                    verify_temporary_consumed_from(proto, next, *dest, true, work, remaining)?;
                    colors[pc] = 2;
                    continue;
                }
            }
            let semantic_read = if moved_to_call {
                matches!(instruction,
                    Instruction::Call { base, arg_count, .. } | Instruction::TailCall { base, arg_count, .. }
                        if in_range(register, *base, arg_count.saturating_add(1)))
            } else {
                temporary_semantic_read(instruction, register)
            };
            if !semantic_read {
                return Err(invalid("native debug temporary 首次讀取不是父運算"));
            }
            colors[pc] = 2;
            continue;
        }
        if write || possible_write {
            return Err(invalid("native debug temporary 在語意使用前被覆寫"));
        }
        let successors = temporary_successors(proto, pc)?;
        if successors.iter().all(Option::is_none) {
            return Err(invalid("native debug temporary 在語意使用前退出"));
        }
        colors[pc] = 1;
        pending.push((pc, true));
        for successor in successors.into_iter().flatten() {
            pending.push((successor, false));
        }
    }
    Ok(())
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
        candidate.temporaries.capacity(),
        size_of::<NativeTemporary>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.initializer_temporaries.capacity(),
        size_of::<NativeInitializerTemporary>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.non_counted_pcs.capacity(),
        size_of::<(ProtoId, InstructionOffset)>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.prototypes.len(),
        size_of::<Range<usize>>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        candidate.prototypes.len(),
        size_of::<Range<usize>>(),
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
    add_bytes(
        &mut bytes,
        candidate.prototypes.len(),
        size_of::<NativeSemanticUpvalueMap>(),
        limits.max_artifact_bytes,
    )?;
    charge(
        work,
        candidate
            .source_name
            .len()
            .checked_add(candidate.prototypes.len())
            .and_then(|sum| sum.checked_add(candidate.temporaries.len()))
            .and_then(|sum| sum.checked_add(candidate.initializer_temporaries.len()))
            .and_then(|sum| sum.checked_add(candidate.non_counted_pcs.len()))
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

fn verify_semantic_upvalues(
    module: &VerifiedModule,
    entry: &NativePrototypeDebug,
    proto: &super::codec::BytecodePrototype,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<NativeSemanticUpvalueMap, BytecodeError> {
    charge(work, proto.instructions.len().saturating_add(1))?;
    let uses_global_environment = proto.instructions.iter().any(|entry| {
        matches!(
            entry.instruction,
            Instruction::GetTable { table, .. } | Instruction::SetTable { table, .. }
                if table == proto.global_environment
        )
    });
    let environment = module.profile() == LuaProfile::Lua55
        && uses_global_environment
        && matches!(
            proto.frame.environment_source,
            EnvironmentSource::RootExternal | EnvironmentSource::ParentFrame { .. }
        );
    let physical_guest_count = module
        .official_execution()
        .filter(|plan| plan.is_native_builtin())
        .and_then(|plan| plan.upvalue_map(proto.id))
        .map_or(proto.upvalues.len(), |map| usize::from(map.guest_count));
    let semantic_count = physical_guest_count
        .checked_add(usize::from(environment))
        .ok_or_else(|| limit("native debug 語意 upvalue 數溢位"))?;
    let expected_names = proto
        .upvalues
        .len()
        .checked_add(usize::from(environment))
        .ok_or_else(|| limit("native debug upvalue 名稱數溢位"))?;
    if semantic_count > limits.max_upvalues_per_prototype
        || expected_names > limits.max_upvalues_per_prototype
    {
        return Err(limit("native debug 語意 upvalue 超過限制"));
    }
    if entry.upvalue_names.len() != expected_names
        || environment
            && entry
                .upvalue_names
                .get(physical_guest_count)
                .and_then(Option::as_deref)
                != Some(b"_ENV")
        || entry.upvalue_names[semantic_count..]
            .iter()
            .any(Option::is_some)
    {
        return Err(invalid("native debug 語意/hidden upvalue 對應無效"));
    }
    Ok(NativeSemanticUpvalueMap {
        physical_guest_count: u16::try_from(physical_guest_count)
            .map_err(|_| limit("native debug guest upvalue 數溢位"))?,
        environment,
    })
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
    let mut prior_non_counted = None;
    for &(prototype, offset) in &candidate.non_counted_pcs {
        charge(work, module.module().prototypes.len().saturating_add(1))?;
        let key = (prototype.0, offset.0);
        if prior_non_counted.is_some_and(|prior| key <= prior) {
            return Err(invalid("native debug non-counted PC 順序或重複無效"));
        }
        let Some(proto) = module
            .module()
            .prototypes
            .iter()
            .find(|entry| entry.id == prototype)
        else {
            return Err(invalid("native debug non-counted prototype 不存在"));
        };
        if !matches!(
            proto
                .instructions
                .get(offset.0 as usize)
                .map(|entry| &entry.instruction),
            Some(
                Instruction::LoadNil { .. }
                    | Instruction::Move { .. }
                    | Instruction::LoadConst { .. }
                    | Instruction::GetUpvalue { .. }
            )
        ) {
            return Err(invalid("native debug non-counted PC 指令無效"));
        }
        prior_non_counted = Some(key);
    }
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug storage 清單配置失敗"))?;
    let mut close_groups = Vec::new();
    close_groups
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug close group 清單配置失敗"))?;
    let mut semantic_upvalues = Vec::new();
    semantic_upvalues
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug 語意 upvalue 清單配置失敗"))?;
    let mut temporary_ranges = Vec::new();
    temporary_ranges
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug temporary range 配置失敗"))?;
    let mut temporary_cursor = 0usize;
    let mut initializer_ranges = Vec::new();
    initializer_ranges
        .try_reserve_exact(candidate.prototypes.len())
        .map_err(|_| limit("native debug initializer range 配置失敗"))?;
    let mut initializer_cursor = 0usize;
    for (entry, proto) in candidate.prototypes.iter().zip(&module.module().prototypes) {
        let root = proto.parent.is_none();
        let valid_definition_range = if root {
            entry.line_defined == 0 && entry.last_line_defined == 0
        } else {
            entry.line_defined > 0 && entry.line_defined <= entry.last_line_defined
        };
        if entry.prototype != proto.id
            || entry.lines.len() != proto.instructions.len()
            || !valid_definition_range
        {
            return Err(invalid("native debug prototype/line/upvalue 對應無效"));
        }
        semantic_upvalues.push(verify_semantic_upvalues(
            module, entry, proto, limits, work,
        )?);
        if entry
            .lines
            .iter()
            .any(|line| *line == 0 || (!root && *line > entry.last_line_defined))
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
        let start = temporary_cursor;
        while candidate
            .temporaries
            .get(temporary_cursor)
            .is_some_and(|temporary| temporary.prototype == proto.id)
        {
            temporary_cursor += 1;
        }
        let mut prior_pc = None;
        let mut prior_register = None;
        for (index, temporary) in candidate.temporaries[start..temporary_cursor]
            .iter()
            .enumerate()
        {
            charge(
                work,
                proto
                    .instructions
                    .len()
                    .checked_mul(2)
                    .and_then(|cost| cost.checked_add(entry.locals.len()))
                    .and_then(|cost| {
                        cost.checked_add(
                            module
                                .official_execution()
                                .map_or(0, |plan| plan.calls().len()),
                        )
                    })
                    .ok_or_else(|| limit("native debug temporary 檢查 work 溢位"))?,
            )?;
            let pc = temporary.call_pc.0 as usize;
            let expected_ordinal = if prior_pc == Some(pc) {
                prior_register
                    .map(|(_, ordinal): (Register, u16)| ordinal.checked_add(1))
                    .flatten()
                    .ok_or_else(|| invalid("native debug temporary ordinal 溢位"))?
            } else {
                1
            };
            let mut duplicate_register = false;
            if prior_pc == Some(pc) {
                for prior in candidate.temporaries[start..start + index]
                    .iter()
                    .rev()
                    .take_while(|prior| prior.call_pc == temporary.call_pc)
                {
                    charge(work, 1)?;
                    duplicate_register |= prior.register == temporary.register;
                }
            }
            if temporary.ordinal != expected_ordinal
                || pc >= proto.instructions.len()
                || prior_pc.is_some_and(|prior| pc < prior)
                || duplicate_register
                || temporary.register.0 >= proto.register_count
                || temporary.register.0 < proto.frame.initial_top.0
                || temporary.register == proto.global_environment
                || entry.locals.iter().any(|local| {
                    local.register == temporary.register
                        && local.start_pc as usize <= pc
                        && pc < local.end_pc as usize
                })
                || module
                    .official_execution()
                    .filter(|plan| plan.is_native_builtin())
                    .is_some_and(|plan| {
                        plan.calls().iter().any(|call| {
                            call.prototype == proto.id && call.call_pc == temporary.call_pc
                        })
                    })
            {
                return Err(invalid(
                    "native debug temporary PC/ordinal/register/alias 無效",
                ));
            }
            let instruction = &proto.instructions[pc].instruction;
            if !matches!(instruction, Instruction::Call { .. }) {
                return Err(invalid("native debug temporary 只能映射 Call"));
            }
            let (input, output, possible_output, _) =
                prototype_register_access(proto, instruction, temporary.register);
            if input || output || possible_output {
                return Err(invalid("native debug temporary 與 Call input/output 重疊"));
            }
            let scratch = limits.max_artifact_bytes.saturating_sub(bytes);
            verify_temporary_initialized(proto, pc, temporary.register, work, scratch)?;
            verify_temporary_consumed(proto, pc, temporary.register, work, scratch)?;
            prior_pc = Some(pc);
            prior_register = Some((temporary.register, temporary.ordinal));
        }
        temporary_ranges.push(start..temporary_cursor);
        let initializer_start = initializer_cursor;
        while candidate
            .initializer_temporaries
            .get(initializer_cursor)
            .is_some_and(|temporary| temporary.prototype == proto.id)
        {
            initializer_cursor += 1;
        }
        let mut previous_initializer: Option<(u32, u32, u8)> = None;
        for initializer in &candidate.initializer_temporaries[initializer_start..initializer_cursor]
        {
            charge(work, entry.locals.len().saturating_add(1))?;
            let local = entry
                .locals
                .iter()
                .find(|local| local.binding == initializer.binding)
                .ok_or_else(|| invalid("native debug initializer binding 不存在"))?;
            let expected_slot = match previous_initializer {
                Some((start, end, slot)) if start == initializer.start_pc => {
                    if end != initializer.end_pc {
                        return Err(invalid("native debug initializer 同組區間不一致"));
                    }
                    slot.checked_add(1)
                        .ok_or_else(|| invalid("native debug initializer slot 溢位"))?
                }
                Some((_, end, _)) if initializer.start_pc < end => {
                    return Err(invalid("native debug initializer 區間重疊或順序無效"));
                }
                _ => {
                    let active = entry
                        .locals
                        .iter()
                        .filter(|local| {
                            local.start_pc <= initializer.start_pc
                                && initializer.start_pc < local.end_pc
                        })
                        .count();
                    u8::try_from(active)
                        .map_err(|_| invalid("native debug initializer active slot 溢位"))?
                }
            };
            if initializer.slot != expected_slot
                || local_storage
                    .iter()
                    .find(|storage| storage.binding == initializer.binding)
                    .is_none_or(|storage| {
                        storage.register != initializer.register
                            || storage.slot != initializer.slot
                            || storage.start_pc > local.initialized_pc
                            || storage.end_pc < local.end_pc
                    })
            {
                return Err(invalid("native debug initializer slot/storage 契約無效"));
            }
            verify_initializer_interval(
                module,
                proto,
                local,
                initializer,
                work,
                limits.max_artifact_bytes.saturating_sub(bytes),
            )?;
            previous_initializer =
                Some((initializer.start_pc, initializer.end_pc, initializer.slot));
        }
        let entries = &candidate.initializer_temporaries[initializer_start..initializer_cursor];
        let mut group_start = 0;
        while group_start < entries.len() {
            let first = entries[group_start];
            let group_end = entries[group_start..]
                .partition_point(|entry| entry.start_pc == first.start_pc)
                + group_start;
            charge(work, entry.locals.len())?;
            let expected = entry
                .locals
                .iter()
                .filter(|local| {
                    local.start_pc == first.end_pc
                        && first.start_pc <= local.initialized_pc
                        && local.initialized_pc < first.end_pc
                })
                .count();
            if group_end - group_start != expected {
                return Err(invalid("native debug initializer future slot 不連續"));
            }
            group_start = group_end;
        }
        initializer_ranges.push(initializer_start..initializer_cursor);
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
    if temporary_cursor != candidate.temporaries.len() {
        return Err(invalid("native debug temporary prototype 順序無效"));
    }
    if initializer_cursor != candidate.initializer_temporaries.len() {
        return Err(invalid("native debug initializer prototype 順序無效"));
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
    add_bytes(
        &mut bytes,
        semantic_upvalues
            .capacity()
            .saturating_sub(candidate.prototypes.len()),
        size_of::<NativeSemanticUpvalueMap>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        temporary_ranges
            .capacity()
            .saturating_sub(candidate.prototypes.len()),
        size_of::<Range<usize>>(),
        limits.max_artifact_bytes,
    )?;
    add_bytes(
        &mut bytes,
        initializer_ranges
            .capacity()
            .saturating_sub(candidate.prototypes.len()),
        size_of::<Range<usize>>(),
        limits.max_artifact_bytes,
    )?;
    Ok(NativeDebug {
        source_name: candidate.source_name,
        prototypes: candidate.prototypes,
        semantic_upvalues,
        storage,
        close_groups,
        temporaries: candidate.temporaries,
        temporary_ranges,
        initializer_temporaries: candidate.initializer_temporaries,
        initializer_ranges,
        non_counted_pcs: candidate.non_counted_pcs,
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
                line_defined: 0,
                last_line_defined: 0,
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
            temporaries: Vec::new(),
            initializer_temporaries: Vec::new(),
            non_counted_pcs: Vec::new(),
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

    fn initializer_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = valid_fixture();
        candidate
            .initializer_temporaries
            .push(NativeInitializerTemporary {
                prototype: ProtoId(0),
                binding: binding(2),
                register: Register(3),
                slot: 0,
                start_pc: 2,
                end_pc: 3,
            });
        (verified, candidate)
    }

    fn two_initializer_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = initializer_fixture();
        let mut raw = verified.module().clone();
        let proto = &mut raw.prototypes[0];
        proto.register_count = 5;
        proto.frame.register_limit = 5;
        proto.frame.initial_top = Register(5);
        proto.frame.dynamic_top = Register(5);
        proto.binding_registers.push((binding(3), Register(4)));
        proto.instructions.insert(
            3,
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(4),
                    constant: ConstId(1),
                },
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 1,
                },
                close_path: None,
            },
        );
        candidate.prototypes[0].lines.push(1);
        candidate.prototypes[0].max_active_locals = 2;
        candidate.prototypes[0].locals[1].start_pc = 4;
        candidate.prototypes[0].locals[1].end_pc = 6;
        candidate.prototypes[0].locals.push(NativeLocal {
            binding: binding(3),
            register: Register(4),
            slot: 1,
            initialized_pc: 3,
            start_pc: 4,
            end_pc: 6,
            name: b"c".to_vec(),
        });
        candidate.initializer_temporaries[0].end_pc = 4;
        candidate
            .initializer_temporaries
            .push(NativeInitializerTemporary {
                prototype: ProtoId(0),
                binding: binding(3),
                register: Register(4),
                slot: 1,
                start_pc: 2,
                end_pc: 4,
            });
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn initializer_interval_maps_only_future_local_slot() {
        let (verified, candidate) = initializer_fixture();
        let debug = check(candidate, &verified).unwrap();
        let entries = debug.initializer_temporaries_for(ProtoId(0)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].binding, binding(2));
        assert_eq!((entries[0].start_pc, entries[0].end_pc), (2, 3));
        assert!(debug.initializer_temporaries_for(ProtoId(99)).is_none());
    }

    #[test]
    fn initializer_interval_rejects_forged_identity_slot_lifetime_and_order() {
        let (verified, candidate) = initializer_fixture();
        let mut cases = Vec::new();
        for change in [
            NativeInitializerTemporary {
                prototype: ProtoId(99),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                binding: binding(99),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                register: Register(0),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                register: Register(1),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                register: Register(2),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                register: Register(99),
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                slot: 1,
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                start_pc: 3,
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                start_pc: 4,
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                end_pc: 2,
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                end_pc: 4,
                ..candidate.initializer_temporaries[0]
            },
            NativeInitializerTemporary {
                end_pc: 99,
                ..candidate.initializer_temporaries[0]
            },
        ] {
            let mut forged = candidate.clone();
            forged.initializer_temporaries[0] = change;
            cases.push(forged);
        }
        let mut duplicate = candidate.clone();
        duplicate
            .initializer_temporaries
            .push(candidate.initializer_temporaries[0]);
        cases.push(duplicate);
        for forged in cases {
            assert_eq!(
                check(forged, &verified).unwrap_err().code,
                BytecodeErrorCode::Verify
            );
        }
    }

    #[test]
    fn initializer_interval_rejects_missing_second_future_slot() {
        let (verified, candidate) = two_initializer_fixture();
        assert_eq!(
            check(candidate.clone(), &verified)
                .unwrap()
                .initializer_temporaries_for(ProtoId(0))
                .unwrap()
                .len(),
            2
        );
        let mut missing = candidate;
        missing.initializer_temporaries.pop();
        let error = check(missing, &verified).unwrap_err();
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("不連續"));
    }

    #[test]
    fn initializer_interval_rejects_cfg_reentry_after_local_activation() {
        let (verified, candidate) = initializer_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::Jump {
            target: InstructionOffset(2),
        };
        let reentering = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let error = check(candidate, &reentering).unwrap_err();
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("initializer"), "{error:?}");
    }

    #[test]
    fn initializer_interval_charges_exact_artifact_and_work_limits() {
        let (verified, candidate) = initializer_fixture();
        let limits = VerifyLimits::default();
        let mut ample = OfficialWorkBudget::new(u64::MAX);
        let debug = verify_native_debug(&verified, candidate.clone(), &limits, &mut ample).unwrap();
        let spent = u64::MAX - ample.remaining();
        let mut exact = OfficialWorkBudget::new(spent);
        assert!(verify_native_debug(&verified, candidate.clone(), &limits, &mut exact).is_ok());
        let mut short = OfficialWorkBudget::new(spent - 1);
        assert_eq!(
            verify_native_debug(&verified, candidate.clone(), &limits, &mut short)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
        let mut lower = debug.allocated_bytes().saturating_sub(1);
        let mut upper = limits.max_artifact_bytes;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            let bounded = VerifyLimits {
                max_artifact_bytes: middle,
                ..limits
            };
            let mut work = OfficialWorkBudget::new(u64::MAX);
            if verify_native_debug(&verified, candidate.clone(), &bounded, &mut work).is_ok() {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        let bounded = VerifyLimits {
            max_artifact_bytes: upper,
            ..limits
        };
        let mut ample = OfficialWorkBudget::new(u64::MAX);
        assert!(verify_native_debug(&verified, candidate.clone(), &bounded, &mut ample).is_ok());
        let bounded = VerifyLimits {
            max_artifact_bytes: upper - 1,
            ..limits
        };
        let mut ample = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(
            verify_native_debug(&verified, candidate, &bounded, &mut ample)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    fn temporary_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        let instructions = vec![
            Instruction::LoadConst {
                dest: Register(4),
                constant: ConstId(0),
            },
            Instruction::Move {
                dest: Register(6),
                src: Register(1),
            },
            Instruction::Call {
                base: Register(6),
                arg_count: 0,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::BinaryOp {
                dest: Register(7),
                op: super::super::BinaryOperation::Add,
                left: Register(4),
                right: Register(6),
            },
            Instruction::Return {
                base: Register(7),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        let module = BytecodeModule {
            format_version: RVLU_V2,
            profile: LuaProfile::Lua55,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 8,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 8,
                    initial_top: Register(2),
                    dynamic_top: Register(2),
                    return_base: Register(0),
                    environment: Register(1),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(1),
                global_environment_binding: binding(0),
                binding_registers: vec![(binding(0), Register(1))],
                constants: vec![BytecodeConstant::Integer(1)],
                upvalues: vec![],
                instructions: instructions
                    .into_iter()
                    .map(|instruction| BytecodeInstruction {
                        instruction,
                        span,
                        close_path: None,
                    })
                    .collect(),
                close_paths: vec![],
            }],
        };
        let candidate = NativeDebugCandidate {
            source_name: b"@temporary.lua".to_vec(),
            prototypes: vec![NativePrototypeDebug {
                prototype: ProtoId(0),
                line_defined: 0,
                last_line_defined: 0,
                lines: vec![1; 5],
                locals: vec![],
                upvalue_names: vec![],
                max_active_locals: 0,
            }],
            temporaries: vec![NativeTemporary {
                prototype: ProtoId(0),
                call_pc: InstructionOffset(2),
                ordinal: 1,
                register: Register(4),
            }],
            initializer_temporaries: Vec::new(),
            non_counted_pcs: Vec::new(),
        };
        (
            verify_module(module, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn temporary_map_accepts_only_call_pending_value_with_parent_binary_read() {
        let (verified, candidate) = temporary_fixture();
        let debug = check(candidate, &verified).unwrap();
        let expected = [NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(2),
            ordinal: 1,
            register: Register(4),
        }];
        assert_eq!(
            debug.temporaries_at(ProtoId(0), InstructionOffset(2)),
            Some(expected.as_slice())
        );
        assert_eq!(
            debug.temporaries_at(ProtoId(0), InstructionOffset(1)),
            Some([].as_slice())
        );
    }

    fn temporary_move_to_call_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = temporary_fixture();
        let mut raw = verified.module().clone();
        let proto = &mut raw.prototypes[0];
        proto.instructions[3].instruction = Instruction::Move {
            dest: Register(7),
            src: Register(4),
        };
        let last = proto.instructions.pop().unwrap();
        proto.instructions.push(BytecodeInstruction {
            instruction: Instruction::Call {
                base: Register(7),
                arg_count: 0,
                result_mode: ResultMode::Fixed(1),
            },
            span: last.span,
            close_path: None,
        });
        proto.instructions.push(last);
        candidate.prototypes[0].lines.push(1);
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn temporary_map_accepts_outer_call_prefix_after_move_or_direct_read() {
        let (verified, candidate) = temporary_move_to_call_fixture();
        assert!(check(candidate, &verified).is_ok());

        let (verified, candidate) = temporary_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::Call {
            base: Register(4),
            arg_count: 0,
            result_mode: ResultMode::Fixed(1),
        };
        raw.prototypes[0].instructions[4].instruction = Instruction::Return {
            base: Register(4),
            result_mode: ResultMode::Fixed(1),
        };
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert!(check(candidate, &verified).is_ok());
    }

    #[test]
    fn temporary_map_accepts_reverse_register_order_with_unique_ordinals() {
        let (verified, mut candidate) = temporary_fixture();
        let mut raw = verified.module().clone();
        let proto = &mut raw.prototypes[0];
        let span = proto.instructions[0].span;
        proto.instructions.insert(
            1,
            BytecodeInstruction {
                instruction: Instruction::LoadConst {
                    dest: Register(3),
                    constant: ConstId(0),
                },
                span,
                close_path: None,
            },
        );
        proto.instructions[4].instruction = Instruction::BinaryOp {
            dest: Register(7),
            op: super::super::BinaryOperation::Add,
            left: Register(4),
            right: Register(3),
        };
        candidate.prototypes[0].lines.push(1);
        candidate.temporaries[0].call_pc = InstructionOffset(3);
        candidate.temporaries.push(NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(3),
            ordinal: 2,
            register: Register(3),
        });
        let verified = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert!(check(candidate.clone(), &verified).is_ok());

        candidate.temporaries[1].register = Register(4);
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn temporary_map_rejects_overwritten_or_unrelated_move_consumer() {
        let (verified, candidate) = temporary_move_to_call_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[4].instruction = Instruction::LoadConst {
            dest: Register(7),
            constant: ConstId(0),
        };
        let overwritten = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate.clone(), &overwritten).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[4].instruction = Instruction::Move {
            dest: Register(6),
            src: Register(7),
        };
        let unrelated = verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate.clone(), &unrelated).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut alias = candidate;
        alias.temporaries[0].register = Register(6);
        assert_eq!(
            check(alias, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    fn non_counted_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = temporary_fixture();
        let mut raw = verified.module().clone();
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        for pc in [4, 4] {
            raw.prototypes[0].instructions.insert(
                pc,
                BytecodeInstruction {
                    instruction: Instruction::LoadNil {
                        start: Register(0),
                        count: 1,
                    },
                    span,
                    close_path: None,
                },
            );
            candidate.prototypes[0].lines.push(1);
        }
        candidate.non_counted_pcs = vec![
            (ProtoId(0), InstructionOffset(4)),
            (ProtoId(0), InstructionOffset(5)),
        ];
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn non_counted_pc_accepts_sorted_anchor_and_rejects_malformed_candidates() {
        let (verified, candidate) = non_counted_fixture();
        let debug = check(candidate.clone(), &verified).unwrap();
        assert!(debug.is_non_counted_pc(ProtoId(0), InstructionOffset(4)));
        assert!(debug.is_non_counted_pc(ProtoId(0), InstructionOffset(5)));
        assert!(!debug.is_non_counted_pc(ProtoId(0), InstructionOffset(3)));
        let mut cases = Vec::new();
        let mut duplicate = candidate.clone();
        duplicate.non_counted_pcs[1].1 = InstructionOffset(4);
        cases.push(duplicate);
        let mut unordered = candidate.clone();
        unordered.non_counted_pcs.reverse();
        cases.push(unordered);
        let mut unknown = candidate.clone();
        unknown.non_counted_pcs[1].0 = ProtoId(99);
        cases.push(unknown);
        let mut out_of_bounds = candidate.clone();
        out_of_bounds.non_counted_pcs[1].1 = InstructionOffset(999);
        cases.push(out_of_bounds);
        let mut real_opcode = candidate;
        real_opcode.non_counted_pcs[0].1 = InstructionOffset(3);
        cases.push(real_opcode);
        for forged in cases {
            assert_eq!(
                check(forged, &verified).unwrap_err().code,
                BytecodeErrorCode::Verify
            );
        }
    }

    #[test]
    fn non_counted_pc_accepts_bounded_expansion_opcode_classes() {
        let (verified, mut candidate) = non_counted_fixture();
        candidate.non_counted_pcs = vec![
            (ProtoId(0), InstructionOffset(0)), // LoadConst 輔助值
            (ProtoId(0), InstructionOffset(1)), // Move 位置調整
            (ProtoId(0), InstructionOffset(4)), // LoadNil 清理
            (ProtoId(0), InstructionOffset(5)), // LoadNil CFG 錨點
        ];
        let debug = check(candidate.clone(), &verified).unwrap();
        for (_, pc) in &candidate.non_counted_pcs {
            assert!(debug.is_non_counted_pc(ProtoId(0), *pc));
        }
        let limits = VerifyLimits::default();
        let mut ample = OfficialWorkBudget::new(u64::MAX);
        verify_native_debug(&verified, candidate.clone(), &limits, &mut ample).unwrap();
        let spent = u64::MAX - ample.remaining();
        let mut exact = OfficialWorkBudget::new(spent);
        assert!(verify_native_debug(&verified, candidate.clone(), &limits, &mut exact).is_ok());
        let mut short = OfficialWorkBudget::new(spent - 1);
        assert_eq!(
            verify_native_debug(&verified, candidate, &limits, &mut short)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn non_counted_pc_charges_exact_artifact_and_work_limits() {
        let (verified, candidate) = non_counted_fixture();
        let limits = VerifyLimits::default();
        let mut ample = OfficialWorkBudget::new(u64::MAX);
        let debug = verify_native_debug(&verified, candidate.clone(), &limits, &mut ample).unwrap();
        let spent = u64::MAX - ample.remaining();
        let mut exact_work = OfficialWorkBudget::new(spent);
        assert!(
            verify_native_debug(&verified, candidate.clone(), &limits, &mut exact_work).is_ok()
        );
        let mut short_work = OfficialWorkBudget::new(spent - 1);
        assert_eq!(
            verify_native_debug(&verified, candidate.clone(), &limits, &mut short_work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit,
        );
        let mut exact_limits = limits;
        let mut lower = 0usize;
        let mut upper = limits.max_artifact_bytes;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            exact_limits.max_artifact_bytes = middle;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            if verify_native_debug(&verified, candidate.clone(), &exact_limits, &mut work).is_ok() {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        assert!(upper >= debug.allocated_bytes());
        exact_limits.max_artifact_bytes = upper;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert!(
            verify_native_debug(&verified, candidate.clone(), &exact_limits, &mut work).is_ok()
        );
        exact_limits.max_artifact_bytes -= 1;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(
            verify_native_debug(&verified, candidate, &exact_limits, &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit,
        );
    }

    #[test]
    fn temporary_map_rejects_pc_ordinal_register_and_call_alias_forgeries() {
        let (verified, candidate) = temporary_fixture();
        let mut cases = Vec::new();
        let mut non_call = candidate.clone();
        non_call.temporaries[0].call_pc = InstructionOffset(1);
        cases.push(non_call);
        let mut zero = candidate.clone();
        zero.temporaries[0].ordinal = 0;
        cases.push(zero);
        let mut gap = candidate.clone();
        gap.temporaries[0].ordinal = 2;
        cases.push(gap);
        let mut duplicate = candidate.clone();
        duplicate.temporaries.push(duplicate.temporaries[0]);
        cases.push(duplicate);
        let mut bounds = candidate.clone();
        bounds.temporaries[0].register = Register(8);
        cases.push(bounds);
        let mut environment = candidate.clone();
        environment.temporaries[0].register = Register(1);
        cases.push(environment);
        let mut call_slot = candidate.clone();
        call_slot.temporaries[0].register = Register(6);
        cases.push(call_slot);
        let mut prototype = candidate;
        prototype.temporaries[0].prototype = ProtoId(1);
        cases.push(prototype);
        for case in cases {
            assert_eq!(
                check(case, &verified).unwrap_err().code,
                BytecodeErrorCode::Verify
            );
        }
    }

    #[test]
    fn temporary_map_rejects_uninitialized_dead_overwritten_and_settable_key() {
        let (verified, candidate) = temporary_fixture();
        let mut uninitialized = candidate.clone();
        uninitialized.temporaries[0].register = Register(5);
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::BinaryOp {
            dest: Register(7),
            op: super::super::BinaryOperation::Add,
            left: Register(5),
            right: Register(6),
        };
        let uninitialized_module =
            verify_module(raw.clone(), LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(uninitialized, &uninitialized_module)
                .unwrap_err()
                .code,
            BytecodeErrorCode::Verify
        );
        assert_eq!(
            check(candidate.clone(), &uninitialized_module)
                .unwrap_err()
                .code,
            BytecodeErrorCode::Verify
        );

        raw.prototypes[0].instructions[3].instruction = Instruction::LoadNil {
            start: Register(4),
            count: 1,
        };
        raw.prototypes[0].instructions.insert(
            4,
            BytecodeInstruction {
                instruction: Instruction::BinaryOp {
                    dest: Register(7),
                    op: super::super::BinaryOperation::Add,
                    left: Register(4),
                    right: Register(6),
                },
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 1,
                },
                close_path: None,
            },
        );
        let overwritten_module =
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut overwritten = candidate.clone();
        overwritten.prototypes[0].lines.push(1);
        assert_eq!(
            check(overwritten, &overwritten_module).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::SetTable {
            table: Register(6),
            key: Register(4),
            value: Register(6),
        };
        raw.prototypes[0].instructions[4].instruction = Instruction::Return {
            base: Register(6),
            result_mode: ResultMode::Fixed(1),
        };
        let settable_module =
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            check(candidate, &settable_module).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn temporary_map_checks_artifact_and_work_exactly() {
        let (verified, candidate) = temporary_fixture();
        let limits = VerifyLimits::default();
        let mut generous = OfficialWorkBudget::new(u64::MAX);
        let debug =
            verify_native_debug(&verified, candidate.clone(), &limits, &mut generous).unwrap();
        let spent = generous.consumed();
        assert!(spent > 0);
        let mut exact = OfficialWorkBudget::new(spent);
        verify_native_debug(&verified, candidate.clone(), &limits, &mut exact).unwrap();
        assert_eq!(exact.remaining(), 0);
        let mut short = OfficialWorkBudget::new(spent - 1);
        assert_eq!(
            verify_native_debug(&verified, candidate.clone(), &limits, &mut short)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
        let mut exact_limits = limits;
        let mut lower = 0usize;
        let mut upper = limits.max_artifact_bytes;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            exact_limits.max_artifact_bytes = middle;
            let mut work = OfficialWorkBudget::new(u64::MAX);
            if verify_native_debug(&verified, candidate.clone(), &exact_limits, &mut work).is_ok() {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        assert!(upper >= debug.allocated_bytes());
        exact_limits.max_artifact_bytes = upper;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert!(
            verify_native_debug(&verified, candidate.clone(), &exact_limits, &mut work).is_ok()
        );
        exact_limits.max_artifact_bytes -= 1;
        let mut work = OfficialWorkBudget::new(u64::MAX);
        assert_eq!(
            verify_native_debug(&verified, candidate, &exact_limits, &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn temporary_map_requires_initialization_and_consumer_on_every_cfg_path() {
        let (verified, candidate) = temporary_fixture();
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        let mut before = verified.module().clone();
        before.prototypes[0].instructions.insert(
            0,
            BytecodeInstruction {
                instruction: Instruction::JumpIfFalse {
                    condition: Register(1),
                    target: InstructionOffset(2),
                },
                span,
                close_path: None,
            },
        );
        let before = verify_module(before, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut before_candidate = candidate.clone();
        before_candidate.prototypes[0].lines.push(1);
        before_candidate.temporaries[0].call_pc = InstructionOffset(3);
        assert_eq!(
            check(before_candidate, &before).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut after = verified.module().clone();
        after.prototypes[0].instructions.insert(
            3,
            BytecodeInstruction {
                instruction: Instruction::JumpIfFalse {
                    condition: Register(1),
                    target: InstructionOffset(5),
                },
                span,
                close_path: None,
            },
        );
        let after = verify_module(after, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        let mut after_candidate = candidate;
        after_candidate.prototypes[0].lines.push(1);
        assert_eq!(
            check(after_candidate, &after).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    fn semantic_environment_fixture() -> (VerifiedModule, NativeDebugCandidate) {
        let (verified, mut candidate) = valid_fixture();
        let mut raw = verified.module().clone();
        raw.prototypes[0].instructions[3].instruction = Instruction::GetTable {
            dest: Register(0),
            table: Register(1),
            key: Register(3),
        };
        candidate.prototypes[0]
            .upvalue_names
            .push(Some(b"_ENV".to_vec()));
        (
            verify_module(raw, LuaProfile::Lua55, &VerifyLimits::default()).unwrap(),
            candidate,
        )
    }

    #[test]
    fn native_semantic_environment_maps_root_without_physical_upvalue() {
        let (verified, candidate) = semantic_environment_fixture();
        let debug = check(candidate, &verified).unwrap();
        assert_eq!(debug.semantic_upvalue_count(ProtoId(0)), Some(1));
        assert_eq!(
            debug.semantic_upvalue(ProtoId(0), 0),
            Some(NativeSemanticUpvalue::Environment)
        );
        assert_eq!(debug.semantic_upvalue(ProtoId(0), 1), None);
        assert_eq!(
            debug.semantic_upvalue_name(ProtoId(0), 0),
            Some(Some(b"_ENV".as_slice()))
        );
        assert_eq!(verified.module().prototypes[0].upvalues.len(), 0);
        assert!(debug.allocated_bytes() > 0);
    }

    #[test]
    fn native_semantic_environment_rejects_forged_source_duplicate_and_bounds() {
        let (verified, candidate) = semantic_environment_fixture();
        let mut missing = candidate.clone();
        missing.prototypes[0].upvalue_names.clear();
        assert_eq!(
            check(missing, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut duplicate = candidate.clone();
        duplicate.prototypes[0]
            .upvalue_names
            .push(Some(b"_ENV".to_vec()));
        assert_eq!(
            check(duplicate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let mut wrong_name = candidate.clone();
        wrong_name.prototypes[0].upvalue_names[0] = Some(b"other".to_vec());
        assert_eq!(
            check(wrong_name, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );

        let (without_use, mut forged) = valid_fixture();
        forged.prototypes[0]
            .upvalue_names
            .push(Some(b"_ENV".to_vec()));
        assert_eq!(
            check(forged, &without_use).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn native_semantic_environment_accounts_for_exact_artifact_budget() {
        let (verified, candidate) = semantic_environment_fixture();
        let debug = check(candidate.clone(), &verified).unwrap();
        let mut limits = VerifyLimits::default();
        let mut lower = 0;
        let mut upper = limits.max_artifact_bytes;
        while lower + 1 < upper {
            let middle = lower + (upper - lower) / 2;
            limits.max_artifact_bytes = middle;
            let mut work = OfficialWorkBudget::for_limits(&limits).unwrap();
            if verify_native_debug(&verified, candidate.clone(), &limits, &mut work).is_ok() {
                upper = middle;
            } else {
                lower = middle;
            }
        }
        assert!(upper >= debug.allocated_bytes());
        limits.max_artifact_bytes = upper;
        let mut work = OfficialWorkBudget::for_limits(&limits).unwrap();
        assert!(verify_native_debug(&verified, candidate.clone(), &limits, &mut work).is_ok());
        limits.max_artifact_bytes = upper - 1;
        let mut work = OfficialWorkBudget::for_limits(&limits).unwrap();
        assert_eq!(
            verify_native_debug(&verified, candidate, &limits, &mut work)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn native_semantic_environment_charges_work_exactly() {
        let (verified, candidate) = semantic_environment_fixture();
        let limits = VerifyLimits::default();
        let mut generous = OfficialWorkBudget::new(u64::MAX);
        verify_native_debug(&verified, candidate.clone(), &limits, &mut generous).unwrap();
        let spent = generous.consumed();
        assert!(spent > 0);
        let mut exact = OfficialWorkBudget::new(spent);
        verify_native_debug(&verified, candidate.clone(), &limits, &mut exact).unwrap();
        assert_eq!(exact.remaining(), 0);
        let mut short = OfficialWorkBudget::new(spent - 1);
        assert_eq!(
            verify_native_debug(&verified, candidate, &limits, &mut short)
                .unwrap_err()
                .code,
            BytecodeErrorCode::CompileLimit
        );
        assert!(short.exhausted());
    }

    #[test]
    fn root_definition_range_is_zero_with_positive_instruction_lines() {
        let (verified, mut candidate) = valid_fixture();
        candidate.prototypes[0].line_defined = 0;
        candidate.prototypes[0].last_line_defined = 0;
        candidate.prototypes[0].lines[0] = 2;
        assert!(candidate.prototypes[0].lines.iter().all(|line| *line > 0));
        check(candidate, &verified).unwrap();
    }

    #[test]
    fn root_nonzero_or_half_zero_definition_range_is_rejected() {
        let (verified, candidate) = valid_fixture();
        for (first, last) in [(1, 1), (0, 1), (1, 0)] {
            let mut forged = candidate.clone();
            forged.prototypes[0].line_defined = first;
            forged.prototypes[0].last_line_defined = last;
            assert_eq!(
                check(forged, &verified).unwrap_err().code,
                BytecodeErrorCode::Verify
            );
        }
    }

    #[test]
    fn child_definition_range_and_instruction_upper_bound_remain_strict() {
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
        check(candidate.clone(), &verified).unwrap();
        candidate.prototypes[1].line_defined = 0;
        candidate.prototypes[1].last_line_defined = 0;
        assert_eq!(
            check(candidate.clone(), &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
        candidate.prototypes[1].line_defined = 1;
        candidate.prototypes[1].last_line_defined = 1;
        candidate.prototypes[1].lines[0] = 2;
        assert_eq!(
            check(candidate, &verified).unwrap_err().code,
            BytecodeErrorCode::Verify
        );
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
