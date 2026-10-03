//! 將一般 RVLU_V2 原型降低成官方 Lua opcode。

use super::codec::{BytecodeConstant, BytecodeExitKind, BytecodePrototype, BytecodeUpvalueSource};
use super::official::{
    OfficialAbsLine, OfficialChunk, OfficialChunkLimits, OfficialConstant, OfficialDebug,
    OfficialLocal, OfficialPrototype, OfficialUpvalue,
};
use super::official_export::{
    OfficialExportError, OfficialExportErrorKind, copy_slice, error, work_charge,
};
use super::official_translation::OfficialWorkBudget;
use super::{
    BinaryOperation, EnvironmentSource, Instruction, InstructionOffset, LuaProfile, ProtoId,
    Register, ResultMode, UnaryOperation, VerifiedModule,
};
use core::mem::size_of;
use std::borrow::Cow;

use super::native_debug::NativeCloseGroup;
use super::official_execution::OfficialPlanCall;

struct Layout {
    tuple_base: u16,
    scratch: Vec<u16>,
    parallel_spare: Vec<u16>,
    max_stack: u8,
    guest_upvalue_offset: u16,
    env_upvalue: Option<u16>,
    mapped: Vec<u8>,
    protected: Vec<u8>,
}

fn native_guest_upvalues(module: &VerifiedModule, proto: &BytecodePrototype) -> usize {
    module
        .official_execution()
        .filter(|plan| plan.is_native_builtin())
        .and_then(|plan| plan.upvalue_map(proto.id))
        .map_or(proto.upvalues.len(), |map| usize::from(map.guest_count))
}

const NO_PARALLEL_COPY: u16 = u16::MAX;
const NO_SPARE_SLOT: u16 = 255;

struct ParallelMoves {
    moves: [(u8, u8); 512],
    len: usize,
}

impl ParallelMoves {
    fn push(
        &mut self,
        dest: u8,
        src: u8,
        id: ProtoId,
        pc: usize,
    ) -> Result<(), OfficialExportError> {
        let Some(slot) = self.moves.get_mut(self.len) else {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "平行搬移指令數超限",
            ));
        };
        *slot = (dest, src);
        self.len += 1;
        Ok(())
    }
}

/// 依來源依賴安排同一個指令的 register 搬移，避免重疊窗口覆寫尚未讀取的值。
fn parallel_copy_plan(
    mapped: &[u8],
    guest: Register,
    count: u16,
    window: u8,
    gather: bool,
    spare: Option<u8>,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<ParallelMoves>, OfficialExportError> {
    let len = usize::from(count);
    if len > 255 || usize::from(window) + len > 255 {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            id,
            pc,
            "平行搬移窗口超過官方 stack",
        ));
    }
    let mut sources = [0u8; 255];
    let mut destinations = [0u8; 255];
    let mut pending = [false; 255];
    let mut destination_seen = [false; 255];
    let mut readers = [0u16; 256];
    let mut plan = ParallelMoves {
        moves: [(0, 0); 512],
        len: 0,
    };
    let mut remaining = 0usize;
    work_charge(work, len, id, pc)?;
    for offset in 0..len {
        let guest_register = usize::from(guest.0).checked_add(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "平行搬移來源 register 溢位",
            )
        })?;
        let mapped_register = *mapped
            .get(guest_register)
            .filter(|slot| **slot != u8::MAX)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    pc,
                    "平行搬移來源 register 未配置",
                )
            })?;
        let window_register = window + offset as u8;
        let (src, dest) = if gather {
            (mapped_register, window_register)
        } else {
            (window_register, mapped_register)
        };
        if destination_seen[usize::from(dest)] {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                pc,
                "平行搬移目的槽重疊",
            ));
        }
        destination_seen[usize::from(dest)] = true;
        sources[offset] = src;
        destinations[offset] = dest;
        if src != dest {
            pending[offset] = true;
            remaining += 1;
            readers[usize::from(src)] += 1;
        }
    }
    if let Some(spare) = spare {
        work_charge(work, len, id, pc)?;
        if (0..len).any(|index| sources[index] == spare || destinations[index] == spare) {
            return Ok(None);
        }
    }
    while remaining > 0 {
        work_charge(work, len, id, pc)?;
        if let Some(index) =
            (0..len).find(|&index| pending[index] && readers[usize::from(destinations[index])] == 0)
        {
            let src = sources[index];
            plan.push(destinations[index], src, id, pc)?;
            readers[usize::from(src)] -= 1;
            pending[index] = false;
            remaining -= 1;
            continue;
        }
        let Some(spare) = spare else {
            return Ok(None);
        };
        if readers[usize::from(spare)] != 0 {
            return Ok(None);
        }
        work_charge(work, pending.len(), id, pc)?;
        let index = pending.iter().position(|item| *item).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                pc,
                "平行搬移待處理集合無效",
            )
        })?;
        let saved = destinations[index];
        plan.push(spare, saved, id, pc)?;
        work_charge(work, len, id, pc)?;
        for source in sources.iter_mut().take(len).enumerate() {
            let (index, source) = source;
            if pending[index] && *source == saved {
                *source = spare;
                readers[usize::from(saved)] -= 1;
                readers[usize::from(spare)] += 1;
            }
        }
    }
    Ok(Some(plan))
}

impl Layout {
    fn register(
        &self,
        register: Register,
        id: ProtoId,
        pc: usize,
    ) -> Result<u8, OfficialExportError> {
        self.mapped
            .get(usize::from(register.0))
            .copied()
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    pc,
                    "native register 不存在",
                )
            })
    }

    fn upvalue(&self, source: u16, id: ProtoId, pc: usize) -> Result<u8, OfficialExportError> {
        let value = self
            .guest_upvalue_offset
            .checked_add(source)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    pc,
                    "官方 upvalue 溢位",
                )
            })?;
        u8::try_from(value).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "官方 upvalue 超出 u8",
            )
        })
    }
}

fn abc(op: u8, a: u8, b: u8, c: u8, k: bool) -> u32 {
    u32::from(op)
        | (u32::from(a) << 7)
        | (u32::from(k) << 15)
        | (u32::from(b) << 16)
        | (u32::from(c) << 24)
}

fn abx(op: u8, a: u8, bx: u32) -> u32 {
    u32::from(op) | (u32::from(a) << 7) | (bx << 15)
}

fn ax(op: u8, value: u32) -> u32 {
    u32::from(op) | (value << 7)
}

fn jump(offset: i64, id: ProtoId, pc: usize) -> Result<u32, OfficialExportError> {
    let encoded = offset
        .checked_add(16_777_215)
        .filter(|value| (0..=33_554_431).contains(value))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "官方 jump 距離超限",
            )
        })?;
    Ok(ax(56, encoded as u32))
}

fn extra_opcode(profile: LuaProfile) -> u8 {
    if profile == LuaProfile::Lua55 { 84 } else { 82 }
}

fn emit_native_list_write(
    builder: &mut Builder<'_>,
    proto: &BytecodePrototype,
    meta: &Layout,
    profile: LuaProfile,
    pc: usize,
    call: &OfficialPlanCall,
) -> Result<(), OfficialExportError> {
    let first_register = Register(call.function_register.0 + 2);
    let first_constant = proto.instructions[..pc]
        .iter()
        .rev()
        .find_map(|entry| match &entry.instruction {
            Instruction::LoadConst { dest, constant } if *dest == first_register => Some(constant),
            _ => None,
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc,
                "native SETLIST index 缺失",
            )
        })?;
    let first = match proto.constants.get(first_constant.0 as usize) {
        Some(BytecodeConstant::Integer(value)) if *value >= 1 => *value as u64,
        _ => {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc,
                "native SETLIST index 無效",
            ));
        }
    };
    let width = if profile == LuaProfile::Lua55 {
        1024u64
    } else {
        256u64
    };
    let zero_based = first - 1;
    let upper = u32::try_from(zero_based / width)
        .ok()
        .filter(|part| *part <= 0x01ff_ffff)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native SETLIST index 超出官方格式",
            )
        })?;
    let lower = (zero_based % width) as u32;
    let table = scratch_register(meta, 3, proto.id, pc)?;
    let word = if profile == LuaProfile::Lua55 {
        u32::from(78u8) | (u32::from(table) << 7) | (u32::from(upper > 0) << 15) | (lower << 22)
    } else {
        abc(78, table, 0, lower as u8, upper > 0)
    };
    builder.push(word, pc)?;
    if upper > 0 {
        builder.push(ax(extra_opcode(profile), upper), pc)?;
    }
    Ok(())
}

fn env_read(instruction: &Instruction, env: Register) -> bool {
    match instruction {
        Instruction::Move { src, .. }
        | Instruction::SetUpvalue { src, .. }
        | Instruction::UnaryOp { src, .. } => *src == env,
        Instruction::GetTable { table, key, .. } => *table == env || *key == env,
        Instruction::SetTable { table, key, value } => {
            *table == env || *key == env || *value == env
        }
        Instruction::BinaryOp { left, right, .. } => *left == env || *right == env,
        Instruction::JumpIfFalse { condition, .. } => *condition == env,
        Instruction::Call {
            base, arg_count, ..
        }
        | Instruction::TailCall {
            base, arg_count, ..
        } => {
            env.0 >= base.0
                && (*arg_count == u16::MAX || env.0 <= base.0.saturating_add(*arg_count))
        }
        Instruction::Return { base, result_mode } => {
            env.0 >= base.0
                && (matches!(result_mode, ResultMode::All)
                    || env.0
                        < base.0.saturating_add(match result_mode {
                            ResultMode::Fixed(count) => *count,
                            ResultMode::All => 0,
                        }))
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
        } => [control, limit, step, visible].contains(&&env),
        _ => false,
    }
}

fn needs_environment(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
    depth: usize,
    limits: &OfficialChunkLimits,
) -> Result<bool, OfficialExportError> {
    if depth > limits.max_depth {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "環境需求 prototype 深度超限",
        ));
    }
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    if proto
        .instructions
        .iter()
        .any(|entry| env_read(&entry.instruction, proto.frame.environment))
    {
        return Ok(true);
    }
    work_charge(work, module.module().prototypes.len(), proto.id, 0)?;
    for child in &module.module().prototypes {
        if child.parent != Some(proto.id) {
            continue;
        }
        work_charge(work, child.upvalues.len(), proto.id, 0)?;
        if child.upvalues.iter().any(|upvalue| {
            matches!(&upvalue.source, BytecodeUpvalueSource::ParentLocal(binding)
                if *binding == proto.global_environment_binding)
        }) || (matches!(
            child.frame.environment_source,
            EnvironmentSource::ParentFrame { .. }
        ) && needs_environment(module, child, work, depth + 1, limits)?)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn visit_range<F: FnMut(Register) -> Result<(), OfficialExportError>>(
    start: Register,
    count: u16,
    mut visit: F,
) -> Result<(), OfficialExportError> {
    for offset in 0..count {
        if let Some(register) = start.0.checked_add(offset) {
            visit(Register(register))?;
        }
    }
    Ok(())
}

fn open_prefix_end(proto: &BytecodePrototype, pc: usize, skip_closes: bool) -> Option<u16> {
    let mut prior = pc.checked_sub(1)?;
    if skip_closes {
        while matches!(
            proto
                .instructions
                .get(prior)
                .map(|entry| &entry.instruction),
            Some(Instruction::Close { .. })
        ) {
            prior = prior.checked_sub(1)?;
        }
    }
    match &proto.instructions.get(prior)?.instruction {
        Instruction::Call {
            base,
            result_mode: ResultMode::All,
            ..
        }
        | Instruction::Vararg {
            base,
            result_mode: ResultMode::All,
        } => Some(base.0),
        _ => None,
    }
}

fn open_root_base(
    proto: &BytecodePrototype,
    producer_pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Register, OfficialExportError> {
    let mut next = producer_pc + 1;
    loop {
        work_charge(work, 1, proto.id, producer_pc)?;
        let entry = proto.instructions.get(next).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                producer_pc,
                "open producer 缺 consumer",
            )
        })?;
        match &entry.instruction {
            Instruction::Call {
                arg_count: u16::MAX,
                result_mode: ResultMode::All,
                ..
            } => {
                next += 1;
            }
            Instruction::Call {
                base,
                arg_count: u16::MAX,
                ..
            }
            | Instruction::TailCall {
                base,
                arg_count: u16::MAX,
                ..
            }
            | Instruction::Return {
                base,
                result_mode: ResultMode::All,
            } => return Ok(*base),
            Instruction::Close { .. } => {
                next += 1;
            }
            _ => {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    producer_pc,
                    "open producer consumer 序列無效",
                ));
            }
        }
    }
}

fn scratch_width_at(
    proto: &BytecodePrototype,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<u16, OfficialExportError> {
    let needed = match &proto.instructions[pc].instruction {
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            let results = match result_mode {
                ResultMode::Fixed(count) => usize::from(*count),
                ResultMode::All => 1,
            };
            if *arg_count == u16::MAX {
                let root = if matches!(result_mode, ResultMode::All) {
                    open_root_base(proto, pc, work)?
                } else {
                    *base
                };
                usize::from(base.0.saturating_sub(root.0)) + results.max(1)
            } else if matches!(result_mode, ResultMode::All) {
                let root = open_root_base(proto, pc, work)?;
                usize::from(base.0.saturating_sub(root.0))
                    .checked_add(usize::from(*arg_count) + 1)
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native open scratch 寬度溢位",
                        )
                    })?
            } else {
                (usize::from(*arg_count) + 1).max(results)
            }
        }
        Instruction::TailCall { arg_count, .. } if *arg_count != u16::MAX => {
            usize::from(*arg_count) + 1
        }
        Instruction::Vararg { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => usize::from(*count).max(1),
            ResultMode::All => {
                let root = open_root_base(proto, pc, work)?;
                usize::from(base.0.saturating_sub(root.0)) + 1
            }
        },
        Instruction::Return {
            result_mode: ResultMode::Fixed(count),
            ..
        } => usize::from(*count).max(1),
        Instruction::Return {
            result_mode: ResultMode::All,
            ..
        }
        | Instruction::TailCall {
            arg_count: u16::MAX,
            ..
        } => 1,
        Instruction::NewTable { .. } | Instruction::Closure { .. } => 1,
        Instruction::BinaryOp {
            op: BinaryOperation::Concat,
            ..
        } => 2,
        _ => 0,
    };
    u16::try_from(needed).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native scratch 寬度超限",
        )
    })
}

fn open_chain_end(
    proto: &BytecodePrototype,
    producer_pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<usize, OfficialExportError> {
    let mut next = producer_pc + 1;
    loop {
        work_charge(work, 1, proto.id, producer_pc)?;
        match proto.instructions.get(next).map(|entry| &entry.instruction) {
            Some(Instruction::Call {
                arg_count: u16::MAX,
                result_mode: ResultMode::All,
                ..
            }) => next += 1,
            Some(
                Instruction::Call {
                    arg_count: u16::MAX,
                    ..
                }
                | Instruction::TailCall {
                    arg_count: u16::MAX,
                    ..
                }
                | Instruction::Return {
                    result_mode: ResultMode::All,
                    ..
                },
            ) => return Ok(next),
            Some(Instruction::Close { .. }) => next += 1,
            _ => {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    producer_pc,
                    "open scratch 鏈缺 consumer",
                ));
            }
        }
    }
}

fn native_close_groups<'a>(
    module: &'a VerifiedModule,
    proto: &BytecodePrototype,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<Cow<'a, [NativeCloseGroup]>, OfficialExportError> {
    if let Some(groups) = module
        .native_debug()
        .and_then(|debug| debug.close_groups_for(proto.id))
    {
        return Ok(Cow::Borrowed(groups));
    }
    super::native_debug::build_close_groups(proto, work, limits.max_allocated_bytes)
        .map(Cow::Owned)
        .map_err(|source| {
            native_debug_error(
                source.code,
                work,
                proto.id,
                0,
                "bare native close group 無法驗證",
            )
        })
}

fn native_debug_error(
    code: super::BytecodeErrorCode,
    work: &OfficialWorkBudget,
    id: ProtoId,
    pc: usize,
    detail: &'static str,
) -> OfficialExportError {
    let kind = match code {
        super::BytecodeErrorCode::CompileLimit if work.remaining() == 0 => {
            OfficialExportErrorKind::WorkExhausted
        }
        super::BytecodeErrorCode::CompileLimit => OfficialExportErrorKind::LimitExceeded,
        _ => OfficialExportErrorKind::InvalidPrototype,
    };
    error(kind, id, pc, detail)
}

fn close_group_at(groups: &[NativeCloseGroup], pc: usize) -> Option<&NativeCloseGroup> {
    groups
        .partition_point(|group| group.start_pc as usize <= pc)
        .checked_sub(1)
        .and_then(|index| groups.get(index))
        .filter(|group| pc < group.end_pc as usize)
}

fn return_close_group(group: &NativeCloseGroup, proto: &BytecodePrototype) -> bool {
    let end = group.end_pc as usize;
    if !matches!(
        proto.instructions.get(end).map(|entry| &entry.instruction),
        Some(Instruction::Return { .. })
    ) {
        return false;
    }
    if group.operands().iter().all(|(_, count)| *count == 0) {
        return true;
    }
    matches!(proto.instructions.get(end.saturating_sub(1)),
        Some(entry) if matches!(entry.instruction, Instruction::Close { count: 1, .. })
            && matches!(entry.close_path.as_ref().map(|path| path.kind),
                Some(BytecodeExitKind::Return)))
}

fn bare_close_cfg_bytes(proto: &BytecodePrototype) -> Result<(usize, usize), OfficialExportError> {
    let count = proto.instructions.len();
    let queue_count = count.checked_mul(4).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "bare close CFG queue 數溢位",
        )
    })?;
    let bytes = count
        .checked_mul(2)
        .and_then(|value| {
            queue_count
                .checked_mul(size_of::<usize>())
                .and_then(|queue| value.checked_add(queue))
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "bare close CFG 暫存大小溢位",
            )
        })?;
    Ok((queue_count, bytes))
}

/// bare 匯出只信任 RVLU P05 指令與由指令推導的 group；逐個保護 register
/// 比對單一 OP_CLOSE 會實際關閉的 open upvalue／TBC 狀態。
fn verify_bare_close_layout(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    groups: &[NativeCloseGroup],
    work: &mut OfficialWorkBudget,
    limits: &OfficialChunkLimits,
) -> Result<(), OfficialExportError> {
    if module.native_debug().is_some() || groups.is_empty() {
        return Ok(());
    }
    let count = proto.instructions.len();
    let (queue_count, bytes) = bare_close_cfg_bytes(proto)?;
    if bytes > limits.max_allocated_bytes {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "bare close CFG 暫存額度超限",
        ));
    }
    work_charge(
        work,
        count
            .checked_mul(2)
            .and_then(|units| units.checked_add(queue_count))
            .and_then(|units| units.checked_add(groups.len()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "bare close CFG 初始化 work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    let mut captures = Vec::new();
    captures.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "bare close capture bitmap 配置失敗",
        )
    })?;
    captures.resize(count, 0u8);
    let mut seen = Vec::new();
    seen.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "bare close CFG state 配置失敗",
        )
    })?;
    seen.resize(count, 0u8);
    let mut pending = Vec::new();
    pending.try_reserve_exact(queue_count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "bare close CFG worklist 配置失敗",
        )
    })?;
    for group in groups {
        work_charge(
            work,
            group.operands().len(),
            proto.id,
            group.start_pc as usize,
        )?;
        let mut previous_tbc = None;
        for (register, kind) in group.operands() {
            if *kind != 1 {
                continue;
            }
            let slot = meta.register(*register, proto.id, group.start_pc as usize)?;
            if previous_tbc.is_some_and(|previous| slot >= previous) {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    group.start_pc as usize,
                    "bare TBC Close 物理槽順序無效",
                ));
            }
            previous_tbc = Some(slot);
        }
    }
    work_charge(work, meta.protected.len(), proto.id, 0)?;
    for (register, &protected) in meta.protected.iter().enumerate() {
        if protected == 0 {
            continue;
        }
        let register = Register(register as u16);
        work_charge(work, proto.binding_registers.len(), proto.id, 0)?;
        let binding = proto
            .binding_registers
            .iter()
            .find_map(|(binding, source)| (*source == register).then_some(*binding));
        work_charge(
            work,
            count.checked_mul(8).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "bare close CFG work 溢位",
                )
            })?,
            proto.id,
            0,
        )?;
        for (pc, instruction) in proto.instructions.iter().enumerate() {
            captures[pc] = if let Some(binding) = binding {
                u8::from(
                    super::native_debug::capture_at(
                        module,
                        &instruction.instruction,
                        binding,
                        work,
                    )
                    .map_err(|source| {
                        native_debug_error(
                            source.code,
                            work,
                            proto.id,
                            pc,
                            "bare close capture metadata 無效",
                        )
                    })?,
                )
            } else {
                0
            };
        }
        seen.fill(0);
        pending.clear();
        seen[0] = 1;
        pending.push(0usize);
        while let Some(encoded) = pending.pop() {
            let pc = encoded / 4;
            let state = encoded % 4;
            let open = state & 1 != 0;
            let to_close = state & 2 != 0;
            let next_state;
            let successors;
            work_charge(work, usize::BITS as usize, proto.id, pc)?;
            if let Some(group) =
                close_group_at(groups, pc).filter(|group| group.start_pc as usize == pc)
            {
                work_charge(work, group.operands().len(), proto.id, pc)?;
                let mut floor = u8::MAX;
                let mut has_upvalue = false;
                let mut has_tbc = false;
                for (source, count) in group.operands() {
                    floor = floor.min(meta.register(*source, proto.id, pc)?);
                    has_upvalue |= *source == register && *count == 0;
                    has_tbc |= *source == register && *count == 1;
                }
                if meta.register(register, proto.id, pc)? >= floor
                    && ((open && !has_upvalue) || (to_close && !has_tbc))
                {
                    return Err(error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "bare OP_CLOSE 提前關閉保護槽",
                    ));
                }
                next_state =
                    usize::from(open && !has_upvalue) | (usize::from(to_close && !has_tbc) << 1);
                successors = [
                    ((group.end_pc as usize) < count).then_some(group.end_pc as usize),
                    None,
                    None,
                ];
            } else {
                let instruction = &proto.instructions[pc];
                let opened = open || captures[pc] != 0;
                let marker = matches!(instruction.instruction,
                    Instruction::Move { dest, .. } if dest == register)
                    && instruction.close_path.is_some();
                next_state = usize::from(opened) | (usize::from(to_close || marker) << 1);
                successors = cfg_successors(proto, pc);
            }
            for successor in successors.into_iter().flatten() {
                work_charge(work, 1, proto.id, pc)?;
                let bit = 1u8 << next_state;
                if seen[successor] & bit == 0 {
                    seen[successor] |= bit;
                    pending.push(successor * 4 + next_state);
                }
            }
        }
    }
    Ok(())
}

/// 只列舉具靜態值的 guest register；開放結果由相鄰 consumer 的暫存區承接。
fn visit_static_registers<F: FnMut(Register) -> Result<(), OfficialExportError>>(
    proto: &BytecodePrototype,
    pc: usize,
    mut visit: F,
) -> Result<(), OfficialExportError> {
    let instruction = &proto.instructions[pc].instruction;
    if matches!(instruction, Instruction::Vararg { .. }) {
        if let Some((_, register)) = proto.named_vararg {
            visit(register)?;
        }
    }
    match instruction {
        Instruction::Move { dest, src } => {
            visit(*src)?;
            visit(*dest)?;
        }
        Instruction::LoadConst { dest, .. }
        | Instruction::GetUpvalue { dest, .. }
        | Instruction::NewTable { dest }
        | Instruction::Closure { dest, .. } => visit(*dest)?,
        Instruction::LoadNil { start, count } => visit_range(*start, *count, visit)?,
        Instruction::SetUpvalue { src, .. } => visit(*src)?,
        Instruction::GetTable { dest, table, key } => {
            visit(*table)?;
            visit(*key)?;
            visit(*dest)?;
        }
        Instruction::SetTable { table, key, value } => {
            visit(*table)?;
            visit(*key)?;
            visit(*value)?;
        }
        Instruction::UnaryOp { dest, src, .. } => {
            visit(*src)?;
            visit(*dest)?;
        }
        Instruction::BinaryOp {
            dest, left, right, ..
        } => {
            visit(*left)?;
            visit(*right)?;
            visit(*dest)?;
        }
        Instruction::JumpIfFalse { condition, .. } => visit(*condition)?,
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            let end = if *arg_count == u16::MAX {
                open_prefix_end(proto, pc, false).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "open Call 缺少相鄰 producer",
                    )
                })?
            } else {
                base.0
                    .checked_add(*arg_count)
                    .and_then(|end| end.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "Call register 範圍溢位",
                        )
                    })?
            };
            visit_range(*base, end.saturating_sub(base.0), &mut visit)?;
            if let ResultMode::Fixed(count) = result_mode {
                visit_range(*base, *count, visit)?;
            }
        }
        Instruction::TailCall {
            base, arg_count, ..
        } => {
            let end = if *arg_count == u16::MAX {
                open_prefix_end(proto, pc, false).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "open TailCall 缺少相鄰 producer",
                    )
                })?
            } else {
                base.0
                    .checked_add(*arg_count)
                    .and_then(|end| end.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "TailCall register 範圍溢位",
                        )
                    })?
            };
            visit_range(*base, end.saturating_sub(base.0), visit)?;
        }
        Instruction::Vararg {
            base,
            result_mode: ResultMode::Fixed(count),
        } => visit_range(*base, *count, visit)?,
        Instruction::Return { base, result_mode } => {
            let count = match result_mode {
                ResultMode::Fixed(count) => *count,
                ResultMode::All => open_prefix_end(proto, pc, true)
                    .and_then(|end| end.checked_sub(base.0))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            proto.id,
                            pc,
                            "open Return 缺少 producer",
                        )
                    })?,
            };
            visit_range(*base, count, visit)?;
        }
        Instruction::Close { base, .. } => visit(*base)?,
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
        } => {
            visit(*control)?;
            visit(*limit)?;
            visit(*step)?;
            visit(*visible)?;
        }
        Instruction::Jump { .. }
        | Instruction::Vararg {
            result_mode: ResultMode::All,
            ..
        } => {}
    }
    Ok(())
}

fn static_register_access(
    proto: &BytecodePrototype,
    pc: usize,
    register: Register,
) -> (bool, bool) {
    let instruction = &proto.instructions[pc].instruction;
    let range = |start: Register, count: u16| register.0 >= start.0 && register.0 - start.0 < count;
    let (read, write) = match instruction {
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            let read = if *arg_count == u16::MAX {
                open_prefix_end(proto, pc, false)
                    .is_some_and(|end| register.0 >= base.0 && register.0 < end)
            } else {
                range(*base, arg_count.saturating_add(1))
            };
            let write = matches!(result_mode, ResultMode::Fixed(count) if range(*base, *count));
            (read, write)
        }
        Instruction::TailCall {
            base, arg_count, ..
        } if *arg_count == u16::MAX => (
            open_prefix_end(proto, pc, false)
                .is_some_and(|end| register.0 >= base.0 && register.0 < end),
            false,
        ),
        Instruction::Vararg {
            result_mode: ResultMode::All,
            ..
        } => (false, false),
        Instruction::Return {
            base,
            result_mode: ResultMode::All,
        } => (
            open_prefix_end(proto, pc, true)
                .is_some_and(|end| register.0 >= base.0 && register.0 < end),
            false,
        ),
        _ => {
            let (read, write, _, _) =
                super::native_debug::register_access(instruction, register, proto.register_count);
            (read, write)
        }
    };
    (
        read || matches!(instruction, Instruction::Vararg { .. })
            && proto
                .named_vararg
                .is_some_and(|(_, named)| named == register),
        write,
    )
}

fn static_access_charge(
    proto: &BytecodePrototype,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<(), OfficialExportError> {
    if matches!(
        proto.instructions[pc].instruction,
        Instruction::Return {
            result_mode: ResultMode::All,
            ..
        }
    ) {
        work_charge(work, pc, proto.id, pc)?;
    }
    Ok(())
}

fn environment_access(
    proto: &BytecodePrototype,
    pc: usize,
    meta: &Layout,
    work: &mut OfficialWorkBudget,
) -> Result<(bool, bool), OfficialExportError> {
    if meta.env_upvalue.is_none()
        || matches!(
            proto.instructions[pc].instruction,
            Instruction::Close { .. }
        )
    {
        return Ok((false, false));
    }
    let env = proto.frame.environment;
    let (_, _, possible_write, _) = super::native_debug::register_access(
        &proto.instructions[pc].instruction,
        env,
        proto.register_count,
    );
    if possible_write
        || matches!(proto.instructions[pc].instruction,
        Instruction::NumericForPrepare { control, visible, .. }
        | Instruction::NumericForNext { control, visible, .. }
            if control == env || visible == env)
    {
        return Err(error(
            OfficialExportErrorKind::Unsupported,
            proto.id,
            pc,
            "native environment 動態或迴圈結果無法同步 upvalue",
        ));
    }
    static_access_charge(proto, pc, work)?;
    Ok(static_register_access(proto, pc, env))
}

fn cfg_successors(proto: &BytecodePrototype, pc: usize) -> [Option<usize>; 3] {
    let next = (pc + 1 < proto.instructions.len()).then_some(pc + 1);
    match &proto.instructions[pc].instruction {
        Instruction::Jump { target } => [Some(target.0 as usize), None, None],
        Instruction::JumpIfFalse { target, .. }
        | Instruction::NumericForPrepare { exit: target, .. } => {
            [Some(target.0 as usize), next, None]
        }
        Instruction::NumericForNext { target, exit, .. } => {
            [Some(target.0 as usize), Some(exit.0 as usize), None]
        }
        Instruction::Return { .. } | Instruction::TailCall { .. } => [None, None, None],
        _ => [next, None, None],
    }
}

/// 對每個暫存 register 逆向追蹤 CFG 的讀取來源，將回邊上的活躍 PC 也納入區間。
/// 使用單一可重用 bitmap/worklist，不儲存 register × PC 矩陣。
fn extend_live_spans(
    proto: &BytecodePrototype,
    mapped: &[u8],
    spans: &mut [(usize, usize)],
    work: &mut OfficialWorkBudget,
) -> Result<(), OfficialExportError> {
    let count = proto.instructions.len();
    work_charge(
        work,
        count.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG 初始 work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    let mut offsets = Vec::new();
    offsets.try_reserve_exact(count + 1).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG predecessor offset 配置失敗",
        )
    })?;
    offsets.resize(count + 1, 0usize);
    work_charge(
        work,
        count.checked_mul(2).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG edge work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    for pc in 0..count {
        for target in cfg_successors(proto, pc).into_iter().flatten() {
            let slot = offsets.get_mut(target + 1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "native CFG target 超出 prototype",
                )
            })?;
            *slot = slot.checked_add(1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native CFG edge 數溢位",
                )
            })?;
        }
    }
    work_charge(work, offsets.len(), proto.id, 0)?;
    for index in 1..offsets.len() {
        offsets[index] = offsets[index]
            .checked_add(offsets[index - 1])
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    index,
                    "native CFG predecessor offset 溢位",
                )
            })?;
    }
    let edge_count = offsets[count];
    work_charge(
        work,
        count.checked_add(edge_count).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG predecessor work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    let mut cursor = Vec::new();
    cursor.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG cursor 配置失敗",
        )
    })?;
    cursor.extend_from_slice(&offsets[..count]);
    let mut edges = Vec::new();
    edges.try_reserve_exact(edge_count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG predecessor 配置失敗",
        )
    })?;
    edges.resize(edge_count, 0usize);
    work_charge(work, count, proto.id, 0)?;
    for pc in 0..count {
        for target in cfg_successors(proto, pc).into_iter().flatten() {
            let at = cursor[target];
            edges[at] = pc;
            cursor[target] += 1;
        }
    }
    drop(cursor);
    work_charge(
        work,
        count.checked_mul(3).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG bitmap work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    let mut effects = Vec::new();
    effects.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG register effect 配置失敗",
        )
    })?;
    effects.resize(count, 0u8);
    let mut live = Vec::new();
    live.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG live bitmap 配置失敗",
        )
    })?;
    live.resize(count, 0u8);
    let mut pending = Vec::new();
    pending.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG live worklist 配置失敗",
        )
    })?;
    work_charge(work, spans.len(), proto.id, 0)?;
    for register in 0..spans.len() {
        if mapped[register] != u8::MAX || spans[register].0 == usize::MAX {
            continue;
        }
        let register_id = Register(register as u16);
        work_charge(
            work,
            count.checked_mul(8).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native CFG per-register work 溢位",
                )
            })?,
            proto.id,
            0,
        )?;
        effects.fill(0);
        live.fill(0);
        pending.clear();
        for pc in 0..count {
            static_access_charge(proto, pc, work)?;
            let (read, write) = static_register_access(proto, pc, register_id);
            effects[pc] = u8::from(read) | (u8::from(write) << 1);
            if read {
                live[pc] = 1;
                pending.push(pc);
            }
        }
        while let Some(pc) = pending.pop() {
            for &predecessor in &edges[offsets[pc]..offsets[pc + 1]] {
                work_charge(work, 1, proto.id, pc)?;
                let (start, end) = &mut spans[register];
                *start = (*start).min(predecessor);
                *end = (*end).max(predecessor + 1);
                // 同一指令若先讀再寫，舊值仍需沿 predecessor 保留。
                if effects[predecessor] & 2 != 0 && effects[predecessor] & 1 == 0 {
                    continue;
                }
                if live[predecessor] == 0 {
                    live[predecessor] = 1;
                    pending.push(predecessor);
                }
            }
        }
    }
    Ok(())
}

/// bare module 沒有 debug sidecar；由已驗證的 Closure/Close CFG 延長捕獲值的
/// 實體儲存期間，直到每一可達路徑都關閉或 frame 結束。
fn extend_capture_spans(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    spans: &mut [(usize, usize)],
    protected: &mut [u8],
    work: &mut OfficialWorkBudget,
) -> Result<(), OfficialExportError> {
    let count = proto.instructions.len();
    if count == 0 {
        return Ok(());
    }
    work_charge(
        work,
        count
            .checked_mul(4)
            .and_then(|amount| amount.checked_add(proto.binding_registers.len()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native capture CFG 初始 work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    let mut captures = Vec::new();
    captures.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native capture bitmap 配置失敗",
        )
    })?;
    captures.resize(count, 0u8);
    let mut seen = Vec::new();
    seen.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native capture CFG state 配置失敗",
        )
    })?;
    seen.resize(count, 0u8);
    let queue_count = count.checked_mul(2).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native capture CFG queue 溢位",
        )
    })?;
    let mut pending = Vec::new();
    pending.try_reserve_exact(queue_count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native capture CFG worklist 配置失敗",
        )
    })?;
    for (binding, register) in &proto.binding_registers {
        work_charge(
            work,
            count.checked_mul(4).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native capture CFG work 溢位",
                )
            })?,
            proto.id,
            0,
        )?;
        let mut any = false;
        for (pc, instruction) in proto.instructions.iter().enumerate() {
            captures[pc] = u8::from(
                super::native_debug::capture_at(module, &instruction.instruction, *binding, work)
                    .map_err(|source| {
                    native_debug_error(
                        source.code,
                        work,
                        proto.id,
                        pc,
                        "native capture metadata 無效",
                    )
                })?,
            );
            any |= captures[pc] != 0;
        }
        if !any {
            continue;
        }
        let first_capture = captures
            .iter()
            .position(|captured| *captured != 0)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "capture bitmap 缺首個位置",
                )
            })?;
        work_charge(work, first_capture + 1, proto.id, first_capture)?;
        let birth = if register.0 <= proto.parameter_count {
            0
        } else {
            let mut first_write = None;
            for pc in 0..=first_capture {
                static_access_charge(proto, pc, work)?;
                if static_register_access(proto, pc, *register).1 {
                    first_write = Some(pc);
                    break;
                }
            }
            first_write.unwrap_or(0)
        };
        let initial_span = &mut spans[usize::from(register.0)];
        initial_span.0 = initial_span.0.min(birth);
        initial_span.1 = initial_span.1.max(first_capture + 1);
        protected[usize::from(register.0)] |= 1;
        seen.fill(0);
        pending.clear();
        seen[0] = 1;
        pending.push(0usize);
        while let Some(encoded) = pending.pop() {
            let pc = encoded / 2;
            let was_open = encoded & 1 != 0;
            let opened = was_open || captures[pc] != 0;
            if opened {
                let span = &mut spans[usize::from(register.0)];
                span.0 = span.0.min(pc);
                span.1 = span.1.max(pc + 1);
            }
            let still_open = opened
                && !matches!(proto.instructions[pc].instruction,
                Instruction::Close { base, count: 0 } if base == *register);
            for successor in cfg_successors(proto, pc).into_iter().flatten() {
                work_charge(work, 1, proto.id, pc)?;
                let state = usize::from(still_open);
                let bit = 1u8 << state;
                if seen[successor] & bit == 0 {
                    seen[successor] |= bit;
                    pending.push(successor * 2 + state);
                }
            }
        }
    }
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    for entry in &proto.instructions {
        if let Instruction::Move { dest, .. } = entry.instruction {
            if entry.close_path.is_some() {
                if let Some(slot) = protected.get_mut(usize::from(dest.0)) {
                    *slot |= 2;
                }
            }
        }
    }
    Ok(())
}

/// 由 P05 local storage 與 guest register 存取區間配置實體槽；每個暫存槽
/// 在保守的 first..last 區間內獨占，因此回邊也不會覆蓋仍可讀的值。
fn compact_map_peak_bytes(
    proto: &BytecodePrototype,
    storage_count: usize,
) -> Result<usize, OfficialExportError> {
    let registers = usize::from(proto.register_count);
    let instructions = proto.instructions.len();
    let register_bytes = registers
        .checked_mul(
            size_of::<u8>() * 2
                + size_of::<(usize, usize)>()
                + size_of::<(usize, usize, usize)>()
                + size_of::<(u8, usize, usize)>(),
        )
        .and_then(|bytes| {
            storage_count
                .checked_mul(size_of::<(u8, usize, usize)>())
                .and_then(|extra| bytes.checked_add(extra))
        });
    let instruction_bytes = instructions
        .checked_mul(size_of::<usize>() * 6 + 4 + size_of::<u16>())
        .and_then(|bytes| bytes.checked_add(size_of::<usize>()));
    register_bytes
        .and_then(|bytes| instruction_bytes.and_then(|extra| bytes.checked_add(extra)))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native mapping peak 大小溢位",
            )
        })
}

fn compact_register_map(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    numeric: &[NumericPair],
    numeric_blocks: u16,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<(Vec<u8>, Vec<u8>, u16, Vec<u16>, Vec<u16>, u8), OfficialExportError> {
    let debug = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id));
    let storage = module
        .native_debug()
        .and_then(|debug| debug.storage_for(proto.id))
        .unwrap_or(&[]);
    if compact_map_peak_bytes(proto, storage.len())? > limits.max_allocated_bytes {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native mapping peak 超過配置額度",
        ));
    }
    let count = usize::from(proto.register_count);
    work_charge(
        work,
        count
            .checked_add(proto.instructions.len())
            .and_then(|total| total.checked_add(storage.len()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native mapping work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    let mut mapped = Vec::new();
    mapped.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native register map 配置失敗",
        )
    })?;
    mapped.resize(count, u8::MAX);
    for local in storage {
        let slot = mapped
            .get_mut(usize::from(local.register.0))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "native local register 超出 prototype",
                )
            })?;
        if *slot != u8::MAX && *slot != local.slot {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                0,
                "native local register 對應衝突",
            ));
        }
        *slot = local.slot;
    }
    let mut fixed = u16::from(debug.map_or(0, |entry| entry.max_active_locals));
    if debug.is_none() {
        for parameter in 0..proto.parameter_count {
            let register = usize::from(parameter) + 1;
            let Some(slot) = mapped.get_mut(register) else {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "native parameter register 不存在",
                ));
            };
            *slot = u8::try_from(parameter).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native parameter slot 超限",
                )
            })?;
        }
        fixed = proto.parameter_count;
        if let Some((_, register)) = proto.named_vararg {
            let slot = mapped.get_mut(usize::from(register.0)).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "native named vararg register 不存在",
                )
            })?;
            *slot = u8::try_from(fixed).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native named vararg slot 超限",
                )
            })?;
            fixed += 1;
        }
    }
    if let Some(env) = mapped.get_mut(usize::from(proto.frame.environment.0)) {
        if *env == u8::MAX {
            *env = u8::try_from(fixed).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native environment slot 超限",
                )
            })?;
            fixed = fixed.checked_add(1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native environment slot 溢位",
                )
            })?;
        }
    }
    let tuple_base = fixed;
    let temp_base = fixed
        .checked_add(numeric_blocks.checked_mul(4).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native numeric tuple 溢位",
            )
        })?)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native temp base 溢位",
            )
        })?;
    let mut span = Vec::new();
    span.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native live span 配置失敗",
        )
    })?;
    span.resize(count, (usize::MAX, 0usize));
    let mut protected = Vec::new();
    protected.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native protected register 配置失敗",
        )
    })?;
    protected.resize(count, 0u8);
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    for pc in 0..proto.instructions.len() {
        static_access_charge(proto, pc, work)?;
        visit_static_registers(proto, pc, |register| {
            work_charge(work, 1, proto.id, pc)?;
            let Some(interval) = span.get_mut(usize::from(register.0)) else {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "native static register 超出 prototype",
                ));
            };
            interval.0 = interval.0.min(pc);
            interval.1 = interval.1.max(pc + 1);
            Ok(())
        })?;
    }
    extend_live_spans(proto, &mapped, &mut span, work)?;
    for register in 1..=proto.parameter_count {
        if let Some(interval) = span.get_mut(usize::from(register)) {
            if interval.0 != usize::MAX {
                interval.0 = 0;
            }
        }
    }
    if let Some((_, register)) = proto.named_vararg {
        if let Some(interval) = span.get_mut(usize::from(register.0)) {
            if interval.0 != usize::MAX {
                interval.0 = 0;
            }
        }
    }
    if debug.is_none() {
        extend_capture_spans(module, proto, &mut span, &mut protected, work)?;
    }
    let mut intervals = Vec::new();
    intervals.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native live interval 配置失敗",
        )
    })?;
    work_charge(work, span.len(), proto.id, 0)?;
    for (register, &(start, end)) in span.iter().enumerate() {
        if start != usize::MAX && mapped[register] == u8::MAX {
            intervals.push((start, end, register));
        }
    }
    work_charge(
        work,
        intervals
            .len()
            .checked_mul(usize::BITS as usize)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native interval sort work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    intervals.sort_unstable_by_key(|&(start, _, register)| (start, register));
    let mut fixed_intervals = Vec::new();
    fixed_intervals
        .try_reserve_exact(count.checked_add(storage.len()).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native fixed interval 數溢位",
            )
        })?)
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native fixed interval 配置失敗",
            )
        })?;
    work_charge(
        work,
        mapped.len().checked_add(storage.len()).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native fixed interval 掃描 work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    for (register, &slot) in mapped.iter().enumerate() {
        if slot != u8::MAX && span[register].0 != usize::MAX {
            fixed_intervals.push((slot, span[register].0, span[register].1));
        }
    }
    for local in storage {
        fixed_intervals.push((local.slot, local.start_pc as usize, local.end_pc as usize));
    }
    work_charge(
        work,
        fixed_intervals
            .len()
            .checked_mul(usize::BITS as usize)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native fixed interval sort work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    fixed_intervals.sort_unstable_by_key(|&(slot, start, _)| (slot, start));
    let mut fixed_boundaries = [0usize; 256];
    let mut fixed_index = 0usize;
    work_charge(
        work,
        fixed_intervals.len().checked_add(255).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native fixed boundary work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    for slot in 0..255usize {
        fixed_boundaries[slot] = fixed_index;
        while fixed_index < fixed_intervals.len()
            && usize::from(fixed_intervals[fixed_index].0) == slot
        {
            fixed_index += 1;
        }
    }
    fixed_boundaries[255] = fixed_index;
    let mut slot_end = [0usize; 255];
    let mut protected_slot_end = [0usize; 255];
    let mut high = temp_base;
    work_charge(
        work,
        intervals.len().checked_mul(255).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native interval 搜尋 work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    for (start, end, register) in intervals {
        let mut floor = 0u16;
        if protected[register] != 0 {
            for slot in 0..high {
                if (protected[register] & 2 != 0 && slot_end[usize::from(slot)] > start)
                    || protected_slot_end[usize::from(slot)] > start
                {
                    floor = floor.max(slot + 1);
                }
            }
        }
        let mut chosen = None;
        for slot in floor..255u16 {
            work_charge(work, 1, proto.id, start)?;
            if slot >= tuple_base && slot < temp_base {
                continue;
            }
            if slot_end[usize::from(slot)] > start {
                continue;
            }
            let fixed = &fixed_intervals
                [fixed_boundaries[usize::from(slot)]..fixed_boundaries[usize::from(slot) + 1]];
            work_charge(work, fixed.len(), proto.id, start)?;
            if fixed
                .iter()
                .any(|&(_, fixed_start, fixed_end)| fixed_start < end && start < fixed_end)
            {
                continue;
            }
            chosen = Some(slot);
            break;
        }
        let slot = chosen.ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                start,
                "native 同時活躍 register 超過官方 stack",
            )
        })?;
        slot_end[usize::from(slot)] = end;
        if protected[register] != 0 {
            protected_slot_end[usize::from(slot)] = end;
        }
        mapped[register] = slot as u8;
        high = high.max(slot + 1);
    }
    let mut scratch = Vec::new();
    work_charge(
        work,
        proto.instructions.len().checked_mul(2).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native scratch 清單 work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
    scratch
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native scratch 佈局配置失敗",
            )
        })?;
    scratch.resize(proto.instructions.len(), temp_base);
    let mut parallel_spare = Vec::new();
    parallel_spare
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native parallel copy 佈局配置失敗",
            )
        })?;
    parallel_spare.resize(proto.instructions.len(), NO_PARALLEL_COPY);
    let mut max_stack = high.max(2);
    let mut pc = 0usize;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    while pc < proto.instructions.len() {
        let end = if matches!(
            proto.instructions[pc].instruction,
            Instruction::Call {
                result_mode: ResultMode::All,
                ..
            } | Instruction::Vararg {
                result_mode: ResultMode::All,
                ..
            }
        ) {
            open_chain_end(proto, pc, work)?
        } else {
            pc
        };
        let mut width = 0u16;
        let mut top = 0u16;
        work_charge(work, end - pc + 1, proto.id, pc)?;
        for at in pc..=end {
            let needed = scratch_width_at(proto, at, work)?;
            if needed == 0 {
                continue;
            }
            width = width.max(needed);
            work_charge(
                work,
                count.checked_add(storage.len()).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        at,
                        "native scratch liveness work 溢位",
                    )
                })?,
                proto.id,
                at,
            )?;
            for (register, &(start, last)) in span.iter().enumerate() {
                if start <= at && at < last && mapped[register] != u8::MAX {
                    top = top.max(u16::from(mapped[register]) + 1);
                }
            }
            for local in storage {
                if (local.start_pc as usize) <= at && at < local.end_pc as usize {
                    top = top.max(u16::from(local.slot) + 1);
                }
            }
            work_charge(work, numeric.len(), proto.id, at)?;
            for pair in numeric {
                if pair.prepare_pc <= at && at <= pair.next_pc {
                    top = top.max(
                        tuple_base
                            .checked_add(
                                pair.block
                                    .checked_add(1)
                                    .and_then(|block| block.checked_mul(4))
                                    .ok_or_else(|| {
                                        error(
                                            OfficialExportErrorKind::LimitExceeded,
                                            proto.id,
                                            at,
                                            "numeric scratch floor 溢位",
                                        )
                                    })?,
                            )
                            .ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    proto.id,
                                    at,
                                    "numeric scratch floor 溢位",
                                )
                            })?,
                    );
                }
            }
        }
        if width > 0 {
            let peak = top.checked_add(width).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native scratch peak 溢位",
                )
            })?;
            if peak > 255 {
                let fixed_copy = match proto.instructions[pc].instruction {
                    Instruction::Call {
                        base,
                        arg_count,
                        result_mode: ResultMode::Fixed(results),
                    } if arg_count != u16::MAX => Some((base, arg_count + 1, results)),
                    Instruction::TailCall {
                        base, arg_count, ..
                    } if arg_count != u16::MAX => Some((base, arg_count + 1, 0)),
                    Instruction::Return {
                        base,
                        result_mode: ResultMode::Fixed(results),
                    } => Some((base, results, 0)),
                    Instruction::Vararg {
                        base,
                        result_mode: ResultMode::Fixed(results),
                    } => Some((base, 0, results)),
                    _ => None,
                };
                let Some((guest, gathered, scattered)) =
                    fixed_copy.filter(|_| end == pc && width <= 255)
                else {
                    return Err(error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native maxstack 超過 255",
                    ));
                };
                let mut immutable = [false; 255];
                let is_call =
                    matches!(proto.instructions[pc].instruction, Instruction::Call { .. });
                let is_vararg = matches!(
                    proto.instructions[pc].instruction,
                    Instruction::Vararg { .. }
                );
                let mut call_floor = 0u16;
                work_charge(
                    work,
                    count.checked_add(storage.len()).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native immutable slot work 溢位",
                        )
                    })?,
                    proto.id,
                    pc,
                )?;
                for (register, &(start, last)) in span.iter().enumerate() {
                    let result_written = register >= usize::from(guest.0)
                        && register - usize::from(guest.0) < usize::from(scattered);
                    if protected[register] != 0
                        && start <= pc
                        && pc < last
                        && mapped[register] != u8::MAX
                        && !(is_vararg && result_written)
                    {
                        immutable[usize::from(mapped[register])] = true;
                    }
                    if is_call && start <= pc && pc < last && mapped[register] != u8::MAX {
                        if protected[register] != 0 || last > pc + 1 && !result_written {
                            call_floor = call_floor.max(u16::from(mapped[register]) + 1);
                        }
                    }
                    if is_vararg && start <= pc && pc < last && mapped[register] != u8::MAX {
                        if !result_written && (last > pc + 1 || protected[register] != 0) {
                            immutable[usize::from(mapped[register])] = true;
                        }
                    }
                }
                for local in storage {
                    if local.start_pc as usize <= pc && pc < local.end_pc as usize {
                        let result_written = is_vararg
                            && local.register.0 >= guest.0
                            && local.register.0 - guest.0 < scattered;
                        if !result_written {
                            immutable[usize::from(local.slot)] = true;
                        }
                        if is_call {
                            call_floor = call_floor.max(u16::from(local.slot) + 1);
                        }
                    }
                }
                if is_vararg && scattered > 0 {
                    if let Some((_, register)) = proto.named_vararg {
                        let slot =
                            mapped
                                .get(usize::from(register.0))
                                .copied()
                                .ok_or_else(|| {
                                    error(
                                        OfficialExportErrorKind::InvalidPrototype,
                                        proto.id,
                                        pc,
                                        "具名 vararg register 不存在",
                                    )
                                })?;
                        immutable[usize::from(slot)] = true;
                    }
                }
                if is_call || is_vararg {
                    work_charge(
                        work,
                        numeric.len().checked_mul(5).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                proto.id,
                                pc,
                                "numeric tuple 保護 work 溢位",
                            )
                        })?,
                        proto.id,
                        pc,
                    )?;
                    for pair in numeric {
                        if pair.prepare_pc <= pc && pc <= pair.next_pc {
                            if is_call {
                                call_floor = call_floor.max(tuple_base + (pair.block + 1) * 4);
                            }
                            if is_vararg {
                                let base = tuple_base + pair.block * 4;
                                for slot in base..base + 4 {
                                    let Some(protected_slot) = immutable.get_mut(usize::from(slot))
                                    else {
                                        return Err(error(
                                            OfficialExportErrorKind::LimitExceeded,
                                            proto.id,
                                            pc,
                                            "numeric tuple 超出官方 stack",
                                        ));
                                    };
                                    *protected_slot = true;
                                }
                            }
                        }
                    }
                }
                let max_base = 255 - width;
                let preferred = mapped
                    .get(usize::from(guest.0))
                    .copied()
                    .filter(|slot| *slot != u8::MAX)
                    .map(u16::from);
                let mut chosen = None;
                work_charge(work, usize::from(max_base) + 2, proto.id, pc)?;
                for candidate in preferred.into_iter().chain(0..=max_base) {
                    if candidate > max_base || candidate < call_floor {
                        continue;
                    }
                    let checked = if is_call || is_vararg {
                        width
                    } else {
                        gathered
                    };
                    work_charge(work, usize::from(checked), proto.id, pc)?;
                    if (0..checked).any(|offset| {
                        let source = if offset < gathered {
                            mapped
                                .get(usize::from(guest.0) + usize::from(offset))
                                .copied()
                                .unwrap_or(u8::MAX)
                        } else {
                            u8::MAX
                        };
                        let dest = candidate + offset;
                        immutable[usize::from(dest)] && u16::from(source) != dest
                    }) {
                        continue;
                    }
                    work_charge(work, usize::from(255 - top), proto.id, pc)?;
                    let spare = (top..255)
                        .find(|slot| *slot < candidate || *slot >= candidate + width)
                        .map(|slot| slot as u8);
                    let candidate = candidate as u8;
                    if parallel_copy_plan(
                        &mapped, guest, gathered, candidate, true, spare, proto.id, pc, work,
                    )?
                    .is_none()
                    {
                        continue;
                    }
                    if scattered > 0
                        && parallel_copy_plan(
                            &mapped, guest, scattered, candidate, false, spare, proto.id, pc, work,
                        )?
                        .is_none()
                    {
                        continue;
                    }
                    chosen = Some((candidate, spare));
                    break;
                }
                let Some((candidate, spare)) = chosen else {
                    return Err(error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native maxstack 無安全重疊窗口",
                    ));
                };
                scratch[pc] = u16::from(candidate);
                parallel_spare[pc] = spare.map_or(NO_SPARE_SLOT, u16::from);
                max_stack = max_stack
                    .max(top)
                    .max(u16::from(candidate) + width)
                    .max(spare.map_or(0, |slot| u16::from(slot) + 1));
                pc += 1;
                continue;
            }
            scratch[pc..=end].fill(top);
            max_stack = max_stack.max(peak);
        }
        pc = end + 1;
    }
    let max_stack = u8::try_from(max_stack).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native maxstack 超過 255",
        )
    })?;
    work_charge(work, mapped.len(), proto.id, 0)?;
    for slot in &mut mapped {
        if *slot == u8::MAX {
            *slot = u8::try_from(temp_base.min(254)).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native 未使用 register fallback 超限",
                )
            })?;
        }
    }
    Ok((
        mapped,
        protected,
        tuple_base,
        scratch,
        parallel_spare,
        max_stack,
    ))
}

fn layout(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    root: bool,
    numeric: &[NumericPair],
    numeric_blocks: u16,
    work: &mut OfficialWorkBudget,
    limits: &OfficialChunkLimits,
) -> Result<Layout, OfficialExportError> {
    let env_needed = needs_environment(module, proto, work, 1, limits)?;
    let synthetic = env_needed
        && matches!(
            proto.frame.environment_source,
            EnvironmentSource::RootExternal | EnvironmentSource::ParentFrame { .. }
        );
    let guest_upvalue_offset = if root && synthetic { 1 } else { 0 };
    let env_upvalue = if synthetic {
        Some(if root {
            0
        } else {
            native_guest_upvalues(module, proto) as u16
        })
    } else if env_needed {
        match proto.frame.environment_source {
            EnvironmentSource::ParentLocal { upvalue }
            | EnvironmentSource::ParentUpvalue { upvalue } => Some(upvalue.0),
            _ => None,
        }
    } else {
        None
    };
    let (mapped, protected, tuple_base, scratch, parallel_spare, max_stack) =
        compact_register_map(module, proto, numeric, numeric_blocks, limits, work)?;
    Ok(Layout {
        tuple_base,
        scratch,
        parallel_spare,
        max_stack,
        guest_upvalue_offset,
        env_upvalue,
        mapped,
        protected,
    })
}

#[derive(Clone, Copy)]
struct NumericPair {
    prepare_pc: usize,
    next_pc: usize,
    body_pc: usize,
    tuple: u8,
    block: u16,
    visible: Register,
    exit: InstructionOffset,
}

fn numeric_pairs(
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
) -> Result<(Vec<NumericPair>, u16), OfficialExportError> {
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    let count = proto
        .instructions
        .iter()
        .filter(|entry| matches!(entry.instruction, Instruction::NumericForPrepare { .. }))
        .count();
    let mut pairs = Vec::new();
    pairs.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric pair 配置失敗",
        )
    })?;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    for (prepare_pc, entry) in proto.instructions.iter().enumerate() {
        let Instruction::NumericForPrepare {
            control,
            limit,
            step,
            visible,
            exit,
        } = entry.instruction
        else {
            continue;
        };
        let body_pc = prepare_pc + 1;
        work_charge(work, proto.instructions.len(), proto.id, prepare_pc)?;
        let next_pc = proto
            .instructions
            .iter()
            .enumerate()
            .find_map(|(pc, candidate)| match candidate.instruction {
                Instruction::NumericForNext {
                    control: c,
                    limit: l,
                    step: s,
                    visible: v,
                    target,
                    exit: next_exit,
                } if c == control
                    && l == limit
                    && s == step
                    && v == visible
                    && target.0 as usize == body_pc
                    && next_exit == exit =>
                {
                    Some(pc)
                }
                _ => None,
            })
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    prepare_pc,
                    "numeric prepare 缺配對 next",
                )
            })?;
        work_charge(
            work,
            pairs
                .len()
                .checked_add(1)
                .and_then(|count| count.checked_mul(256))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        prepare_pc,
                        "numeric tuple 搜尋工作量溢位",
                    )
                })?,
            proto.id,
            prepare_pc,
        )?;
        let block = (0..=u8::MAX)
            .find(|candidate| {
                !pairs.iter().any(|pair: &NumericPair| {
                    pair.block == u16::from(*candidate) && pair.next_pc >= prepare_pc
                })
            })
            .map(u16::from)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    prepare_pc,
                    "numeric tuple 同時活躍數超限",
                )
            })?;
        pairs.push(NumericPair {
            prepare_pc,
            next_pc,
            body_pc,
            tuple: 0,
            block,
            visible,
            exit,
        });
    }
    work_charge(work, pairs.len(), proto.id, 0)?;
    let blocks = pairs.iter().map(|pair| pair.block + 1).max().unwrap_or(0);
    Ok((pairs, blocks))
}

struct Builder<'a> {
    id: ProtoId,
    limits: &'a OfficialChunkLimits,
    work: &'a mut OfficialWorkBudget,
    total_instructions: &'a mut usize,
    max_words: usize,
    code: Vec<u32>,
    source_lines: Option<&'a [u32]>,
    lines: Vec<u32>,
}

impl Builder<'_> {
    fn push(&mut self, word: u32, pc: usize) -> Result<(), OfficialExportError> {
        work_charge(self.work, 1, self.id, pc)?;
        if self.code.len() >= self.max_words {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                self.id,
                pc,
                "native 指令數超出預付額度",
            ));
        }
        *self.total_instructions = self.total_instructions.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                self.id,
                pc,
                "官方指令數溢位",
            )
        })?;
        if *self.total_instructions > self.limits.max_instructions {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                self.id,
                pc,
                "官方指令數超限",
            ));
        }
        self.code.try_reserve(1).map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                self.id,
                pc,
                "官方指令配置失敗",
            )
        })?;
        if let Some(source) = self.source_lines {
            self.lines.try_reserve(1).map_err(|_| {
                error(
                    OfficialExportErrorKind::AllocationFailed,
                    self.id,
                    pc,
                    "官方行號配置失敗",
                )
            })?;
            self.lines.push(
                source
                    .get(pc)
                    .copied()
                    .or_else(|| source.last().copied())
                    .unwrap_or(1),
            );
        }
        self.code.push(word);
        Ok(())
    }
}

fn native_line_info(
    id: ProtoId,
    lines: &[u32],
    line_defined: u32,
    work: &mut OfficialWorkBudget,
) -> Result<(Vec<i8>, Vec<OfficialAbsLine>), OfficialExportError> {
    let mut deltas = Vec::new();
    deltas.try_reserve_exact(lines.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            id,
            0,
            "native line info 配置失敗",
        )
    })?;
    let mut absolute = Vec::new();
    absolute.try_reserve_exact(lines.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            id,
            0,
            "native absolute line 配置失敗",
        )
    })?;
    let mut previous = i64::from(line_defined);
    let mut since_absolute = 0usize;
    for (pc, &line) in lines.iter().enumerate() {
        work_charge(work, 1, id, pc)?;
        let current = i64::from(line);
        let delta = current - previous;
        if !(-127..=127).contains(&delta) || since_absolute >= 128 {
            deltas.push(-128);
            absolute.push(OfficialAbsLine {
                pc: u32::try_from(pc).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        pc,
                        "native absolute line PC 溢位",
                    )
                })?,
                line: i32::try_from(line).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        pc,
                        "native absolute line 值超限",
                    )
                })?,
            });
            since_absolute = 1;
        } else {
            deltas.push(delta as i8);
            since_absolute += 1;
        }
        previous = current;
    }
    Ok((deltas, absolute))
}

fn scratch_register(
    meta: &Layout,
    offset: u16,
    id: ProtoId,
    pc: usize,
) -> Result<u8, OfficialExportError> {
    meta.scratch
        .get(pc)
        .copied()
        .and_then(|base| base.checked_add(offset))
        .and_then(|slot| u8::try_from(slot).ok())
        .filter(|slot| *slot < meta.max_stack)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "native scratch register 超出 maxstack",
            )
        })
}

fn planned_copy(
    meta: &Layout,
    guest: Register,
    count: u16,
    offset: u16,
    gather: bool,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<ParallelMoves>, OfficialExportError> {
    let Some(&marker) = meta.parallel_spare.get(pc) else {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "平行搬移 PC 不存在",
        ));
    };
    if marker == NO_PARALLEL_COPY {
        return Ok(None);
    }
    let spare = if marker == NO_SPARE_SLOT {
        None
    } else {
        Some(u8::try_from(marker).map_err(|_| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                pc,
                "平行搬移備用槽無效",
            )
        })?)
    };
    let window = scratch_register(meta, offset, id, pc)?;
    parallel_copy_plan(
        &meta.mapped,
        guest,
        count,
        window,
        gather,
        spare,
        id,
        pc,
        work,
    )?
    .map(Some)
    .ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "平行搬移計畫與佈局不一致",
        )
    })
}

fn emit_gather(
    builder: &mut Builder<'_>,
    meta: &Layout,
    source: Register,
    count: u16,
    target_offset: u16,
    pc: usize,
) -> Result<(), OfficialExportError> {
    if let Some(plan) = planned_copy(
        meta,
        source,
        count,
        target_offset,
        true,
        builder.id,
        pc,
        builder.work,
    )? {
        for &(dest, src) in &plan.moves[..plan.len] {
            builder.push(abc(0, dest, src, 0, false), pc)?;
        }
        return Ok(());
    }
    for offset in 0..count {
        let source_register = source.0.checked_add(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                builder.id,
                pc,
                "native gather source 溢位",
            )
        })?;
        let target = target_offset.checked_add(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                builder.id,
                pc,
                "native gather target 溢位",
            )
        })?;
        builder.push(
            abc(
                0,
                scratch_register(meta, target, builder.id, pc)?,
                meta.register(Register(source_register), builder.id, pc)?,
                0,
                false,
            ),
            pc,
        )?;
    }
    Ok(())
}

fn emit_scatter(
    builder: &mut Builder<'_>,
    meta: &Layout,
    destination: Register,
    count: u16,
    source_offset: u16,
    pc: usize,
) -> Result<(), OfficialExportError> {
    if let Some(plan) = planned_copy(
        meta,
        destination,
        count,
        source_offset,
        false,
        builder.id,
        pc,
        builder.work,
    )? {
        for &(dest, src) in &plan.moves[..plan.len] {
            builder.push(abc(0, dest, src, 0, false), pc)?;
        }
        return Ok(());
    }
    for offset in 0..count {
        let destination_register = destination.0.checked_add(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                builder.id,
                pc,
                "native scatter destination 溢位",
            )
        })?;
        let source = source_offset.checked_add(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                builder.id,
                pc,
                "native scatter source 溢位",
            )
        })?;
        builder.push(
            abc(
                0,
                meta.register(Register(destination_register), builder.id, pc)?,
                scratch_register(meta, source, builder.id, pc)?,
                0,
                false,
            ),
            pc,
        )?;
    }
    Ok(())
}

#[derive(Default)]
struct NativePreflight {
    prototypes: usize,
    instructions: usize,
    constants: usize,
    upvalues: usize,
    strings: usize,
    string_bytes: usize,
    allocated_bytes: usize,
}

impl NativePreflight {
    fn add(
        value: &mut usize,
        amount: usize,
        max: usize,
        id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        *value = value
            .checked_add(amount)
            .filter(|total| *total <= max)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "native 官方輸出配額或整數溢位",
                )
            })?;
        Ok(())
    }

    fn bytes(
        &mut self,
        count: usize,
        size: usize,
        limits: &OfficialChunkLimits,
        id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        let amount = count.checked_mul(size).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                0,
                "native 配置大小溢位",
            )
        })?;
        Self::add(
            &mut self.allocated_bytes,
            amount,
            limits.max_allocated_bytes,
            id,
        )
    }

    fn string(
        &mut self,
        bytes: &[u8],
        limits: &OfficialChunkLimits,
        id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        if bytes.len() > limits.max_string_bytes {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                0,
                "native 字串超限",
            ));
        }
        Self::add(&mut self.strings, 1, limits.max_strings, id)?;
        Self::add(
            &mut self.string_bytes,
            bytes.len(),
            limits.max_total_string_bytes,
            id,
        )?;
        self.bytes(bytes.len(), 1, limits, id)
    }
}

fn native_opcode_words(
    groups: &[NativeCloseGroup],
    proto: &BytecodePrototype,
    meta: &Layout,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<usize, OfficialExportError> {
    let entry = &proto.instructions[pc];
    let words = match &entry.instruction {
        Instruction::Move { .. } if entry.close_path.is_some() => 2,
        Instruction::LoadConst { constant, .. } if constant.0 > 131_071 => 2,
        Instruction::LoadNil { count, .. } => usize::from(*count),
        Instruction::NewTable { .. } => 3,
        Instruction::Closure { .. } => 2,
        Instruction::JumpIfFalse { .. } | Instruction::NumericForNext { .. } => 2,
        Instruction::BinaryOp { op, .. } => match op {
            BinaryOperation::Concat
            | BinaryOperation::Equal
            | BinaryOperation::NotEqual
            | BinaryOperation::Less
            | BinaryOperation::LessEqual
            | BinaryOperation::Greater
            | BinaryOperation::GreaterEqual => 4,
            _ => 2,
        },
        Instruction::NumericForPrepare { .. } => 5,
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            let gathered = if *arg_count == u16::MAX {
                0usize
            } else {
                let root = if matches!(result_mode, ResultMode::All) {
                    open_root_base(proto, pc, work)?
                } else {
                    *base
                };
                usize::from(base.0.checked_sub(root.0).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "Call open prefix 逆序",
                    )
                })?) + usize::from(*arg_count)
                    + 1
            };
            let scattered = match result_mode {
                ResultMode::Fixed(count) => usize::from(*count),
                ResultMode::All => 0,
            };
            let scatter_count = match result_mode {
                ResultMode::Fixed(count) => *count,
                ResultMode::All => 0,
            };
            let gathered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                planned_copy(
                    meta,
                    *base,
                    u16::try_from(gathered).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "Call gather 數超限",
                        )
                    })?,
                    0,
                    true,
                    proto.id,
                    pc,
                    work,
                )?
                .map_or(gathered, |plan| plan.len)
            } else {
                gathered
            };
            let scattered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                planned_copy(meta, *base, scatter_count, 0, false, proto.id, pc, work)?
                    .map_or(scattered, |plan| plan.len)
            } else {
                scattered
            };
            1usize
                .checked_add(gathered)
                .and_then(|words| words.checked_add(scattered))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "Call opcode 數溢位",
                    )
                })?
        }
        Instruction::TailCall {
            base, arg_count, ..
        } => {
            let gathered = if *arg_count == u16::MAX {
                0
            } else {
                usize::from(*arg_count) + 1
            };
            let gathered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                planned_copy(meta, *base, gathered as u16, 0, true, proto.id, pc, work)?
                    .map_or(gathered, |plan| plan.len)
            } else {
                gathered
            };
            1 + gathered
        }
        Instruction::Vararg { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => {
                let scattered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                    planned_copy(meta, *base, *count, 0, false, proto.id, pc, work)?
                        .map_or(usize::from(*count), |plan| plan.len)
                } else {
                    usize::from(*count)
                };
                1 + scattered
            }
            ResultMode::All => {
                let root = open_root_base(proto, pc, work)?;
                1 + usize::from(base.0.checked_sub(root.0).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "Vararg open prefix 逆序",
                    )
                })?)
            }
        },
        Instruction::Return {
            base,
            result_mode: ResultMode::Fixed(count),
        } => {
            let gathered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                planned_copy(meta, *base, *count, 0, true, proto.id, pc, work)?
                    .map_or(usize::from(*count), |plan| plan.len)
            } else {
                usize::from(*count)
            };
            1 + gathered
        }
        Instruction::Close { .. } => {
            work_charge(work, usize::BITS as usize, proto.id, pc)?;
            if let Some(group) = close_group_at(groups, pc) {
                usize::from(group.emit_pc as usize == pc && !return_close_group(group, proto))
            } else {
                1
            }
        }
        _ => 1,
    };
    let (reads_env, writes_env) = environment_access(proto, pc, meta, work)?;
    words
        .checked_add(usize::from(reads_env) + usize::from(writes_env))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native environment 同步指令數溢位",
            )
        })
}

fn native_word_count(
    module: &VerifiedModule,
    groups: &[NativeCloseGroup],
    proto: &BytecodePrototype,
    meta: &Layout,
    root: bool,
    work: &mut OfficialWorkBudget,
) -> Result<usize, OfficialExportError> {
    let variadic = proto.is_variadic || root && proto.parent.is_none();
    let prologue = usize::from(variadic)
        .checked_add(usize::from(proto.parameter_count))
        .and_then(|total| total.checked_add(usize::from(meta.env_upvalue.is_some())))
        .and_then(|total| total.checked_add(usize::from(proto.named_vararg.is_some())))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native prologue 指令數溢位",
            )
        })?;
    let mut words = prologue;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    for pc in 0..proto.instructions.len() {
        words = words
            .checked_add(native_opcode_words(groups, proto, meta, pc, work)?)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native 指令數溢位",
                )
            })?;
    }
    if let Some(plan) = module
        .official_execution()
        .filter(|plan| plan.is_native_builtin())
    {
        work_charge(work, plan.calls().len(), proto.id, 0)?;
        let helpers = plan
            .calls()
            .iter()
            .filter(|call| call.prototype == proto.id)
            .count();
        words = words
            .checked_add(helpers.checked_mul(2).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native SETLIST 指令數溢位",
                )
            })?)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native SETLIST 指令數溢位",
                )
            })?;
    }
    Ok(words)
}

fn preflight_native_prototype(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    root: bool,
    strip: bool,
    depth: usize,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    stats: &mut NativePreflight,
) -> Result<(), OfficialExportError> {
    work_charge(work, 1, proto.id, 0)?;
    if depth > limits.max_depth {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native 子樹深度超限",
        ));
    }
    NativePreflight::add(&mut stats.prototypes, 1, limits.max_prototypes, proto.id)?;
    if module.native_debug().is_none() {
        let (group_count, close_count) = super::native_debug::close_group_counts(proto, work)
            .map_err(|source| {
                native_debug_error(
                    source.code,
                    work,
                    proto.id,
                    0,
                    "bare native close group 額度超限",
                )
            })?;
        stats.bytes(group_count, size_of::<NativeCloseGroup>(), limits, proto.id)?;
        stats.bytes(close_count, size_of::<(Register, u16)>(), limits, proto.id)?;
        stats.bytes(proto.instructions.len(), size_of::<u8>(), limits, proto.id)?;
        if group_count > 0 {
            let (_, cfg_bytes) = bare_close_cfg_bytes(proto)?;
            stats.bytes(1, cfg_bytes, limits, proto.id)?;
        }
    }
    let close_groups = native_close_groups(module, proto, limits, work)?;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    let numeric_count = proto
        .instructions
        .iter()
        .filter(|entry| matches!(entry.instruction, Instruction::NumericForPrepare { .. }))
        .count();
    stats.bytes(numeric_count, size_of::<NumericPair>(), limits, proto.id)?;
    let storage_count = module
        .native_debug()
        .and_then(|debug| debug.storage_for(proto.id))
        .map_or(0, |storage| storage.len());
    stats.bytes(
        1,
        compact_map_peak_bytes(proto, storage_count)?,
        limits,
        proto.id,
    )?;
    let (numeric, numeric_blocks) = numeric_pairs(proto, work)?;
    let meta = layout(module, proto, root, &numeric, numeric_blocks, work, limits)?;
    let words = native_word_count(module, &close_groups, proto, &meta, root, work)?;
    NativePreflight::add(
        &mut stats.instructions,
        words,
        limits.max_instructions,
        proto.id,
    )?;
    NativePreflight::add(
        &mut stats.constants,
        proto.constants.len(),
        limits.max_constants,
        proto.id,
    )?;
    let extra_upvalue = meta.env_upvalue.is_some()
        && (root
            || matches!(
                proto.frame.environment_source,
                EnvironmentSource::ParentFrame { .. }
            ));
    let upvalues = proto.upvalues.len() + usize::from(extra_upvalue);
    NativePreflight::add(&mut stats.upvalues, upvalues, limits.max_upvalues, proto.id)?;
    stats.bytes(words, size_of::<u32>(), limits, proto.id)?;
    if !strip {
        if let Some(entry) = module
            .native_debug()
            .and_then(|debug| debug.prototype(proto.id))
        {
            stats.bytes(words, size_of::<u32>(), limits, proto.id)?;
            stats.bytes(words, size_of::<i8>(), limits, proto.id)?;
            stats.bytes(words, size_of::<OfficialAbsLine>(), limits, proto.id)?;
            stats.bytes(
                entry.locals.len(),
                size_of::<OfficialLocal>(),
                limits,
                proto.id,
            )?;
            stats.bytes(upvalues, size_of::<Option<Vec<u8>>>(), limits, proto.id)?;
            work_charge(
                work,
                entry
                    .locals
                    .len()
                    .checked_add(entry.upvalue_names.len())
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            0,
                            "native debug 名稱掃描 work 溢位",
                        )
                    })?,
                proto.id,
                0,
            )?;
            for local in &entry.locals {
                stats.string(&local.name, limits, proto.id)?;
            }
            for name in &entry.upvalue_names {
                if let Some(name) = name {
                    stats.string(name, limits, proto.id)?;
                }
            }
            let synthetic = usize::from(root && meta.guest_upvalue_offset == 1);
            let fallback = usize::from(entry.upvalue_names.len() + synthetic < upvalues);
            for _ in 0..synthetic + fallback {
                stats.string(b"_ENV", limits, proto.id)?;
            }
        }
        if root {
            if let Some(native) = module.native_debug() {
                stats.string(native.source_name(), limits, proto.id)?;
            } else {
                stats.string(b"=RivetLua", limits, proto.id)?;
            }
        }
    }
    stats.bytes(
        proto.constants.len(),
        size_of::<OfficialConstant>(),
        limits,
        proto.id,
    )?;
    stats.bytes(upvalues, size_of::<OfficialUpvalue>(), limits, proto.id)?;
    stats.bytes(
        proto.instructions.len(),
        size_of::<usize>(),
        limits,
        proto.id,
    )?;
    stats.bytes(
        proto.instructions.len(),
        size_of::<(usize, InstructionOffset)>(),
        limits,
        proto.id,
    )?;
    stats.bytes(numeric_count, size_of::<(usize, usize)>(), limits, proto.id)?;
    stats.bytes(numeric_count, size_of::<usize>(), limits, proto.id)?;
    work_charge(work, proto.constants.len(), proto.id, 0)?;
    for constant in &proto.constants {
        if let BytecodeConstant::Name(bytes) | BytecodeConstant::String(bytes) = constant {
            stats.string(bytes, limits, proto.id)?;
            work_charge(work, bytes.len(), proto.id, 0)?;
        }
    }
    work_charge(work, module.module().prototypes.len(), proto.id, 0)?;
    let child_count = module
        .module()
        .prototypes
        .iter()
        .filter(|child| child.parent == Some(proto.id))
        .count();
    stats.bytes(
        child_count,
        size_of::<OfficialPrototype>(),
        limits,
        proto.id,
    )?;
    work_charge(work, module.module().prototypes.len(), proto.id, 0)?;
    for child in module
        .module()
        .prototypes
        .iter()
        .filter(|child| child.parent == Some(proto.id))
    {
        preflight_native_prototype(module, child, false, strip, depth + 1, limits, work, stats)?;
    }
    Ok(())
}

fn native_constants(
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<OfficialConstant>, OfficialExportError> {
    let mut constants = Vec::new();
    constants
        .try_reserve_exact(proto.constants.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "官方常數配置失敗",
            )
        })?;
    for constant in &proto.constants {
        work_charge(work, 1, proto.id, 0)?;
        constants.push(match constant {
            BytecodeConstant::Integer(value) => OfficialConstant::Integer(*value),
            BytecodeConstant::FloatBits(bits) => OfficialConstant::Number(f64::from_bits(*bits)),
            BytecodeConstant::Boolean(value) => OfficialConstant::Boolean(*value),
            BytecodeConstant::Name(bytes) | BytecodeConstant::String(bytes) => {
                OfficialConstant::String {
                    bytes: copy_slice(bytes, proto.id, work)?,
                    long: bytes.len() > 40,
                }
            }
        });
    }
    Ok(constants)
}

fn native_upvalues(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    parent: Option<(&BytecodePrototype, &Layout)>,
    root: bool,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<OfficialUpvalue>, OfficialExportError> {
    let guest_count = native_guest_upvalues(module, proto);
    let capacity = guest_count + usize::from(meta.env_upvalue.is_some());
    let mut upvalues = Vec::new();
    upvalues.try_reserve_exact(capacity).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "官方 upvalue 配置失敗",
        )
    })?;
    work_charge(work, proto.upvalues.len(), proto.id, 0)?;
    if root && meta.guest_upvalue_offset == 1 {
        upvalues.push(OfficialUpvalue {
            in_stack: true,
            index: 0,
            kind: 0,
        });
    }
    for (index, upvalue) in proto.upvalues.iter().take(guest_count).enumerate() {
        let (in_stack, source) = if let Some((parent_proto, parent_layout)) = parent {
            match &upvalue.source {
                BytecodeUpvalueSource::ParentLocal(binding) => {
                    if *binding == parent_proto.global_environment_binding {
                        let index = parent_layout.env_upvalue.ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::InvalidPrototype,
                                proto.id,
                                0,
                                "parent environment 缺共用 upvalue",
                            )
                        })?;
                        (
                            false,
                            u8::try_from(index).map_err(|_| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    proto.id,
                                    0,
                                    "parent environment upvalue index 超限",
                                )
                            })?,
                        )
                    } else {
                        work_charge(work, parent_proto.binding_registers.len(), proto.id, 0)?;
                        let register = parent_proto
                            .binding_registers
                            .iter()
                            .find_map(|(id, register)| (id == binding).then_some(*register))
                            .ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::InvalidPrototype,
                                    proto.id,
                                    0,
                                    "parent binding 不存在",
                                )
                            })?;
                        (true, parent_layout.register(register, proto.id, 0)?)
                    }
                }
                BytecodeUpvalueSource::ParentUpvalue(id) => {
                    (false, parent_layout.upvalue(id.0, proto.id, 0)?)
                }
            }
        } else {
            (
                false,
                u8::try_from(index + usize::from(meta.guest_upvalue_offset)).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        0,
                        "root upvalue index 超限",
                    )
                })?,
            )
        };
        upvalues.push(OfficialUpvalue {
            in_stack,
            index: source,
            kind: 0,
        });
    }
    if !root
        && matches!(
            proto.frame.environment_source,
            EnvironmentSource::ParentFrame { .. }
        )
        && meta.env_upvalue.is_some()
    {
        let (_, parent_layout) = parent.ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                0,
                "child 缺 parent layout",
            )
        })?;
        upvalues.push(OfficialUpvalue {
            in_stack: false,
            index: u8::try_from(parent_layout.env_upvalue.ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "forwarded environment 缺共用 upvalue",
                )
            })?)
            .map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "forwarded environment upvalue index 超限",
                )
            })?,
            kind: 0,
        });
    }
    if upvalues.len() > u8::MAX as usize {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "官方 upvalue 數超過 255",
        ));
    }
    Ok(upvalues)
}

fn native_prototype(
    module: &VerifiedModule,
    id: ProtoId,
    parent: Option<(&BytecodePrototype, &Layout)>,
    root: bool,
    strip: bool,
    depth: usize,
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    total_instructions: &mut usize,
) -> Result<OfficialPrototype, OfficialExportError> {
    if depth > limits.max_depth {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            id,
            0,
            "官方 prototype 深度超限",
        ));
    }
    work_charge(work, module.module().prototypes.len(), id, 0)?;
    let proto = module
        .module()
        .prototypes
        .iter()
        .find(|candidate| candidate.id == id)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                0,
                "prototype 不存在",
            )
        })?;
    let close_groups = native_close_groups(module, proto, limits, work)?;
    let variadic = proto.is_variadic || root && proto.parent.is_none();
    let (mut numeric, numeric_blocks) = numeric_pairs(proto, work)?;
    let meta = layout(module, proto, root, &numeric, numeric_blocks, work, limits)?;
    let word_limit = native_word_count(module, &close_groups, proto, &meta, root, work)?;
    verify_bare_close_layout(module, proto, &meta, &close_groups, work, limits)?;
    for pair in &mut numeric {
        pair.tuple = meta
            .tuple_base
            .checked_add(pair.block.checked_mul(4).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    pair.prepare_pc,
                    "numeric tuple 溢位",
                )
            })?)
            .and_then(|slot| u8::try_from(slot).ok())
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    pair.prepare_pc,
                    "numeric tuple 超出官方 register",
                )
            })?;
    }
    let constants = native_constants(proto, work)?;
    let upvalues = native_upvalues(module, proto, &meta, parent, root, work)?;
    let mut children = Vec::new();
    work_charge(work, module.module().prototypes.len(), id, 0)?;
    let child_count = module
        .module()
        .prototypes
        .iter()
        .filter(|candidate| candidate.parent == Some(id))
        .count();
    children.try_reserve_exact(child_count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            id,
            0,
            "官方 child 配置失敗",
        )
    })?;
    work_charge(work, module.module().prototypes.len(), id, 0)?;
    for child in module
        .module()
        .prototypes
        .iter()
        .filter(|candidate| candidate.parent == Some(id))
    {
        children.push(native_prototype(
            module,
            child.id,
            Some((proto, &meta)),
            false,
            strip,
            depth + 1,
            profile,
            limits,
            work,
            total_instructions,
        )?);
    }
    let debug_entry = if strip {
        None
    } else {
        module.native_debug().and_then(|debug| debug.prototype(id))
    };
    let mut code = Vec::new();
    code.try_reserve_exact(word_limit).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            id,
            0,
            "native 指令預付配置失敗",
        )
    })?;
    let mut lines = Vec::new();
    if debug_entry.is_some() {
        lines.try_reserve_exact(word_limit).map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "native 行號預付配置失敗",
            )
        })?;
    }
    let mut builder = Builder {
        id,
        limits,
        work,
        total_instructions,
        max_words: word_limit,
        code,
        source_lines: debug_entry.map(|entry| entry.lines.as_slice()),
        lines,
    };
    if variadic {
        builder.push(
            abc(
                if profile == LuaProfile::Lua55 { 83 } else { 81 },
                if profile == LuaProfile::Lua55 {
                    0
                } else {
                    proto.parameter_count as u8
                },
                0,
                0,
                false,
            ),
            0,
        )?;
    }
    for index in (0..proto.parameter_count).rev() {
        let target = meta.register(Register(index + 1), id, 0)?;
        builder.push(abc(0, target, index as u8, 0, false), 0)?;
    }
    if profile == LuaProfile::Lua55 {
        if let Some((_, register)) = proto.named_vararg {
            let source = u8::try_from(proto.parameter_count).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "具名 vararg table 起始 register 超限",
                )
            })?;
            builder.push(abc(0, meta.register(register, id, 0)?, source, 0, false), 0)?;
        }
    }
    if let Some(index) = meta.env_upvalue {
        let env = meta.register(proto.frame.environment, id, 0)?;
        builder.push(
            abc(
                9,
                env,
                u8::try_from(index).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        0,
                        "環境 upvalue index 超限",
                    )
                })?,
                0,
                false,
            ),
            0,
        )?;
    }
    let mut anchors = Vec::new();
    anchors
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "官方 PC anchor 配置失敗",
            )
        })?;
    let mut patches: Vec<(usize, InstructionOffset)> = Vec::new();
    patches
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "官方 jump patch 配置失敗",
            )
        })?;
    let mut numeric_patch = Vec::new();
    numeric_patch
        .try_reserve_exact(numeric.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "numeric patch 配置失敗",
            )
        })?;
    let mut numeric_entry = Vec::new();
    numeric_entry
        .try_reserve_exact(numeric.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "numeric entry 配置失敗",
            )
        })?;
    work_charge(builder.work, numeric.len(), id, 0)?;
    numeric_entry.resize(numeric.len(), usize::MAX);
    let lookup_work = numeric
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_mul(proto.instructions.len()))
        .and_then(|count| count.checked_add(proto.instructions.len()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                0,
                "numeric lookup 工作量溢位",
            )
        })?;
    work_charge(builder.work, lookup_work, id, 0)?;
    for (pc, entry) in proto.instructions.iter().enumerate() {
        let r = |register| meta.register(register, id, pc);
        if let Some((pair_index, pair)) = numeric
            .iter()
            .enumerate()
            .find(|(_, pair)| pair.body_pc == pc)
        {
            // 官方 FORLOOP 回邊先更新可見變數；一般 RVLU goto 直接進入 body PC。
            numeric_entry[pair_index] = builder.code.len();
            let source = pair.tuple + if profile == LuaProfile::Lua54 { 3 } else { 2 };
            builder.push(abc(0, r(pair.visible)?, source, 0, false), pc)?;
        }
        anchors.push(builder.code.len());
        let (reads_env, writes_env) = environment_access(proto, pc, &meta, builder.work)?;
        if reads_env {
            builder.push(
                abc(
                    9,
                    r(proto.frame.environment)?,
                    u8::try_from(meta.env_upvalue.ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "environment read 缺 upvalue",
                        )
                    })?)
                    .map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "environment upvalue index 超限",
                        )
                    })?,
                    0,
                    false,
                ),
                pc,
            )?;
        }
        match &entry.instruction {
            Instruction::Move { dest, src } => {
                builder.push(abc(0, r(*dest)?, r(*src)?, 0, false), pc)?;
                if entry.close_path.is_some() {
                    builder.push(abc(55, r(*dest)?, 0, 0, false), pc)?;
                }
            }
            Instruction::LoadConst { dest, constant } => {
                if constant.0 <= 131_071 {
                    builder.push(abx(3, r(*dest)?, constant.0), pc)?;
                } else {
                    builder.push(abc(4, r(*dest)?, 0, 0, false), pc)?;
                    builder.push(ax(extra_opcode(profile), constant.0), pc)?;
                }
            }
            Instruction::LoadNil { start, count } => {
                for offset in 0..*count {
                    let register = start.0.checked_add(offset).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "LoadNil register 溢位",
                        )
                    })?;
                    builder.push(abc(8, r(Register(register))?, 0, 0, false), pc)?;
                }
            }
            Instruction::GetUpvalue { dest, upvalue } => {
                if usize::from(upvalue.0) < native_guest_upvalues(module, proto) {
                    builder.push(
                        abc(9, r(*dest)?, meta.upvalue(upvalue.0, id, pc)?, 0, false),
                        pc,
                    )?;
                }
            }
            Instruction::SetUpvalue { upvalue, src } => builder.push(
                abc(10, r(*src)?, meta.upvalue(upvalue.0, id, pc)?, 0, false),
                pc,
            )?,
            Instruction::NewTable { dest } => {
                let staging = scratch_register(&meta, 0, id, pc)?;
                builder.push(abc(19, staging, 0, 0, false), pc)?;
                builder.push(ax(extra_opcode(profile), 0), pc)?;
                builder.push(abc(0, r(*dest)?, staging, 0, false), pc)?;
            }
            Instruction::GetTable { dest, table, key } => {
                builder.push(abc(12, r(*dest)?, r(*table)?, r(*key)?, false), pc)?
            }
            Instruction::SetTable { table, key, value } => {
                builder.push(abc(16, r(*table)?, r(*key)?, r(*value)?, false), pc)?
            }
            Instruction::UnaryOp { dest, op, src } => {
                let opcode = match op {
                    UnaryOperation::Negate => 49,
                    UnaryOperation::BitNot => 50,
                    UnaryOperation::Not => 51,
                    UnaryOperation::Length => 52,
                };
                builder.push(abc(opcode, r(*dest)?, r(*src)?, 0, false), pc)?;
            }
            Instruction::BinaryOp {
                dest,
                op,
                left,
                right,
            } => {
                let arithmetic = match op {
                    BinaryOperation::Add => Some((34, 6)),
                    BinaryOperation::Subtract => Some((35, 7)),
                    BinaryOperation::Multiply => Some((36, 8)),
                    BinaryOperation::Modulo => Some((37, 9)),
                    BinaryOperation::Power => Some((38, 10)),
                    BinaryOperation::Divide => Some((39, 11)),
                    BinaryOperation::FloorDivide => Some((40, 12)),
                    BinaryOperation::Ampersand => Some((41, 13)),
                    BinaryOperation::Pipe => Some((42, 14)),
                    BinaryOperation::BitXor => Some((43, 15)),
                    BinaryOperation::ShiftLeft => Some((44, 16)),
                    BinaryOperation::ShiftRight => Some((45, 17)),
                    _ => None,
                };
                if let Some((opcode, event)) = arithmetic {
                    builder.push(abc(opcode, r(*dest)?, r(*left)?, r(*right)?, false), pc)?;
                    builder.push(abc(46, r(*left)?, r(*right)?, event, false), pc)?;
                } else if *op == BinaryOperation::Concat {
                    let first = scratch_register(&meta, 0, id, pc)?;
                    let second = first.checked_add(1).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "CONCAT scratch 超限",
                        )
                    })?;
                    builder.push(abc(0, first, r(*left)?, 0, false), pc)?;
                    builder.push(abc(0, second, r(*right)?, 0, false), pc)?;
                    builder.push(abc(53, first, 2, 0, false), pc)?;
                    builder.push(abc(0, r(*dest)?, first, 0, false), pc)?;
                } else if let Some((opcode, swap, invert)) = match op {
                    BinaryOperation::Equal => Some((57, false, false)),
                    BinaryOperation::NotEqual => Some((57, false, true)),
                    BinaryOperation::Less => Some((58, false, false)),
                    BinaryOperation::LessEqual => Some((59, false, false)),
                    BinaryOperation::Greater => Some((58, true, false)),
                    BinaryOperation::GreaterEqual => Some((59, true, false)),
                    _ => None,
                } {
                    let (a, b) = if swap {
                        (r(*right)?, r(*left)?)
                    } else {
                        (r(*left)?, r(*right)?)
                    };
                    builder.push(abc(5, r(*dest)?, 0, 0, false), pc)?;
                    builder.push(abc(opcode, a, b, 0, invert), pc)?;
                    builder.push(jump(1, id, pc)?, pc)?;
                    builder.push(abc(7, r(*dest)?, 0, 0, false), pc)?;
                } else {
                    return Err(error(
                        OfficialExportErrorKind::Unsupported,
                        id,
                        pc,
                        "RVLU binary operation 官方無對應",
                    ));
                }
            }
            Instruction::Jump { target } => {
                patches.push((builder.code.len(), *target));
                builder.push(jump(0, id, pc)?, pc)?;
            }
            Instruction::JumpIfFalse { condition, target } => {
                builder.push(abc(66, r(*condition)?, 0, 0, false), pc)?;
                patches.push((builder.code.len(), *target));
                builder.push(jump(0, id, pc)?, pc)?;
            }
            Instruction::Closure { dest, proto: child } => {
                work_charge(builder.work, module.module().prototypes.len(), id, pc)?;
                let child_index = module
                    .module()
                    .prototypes
                    .iter()
                    .filter(|candidate| candidate.parent == Some(id))
                    .position(|candidate| candidate.id == *child)
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "child prototype 不存在",
                        )
                    })?;
                let staging = scratch_register(&meta, 0, id, pc)?;
                builder.push(
                    abx(
                        79,
                        staging,
                        u32::try_from(child_index).map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "child index 超限",
                            )
                        })?,
                    ),
                    pc,
                )?;
                builder.push(abc(0, r(*dest)?, staging, 0, false), pc)?;
            }
            Instruction::Call {
                base,
                arg_count,
                result_mode,
            } => {
                let native_plan = module
                    .official_execution()
                    .filter(|plan| plan.is_native_builtin());
                if let Some(call) =
                    native_plan.and_then(|plan| plan.call(id, InstructionOffset(pc as u32)))
                {
                    emit_native_list_write(&mut builder, proto, &meta, profile, pc, call)?;
                } else {
                    let open_root = if matches!(result_mode, ResultMode::All) {
                        Some(open_root_base(proto, pc, builder.work)?)
                    } else {
                        None
                    };
                    let call_offset = open_root.map_or(0, |root| base.0.saturating_sub(root.0));
                    if *arg_count != u16::MAX {
                        let gather_start = open_root.unwrap_or(*base);
                        let gather_count = base
                            .0
                            .checked_sub(gather_start.0)
                            .and_then(|prefix| prefix.checked_add(*arg_count))
                            .and_then(|count| count.checked_add(1))
                            .ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "Call gather 範圍溢位",
                                )
                            })?;
                        emit_gather(&mut builder, &meta, gather_start, gather_count, 0, pc)?;
                    }
                    if let Some(helper) = native_plan
                        .and_then(|plan| plan.call(id, InstructionOffset((pc + 1) as u32)))
                    {
                        let table_register = Register(helper.function_register.0 + 1);
                        builder.push(
                            abc(
                                0,
                                scratch_register(&meta, 3, id, pc)?,
                                r(table_register)?,
                                0,
                                false,
                            ),
                            pc,
                        )?;
                    }
                    let b = if *arg_count == u16::MAX {
                        0
                    } else {
                        u8::try_from(arg_count.checked_add(1).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "Call 參數數溢位",
                            )
                        })?)
                        .map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "Call 參數數超限",
                            )
                        })?
                    };
                    let c = match result_mode {
                        ResultMode::Fixed(count) => {
                            u8::try_from(count.checked_add(1).ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "Call 結果數溢位",
                                )
                            })?)
                            .map_err(|_| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "Call 結果數超限",
                                )
                            })?
                        }
                        ResultMode::All => 0,
                    };
                    builder.push(
                        abc(
                            68,
                            scratch_register(&meta, call_offset, id, pc)?,
                            b,
                            c,
                            false,
                        ),
                        pc,
                    )?;
                    if let ResultMode::Fixed(count) = result_mode {
                        emit_scatter(&mut builder, &meta, *base, *count, call_offset, pc)?;
                    }
                }
            }
            Instruction::TailCall {
                base,
                arg_count,
                result_mode: ResultMode::All,
            } => {
                if *arg_count != u16::MAX {
                    emit_gather(
                        &mut builder,
                        &meta,
                        *base,
                        arg_count.checked_add(1).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "TailCall gather 範圍溢位",
                            )
                        })?,
                        0,
                        pc,
                    )?;
                }
                let b = if *arg_count == u16::MAX {
                    0
                } else {
                    u8::try_from(arg_count.checked_add(1).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "TailCall 參數數溢位",
                        )
                    })?)
                    .map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "TailCall 參數數超限",
                        )
                    })?
                };
                let c = if variadic
                    && !(profile == LuaProfile::Lua55 && proto.named_vararg.is_some())
                {
                    u8::try_from(proto.parameter_count + 1).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "TailCall variadic 參數數超限",
                        )
                    })?
                } else {
                    0
                };
                // Tailcall 會覆用目前 frame；先關閉 open upvalue 才不會指向被搬移的參數。
                builder.push(abc(69, scratch_register(&meta, 0, id, pc)?, b, c, true), pc)?;
            }
            Instruction::Vararg { base, result_mode } => {
                let open_root = if matches!(result_mode, ResultMode::All) {
                    Some(open_root_base(proto, pc, builder.work)?)
                } else {
                    None
                };
                let vararg_offset = open_root.map_or(0, |root| base.0.saturating_sub(root.0));
                if let Some(root) = open_root {
                    emit_gather(&mut builder, &meta, root, vararg_offset, 0, pc)?;
                }
                if let Some(helper) = module
                    .official_execution()
                    .filter(|plan| plan.is_native_builtin())
                    .and_then(|plan| plan.call(id, InstructionOffset((pc + 1) as u32)))
                {
                    let table_register = Register(helper.function_register.0 + 1);
                    builder.push(
                        abc(
                            0,
                            scratch_register(&meta, 3, id, pc)?,
                            r(table_register)?,
                            0,
                            false,
                        ),
                        pc,
                    )?;
                }
                let c = match result_mode {
                    ResultMode::Fixed(count) => {
                        u8::try_from(count.checked_add(1).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "Vararg 結果數溢位",
                            )
                        })?)
                        .map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "Vararg 結果數超限",
                            )
                        })?
                    }
                    ResultMode::All => 0,
                };
                let named = proto.named_vararg.map(|(_, register)| register);
                let b = named.map(r).transpose()?.unwrap_or(0);
                builder.push(
                    abc(
                        80,
                        scratch_register(&meta, vararg_offset, id, pc)?,
                        b,
                        c,
                        named.is_some(),
                    ),
                    pc,
                )?;
                if let ResultMode::Fixed(count) = result_mode {
                    emit_scatter(&mut builder, &meta, *base, *count, 0, pc)?;
                }
            }
            Instruction::Close { base, .. } => {
                work_charge(builder.work, usize::BITS as usize, id, pc)?;
                let group = close_group_at(&close_groups, pc);
                if let Some(group) = group {
                    if group.emit_pc as usize == pc && !return_close_group(group, proto) {
                        let mut first = u8::MAX;
                        work_charge(builder.work, group.operands().len(), id, pc)?;
                        for (register, _) in group.operands() {
                            first = first.min(r(*register)?);
                        }
                        if first == u8::MAX {
                            return Err(error(
                                OfficialExportErrorKind::InvalidPrototype,
                                id,
                                pc,
                                "native close group 為空",
                            ));
                        }
                        builder.push(abc(54, first, 0, 0, false), pc)?;
                    }
                } else {
                    builder.push(abc(54, r(*base)?, 0, 0, false), pc)?;
                }
            }
            Instruction::NumericForPrepare {
                control,
                limit,
                step,
                ..
            } => {
                let (pair_index, pair) = numeric
                    .iter()
                    .enumerate()
                    .find(|(_, pair)| pair.prepare_pc == pc)
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "numeric prepare pair 不存在",
                        )
                    })?;
                for (offset, source) in [*control, *limit, *step].iter().enumerate() {
                    builder.push(abc(0, pair.tuple + offset as u8, r(*source)?, 0, false), pc)?;
                }
                let at = builder.code.len();
                builder.push(abx(74, pair.tuple, 0), pc)?;
                numeric_patch.push((at, pair_index));
            }
            Instruction::NumericForNext { .. } => {
                let pair = numeric
                    .iter()
                    .find(|pair| pair.next_pc == pc)
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "numeric next pair 不存在",
                        )
                    })?;
                builder.push(abx(73, pair.tuple, 0), pc)?;
                patches.push((builder.code.len(), pair.exit));
                builder.push(jump(0, id, pc)?, pc)?;
            }
            Instruction::Return { base, result_mode } => {
                if let ResultMode::Fixed(fixed) = result_mode {
                    emit_gather(&mut builder, &meta, *base, *fixed, 0, pc)?;
                }
                let count = match result_mode {
                    ResultMode::Fixed(count) => {
                        u8::try_from(count.checked_add(1).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "return count 溢位",
                            )
                        })?)
                        .map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "return count 超限",
                            )
                        })?
                    }
                    ResultMode::All => 0,
                };
                let c = if variadic
                    && !(profile == LuaProfile::Lua55 && proto.named_vararg.is_some())
                {
                    u8::try_from(proto.parameter_count + 1).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "Return variadic 參數數超限",
                        )
                    })?
                } else {
                    0
                };
                builder.push(
                    abc(70, scratch_register(&meta, 0, id, pc)?, count, c, true),
                    pc,
                )?;
            }
            _ => {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    id,
                    pc,
                    "RVLU opcode 官方降低尚未實作",
                ));
            }
        }
        if writes_env {
            builder.push(
                abc(
                    10,
                    r(proto.frame.environment)?,
                    u8::try_from(meta.env_upvalue.ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "environment write 缺 upvalue",
                        )
                    })?)
                    .map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "environment upvalue index 超限",
                        )
                    })?,
                    0,
                    false,
                ),
                pc,
            )?;
        }
    }
    work_charge(builder.work, patches.len(), id, 0)?;
    for (at, target) in patches {
        let destination = *anchors.get(target.0 as usize).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                at,
                "jump target 無 PC anchor",
            )
        })?;
        let offset = i64::try_from(destination)
            .ok()
            .and_then(|destination| {
                i64::try_from(at + 1)
                    .ok()
                    .and_then(|next| destination.checked_sub(next))
            })
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    at,
                    "jump offset 溢位",
                )
            })?;
        builder.code[at] = jump(offset, id, at)?;
    }
    work_charge(builder.work, numeric_patch.len(), id, 0)?;
    for (prepare_at, pair_index) in numeric_patch {
        let pair = numeric[pair_index];
        let loop_at = *anchors.get(pair.next_pc).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                pair.next_pc,
                "numeric next anchor 不存在",
            )
        })?;
        let distance = loop_at.checked_sub(prepare_at).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                prepare_at,
                "numeric pair 距離無效",
            )
        })?;
        let prep_bx = u32::try_from(distance - 1).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                prepare_at,
                "FORPREP 距離超限",
            )
        })?;
        let body_entry = numeric_entry[pair_index];
        let loop_distance = loop_at
            .checked_add(1)
            .and_then(|next| next.checked_sub(body_entry))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    prepare_at,
                    "numeric body entry 無效",
                )
            })?;
        let loop_bx = u32::try_from(loop_distance).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                loop_at,
                "FORLOOP 距離超限",
            )
        })?;
        if loop_bx > 131_071 {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                loop_at,
                "numeric for 距離超限",
            ));
        }
        builder.code[prepare_at] = abx(74, pair.tuple, prep_bx);
        builder.code[loop_at] = abx(73, pair.tuple, loop_bx);
    }
    let debug = if let Some(entry) = debug_entry {
        let (line_info, abs_line_info) =
            native_line_info(id, &builder.lines, entry.line_defined, builder.work)?;
        let mut locals = Vec::new();
        locals.try_reserve_exact(entry.locals.len()).map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "native official locals 配置失敗",
            )
        })?;
        for local in &entry.locals {
            work_charge(builder.work, 1, id, local.start_pc as usize)?;
            let source_pc = |pc: u32| -> Result<u32, OfficialExportError> {
                let offset = if pc as usize == proto.instructions.len() {
                    builder.code.len()
                } else {
                    *anchors.get(pc as usize).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc as usize,
                            "native debug local PC 無 anchor",
                        )
                    })?
                };
                u32::try_from(offset).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        pc as usize,
                        "native debug local PC 溢位",
                    )
                })
            };
            locals.push(OfficialLocal {
                name: Some(copy_slice(&local.name, id, builder.work)?),
                start_pc: source_pc(local.start_pc)?,
                end_pc: source_pc(local.end_pc)?,
            });
        }
        let mut upvalue_names = Vec::new();
        upvalue_names
            .try_reserve_exact(upvalues.len())
            .map_err(|_| {
                error(
                    OfficialExportErrorKind::AllocationFailed,
                    id,
                    0,
                    "native official upvalue names 配置失敗",
                )
            })?;
        if root && meta.guest_upvalue_offset == 1 {
            upvalue_names.push(Some(copy_slice(b"_ENV", id, builder.work)?));
        }
        work_charge(builder.work, entry.upvalue_names.len(), id, 0)?;
        for name in entry
            .upvalue_names
            .iter()
            .take(native_guest_upvalues(module, proto))
        {
            upvalue_names.push(
                name.as_ref()
                    .map(|bytes| copy_slice(bytes, id, builder.work))
                    .transpose()?,
            );
        }
        if upvalue_names.len() < upvalues.len() {
            upvalue_names.push(Some(copy_slice(b"_ENV", id, builder.work)?));
        }
        OfficialDebug {
            line_info,
            abs_line_info,
            locals,
            upvalue_names,
        }
    } else {
        OfficialDebug::default()
    };
    let source = if root && !strip {
        Some(if let Some(native) = module.native_debug() {
            copy_slice(native.source_name(), id, builder.work)?
        } else {
            copy_slice(b"=RivetLua", id, builder.work)?
        })
    } else {
        None
    };
    Ok(OfficialPrototype {
        source,
        line_defined: debug_entry.map_or(0, |entry| entry.line_defined),
        last_line_defined: debug_entry.map_or(0, |entry| entry.last_line_defined),
        num_params: u8::try_from(proto.parameter_count).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                0,
                "官方參數數超限",
            )
        })?,
        flags: if proto.named_vararg.is_some() {
            2
        } else {
            u8::from(variadic)
        },
        max_stack_size: meta.max_stack,
        code: builder.code,
        constants,
        upvalues,
        children,
        debug,
    })
}

pub(super) fn emit_native_chunk(
    module: &VerifiedModule,
    selected: ProtoId,
    profile: LuaProfile,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<OfficialChunk, OfficialExportError> {
    work_charge(work, 1, selected, 0)?;
    let mut preflight = NativePreflight::default();
    preflight.bytes(1, size_of::<OfficialChunk>(), limits, selected)?;
    work_charge(work, module.module().prototypes.len(), selected, 0)?;
    let root = module
        .module()
        .prototypes
        .iter()
        .find(|proto| proto.id == selected)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                selected,
                0,
                "native selected prototype 不存在",
            )
        })?;
    preflight_native_prototype(module, root, true, strip, 1, limits, work, &mut preflight)?;
    work_charge(work, preflight.allocated_bytes, selected, 0)?;
    let mut total_instructions = 0;
    let main = native_prototype(
        module,
        selected,
        None,
        true,
        strip,
        1,
        profile,
        limits,
        work,
        &mut total_instructions,
    )?;
    let root_upvalues = u8::try_from(main.upvalues.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            selected,
            0,
            "官方 root upvalue 超限",
        )
    })?;
    Ok(OfficialChunk {
        profile,
        root_upvalues,
        main,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(mapped: &[u8], gather: bool, spare: Option<u8>, original: &[i32]) -> Option<Vec<i32>> {
        let mut work = OfficialWorkBudget::new(10_000);
        let plan = parallel_copy_plan(
            mapped,
            Register(0),
            mapped.len() as u16,
            0,
            gather,
            spare,
            ProtoId(0),
            0,
            &mut work,
        )
        .unwrap()?;
        let mut values = original.to_vec();
        for &(dest, src) in &plan.moves[..plan.len] {
            values[usize::from(dest)] = values[usize::from(src)];
        }
        values.truncate(mapped.len());
        Some(values)
    }

    #[test]
    fn parallel_moves_preserve_two_and_three_cycles_in_both_directions() {
        assert_eq!(
            run(&[1, 0], true, Some(2), &[10, 20, 0]),
            Some(vec![20, 10])
        );
        assert_eq!(
            run(&[1, 0], false, Some(2), &[10, 20, 0]),
            Some(vec![20, 10])
        );
        assert_eq!(
            run(&[1, 2, 0], true, Some(3), &[10, 20, 30, 0]),
            Some(vec![20, 30, 10])
        );
        assert_eq!(
            run(&[1, 2, 0], false, Some(3), &[10, 20, 30, 0]),
            Some(vec![30, 10, 20])
        );
    }

    #[test]
    fn parallel_moves_preserve_repeated_sources_and_identity_without_spare() {
        assert_eq!(
            run(&[1, 1, 2], true, Some(3), &[10, 20, 30, 0]),
            Some(vec![20, 20, 30])
        );
        assert_eq!(
            run(&[0, 1, 2], true, None, &[10, 20, 30]),
            Some(vec![10, 20, 30])
        );
        assert_eq!(
            run(&[1, 2, 3], true, None, &[10, 20, 30, 40]),
            Some(vec![20, 30, 40])
        );
        assert_eq!(run(&[1, 0], true, None, &[10, 20]), None);
    }
}
