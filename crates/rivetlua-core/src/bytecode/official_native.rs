//! 將一般 RVLU_V2 原型降低成官方 Lua opcode。

use alloc::vec::Vec;

use super::codec::{
    BytecodeConstant, BytecodeExitKind, BytecodeInstruction, BytecodePrototype,
    BytecodeUpvalueSource,
};
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
use alloc::borrow::Cow;
use core::mem::size_of;

use super::native_debug::{
    NativeCloseGroup, NativeInitializerTemporary, NativeLocal, NativePrototypeDebug,
    NativeStorageInterval, NativeTemporary, register_access,
};
use super::official_execution::OfficialPlanCall;

struct Layout {
    anonymous_vararg_slot: Option<u8>,
    tuple_base: u16,
    scratch: Vec<u16>,
    parallel_spare: Vec<u16>,
    call_cleanup_slots: Vec<(usize, [u8; 32])>,
    max_stack: u8,
    guest_upvalue_offset: u16,
    env_upvalue: Option<u16>,
    mapped: Vec<u8>,
    protected: Vec<u8>,
    span: Vec<(usize, usize)>,
    live_at: Vec<LiveRow>,
    numeric_aliases: Vec<NumericAlias>,
}

#[derive(Debug)]
enum LiveRow {
    Uncomputed,
    Bits { base_pc: usize, bytes: Vec<u8> },
}

#[derive(Clone, Copy)]
struct NumericAlias {
    visible: Register,
    prepare_pc: usize,
    body_pc: usize,
    next_pc: usize,
    tuple: u8,
    width: u8,
    anchor: Register,
    share_nil_slot: bool,
    preserve_mapped_home: bool,
}

fn numeric_alias_anchor_observed(
    pc: usize,
    prepare_pc: usize,
    next_pc: usize,
    read: bool,
    close: bool,
    reenters_before_prepare: bool,
) -> bool {
    close || (read && pc <= next_pc && (pc >= prepare_pc || reenters_before_prepare))
}

// body 的 nil 寫入被省略後，只有在所有 CFG 路徑先確定覆寫 anchor，
// 才能允許後續讀取重用同一個 guest register 的值。
fn numeric_alias_later_reads_defined(
    proto: &BytecodePrototype,
    body_pc: usize,
    anchor: Register,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let count = proto.instructions.len();
    if body_pc >= count {
        return Ok(false);
    }
    work_charge(
        work,
        count.checked_mul(12).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                body_pc,
                "numeric alias CFG 工作量溢位",
            )
        })?,
        proto.id,
        body_pc,
    )?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            body_pc,
            "numeric alias CFG visited 配置失敗",
        )
    })?;
    seen.resize(count, 0u8);
    let mut queue = Vec::<u32>::new();
    queue.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            body_pc,
            "numeric alias CFG worklist 配置失敗",
        )
    })?;
    let actual = seen
        .capacity()
        .checked_add(
            queue
                .capacity()
                .checked_mul(size_of::<u32>())
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        body_pc,
                        "numeric alias CFG 容量溢位",
                    )
                })?,
        )
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                body_pc,
                "numeric alias CFG 容量溢位",
            )
        })?;
    let cap = count
        .checked_mul(2 * (1 + size_of::<u32>()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                body_pc,
                "numeric alias CFG 預檢容量溢位",
            )
        })?;
    if actual > cap {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            body_pc,
            "numeric alias CFG 容量超過預檢上界",
        ));
    }
    seen[body_pc] = 1;
    queue.push(u32::try_from(body_pc).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            body_pc,
            "numeric alias CFG body PC 超出 u32",
        )
    })?);
    while let Some(offset) = queue.pop() {
        let pc = offset as usize;
        if pc != body_pc {
            let (read, write, possible_write, close) = register_access(
                &proto.instructions[pc].instruction,
                anchor,
                proto.register_count,
            );
            if read || close {
                return Ok(false);
            }
            if write && !possible_write {
                continue;
            }
        }
        for successor in cfg_successors(proto, pc).into_iter().flatten() {
            let Some(mark) = seen.get_mut(successor) else {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "numeric alias CFG target 超出範圍",
                ));
            };
            if *mark == 0 {
                *mark = 1;
                queue.push(u32::try_from(successor).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "numeric alias CFG successor 超出 u32",
                    )
                })?);
            }
        }
    }
    Ok(true)
}

fn numeric_alias_preserves_mapped_home(aliases: &[NumericAlias], anchor: Register) -> bool {
    aliases
        .iter()
        .any(|alias| alias.anchor == anchor && alias.preserve_mapped_home)
}

fn numeric_alias_nil_slots(
    aliases: &[NumericAlias],
    proto: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<(bool, usize), OfficialExportError> {
    let units = aliases
        .len()
        .checked_mul(aliases.len().checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto,
                0,
                "numeric nil alias 分類工作量溢位",
            )
        })?)
        .and_then(|units| units.checked_mul(2))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto,
                0,
                "numeric nil alias 分類工作量溢位",
            )
        })?;
    work_charge(work, units, proto, 0)?;
    let shared = aliases.iter().any(|alias| alias.share_nil_slot);
    let mut count = usize::from(shared);
    for (index, alias) in aliases.iter().enumerate() {
        if !alias.share_nil_slot
            && !numeric_alias_preserves_mapped_home(aliases, alias.anchor)
            && !aliases[..index]
                .iter()
                .any(|earlier| !earlier.share_nil_slot && earlier.anchor == alias.anchor)
        {
            count = count.checked_add(1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto,
                    alias.body_pc,
                    "numeric nil alias slot 數溢位",
                )
            })?;
        }
    }
    Ok((shared, count))
}

// 只有整個 prototype 中從未讀取、關閉或動態覆寫，且確定寫入永遠是 nil
// 的匿名 anchor，才可與其他同類 anchor 共用同一實體槽。
fn numeric_alias_nil_only(
    proto: &BytecodePrototype,
    anchor: Register,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    for (pc, entry) in proto.instructions.iter().enumerate() {
        static_access_charge(proto, pc, work)?;
        let (read, write) = static_register_access(proto, pc, anchor);
        let (_, _, possible_write, close) =
            register_access(&entry.instruction, anchor, proto.register_count);
        if read || close || possible_write {
            return Ok(false);
        }
        if write {
            let Instruction::LoadNil { start, count } = entry.instruction else {
                return Ok(false);
            };
            if entry.close_path.is_some() || anchor.0 < start.0 || anchor.0 - start.0 >= count {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn numeric_alias_shared_home_eligible(
    proto: &BytecodePrototype,
    anchor: Register,
    prototypes: &[BytecodePrototype],
    locals: &[NativeLocal],
    storage: &[NativeStorageInterval],
    pending: &[NativeTemporary],
    initializer: &[NativeInitializerTemporary],
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let metadata = prototypes
        .len()
        .checked_add(proto.binding_registers.len())
        .and_then(|n| n.checked_add(locals.len()))
        .and_then(|n| n.checked_add(storage.len()))
        .and_then(|n| n.checked_add(pending.len()))
        .and_then(|n| n.checked_add(initializer.len()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "numeric nil anchor metadata work 溢位",
            )
        })?;
    work_charge(work, metadata, proto.id, 0)?;
    if anchor == proto.frame.environment
        || anchor.0 <= proto.parameter_count
        || proto
            .named_vararg
            .is_some_and(|(_, register)| register == anchor)
        || proto
            .binding_registers
            .iter()
            .any(|(_, register)| *register == anchor)
        || prototypes.iter().any(|child| {
            child.parent == Some(proto.id)
                && matches!(child.frame.environment_source,
                    EnvironmentSource::ParentFrame { parent, register }
                        if parent == proto.id && register == anchor)
        })
        || locals.iter().any(|local| local.register == anchor)
        || storage.iter().any(|local| local.register == anchor)
        || pending.iter().any(|entry| entry.register == anchor)
        || initializer.iter().any(|entry| entry.register == anchor)
    {
        return Ok(false);
    }
    numeric_alias_nil_only(proto, anchor, work)
}

#[derive(Clone, Copy)]
struct CompareBranchFusion {
    phi: Register,
    target: InstructionOffset,
    opcode: u8,
    left: Register,
    right: Register,
    invert: bool,
}

#[derive(Clone, Copy)]
struct TerminalCompareFusion {
    phi: Register,
    opcode: u8,
    left: Register,
    right: Register,
    invert: bool,
}

fn terminal_compare_fusions(
    proto: &BytecodePrototype,
    meta: &Layout,
    debug: Option<&NativePrototypeDebug>,
    first: &[Option<CompareBranchFusion>],
    work: &mut OfficialWorkBudget,
) -> Result<Vec<Option<TerminalCompareFusion>>, OfficialExportError> {
    let count = proto.instructions.len();
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "終端比較配置失敗",
        )
    })?;
    result.resize(count, None);
    work_charge(work, count, proto.id, 0)?;
    let Some(debug) = debug else {
        return Ok(result);
    };
    for (start, fusion) in first.iter().enumerate() {
        let Some(fusion) = fusion else { continue };
        let end = fusion.target.0 as usize;
        if end < start + 5 || end > count {
            continue;
        }
        let pc = end - 2;
        let Instruction::BinaryOp {
            dest,
            op,
            left,
            right,
        } = &proto.instructions[pc].instruction
        else {
            continue;
        };
        let Some((opcode, swap, invert)) = comparison_opcode(op) else {
            continue;
        };
        let Instruction::Move { dest: target, src } = proto.instructions[pc + 1].instruction else {
            continue;
        };
        if target != fusion.phi
            || src != *dest
            || *dest == fusion.phi
            || proto.instructions[pc].close_path.is_some()
            || proto.instructions[pc + 1].close_path.is_some()
            || debug.lines.get(pc).is_none()
            || debug.lines.get(pc) != debug.lines.get(pc + 1)
            || meta.register(fusion.phi, proto.id, start)?
                != meta.register(fusion.phi, proto.id, pc)?
        {
            continue;
        }
        work_charge(
            work,
            count
                .checked_mul(2)
                .and_then(|units| units.checked_add(proto.binding_registers.len()))
                .and_then(|units| units.checked_add(debug.locals.len()))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "終端比較驗證工作量溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        let (later_read, later_close) = proto.instructions.iter().skip(pc + 2).fold(
            (false, false),
            |(read_seen, close_seen), entry| {
                let (read, _, _, close) =
                    register_access(&entry.instruction, *dest, proto.register_count);
                (read_seen || read, close_seen || close)
            },
        );
        if proto
            .binding_registers
            .iter()
            .any(|(_, register)| register == dest)
            || debug.locals.iter().any(|local| {
                local.register == *dest
                    || local.start_pc as usize == pc + 1
                    || local.initialized_pc as usize == pc + 1
                    || local.end_pc as usize == pc + 1
            })
            || later_close
            || (later_read && generation_live_after_consumer(proto, meta, *dest, pc + 1))
            || proto.instructions.iter().any(|entry| {
                let targets = match entry.instruction {
                    Instruction::Jump { target }
                    | Instruction::JumpIfFalse { target, .. }
                    | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                    Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                    _ => [None, None],
                };
                targets
                    .into_iter()
                    .flatten()
                    .any(|target| target.0 as usize == pc + 1)
            })
        {
            continue;
        }
        let phi_slot = meta.register(fusion.phi, proto.id, pc)?;
        if phi_slot == meta.register(*left, proto.id, pc)?
            || phi_slot == meta.register(*right, proto.id, pc)?
        {
            continue;
        }
        let (left, right) = if swap {
            (*right, *left)
        } else {
            (*left, *right)
        };
        result[pc] = Some(TerminalCompareFusion {
            phi: fusion.phi,
            opcode,
            left,
            right,
            invert,
        });
    }
    Ok(result)
}

#[derive(Clone, Copy)]
struct DirectNumericInit {
    prepare_pc: usize,
    first_load_pc: usize,
    tuple: u8,
}

#[derive(Clone, Copy)]
struct DirectConstCopy {
    first_pc: usize,
    slot: u8,
}

#[derive(Clone, Copy)]
struct EnvFieldFusion {
    field: u8,
}

fn env_field_key_observed_later(
    proto: &BytecodePrototype,
    meta: &Layout,
    key: Register,
    pc: usize,
) -> bool {
    env_field_key_observed_later_live(proto, &meta.span, &meta.protected, &meta.live_at, key, pc)
}

fn env_field_key_observed_later_live(
    proto: &BytecodePrototype,
    spans: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    key: Register,
    pc: usize,
) -> bool {
    let (reads_later, closes_later) = proto.instructions.iter().skip(pc + 1).fold(
        (false, false),
        |(read_seen, close_seen), entry| {
            let (read, _, _, close) =
                register_access(&entry.instruction, key, proto.register_count);
            (read_seen || read, close_seen || close)
        },
    );
    closes_later
        || (reads_later
            && cfg_successors(proto, pc)
                .into_iter()
                .flatten()
                .any(|next| live_at_pc(spans, protected, live_at, usize::from(key.0), next)))
}

#[derive(Clone, Copy)]
struct LoopExitNilFusion {
    first_slot: u8,
    count: u8,
}

// LOADNIL 可跨越的槽必須在出口兩個清槽點都已死亡；未能辨認的
// scratch/private home 一律不擴大清除範圍。
fn loop_exit_nil_gap_safe(
    proto: &BytecodePrototype,
    meta: &Layout,
    debug: &NativePrototypeDebug,
    pairs: &[NumericPair],
    pair: &NumericPair,
    profile: LuaProfile,
    pc: usize,
    first_slot: u8,
    second_slot: u8,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let low = first_slot.min(second_slot);
    let high = first_slot.max(second_slot);
    let gap = usize::from(high - low - 1);
    let count = proto.instructions.len();
    let local_units = meta
        .numeric_aliases
        .len()
        .checked_add(1)
        .and_then(|units| debug.locals.len().checked_mul(units))
        .and_then(|units| units.checked_mul(2))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "迴圈出口 local 工作量溢位",
            )
        })?;
    let per_slot = count
        .checked_add(2)
        .and_then(|entries| meta.mapped.len().checked_mul(entries))
        .and_then(|units| units.checked_add(local_units))
        .and_then(|units| units.checked_add(pairs.len()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "迴圈出口清槽證明工作量溢位",
            )
        })?;
    work_charge(
        work,
        gap.checked_mul(per_slot)
            .and_then(|units| units.checked_add(count))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "迴圈出口清槽證明工作量溢位",
                )
            })?,
        proto.id,
        pc,
    )?;
    let tuple_width = if profile == LuaProfile::Lua54 {
        4u16
    } else {
        3u16
    };
    let targets_first = proto.instructions.iter().enumerate().any(|(from, entry)| {
        if from == pair.prepare_pc || from == pair.next_pc {
            return false;
        }
        let targets = match entry.instruction {
            Instruction::Jump { target }
            | Instruction::JumpIfFalse { target, .. }
            | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
            Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
            _ => [None, None],
        };
        targets
            .into_iter()
            .flatten()
            .any(|target| target.0 as usize == pc)
    });
    if targets_first {
        return Ok(false);
    }
    for slot in low + 1..high {
        if meta.anonymous_vararg_slot == Some(slot)
            || pairs.iter().any(|other| {
                other.prepare_pc != pair.prepare_pc
                    && other.prepare_pc <= pc
                    && pc <= other.next_pc
                    && u16::from(other.tuple) <= u16::from(slot)
                    && u16::from(slot) < u16::from(other.tuple) + tuple_width
            })
        {
            return Ok(false);
        }
        let mut identified = u16::from(pair.tuple) <= u16::from(slot)
            && u16::from(slot) < u16::from(pair.tuple) + tuple_width;
        for (register, &home) in meta.mapped.iter().enumerate() {
            if home != slot {
                continue;
            }
            identified = true;
            if meta.protected[register] != 0
                || register == usize::from(proto.frame.environment.0)
                || register == usize::from(proto.global_environment.0)
                || live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc)
                || live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc + 1)
                || proto.instructions.iter().skip(pc + 2).any(|entry| {
                    register_access(
                        &entry.instruction,
                        Register(register as u16),
                        proto.register_count,
                    )
                    .3
                })
            {
                return Ok(false);
            }
        }
        if !identified {
            return Ok(false);
        }
        for local in &debug.locals {
            for at in [pc, pc + 1] {
                if local.initialized_pc as usize <= at
                    && at < local.end_pc as usize
                    && meta.register(local.register, proto.id, at)? == slot
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn loop_exit_nil_fusions(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    pairs: &[NumericPair],
    profile: LuaProfile,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<Option<LoopExitNilFusion>>, OfficialExportError> {
    let count = proto.instructions.len();
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "迴圈出口清槽配置失敗",
        )
    })?;
    result.resize(count, None);
    work_charge(work, count, proto.id, 0)?;
    let Some(debug) = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id))
    else {
        return Ok(result);
    };
    for pair in pairs {
        let pc = pair.next_pc + 1;
        if pair.exit.0 as usize != pc || pc + 1 >= count {
            continue;
        }
        let Instruction::LoadNil {
            start: temporary,
            count: 1,
        } = proto.instructions[pc].instruction
        else {
            continue;
        };
        let Instruction::LoadNil {
            start: visible,
            count: 1,
        } = proto.instructions[pc + 1].instruction
        else {
            continue;
        };
        if visible != pair.visible
            || temporary == visible
            || proto.instructions[pc].close_path.is_some()
            || proto.instructions[pc + 1].close_path.is_some()
            || call_cleanup_range(proto, pc).is_some()
            || call_cleanup_range(proto, pc + 1).is_some()
            || debug.lines.get(pc) != debug.lines.get(pc + 1)
            || proto
                .binding_registers
                .iter()
                .any(|(_, register)| *register == temporary)
            || meta
                .numeric_aliases
                .iter()
                .any(|alias| alias.body_pc == pc || alias.body_pc == pc + 1)
        {
            continue;
        }
        let Some(local) = debug.locals.iter().find(|local| {
            local.register == visible
                && local.start_pc as usize <= pair.body_pc
                && local.end_pc as usize == pc + 2
        }) else {
            continue;
        };
        let child_work = module
            .module()
            .prototypes
            .iter()
            .try_fold(0usize, |units, child| {
                units.checked_add(child.upvalues.len())
            })
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "迴圈出口 child 工作量溢位",
                )
            })?;
        work_charge(
            work,
            count
                .checked_mul(2)
                .and_then(|units| {
                    debug
                        .locals
                        .len()
                        .checked_mul(3)
                        .and_then(|locals| units.checked_add(locals))
                })
                .and_then(|units| units.checked_add(module.module().prototypes.len()))
                .and_then(|units| units.checked_add(child_work))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "迴圈出口清槽工作量溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        if module.module().prototypes.iter().any(|child| {
            child.parent == Some(proto.id)
                && child.upvalues.iter().any(|upvalue| {
                    matches!(&upvalue.source, BytecodeUpvalueSource::ParentLocal(binding)
                    if *binding == local.binding)
                })
        }) || debug.locals.iter().any(|other| {
            other.register == temporary
                || other.start_pc as usize == pc + 1
                || other.initialized_pc as usize == pc + 1
                || other.end_pc as usize == pc + 1
        }) {
            continue;
        }
        let enters_second = proto.instructions.iter().any(|entry| {
            let targets = match entry.instruction {
                Instruction::Jump { target }
                | Instruction::JumpIfFalse { target, .. }
                | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            targets
                .into_iter()
                .flatten()
                .any(|target| target.0 as usize == pc + 1)
        });
        if enters_second {
            continue;
        }
        let first_slot = meta.register(temporary, proto.id, pc)?;
        let second_slot = meta.register(visible, proto.id, pc + 1)?;
        let distance = first_slot.abs_diff(second_slot);
        if distance == 0
            || (distance > 1
                && !loop_exit_nil_gap_safe(
                    proto,
                    meta,
                    debug,
                    pairs,
                    pair,
                    profile,
                    pc,
                    first_slot,
                    second_slot,
                    work,
                )?)
        {
            continue;
        }
        let mut collides_with_other_local = false;
        for other in &debug.locals {
            if other.register == temporary || other.register == visible {
                continue;
            }
            for at in [pc, pc + 1] {
                if other.initialized_pc as usize <= at && at < other.end_pc as usize {
                    let slot = meta.register(other.register, proto.id, at)?;
                    collides_with_other_local |= slot == first_slot || slot == second_slot;
                }
            }
        }
        if collides_with_other_local {
            continue;
        }
        result[pc] = Some(LoopExitNilFusion {
            first_slot: first_slot.min(second_slot),
            count: distance,
        });
    }
    Ok(result)
}

fn env_field_fusion_candidate(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<(EnvFieldFusion, Register)>, OfficialExportError> {
    let Some(prior) = pc.checked_sub(1) else {
        return Ok(None);
    };
    let Some(debug) = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id))
    else {
        return Ok(None);
    };
    let Instruction::LoadConst {
        dest: key,
        constant,
    } = proto.instructions[prior].instruction
    else {
        return Ok(None);
    };
    let Instruction::GetTable {
        dest,
        table,
        key: used_key,
    } = proto.instructions[pc].instruction
    else {
        return Ok(None);
    };
    if table != proto.frame.environment
        || used_key != key
        || key == table
        || dest == table
        || proto.instructions[prior].close_path.is_some()
        || proto.instructions[pc].close_path.is_some()
        || debug.lines.get(prior) != debug.lines.get(pc)
    {
        return Ok(None);
    }
    let Some(BytecodeConstant::Name(bytes) | BytecodeConstant::String(bytes)) =
        proto.constants.get(constant.0 as usize)
    else {
        return Ok(None);
    };
    let field = if let Ok(field) = u8::try_from(constant.0) {
        field
    } else {
        // 同值字串在較早的官方常數槽已存在時，可沿用 8-bit 欄位索引。
        let mut earlier = None;
        for (index, candidate) in proto.constants.iter().take(256).enumerate() {
            work_charge(work, 1, proto.id, pc)?;
            let (BytecodeConstant::Name(other) | BytecodeConstant::String(other)) = candidate
            else {
                continue;
            };
            if other.len() != bytes.len() {
                continue;
            }
            work_charge(work, bytes.len(), proto.id, pc)?;
            if other == bytes {
                earlier = Some(u8::try_from(index).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "環境欄位常數索引超限",
                    )
                })?);
                break;
            }
        }
        let Some(field) = earlier else {
            return Ok(None);
        };
        field
    };
    if bytes.len() > 40
        || proto
            .binding_registers
            .iter()
            .any(|(_, register)| *register == key)
        || debug.locals.iter().any(|local| {
            local.register == key
                || local.start_pc as usize == pc
                || local.initialized_pc as usize == pc
                || local.end_pc as usize == pc
        })
    {
        return Ok(None);
    }
    work_charge(
        work,
        proto
            .instructions
            .len()
            .checked_mul(2)
            .and_then(|units| units.checked_add(debug.locals.len()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "環境欄位工作量溢位",
                )
            })?,
        proto.id,
        pc,
    )?;
    let enters_pair = proto.instructions.iter().any(|entry| {
        let targets = match entry.instruction {
            Instruction::Jump { target }
            | Instruction::JumpIfFalse { target, .. }
            | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
            Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
            _ => [None, None],
        };
        targets
            .into_iter()
            .flatten()
            .any(|target| [prior, pc].contains(&(target.0 as usize)))
    });
    Ok((!enters_pair).then_some((EnvFieldFusion { field }, key)))
}

fn env_field_fusions(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<Option<EnvFieldFusion>>, OfficialExportError> {
    let count = proto.instructions.len();
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "環境欄位配置失敗",
        )
    })?;
    result.resize(count, None);
    work_charge(work, count, proto.id, 0)?;
    if meta.env_upvalue.is_none() {
        return Ok(result);
    }
    for pc in 1..count {
        if let Some((fusion, key)) = env_field_fusion_candidate(module, proto, pc, work)? {
            if !env_field_key_observed_later(proto, meta, key, pc) {
                result[pc] = Some(fusion);
            }
        }
    }
    Ok(result)
}

fn direct_const_copies(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<DirectConstCopy>, OfficialExportError> {
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(proto.instructions.len() / 4)
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "常數搬移配置失敗",
            )
        })?;
    let Some(debug) = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id))
    else {
        return Ok(plans);
    };
    for pc in 0..proto.instructions.len().saturating_sub(3) {
        let Instruction::LoadConst {
            dest: first,
            constant,
        } = proto.instructions[pc].instruction
        else {
            continue;
        };
        if !matches!(
            proto.constants.get(constant.0 as usize),
            Some(BytecodeConstant::Integer(_))
        ) {
            continue;
        }
        let Instruction::Move { dest: middle, src } = proto.instructions[pc + 1].instruction else {
            continue;
        };
        let Instruction::Move {
            dest: final_register,
            src: second_src,
        } = proto.instructions[pc + 2].instruction
        else {
            continue;
        };
        let Instruction::LoadNil { start, count } = proto.instructions[pc + 3].instruction else {
            continue;
        };
        let end = start.0.checked_add(count).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc + 3,
                "暫存清槽範圍溢位",
            )
        })?;
        if src != first
            || second_src != middle
            || first == middle
            || first == final_register
            || middle == final_register
            || !(start.0 <= first.0 && first.0 < end)
            || !(start.0 <= middle.0 && middle.0 < end)
            || proto.instructions[pc..=pc + 2]
                .iter()
                .any(|entry| entry.close_path.is_some())
            || debug.lines.get(pc) != debug.lines.get(pc + 1)
            || debug.lines.get(pc) != debug.lines.get(pc + 2)
        {
            continue;
        }
        work_charge(
            work,
            proto
                .instructions
                .len()
                .checked_mul(4)
                .and_then(|n| n.checked_add(debug.locals.len()))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "常數搬移工作量溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        if proto
            .binding_registers
            .iter()
            .any(|(_, register)| *register == first || *register == middle)
            || debug.locals.iter().any(|local| {
                local.register == first
                    || local.register == middle
                    || [pc + 1, pc + 2].contains(&(local.start_pc as usize))
                    || [pc + 1, pc + 2].contains(&(local.initialized_pc as usize))
                    || [pc + 1, pc + 2].contains(&(local.end_pc as usize))
            })
            || proto.instructions.iter().any(|entry| {
                let targets = match entry.instruction {
                    Instruction::Jump { target }
                    | Instruction::JumpIfFalse { target, .. }
                    | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                    Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                    _ => [None, None],
                };
                targets
                    .into_iter()
                    .flatten()
                    .any(|target| target.0 as usize == pc + 1 || target.0 as usize == pc + 2)
            })
        {
            continue;
        }
        let final_slot = meta.register(final_register, proto.id, pc)?;
        if final_slot != meta.register(final_register, proto.id, pc + 2)? {
            continue;
        }
        let mut overlaps_local = false;
        for local in &debug.locals {
            if local.register != final_register
                && local.initialized_pc as usize <= pc
                && pc < local.end_pc as usize
                && meta.register(local.register, proto.id, pc)? == final_slot
            {
                overlaps_local = true;
                break;
            }
        }
        if overlaps_local {
            continue;
        }
        plans.push(DirectConstCopy {
            first_pc: pc,
            slot: final_slot,
        });
    }
    Ok(plans)
}

// 只在相鄰的 Call cleanup 確實清過此實體槽，且直接常數搬移的兩個
// temporary 寫入均已被抑制時，略過隨後普通 LoadNil 的重複清槽。
fn nil_after_direct_const_copy(
    proto: &BytecodePrototype,
    meta: &Layout,
    direct_copies: &[DirectConstCopy],
    direct_inits: &[DirectNumericInit],
    exit_nil_fusions: &[Option<LoopExitNilFusion>],
    numeric: &[NumericPair],
    pc: usize,
    slot: u8,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let Some(first_pc) = pc.checked_sub(3) else {
        return Ok(false);
    };
    let Some(prior_pc) = first_pc.checked_sub(1) else {
        return Ok(false);
    };
    work_charge(work, direct_copies.len(), proto.id, pc)?;
    let Some(copy) = direct_copies.iter().find(|copy| copy.first_pc == first_pc) else {
        return Ok(false);
    };
    let aliases = meta.numeric_aliases.len();
    let owner_work = aliases
        .checked_add(5)
        .and_then(|per_owner| usize::from(proto.register_count).checked_mul(per_owner));
    let scan_work = aliases
        .checked_mul(3)
        .and_then(|amount| amount.checked_add(direct_inits.len()))
        .and_then(|amount| amount.checked_add(numeric.len()))
        .and_then(|amount| amount.checked_add(proto.instructions.len()))
        .and_then(|amount| owner_work.and_then(|owners| amount.checked_add(owners)))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "重複 nil 證明工作量溢位",
            )
        })?;
    work_charge(work, scan_work, proto.id, pc)?;
    let Some(prior) = proto.instructions.get(prior_pc) else {
        return Ok(false);
    };
    let Some(current) = proto.instructions.get(pc) else {
        return Ok(false);
    };
    if prior.close_path.is_some()
        || current.close_path.is_some()
        || call_cleanup_range(proto, prior_pc).is_none()
        || exit_nil_fusions.get(prior_pc).is_some_and(Option::is_some)
        || prior_pc > 0 && exit_nil_fusions[prior_pc - 1].is_some()
        || meta.numeric_aliases.iter().any(|alias| {
            matches!(prior.instruction, Instruction::LoadNil { start, count: 1 }
                if alias.body_pc == prior_pc && alias.anchor == start)
        })
    {
        return Ok(false);
    }
    let Instruction::LoadConst { dest: first, .. } = proto.instructions[first_pc].instruction
    else {
        return Ok(false);
    };
    let Instruction::Move { dest: middle, src } = proto.instructions[first_pc + 1].instruction
    else {
        return Ok(false);
    };
    let Instruction::Move {
        dest: final_register,
        src: second_src,
    } = proto.instructions[first_pc + 2].instruction
    else {
        return Ok(false);
    };
    let Instruction::LoadNil { start, count } = current.instruction else {
        return Ok(false);
    };
    if src != first
        || second_src != middle
        || start.0 > first.0
        || first.0 - start.0 >= count
        || start.0 > middle.0
        || middle.0 - start.0 >= count
        || proto.instructions[first_pc..pc]
            .iter()
            .any(|entry| entry.close_path.is_some())
        || [first, middle, final_register].contains(&proto.frame.environment)
        || slot == copy.slot
        || slot == meta.register(proto.frame.environment, proto.id, pc)?
    {
        return Ok(false);
    }
    // 後續 numeric pair 的預留 tuple 尚未執行 Prepare；本段也已拒絕
    // 任何跳入，所以只有已開始的 pair/alias 可能改寫先前已清的實體槽。
    if direct_inits
        .iter()
        .any(|plan| plan.first_load_pc <= pc && plan.first_load_pc.saturating_add(5) >= first_pc)
        || numeric.iter().any(|pair| {
            pair.prepare_pc <= pc
                && u16::from(slot) >= u16::from(pair.tuple)
                && u16::from(slot) < u16::from(pair.tuple) + 4
        })
        || meta.numeric_aliases.iter().any(|alias| {
            alias.prepare_pc <= pc
                && u16::from(slot) >= u16::from(alias.tuple)
                && u16::from(slot) < u16::from(alias.tuple) + u16::from(alias.width)
        })
    {
        return Ok(false);
    }
    let cleanup = cleanup_slots_at(&meta.call_cleanup_slots, proto, prior_pc, work)?;
    if !cleanup_slot_contains(cleanup, slot) {
        return Ok(false);
    }
    // 任何跳入 LOADK、兩個 Move 或目前清槽的邊，都可繞過先前的 nil。
    for entry in &proto.instructions {
        let targets = match entry.instruction {
            Instruction::Jump { target }
            | Instruction::JumpIfFalse { target, .. }
            | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
            Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
            _ => [None, None],
        };
        if targets
            .into_iter()
            .flatten()
            .any(|target| first_pc <= target.0 as usize && target.0 as usize <= pc)
        {
            return Ok(false);
        }
    }
    for owner in 0..proto.register_count {
        if meta.register(Register(owner), proto.id, pc)? != slot {
            continue;
        }
        let index = usize::from(owner);
        if meta.protected[index] != 0
            || owner != first.0
                && owner != middle.0
                && (first_pc..=pc)
                    .any(|at| live_at_pc(&meta.span, &meta.protected, &meta.live_at, index, at))
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn direct_numeric_inits(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    pairs: &[NumericPair],
    work: &mut OfficialWorkBudget,
) -> Result<Vec<DirectNumericInit>, OfficialExportError> {
    let mut plans = Vec::new();
    plans.try_reserve_exact(pairs.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric 初始化配置失敗",
        )
    })?;
    let Some(native_debug) = module.native_debug() else {
        return Ok(plans);
    };
    let Some(debug) = native_debug.prototype(proto.id) else {
        return Ok(plans);
    };
    for pair in pairs {
        let Some(alias) = meta
            .numeric_aliases
            .iter()
            .find(|alias| alias.prepare_pc == pair.prepare_pc)
        else {
            continue;
        };
        let Some(first) = pair.prepare_pc.checked_sub(6) else {
            continue;
        };
        let Instruction::NumericForPrepare {
            control,
            limit,
            step,
            ..
        } = proto.instructions[pair.prepare_pc].instruction
        else {
            continue;
        };
        let controls = [control, limit, step];
        let mut temporaries = [Register(0); 3];
        let mut pattern = true;
        for offset in 0..3 {
            let load_pc = first + offset * 2;
            let move_pc = load_pc + 1;
            let Instruction::LoadConst { dest, .. } = proto.instructions[load_pc].instruction
            else {
                pattern = false;
                break;
            };
            let Instruction::Move { dest: moved, src } = proto.instructions[move_pc].instruction
            else {
                pattern = false;
                break;
            };
            if moved != controls[offset]
                || src != dest
                || !native_debug.is_non_counted_pc(proto.id, InstructionOffset(move_pc as u32))
                || debug.lines.get(load_pc) != debug.lines.get(move_pc)
                || proto.instructions[load_pc].close_path.is_some()
                || proto.instructions[move_pc].close_path.is_some()
            {
                pattern = false;
                break;
            }
            temporaries[offset] = dest;
        }
        if !pattern
            || debug.lines.get(first) != debug.lines.get(pair.prepare_pc)
            || temporaries[0] == temporaries[1]
            || temporaries[0] == temporaries[2]
            || temporaries[1] == temporaries[2]
        {
            continue;
        }
        work_charge(
            work,
            proto
                .instructions
                .len()
                .checked_mul(meta.mapped.len().saturating_add(8))
                .and_then(|n| n.checked_add(debug.locals.len()))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        first,
                        "numeric 初始化工作量溢位",
                    )
                })?,
            proto.id,
            first,
        )?;
        if controls.iter().chain(temporaries.iter()).any(|register| {
            proto
                .binding_registers
                .iter()
                .any(|(_, bound)| bound == register)
                || debug.locals.iter().any(|local| local.register == *register)
        }) {
            continue;
        }
        let mut safe = true;
        let mut later_read = [false; 3];
        for (pc, entry) in proto.instructions.iter().enumerate() {
            let targets = match entry.instruction {
                Instruction::Jump { target }
                | Instruction::JumpIfFalse { target, .. }
                | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            if targets
                .into_iter()
                .flatten()
                .any(|target| first < target.0 as usize && (target.0 as usize) <= pair.prepare_pc)
            {
                safe = false;
                break;
            }
            for offset in 0..3 {
                let load_pc = first + offset * 2;
                let move_pc = load_pc + 1;
                let (temporary_read, _, _, temporary_close) = register_access(
                    &entry.instruction,
                    temporaries[offset],
                    proto.register_count,
                );
                let (control_read, control_write, control_possible, control_close) =
                    register_access(&entry.instruction, controls[offset], proto.register_count);
                if pc >= first && temporary_read && pc != move_pc {
                    if pc <= move_pc {
                        safe = false;
                    } else {
                        later_read[offset] = true;
                    }
                }
                if (pc >= first && temporary_close)
                    || (first <= pc
                        && pc <= pair.next_pc
                        && ((control_read && pc != pair.prepare_pc && pc != pair.next_pc)
                            || control_close
                            || ((control_write || control_possible)
                                && pc != move_pc
                                && pc != pair.prepare_pc
                                && pc != pair.next_pc)))
                {
                    safe = false;
                }
            }
            if first <= pc && pc <= pair.prepare_pc {
                for (register, &slot) in meta.mapped.iter().enumerate() {
                    if controls
                        .iter()
                        .chain(temporaries.iter())
                        .any(|value| value.0 as usize == register)
                        || !(alias.tuple <= slot && slot < alias.tuple + 3)
                        || (register == usize::from(alias.visible.0) && pc == pair.prepare_pc)
                    {
                        continue;
                    }
                    let (read, write, possible, close) = register_access(
                        &entry.instruction,
                        Register(register as u16),
                        proto.register_count,
                    );
                    if read || write || possible || close {
                        safe = false;
                    }
                }
            }
            if !safe {
                break;
            }
        }
        if safe
            && later_read.iter().enumerate().any(|(offset, read)| {
                *read
                    && generation_live_after_consumer(
                        proto,
                        meta,
                        temporaries[offset],
                        first + offset * 2 + 1,
                    )
            })
        {
            safe = false;
        }
        if safe {
            plans.push(DirectNumericInit {
                prepare_pc: pair.prepare_pc,
                first_load_pc: first,
                tuple: alias.tuple,
            });
        }
    }
    Ok(plans)
}

fn comparison_opcode(op: &BinaryOperation) -> Option<(u8, bool, bool)> {
    match op {
        BinaryOperation::Equal => Some((57, false, false)),
        BinaryOperation::NotEqual => Some((57, false, true)),
        BinaryOperation::Less => Some((58, false, false)),
        BinaryOperation::LessEqual => Some((59, false, false)),
        BinaryOperation::Greater => Some((58, true, false)),
        BinaryOperation::GreaterEqual => Some((59, true, false)),
        _ => None,
    }
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
const ANONYMOUS_VARARG_LOCAL: &[u8] = b"(vararg table)";
const NUMERIC_CONTROL_LOCAL: &[u8] = b"(for state)";

fn anonymous_vararg_slot(
    proto: &BytecodePrototype,
    profile: LuaProfile,
) -> Result<Option<u8>, OfficialExportError> {
    // Lua 5.5 mainfunc 設為 variadic，但不建立子函式 parlist 的匿名 vararg local。
    if profile != LuaProfile::Lua55
        || proto.parent.is_none()
        || !proto.is_variadic
        || proto.named_vararg.is_some()
    {
        return Ok(None);
    }
    u8::try_from(proto.parameter_count)
        .ok()
        .filter(|slot| *slot < 255)
        .map(Some)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "匿名 vararg table slot 超出官方 stack",
            )
        })
}

fn official_storage_slot(
    slot: u8,
    anonymous_vararg_slot: Option<u8>,
    id: ProtoId,
    pc: usize,
) -> Result<u8, OfficialExportError> {
    if anonymous_vararg_slot.is_some_and(|boundary| slot >= boundary) {
        slot.checked_add(1)
            .filter(|shifted| *shifted < 255)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    pc,
                    "匿名 vararg 後續 local slot 超出官方 stack",
                )
            })
    } else {
        Ok(slot)
    }
}

struct ParallelMoves {
    moves: [(u8, u8); 512],
    len: usize,
    used_spare: bool,
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
        used_spare: false,
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
        plan.used_spare = true;
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

fn native_layout_register_at(
    mapped: &[u8],
    numeric_aliases: &[NumericAlias],
    register: Register,
    id: ProtoId,
    pc: usize,
) -> Result<u8, OfficialExportError> {
    if let Some(alias) = numeric_aliases
        .iter()
        .find(|alias| alias.visible == register && alias.body_pc <= pc && pc <= alias.next_pc)
    {
        return alias.tuple.checked_add(alias.width).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "numeric 可見 local slot 溢位",
            )
        });
    }
    mapped.get(usize::from(register.0)).copied().ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "native register 不存在",
        )
    })
}

impl Layout {
    fn register(
        &self,
        register: Register,
        id: ProtoId,
        pc: usize,
    ) -> Result<u8, OfficialExportError> {
        native_layout_register_at(&self.mapped, &self.numeric_aliases, register, id, pc)
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

fn chained_compare_words(
    opcode: u8,
    left: u8,
    right: u8,
    invert: bool,
    id: ProtoId,
    pc: usize,
) -> Result<[u32; 2], OfficialExportError> {
    // k=invert：Lua 布林結果為 false 時執行下一個 JMP；true 時略過它。
    Ok([abc(opcode, left, right, 0, invert), jump(0, id, pc)?])
}

fn terminal_compare_words(
    opcode: u8,
    left: u8,
    right: u8,
    phi: u8,
    invert: bool,
    id: ProtoId,
    pc: usize,
) -> Result<[u32; 4], OfficialExportError> {
    // 比較錯誤必須先於 phi 寫入；true 跳過 LFALSESKIP，false 由它跳過 LOADTRUE。
    Ok([
        abc(opcode, left, right, 0, !invert),
        jump(1, id, pc)?,
        abc(6, phi, 0, 0, false),
        abc(7, phi, 0, 0, false),
    ])
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
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    producer_pc,
                    "open scratch 鏈缺 consumer",
                ));
            }
        }
    }
}

/// 僅辨識相鄰的 All producer 與動態引數 consumer；Return 的開放結果
/// 繼續使用既有佈局，Close 不可插入動態引數鏈。
fn strict_open_call_terminal(
    proto: &BytecodePrototype,
    producer_pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<usize>, OfficialExportError> {
    if !matches!(
        proto.instructions[producer_pc].instruction,
        Instruction::Call {
            result_mode: ResultMode::All,
            ..
        }
    ) {
        return Ok(None);
    }
    let mut next = producer_pc + 1;
    loop {
        work_charge(work, 1, proto.id, next)?;
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
                },
            ) => break,
            Some(Instruction::Return {
                result_mode: ResultMode::All,
                ..
            }) => return Ok(None),
            Some(Instruction::Close { .. }) => {
                if matches!(
                    proto
                        .instructions
                        .get(open_chain_end(proto, producer_pc, work)?)
                        .map(|entry| &entry.instruction),
                    Some(
                        Instruction::Call {
                            arg_count: u16::MAX,
                            ..
                        } | Instruction::TailCall {
                            arg_count: u16::MAX,
                            ..
                        }
                    )
                ) {
                    return Err(error(
                        OfficialExportErrorKind::Unsupported,
                        proto.id,
                        producer_pc,
                        "open Call 鏈不可插入 Close",
                    ));
                }
                return Ok(None);
            }
            _ => return Ok(None),
        }
    }
    work_charge(work, proto.instructions.len(), proto.id, producer_pc)?;
    for entry in &proto.instructions {
        let targets = match &entry.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                [Some(target.0 as usize), None]
            }
            Instruction::NumericForPrepare { exit, .. } => [Some(exit.0 as usize), None],
            Instruction::NumericForNext { target, exit, .. } => {
                [Some(target.0 as usize), Some(exit.0 as usize)]
            }
            _ => [None, None],
        };
        if targets
            .into_iter()
            .flatten()
            .any(|target| producer_pc <= target && target <= next)
        {
            return Err(error(
                OfficialExportErrorKind::Unsupported,
                proto.id,
                producer_pc,
                "open Call 鏈不可由跳躍進入",
            ));
        }
    }
    Ok(Some(next))
}

/// `_ENV` 的實體 upvalue 是權威值；僅在相鄰的開放引數呼叫鏈沒有使用
/// guest environment register 時，允許官方動態結果覆寫其 stack 快取。
fn environment_cache_chain_safe(
    proto: &BytecodePrototype,
    producer_pc: usize,
    candidate: Register,
    has_physical_upvalue: bool,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    if !has_physical_upvalue || candidate != proto.global_environment {
        return Ok(false);
    }
    let Some(terminal) = strict_open_call_terminal(proto, producer_pc, work)? else {
        return Ok(false);
    };
    for pc in producer_pc..=terminal {
        work_charge(work, 1, proto.id, pc)?;
        let (read, write, possible_write, close) = register_access(
            &proto.instructions[pc].instruction,
            candidate,
            proto.register_count,
        );
        if read || write || possible_write || close {
            return Ok(false);
        }
    }
    Ok(true)
}

// pending 覆寫 _ENV 的 stack 快取時，期間每次真正讀取都必須由 upvalue
// 直接取得；之後的非融合讀取會先重新載入快取。
fn environment_cache_pending_alias_safe(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    start: usize,
    end: usize,
    spans: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    work_charge(work, end - start, proto.id, start)?;
    let env = proto.frame.environment;
    for pc in start..end {
        let (read, write, possible_write, close) = register_access(
            &proto.instructions[pc].instruction,
            env,
            proto.register_count,
        );
        if write || possible_write || close {
            return Ok(false);
        }
        if !read {
            continue;
        }
        let Some((_, key)) = env_field_fusion_candidate(module, proto, pc, work)? else {
            return Ok(false);
        };
        let later = &proto.instructions[pc + 1..];
        work_charge(work, later.len(), proto.id, pc)?;
        if env_field_key_observed_later_live(proto, spans, protected, live_at, key, pc) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn environment_cache_slot_exclusive(
    intervals: &[(u8, usize, usize)],
    slot: u8,
    pc: usize,
    id: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    work_charge(work, intervals.len(), id, pc)?;
    Ok(intervals
        .iter()
        .filter(|&&(occupied, start, end)| occupied == slot && start <= pc && pc < end)
        .take(2)
        .count()
        == 1)
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
        Instruction::LoadNil { start, count } => {
            if call_cleanup_range(proto, pc).is_none() {
                visit_range(*start, *count, visit)?;
            }
        }
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

/// statement Call 的尾端 cleanup 會涵蓋此時尚未使用的 guest register。
/// 這些 nil 寫入是物理槽的 root 清理，不能使未來值從本 PC 起佔用獨立槽。
fn call_cleanup_range(proto: &BytecodePrototype, pc: usize) -> Option<(usize, usize)> {
    let Instruction::LoadNil { start, count } = proto.instructions.get(pc)?.instruction else {
        return None;
    };
    let Instruction::Call {
        base,
        result_mode: ResultMode::Fixed(0),
        ..
    } = proto.instructions.get(pc.checked_sub(1)?)?.instruction
    else {
        return None;
    };
    let first = usize::from(start.0);
    let end = first.checked_add(usize::from(count))?;
    (first <= usize::from(base.0) && end == usize::from(proto.register_count))
        .then_some((first, end))
}

static EMPTY_CLEANUP_SLOTS: [u8; 32] = [0; 32];

fn cleanup_slots_at<'a>(
    slots: &'a [(usize, [u8; 32])],
    proto: &BytecodePrototype,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<&'a [u8; 32], OfficialExportError> {
    // Vec 依 PC 遞增且每個 cleanup PC 只進入一次；BITS 比最大搜尋深度保守。
    work_charge(work, usize::BITS as usize, proto.id, pc)?;
    Ok(slots
        .binary_search_by_key(&pc, |entry| entry.0)
        .map_or(&EMPTY_CLEANUP_SLOTS, |index| &slots[index].1))
}

fn cleanup_slot_set(slots: &mut [u8; 32], slot: u8) {
    slots[usize::from(slot) / 8] |= 1 << (slot % 8);
}

fn cleanup_slot_contains(slots: &[u8; 32], slot: u8) -> bool {
    slots[usize::from(slot) / 8] & (1 << (slot % 8)) != 0
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
                register.0 >= base.0
                    && register.0
                        < open_prefix_end(proto, pc, false).unwrap_or(proto.register_count)
            } else {
                range(*base, arg_count.saturating_add(1))
            };
            let write = matches!(result_mode, ResultMode::Fixed(count) if range(*base, *count));
            (read, write)
        }
        Instruction::TailCall {
            base, arg_count, ..
        } if *arg_count == u16::MAX => (
            register.0 >= base.0
                && register.0 < open_prefix_end(proto, pc, false).unwrap_or(proto.register_count),
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
            register.0 >= base.0
                && register.0 < open_prefix_end(proto, pc, true).unwrap_or(proto.register_count),
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

#[derive(Clone, Copy)]
struct NumericOwnedNext {
    next_pc: usize,
    control: Register,
    limit: Register,
    step: Register,
}

// 僅官方 FORLOOP 的 tuple 接管已證明的 control/limit/step。IR 的
// static_register_access 仍描述原 bytecode；這個局部效果只供 native mapper。
fn numeric_native_access(
    proto: &BytecodePrototype,
    pc: usize,
    register: Register,
    owned: &[NumericOwnedNext],
    work: &mut OfficialWorkBudget,
) -> Result<(bool, bool), OfficialExportError> {
    static_access_charge(proto, pc, work)?;
    let raw = static_register_access(proto, pc, register);
    if !matches!(
        proto.instructions[pc].instruction,
        Instruction::NumericForNext { .. }
    ) || owned.is_empty()
    {
        return Ok(raw);
    }
    work_charge(work, usize::BITS as usize, proto.id, pc)?;
    if let Ok(index) = owned.binary_search_by_key(&pc, |entry| entry.next_pc) {
        let entry = owned[index];
        if [entry.control, entry.limit, entry.step].contains(&register) {
            return Ok((false, false));
        }
    }
    Ok(raw)
}

fn numeric_pair_tuple_owned(
    proto: &BytecodePrototype,
    pair: &NumericPair,
    numeric: &[NumericPair],
    mapped: &[u8],
    debug: &NativePrototypeDebug,
    storage: &[NativeStorageInterval],
    pending: &[NativeTemporary],
    initializer: &[NativeInitializerTemporary],
    child_environment_registers: &[Register],
    seen: &mut [u8],
    queue: &mut Vec<u32>,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let count = proto.instructions.len();
    let metadata = numeric
        .len()
        .checked_add(proto.binding_registers.len())
        .and_then(|n| n.checked_add(debug.locals.len()))
        .and_then(|n| n.checked_add(storage.len()))
        .and_then(|n| n.checked_add(pending.len()))
        .and_then(|n| n.checked_add(initializer.len()))
        .and_then(|n| n.checked_add(child_environment_registers.len()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pair.prepare_pc,
                "numeric tuple-owned metadata work 溢位",
            )
        })?;
    // CFG ingress、body 三值存取、三次出口可觀測性掃描皆由此上界預付。
    let scan_work = count
        .checked_mul(32)
        .and_then(|units| {
            metadata
                .checked_mul(4)
                .and_then(|extra| units.checked_add(extra))
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pair.prepare_pc,
                "numeric tuple-owned proof work 溢位",
            )
        })?;
    work_charge(work, scan_work, proto.id, pair.prepare_pc)?;
    if pair.prepare_pc.checked_add(1) != Some(pair.body_pc)
        || pair.body_pc >= pair.next_pc
        || pair.next_pc >= count
        || seen.len() != count
    {
        return Ok(false);
    }
    let Instruction::NumericForPrepare {
        control,
        limit,
        step,
        visible,
        exit,
    } = proto.instructions[pair.prepare_pc].instruction
    else {
        return Ok(false);
    };
    let Instruction::NumericForNext {
        control: next_control,
        limit: next_limit,
        step: next_step,
        visible: next_visible,
        target,
        exit: next_exit,
    } = proto.instructions[pair.next_pc].instruction
    else {
        return Ok(false);
    };
    let inputs = [control, limit, step];
    // 每個重疊候選須核對配對指令、block 與四乘四 guest 身分比較。
    work_charge(
        work,
        numeric.len().checked_mul(64).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pair.prepare_pc,
                "numeric nested pair proof work 溢位",
            )
        })?,
        proto.id,
        pair.prepare_pc,
    )?;
    if next_control != control
        || next_limit != limit
        || next_step != step
        || next_visible != visible
        || target.0 as usize != pair.body_pc
        || exit != next_exit
        || exit != pair.exit
        || visible != pair.visible
        || inputs[0] == inputs[1]
        || inputs[0] == inputs[2]
        || inputs[1] == inputs[2]
        || inputs.contains(&visible)
        || proto.instructions[pair.prepare_pc].close_path.is_some()
        || proto.instructions[pair.next_pc].close_path.is_some()
        || numeric.iter().any(|other| {
            if other.prepare_pc == pair.prepare_pc
                && other.next_pc == pair.next_pc
                && other.body_pc == pair.body_pc
                && other.block == pair.block
            {
                return false;
            }
            if other.prepare_pc > pair.next_pc || pair.prepare_pc > other.next_pc {
                return false;
            }
            // 交錯或同層覆蓋會讓兩個 FORLOOP 共享控制流程；僅嚴格巢狀可獨立。
            let strictly_nested = (pair.prepare_pc < other.prepare_pc
                && other.next_pc < pair.next_pc)
                || (other.prepare_pc < pair.prepare_pc && pair.next_pc < other.next_pc);
            if !strictly_nested
                || other.block == pair.block
                || other.prepare_pc.checked_add(1) != Some(other.body_pc)
                || other.body_pc >= other.next_pc
                || other.next_pc >= count
            {
                return true;
            }
            let Some(Instruction::NumericForPrepare {
                control: other_control,
                limit: other_limit,
                step: other_step,
                visible: other_visible,
                exit: other_exit,
            }) = proto
                .instructions
                .get(other.prepare_pc)
                .map(|entry| &entry.instruction)
            else {
                return true;
            };
            let Some(Instruction::NumericForNext {
                control: next_control,
                limit: next_limit,
                step: next_step,
                visible: next_visible,
                target: next_target,
                exit: next_exit,
            }) = proto
                .instructions
                .get(other.next_pc)
                .map(|entry| &entry.instruction)
            else {
                return true;
            };
            let other_registers = [*other_control, *other_limit, *other_step, *other_visible];
            let this_registers = [control, limit, step, visible];
            other_registers
                .iter()
                .any(|register| this_registers.contains(register))
                || next_control != other_control
                || next_limit != other_limit
                || next_step != other_step
                || next_visible != other_visible
                || next_target.0 as usize != other.body_pc
                || next_exit != other_exit
                || *other_exit != other.exit
                || *other_visible != other.visible
        })
    {
        return Ok(false);
    }
    for input in inputs {
        let index = usize::from(input.0);
        if input == proto.frame.environment
            || input.0 <= proto.parameter_count
            || proto
                .named_vararg
                .is_some_and(|(_, register)| register == input)
            || mapped.get(index).copied() != Some(u8::MAX)
            || proto
                .binding_registers
                .iter()
                .any(|(_, register)| *register == input)
            || debug.locals.iter().any(|local| local.register == input)
            || storage.iter().any(|local| local.register == input)
            || pending.iter().any(|entry| entry.register == input)
            || initializer.iter().any(|entry| entry.register == input)
            || child_environment_registers.contains(&input)
        {
            return Ok(false);
        }
    }
    for (pc, entry) in proto.instructions.iter().enumerate() {
        for successor in cfg_successors(proto, pc).into_iter().flatten() {
            if successor >= count {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "numeric tuple-owned CFG target 超出範圍",
                ));
            }
            if pair.body_pc <= successor
                && successor <= pair.next_pc
                && !(pair.body_pc <= pc && pc <= pair.next_pc)
                && !(pc == pair.prepare_pc && successor == pair.body_pc)
            {
                return Ok(false);
            }
            if pair.body_pc <= pc
                && pc < pair.next_pc
                && !(pair.body_pc <= successor && successor <= pair.next_pc)
                && successor != exit.0 as usize
            {
                // body 的其他出口不在下方從 pair.exit 開始的後讀證明內。
                return Ok(false);
            }
        }
        if pair.body_pc <= pc && pc < pair.next_pc {
            for input in inputs {
                let (read, write, possible, close) =
                    register_access(&entry.instruction, input, proto.register_count);
                if read || write || possible || close {
                    return Ok(false);
                }
            }
        }
    }
    // FORLOOP 的回邊只循 tuple；離開迴圈後仍需證明原 home
    // 在下次確定定義前不會被讀取或關閉（含 CFG 回跳）。
    for input in inputs {
        seen.fill(0);
        queue.clear();
        let Ok(start) = usize::try_from(exit.0) else {
            return Ok(false);
        };
        let Some(mark) = seen.get_mut(start) else {
            return Ok(false);
        };
        *mark = 1;
        queue.push(exit.0);
        while let Some(offset) = queue.pop() {
            let pc = usize::try_from(offset).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pair.next_pc,
                    "numeric tuple-owned PC 超出平台範圍",
                )
            })?;
            let entry = &proto.instructions[pc];
            let (read, write, possible, close) =
                register_access(&entry.instruction, input, proto.register_count);
            if read || close {
                return Ok(false);
            }
            if write && !possible {
                continue;
            }
            for successor in cfg_successors(proto, pc).into_iter().flatten() {
                let Some(mark) = seen.get_mut(successor) else {
                    return Err(error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "numeric tuple-owned 後讀 CFG target 超出範圍",
                    ));
                };
                if *mark == 0 {
                    *mark = 1;
                    queue.push(u32::try_from(successor).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "numeric tuple-owned successor 超出 u32",
                        )
                    })?);
                }
            }
        }
    }
    Ok(true)
}

fn numeric_owned_next_pairs(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    numeric: &[NumericPair],
    mapped: &[u8],
    work: &mut OfficialWorkBudget,
) -> Result<Vec<NumericOwnedNext>, OfficialExportError> {
    let mut owned = Vec::new();
    let Some(native) = module.native_debug() else {
        return Ok(owned);
    };
    let Some(debug) = native.prototype(proto.id) else {
        return Ok(owned);
    };
    if numeric.is_empty() {
        return Ok(owned);
    }
    let count = proto.instructions.len();
    // 即使所有 pair 都在 proof 前被排除，visited 的初始化仍須計費。
    work_charge(work, count, proto.id, 0)?;
    owned.try_reserve_exact(numeric.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric tuple-owned 稀疏索引配置失敗",
        )
    })?;
    let mut seen = Vec::new();
    seen.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric tuple-owned visited 配置失敗",
        )
    })?;
    seen.resize(count, 0u8);
    let mut queue = Vec::new();
    queue.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric tuple-owned worklist 配置失敗",
        )
    })?;
    let actual = owned
        .capacity()
        .checked_mul(size_of::<NumericOwnedNext>())
        .and_then(|n| n.checked_add(seen.capacity()))
        .and_then(|n| {
            queue
                .capacity()
                .checked_mul(size_of::<u32>())
                .and_then(|extra| n.checked_add(extra))
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "numeric tuple-owned 實際容量溢位",
            )
        })?;
    let cap = numeric
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_mul(size_of::<NumericOwnedNext>()))
        .and_then(|n| {
            count
                .checked_mul(2)
                .and_then(|c| c.checked_mul(size_of::<u32>() + 1))
                .and_then(|extra| n.checked_add(extra))
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "numeric tuple-owned 容量上界溢位",
            )
        })?;
    if actual > cap {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "numeric tuple-owned 實際容量超過預檢上界",
        ));
    }
    let storage = native.storage_for(proto.id).unwrap_or(&[]);
    let pending = native.temporaries_for(proto.id).unwrap_or(&[]);
    let initializer = native.initializer_temporaries_for(proto.id).unwrap_or(&[]);
    for pair in numeric {
        let Some(prepare_entry) = proto.instructions.get(pair.prepare_pc) else {
            continue;
        };
        let blocked_by_child_environment = match prepare_entry.instruction {
            Instruction::NumericForPrepare {
                control,
                limit,
                step,
                ..
            } => {
                work_charge(
                    work,
                    module.module().prototypes.len(),
                    proto.id,
                    pair.prepare_pc,
                )?;
                module.module().prototypes.iter().any(|child| {
                    child.parent == Some(proto.id)
                        && matches!(child.frame.environment_source,
                            EnvironmentSource::ParentFrame { parent, register }
                                if parent == proto.id
                                    && [control, limit, step].contains(&register))
                })
            }
            _ => true,
        };
        if blocked_by_child_environment {
            continue;
        }
        if numeric_pair_tuple_owned(
            proto,
            pair,
            numeric,
            mapped,
            debug,
            storage,
            pending,
            initializer,
            &[],
            &mut seen,
            &mut queue,
            work,
        )? {
            let Instruction::NumericForPrepare {
                control,
                limit,
                step,
                ..
            } = proto.instructions[pair.prepare_pc].instruction
            else {
                continue;
            };
            owned.push(NumericOwnedNext {
                next_pc: pair.next_pc,
                control,
                limit,
                step,
            });
        }
    }
    work_charge(
        work,
        owned
            .len()
            .checked_mul(usize::BITS as usize)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "numeric tuple-owned sort work 溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    owned.sort_unstable_by_key(|entry| entry.next_pc);
    Ok(owned)
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
    owned: &[NumericOwnedNext],
    bitmap_limit: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<LiveRow>, OfficialExportError> {
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
    let mut live_at = Vec::new();
    live_at.try_reserve_exact(spans.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native CFG per-register live 配置失敗",
        )
    })?;
    if live_at.capacity() > spans.len() {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native CFG per-register live 實際容量超過預檢上限",
        ));
    }
    live_at.resize_with(spans.len(), || LiveRow::Uncomputed);
    let mut bitmap_bytes = 0usize;
    for register in 0..spans.len() {
        if mapped[register] != u8::MAX
            || register == usize::from(proto.frame.environment.0)
            || spans[register].0 == usize::MAX
        {
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
        let mut first_live = count;
        let mut last_live = 0usize;
        for pc in 0..count {
            let (read, write) = numeric_native_access(proto, pc, register_id, owned, work)?;
            effects[pc] = u8::from(read) | (u8::from(write) << 1);
            if read {
                live[pc] = 1;
                pending.push(pc);
                first_live = first_live.min(pc);
                last_live = last_live.max(pc);
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
                    first_live = first_live.min(predecessor);
                    last_live = last_live.max(predecessor);
                }
            }
        }
        let base_byte = if first_live < count {
            first_live / 8
        } else {
            0
        };
        let bytes = if first_live < count {
            last_live / 8 - base_byte + 1
        } else {
            0
        };
        let packing_start = base_byte.checked_mul(8).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG live snapshot 起點溢位",
            )
        })?;
        let packing_end = base_byte
            .checked_add(bytes)
            .and_then(|last| last.checked_mul(8))
            .map(|last| last.min(count))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native CFG live snapshot 終點溢位",
                )
            })?;
        let packing_len = packing_end.checked_sub(packing_start).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG live snapshot 範圍溢位",
            )
        })?;
        work_charge(
            work,
            packing_len.checked_add(bytes).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native CFG live snapshot work 溢位",
                )
            })?,
            proto.id,
            0,
        )?;
        if bitmap_bytes
            .checked_add(bytes)
            .map_or(true, |total| total > bitmap_limit)
        {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG live snapshot 超過配置額度",
            ));
        }
        let mut bits = Vec::new();
        bits.try_reserve_exact(bytes).map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native CFG live snapshot 配置失敗",
            )
        })?;
        bitmap_bytes = bitmap_bytes
            .checked_add(bits.capacity())
            .filter(|total| *total <= bitmap_limit)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native CFG live snapshot 實際容量超過配置額度",
                )
            })?;
        bits.resize(bytes, 0);
        for (offset, &active) in live[packing_start..packing_end].iter().enumerate() {
            if active != 0 {
                let pc = packing_start + offset;
                bits[pc / 8 - base_byte] |= 1 << (pc % 8);
            }
        }
        live_at[register] = LiveRow::Bits {
            base_pc: packing_start,
            bytes: bits,
        };
    }
    Ok(live_at)
}

// 普通 LoadNil 的 emitter 先標記已初始化、且不在 clear guest 範圍內的
// local 實體槽，再略過該槽的清除。只有同一寫入確實被略過，且 temporary
// 在此指令前後均已死，fixed interval 才可忽略該虛寫。
fn suppressed_ordinary_load_nil_write(
    proto: &BytecodePrototype,
    debug: Option<&NativePrototypeDebug>,
    mapped: &[u8],
    numeric_aliases: &[NumericAlias],
    spans: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    candidate: usize,
    slot: u8,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    if protected[candidate] != 0
        || live_at_pc(spans, protected, live_at, candidate, pc)
        || live_at_pc(spans, protected, live_at, candidate, pc + 1)
    {
        return Ok(false);
    }
    let Some(entry) = proto.instructions.get(pc) else {
        return Ok(false);
    };
    let Instruction::LoadNil { start, count } = entry.instruction else {
        return Ok(false);
    };
    // 兩種出口/數值別名 fusion 都只處理 count=1；Call cleanup 有獨立佈局。
    if count <= 1 || entry.close_path.is_some() || call_cleanup_range(proto, pc).is_some() {
        return Ok(false);
    }
    let clear_start = usize::from(start.0);
    let clear_end = clear_start.checked_add(usize::from(count)).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "LoadNil clear 範圍溢位",
        )
    })?;
    if candidate < clear_start || candidate >= clear_end {
        return Ok(false);
    }
    let Some(debug) = debug else {
        return Ok(false);
    };
    let per_local = numeric_aliases.len().checked_add(1).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "LoadNil occupied local 工作量溢位",
        )
    })?;
    let scan_work = debug.locals.len().checked_mul(per_local).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "LoadNil occupied local 工作量溢位",
        )
    })?;
    work_charge(work, scan_work, proto.id, pc)?;
    for local in &debug.locals {
        let register = usize::from(local.register.0);
        if clear_start <= register && register < clear_end
            || local.initialized_pc as usize > pc
            || pc >= local.end_pc as usize
        {
            continue;
        }
        let home =
            native_layout_register_at(mapped, numeric_aliases, local.register, proto.id, pc)?;
        if home != u8::MAX && home == slot {
            return Ok(true);
        }
    }
    Ok(false)
}

// 同一物理槽可供不同 guest register 的互斥生命期使用；讀取、存活出邊
// 與同一指令的寫入皆會占槽。單一 register 的 home 仍維持固定。
fn mapped_owner_interferes(
    proto: &BytecodePrototype,
    spans: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    owned: &[NumericOwnedNext],
    candidate: usize,
    owner: usize,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let start = spans[candidate].0.max(spans[owner].0);
    let end = spans[candidate].1.min(spans[owner].1);
    if start >= end {
        return Ok(false);
    }
    let candidate_register = Register(candidate as u16);
    let owner_register = Register(owner as u16);
    for pc in start..end {
        work_charge(work, 1, proto.id, pc)?;
        let candidate_live = live_at_pc(spans, protected, live_at, candidate, pc)
            || live_at_pc(spans, protected, live_at, candidate, pc + 1);
        let owner_live = live_at_pc(spans, protected, live_at, owner, pc)
            || live_at_pc(spans, protected, live_at, owner, pc + 1);
        if candidate_live && owner_live {
            // GETTABLE 先讀 table/key，再寫 dest；只允許這一個 PC 上
            // 已死 key 的 home 轉交給剛出生的 dest。其他 PC 仍逐一檢查。
            if protected[candidate] == 0
                && protected[owner] == 0
                && !live_at_pc(spans, protected, live_at, candidate, pc)
                && live_at_pc(spans, protected, live_at, candidate, pc + 1)
                && live_at_pc(spans, protected, live_at, owner, pc)
                && !live_at_pc(spans, protected, live_at, owner, pc + 1)
            {
                static_access_charge(proto, pc, work)?;
                let entry = &proto.instructions[pc];
                let gettable_key = matches!(entry.instruction,
                    Instruction::GetTable { dest, key, .. }
                        if dest == candidate_register && key == owner_register);
                let plain_move = entry.close_path.is_none()
                    && matches!(entry.instruction,
                        Instruction::Move { dest, src }
                            if dest == candidate_register && src == owner_register);
                if gettable_key || plain_move {
                    continue;
                }
            }
            return Ok(true);
        }
        if candidate_live {
            if numeric_native_access(proto, pc, owner_register, owned, work)?.1 {
                // 大範圍 nil 清理中的舊 guest 值已死；輸出器會略過此時
                // 正由另一個活值佔用的實體槽，不能把虛寫視為干涉。
                let entry = &proto.instructions[pc];
                let dead_bulk_nil = matches!(entry.instruction,
                    Instruction::LoadNil { start, count }
                        if count > 1
                            && usize::from(start.0).checked_add(usize::from(count))
                                .is_some_and(|end| usize::from(start.0) <= owner
                                    && owner < end
                                    && (candidate < usize::from(start.0) || candidate >= end)))
                    && entry.close_path.is_none()
                    && call_cleanup_range(proto, pc).is_none()
                    && protected[candidate] == 0
                    && live_at_pc(spans, protected, live_at, candidate, pc)
                    && live_at_pc(spans, protected, live_at, candidate, pc + 1);
                if dead_bulk_nil {
                    continue;
                }
                return Ok(true);
            }
        } else if owner_live {
            if numeric_native_access(proto, pc, candidate_register, owned, work)?.1 {
                return Ok(true);
            }
        } else {
            let candidate_writes =
                numeric_native_access(proto, pc, candidate_register, owned, work)?.1;
            let owner_writes = numeric_native_access(proto, pc, owner_register, owned, work)?.1;
            if candidate_writes && owner_writes {
                // 同一 LoadNil 同時寫入兩個已死 guest 值，物理槽收到的
                // 都是 nil；後續不同寫入仍由逐 PC 衝突檢查攔截。
                if matches!(
                    proto.instructions[pc].instruction,
                    Instruction::LoadNil { .. }
                ) {
                    continue;
                }
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn live_at_pc(
    spans: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    register: usize,
    pc: usize,
) -> bool {
    let (start, end) = spans[register];
    start <= pc
        && pc < end
        && (protected[register] != 0
            || match live_at.get(register) {
                Some(LiveRow::Bits { base_pc, bytes }) => pc
                    .checked_sub(*base_pc)
                    .and_then(|offset| bytes.get(offset / 8))
                    .is_some_and(|byte| *byte & (1u8 << (pc % 8)) != 0),
                Some(LiveRow::Uncomputed) | None => true,
            })
}

// consumer PC 的既定讀取仍由原融合處理；後繼若需要舊值，代表某條 CFG 路徑
// 在再次定義之前會讀取它。protected/uncomputed 一律保守拒絕。
fn generation_live_after_consumer(
    proto: &BytecodePrototype,
    meta: &Layout,
    register: Register,
    consumer_pc: usize,
) -> bool {
    cfg_successors(proto, consumer_pc)
        .into_iter()
        .flatten()
        .any(|pc| {
            live_at_pc(
                &meta.span,
                &meta.protected,
                &meta.live_at,
                usize::from(register.0),
                pc,
            )
        })
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
                // Return close group 由官方 RETURN 關閉；整組 Close 的捕獲槽
                // 在 gather 結果前都必須存活，不能只延長緊鄰 Return 的一項。
                if matches!(proto.instructions[pc].instruction,
                    Instruction::Close { base, .. } if base == *register)
                {
                    let mut end = pc;
                    while let Some(entry) = proto.instructions.get(end) {
                        work_charge(work, 1, proto.id, end)?;
                        if !matches!(entry.instruction, Instruction::Close { count: 0, .. }) {
                            break;
                        }
                        end += 1;
                    }
                    if matches!(
                        proto.instructions.get(end).map(|entry| &entry.instruction),
                        Some(Instruction::Return { .. })
                    ) {
                        span.1 = span.1.max(end + 1);
                    } else if matches!(
                        proto
                            .instructions
                            .get(pc + 1)
                            .map(|entry| &entry.instruction),
                        Some(Instruction::Return { .. })
                    ) && matches!(
                        proto.instructions[pc]
                            .close_path
                            .as_ref()
                            .map(|path| path.kind),
                        Some(BytecodeExitKind::Return)
                    ) {
                        span.1 = span.1.max(pc + 2);
                    }
                }
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

#[derive(Clone, Copy)]
struct TemporaryCallLayout {
    pc: usize,
    first_slot: u16,
    window_start: u16,
    window_width: u16,
    window_end: u16,
    call_base: u16,
    open_chain: bool,
}

// Call 佈局依 IR PC 建立；候選 home 只需檢查其生命區間內的 Call。
// 每次二分 probe 都先扣 work，回傳原陣列索引供 dead-open cache 使用。
fn call_layout_range(
    calls: &[TemporaryCallLayout],
    start: usize,
    end: usize,
    id: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<(usize, usize), OfficialExportError> {
    if start > end {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            start,
            "native Call 候選區間次序無效",
        ));
    }
    let mut lower_bound = |pc: usize| -> Result<usize, OfficialExportError> {
        let mut low = 0usize;
        let mut high = calls.len();
        while low < high {
            let middle = low + (high - low) / 2;
            work_charge(work, 1, id, pc)?;
            if calls[middle].pc < pc {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        Ok(low)
    };
    Ok((lower_bound(start)?, lower_bound(end)?))
}

// 嚴格相鄰的 open 鏈中，pending 值可留在 Call base 以下的原位前綴。
// 只有 guest register 與官方窗口位置完全相同時，gather 才不會搬走它。
fn pending_call_prefix_home(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    call: &TemporaryCallLayout,
    register: usize,
    slot: u16,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    if !call.open_chain || slot < call.window_start || slot >= call.call_base {
        return Ok(false);
    }
    let base = match proto.instructions[call.pc].instruction {
        Instruction::Call { base, .. } | Instruction::TailCall { base, .. } => base,
        _ => return Ok(false),
    };
    let offset = call
        .call_base
        .checked_sub(call.window_start)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                call.pc,
                "open Call pending prefix 逆序",
            )
        })?;
    let guest = base
        .0
        .checked_sub(offset)
        .and_then(|root| root.checked_add(slot - call.window_start));
    if guest.map(usize::from) != Some(register) {
        return Ok(false);
    }
    let call_pc = InstructionOffset(u32::try_from(call.pc).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            call.pc,
            "open Call pending prefix PC 超出範圍",
        )
    })?);
    let pending = module
        .native_debug()
        .and_then(|debug| debug.temporaries_at(proto.id, call_pc))
        .unwrap_or(&[]);
    work_charge(work, pending.len(), proto.id, call.pc)?;
    Ok(pending.iter().any(|temporary| {
        usize::from(temporary.register.0) == register
            && temporary.ordinal > 0
            && call.first_slot.checked_add(temporary.ordinal - 1) == Some(slot)
    }))
}

#[derive(Clone, Copy)]
struct PendingRelayPair {
    source: Register,
    destination: Register,
    move_pc: usize,
    consumer_pc: usize,
    slot: u8,
}

/// 辨識 Call 是否位於回邊，供開放結果保留出生至 Call 的峰值前綴。
fn call_within_backward_edge(
    proto: &BytecodePrototype,
    call_pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    work_charge(work, proto.instructions.len(), proto.id, call_pc)?;
    for source in call_pc..proto.instructions.len() {
        if cfg_successors(proto, source)
            .into_iter()
            .flatten()
            .any(|target| target <= call_pc && call_pc <= source)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn pending_relay_reverse_revisit(
    pair: PendingRelayPair,
    source: Register,
    destination: Register,
    slot: u8,
    call_pc: usize,
    terminal_pc: Option<usize>,
    source_span: (usize, usize),
    destination_span: (usize, usize),
    reservations: &[(u8, usize, usize)],
) -> bool {
    pair.source == source
        && pair.destination == destination
        && pair.slot == slot
        && pair.move_pc + 1 == source_span.1
        && pair.move_pc == destination_span.0
        && pair.move_pc < call_pc
        && call_pc < pair.consumer_pc
        && terminal_pc == Some(pair.consumer_pc)
        && reservations.iter().any(|&(reserved_slot, start, end)| {
            reserved_slot == slot && start == pair.move_pc + 1 && end >= start
        })
}

// open Call 的 pending 與 callee 在 Call 前同時存在；未固定 callee
// 雖在 Call 中死亡，仍需獨立於 pending 的 home。
fn open_call_frontier_with_callee(
    current: usize,
    open_chain: bool,
    pending: &[NativeTemporary],
    base: Register,
    mapped: &[u8],
    environment: Register,
    global_environment: Register,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<usize, OfficialExportError> {
    if !open_chain || pending.is_empty() {
        return Ok(current);
    }
    work_charge(
        work,
        pending.len().checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "native open Call callee 掃描 work 溢位",
            )
        })?,
        id,
        pc,
    )?;
    let Some(&home) = mapped.get(usize::from(base.0)) else {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "native open Call callee register 超出 prototype",
        ));
    };
    if home != u8::MAX
        || base == environment
        || base == global_environment
        || pending.iter().any(|entry| entry.register == base)
    {
        return Ok(current);
    }
    current.checked_add(1).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            id,
            pc,
            "native open Call callee frontier 溢位",
        )
    })
}

fn unmapped_callee_alive_at_birth(
    callee_unmapped: bool,
    spans: &[(usize, usize)],
    base: Register,
    birth: usize,
) -> bool {
    callee_unmapped
        && spans
            .get(usize::from(base.0))
            .is_some_and(|&(start, end)| start <= birth && birth < end)
}

fn fixed_pending_birth_retained(
    active: usize,
    pending: &[NativeTemporary],
    mapped: &[u8],
    span: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    base: Register,
    environment: Register,
    global_environment: Register,
    locals_count: usize,
    storage_count: usize,
    active_at_birth: impl Fn(usize) -> Result<usize, OfficialExportError>,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<usize, OfficialExportError> {
    if pending.is_empty() {
        return Ok(0);
    }
    work_charge(work, pending.len(), id, pc)?;
    let crosses_call = pending.iter().any(|temporary| {
        span.get(usize::from(temporary.register.0))
            .is_some_and(|&(start, end)| start <= pc && pc + 1 < end)
    });
    if !crosses_call {
        return Ok(0);
    }
    let pending_count = pending.len();
    let per_birth = span
        .len()
        .checked_mul(pending_count.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "fixed Call pending 數溢位",
            )
        })?)
        .and_then(|units| units.checked_add(locals_count))
        .and_then(|units| units.checked_add(storage_count))
        .and_then(|units| units.checked_add(pending_count))
        .and_then(|units| units.checked_add(4))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "fixed Call 出生掃描 work 溢位",
            )
        })?;
    work_charge(
        work,
        pending_count.checked_mul(per_birth).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "fixed Call 出生掃描 work 溢位",
            )
        })?,
        id,
        pc,
    )?;
    if mapped.len() != span.len() {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "fixed Call register 佈局長度不一致",
        ));
    }
    let base_index = usize::from(base.0);
    let base_home = mapped.get(base_index).copied().ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "fixed Call callee register 不存在",
        )
    })?;
    let callee_unmapped = base_home == u8::MAX
        && base != environment
        && base != global_environment
        && !pending.iter().any(|entry| entry.register == base);
    let excluded = |register: usize| {
        mapped[register] != u8::MAX
            || register == usize::from(environment.0)
            || register == usize::from(global_environment.0)
            || register == base_index
            || pending
                .iter()
                .any(|entry| usize::from(entry.register.0) == register)
    };
    let mut peak = active;
    for temporary in pending {
        let birth = span
            .get(usize::from(temporary.register.0))
            .map(|range| range.0)
            .filter(|&birth| birth != usize::MAX && birth <= pc)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    pc,
                    "fixed Call pending 出生點無效",
                )
            })?;
        let after_birth = birth.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                id,
                pc,
                "fixed Call 出生後 PC 溢位",
            )
        })?;
        let active_birth = active_at_birth(birth)?;
        // 出生指令讀完即死的 operand 可在指令邊界交出槽；只有下一 PC
        // 仍存活的值，才佔用 pending 的出生前綴。
        let live_birth = span
            .iter()
            .enumerate()
            .filter(|(register, range)| {
                let (start, end) = **range;
                !excluded(*register)
                    && start <= birth
                    && after_birth < end
                    && live_at_pc(span, protected, live_at, *register, after_birth)
            })
            .count();
        let callee_birth = unmapped_callee_alive_at_birth(callee_unmapped, span, base, birth);
        let at_birth = active_birth
            .checked_add(live_birth)
            .and_then(|value| value.checked_add(usize::from(callee_birth)))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    pc,
                    "fixed Call 出生前綴數溢位",
                )
            })?;
        peak = peak.max(at_birth);
    }
    peak.checked_sub(active).ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            id,
            pc,
            "fixed Call 出生前綴低於 active local",
        )
    })
}

fn temporary_call_layouts(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    anonymous_vararg_slot: Option<u8>,
    numeric: &[NumericPair],
    tuple_base: Option<u16>,
    mapped: &[u8],
    span: &[(usize, usize)],
    protected: &[u8],
    live_at: &[LiveRow],
    work: &mut OfficialWorkBudget,
) -> Result<Vec<TemporaryCallLayout>, OfficialExportError> {
    let Some(debug) = module.native_debug() else {
        return Ok(Vec::new());
    };
    let locals = &debug
        .prototype(proto.id)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                0,
                "native temporary 缺少 prototype debug",
            )
        })?
        .locals;
    let storage = debug.storage_for(proto.id).ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            proto.id,
            0,
            "native Call frontier 缺少 local storage",
        )
    })?;
    let plan_calls = module
        .official_execution()
        .map_or(&[][..], |plan| plan.calls());
    let mut calls = Vec::new();
    let call_count = proto
        .instructions
        .iter()
        .filter(|entry| {
            matches!(entry.instruction, Instruction::Call { .. })
                || matches!(
                    entry.instruction,
                    Instruction::TailCall {
                        arg_count: u16::MAX,
                        ..
                    }
                )
        })
        .count();
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    calls.try_reserve_exact(call_count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native Call 佈局配置失敗",
        )
    })?;
    for (pc, entry) in proto.instructions.iter().enumerate() {
        let (base, arg_count) = match &entry.instruction {
            Instruction::Call {
                base, arg_count, ..
            }
            | Instruction::TailCall {
                base, arg_count, ..
            } => (*base, *arg_count),
            _ => continue,
        };
        let chain_terminal = if matches!(
            entry.instruction,
            Instruction::Call {
                result_mode: ResultMode::All,
                ..
            }
        ) {
            strict_open_call_terminal(proto, pc, work)?
        } else {
            None
        };
        let chain_terminal = if let Some(terminal) = chain_terminal {
            work_charge(work, plan_calls.len(), proto.id, pc)?;
            (!plan_calls
                .iter()
                .any(|call| call.prototype == proto.id && call.call_pc.0 as usize == terminal))
            .then_some(terminal)
        } else {
            None
        };
        let helper_here = if arg_count == u16::MAX {
            work_charge(work, plan_calls.len(), proto.id, pc)?;
            plan_calls
                .iter()
                .any(|call| call.prototype == proto.id && call.call_pc.0 as usize == pc)
        } else {
            false
        };
        let is_terminal = arg_count == u16::MAX
            && !helper_here
            && pc.checked_sub(1).is_some_and(|prior| {
                matches!(
                    proto.instructions[prior].instruction,
                    Instruction::Call {
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            })
            && strict_open_call_terminal(proto, pc - 1, work)? == Some(pc);
        let open_chain = chain_terminal.is_some() || is_terminal;
        let fixed_call = matches!(entry.instruction, Instruction::Call {
            arg_count,
            result_mode: ResultMode::Fixed(_),
            ..
        } if arg_count != u16::MAX);
        if !fixed_call && !open_chain {
            continue;
        }
        let call_pc = InstructionOffset(u32::try_from(pc).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native Call PC 超出範圍",
            )
        })?);
        let pending = debug.temporaries_at(proto.id, call_pc).unwrap_or(&[]);
        work_charge(
            work,
            numeric
                .len()
                .checked_mul(
                    span.len()
                        .checked_add(pending.len())
                        .and_then(|count| count.checked_add(2))
                        .ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                proto.id,
                                pc,
                                "numeric Call frontier 工作量溢位",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "numeric Call frontier 工作量溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        work_charge(
            work,
            pending
                .len()
                .checked_add(locals.len())
                .and_then(|count| count.checked_add(1))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native Call frontier 掃描 work 溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        let active_local_frontier = |at: usize| -> Result<usize, OfficialExportError> {
            let mut frontier = anonymous_vararg_slot.map_or(0, |slot| usize::from(slot) + 1);
            for (local, storage) in locals.iter().zip(storage) {
                if local.start_pc as usize <= at
                    && at < local.end_pc as usize
                    && storage.start_pc as usize <= at
                    && at < storage.end_pc as usize
                {
                    let home =
                        official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, at)?;
                    frontier = frontier.max(usize::from(home) + 1);
                }
            }
            if let Some(tuple_base) = tuple_base {
                for pair in numeric {
                    if pair.prepare_pc <= at && at <= pair.next_pc {
                        let end = pair
                            .block
                            .checked_add(1)
                            .and_then(|block| block.checked_mul(4))
                            .and_then(|width| tuple_base.checked_add(width))
                            .ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    proto.id,
                                    at,
                                    "numeric Call frontier 溢位",
                                )
                            })?;
                        frontier = frontier.max(usize::from(end));
                    }
                }
            }
            Ok(frontier)
        };
        let active = active_local_frontier(pc)?;
        // 開放結果會覆寫 Call base 以上的槽。既有 Call 當下與回邊下界
        // 均保留，另以每個 pending 出生時的存活峰值避開較早的 home。
        let retained = if open_chain {
            let in_backedge = call_within_backward_edge(proto, pc, work)?;
            let excluded = |register: usize| {
                mapped[register] != u8::MAX
                    || register == usize::from(proto.frame.environment.0)
                    || register == usize::from(proto.global_environment.0)
                    || register == usize::from(base.0)
                    || pending
                        .iter()
                        .any(|entry| usize::from(entry.register.0) == register)
            };
            let scan_work = span
                .len()
                .checked_mul(2)
                .and_then(|units| units.checked_mul(pending.len().checked_add(1)?))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native Call frontier 掃描 work 溢位",
                    )
                })?;
            work_charge(work, scan_work, proto.id, pc)?;
            let live_across = |register: usize, range: &(usize, usize)| {
                !excluded(register)
                    && range.0 <= pc
                    && range.1 > pc + 1
                    && live_at_pc(span, protected, live_at, register, pc)
                    && live_at_pc(span, protected, live_at, register, pc + 1)
            };
            let current = if !in_backedge {
                span.iter()
                    .enumerate()
                    .filter(|(register, range)| live_across(*register, range))
                    .count()
            } else if let Some(earliest) = span
                .iter()
                .enumerate()
                .filter(|(register, range)| live_across(*register, range))
                .map(|(_, &(start, _))| start)
                .min()
            {
                let steps = pc
                    .checked_sub(earliest)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native Call frontier 長度溢位",
                        )
                    })?;
                work_charge(
                    work,
                    steps.checked_mul(scan_work).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native Call frontier work 溢位",
                        )
                    })?,
                    proto.id,
                    pc,
                )?;
                (earliest..=pc)
                    .map(|at| {
                        span.iter()
                            .enumerate()
                            .filter(|(register, range)| {
                                let (start, end) = **range;
                                !excluded(*register)
                                    && start <= at
                                    && at < end
                                    && live_at_pc(span, protected, live_at, *register, at)
                            })
                            .count()
                    })
                    .max()
                    .unwrap_or(0)
            } else {
                0
            };
            if !in_backedge {
                // callee 已佔 call_base，不再放進 pending 前綴。
                current
            } else {
                let current_with_callee = open_call_frontier_with_callee(
                    current,
                    open_chain,
                    pending,
                    base,
                    mapped,
                    proto.frame.environment,
                    proto.global_environment,
                    proto.id,
                    pc,
                    work,
                )?;
                let callee_unmapped = current_with_callee != current;
                let current = current_with_callee;
                // 回邊會重訪先前出生的 pending；直線拷貝的原值與其新 home
                // 由後續 live/Move 別名證明，不應在此重複計入。
                let per_birth = scan_work
                    .checked_add(locals.len())
                    .and_then(|units| units.checked_add(storage.len()))
                    .and_then(|units| units.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native pending 出生掃描 work 溢位",
                        )
                    })?;
                let birth_work = pending.len().checked_mul(per_birth).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native pending 出生掃描 work 溢位",
                    )
                })?;
                work_charge(work, birth_work, proto.id, pc)?;
                let mut frontier = active.checked_add(current).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native temporary frontier 數溢位",
                    )
                })?;
                for temporary in pending {
                    let register = usize::from(temporary.register.0);
                    let birth = span
                        .get(register)
                        .map(|range| range.0)
                        .filter(|&birth| birth != usize::MAX && birth <= pc)
                        .ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::InvalidPrototype,
                                proto.id,
                                pc,
                                "native pending 出生點無效",
                            )
                        })?;
                    let active_at_birth = active_local_frontier(birth)?;
                    let live_at_birth = span
                        .iter()
                        .enumerate()
                        .filter(|(register, range)| {
                            let (start, end) = **range;
                            !excluded(*register)
                                && start <= birth
                                && birth < end
                                && (live_at_pc(span, protected, live_at, *register, birth)
                                    || live_at_pc(span, protected, live_at, *register, birth + 1))
                        })
                        .count();
                    let callee_at_birth = callee_unmapped
                        && (live_at_pc(span, protected, live_at, usize::from(base.0), birth)
                            || live_at_pc(
                                span,
                                protected,
                                live_at,
                                usize::from(base.0),
                                birth + 1,
                            ));
                    let at_birth = active_at_birth
                        .checked_add(live_at_birth)
                        .and_then(|value| value.checked_add(usize::from(callee_at_birth)))
                        .ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                proto.id,
                                pc,
                                "native pending 出生前綴數溢位",
                            )
                        })?;
                    frontier = frontier.max(at_birth);
                }
                frontier.checked_sub(active).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "native pending 出生前綴低於 Call local",
                    )
                })?
            }
        } else {
            // C 函式從參數後的 top 推入暫存值；跨 Call 的原值必須先於
            // callee，而非只避開已知的參數／結果窗口。pending 由前綴保存。
            work_charge(work, span.len(), proto.id, pc)?;
            let fixed_results = match entry.instruction {
                Instruction::Call {
                    base,
                    result_mode: ResultMode::Fixed(results),
                    ..
                } => Some((usize::from(base.0), usize::from(results))),
                _ => None,
            };
            let crosses_call = |register: usize, range: &(usize, usize)| {
                let (start, end) = *range;
                mapped[register] == u8::MAX
                    && register != usize::from(proto.frame.environment.0)
                    && register != usize::from(proto.global_environment.0)
                    && register != usize::from(base.0)
                    && !fixed_results
                        .is_some_and(|(first, count)| register >= first && register - first < count)
                    && !pending
                        .iter()
                        .any(|entry| usize::from(entry.register.0) == register)
                    && start <= pc
                    && pc + 1 < end
                    && live_at_pc(span, protected, live_at, register, pc)
                    && live_at_pc(span, protected, live_at, register, pc + 1)
            };
            let mut current = 0usize;
            let mut live_start = usize::MAX;
            let mut live_end = 0usize;
            for (register, range) in span.iter().enumerate() {
                if crosses_call(register, range) {
                    current += 1;
                    live_start = live_start.min(range.0);
                    live_end = live_end.max(range.1);
                }
            }
            let mut frontier = active.checked_add(current).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "fixed Call frontier 數溢位",
                )
            })?;
            if current != 0 {
                // 跨 Call 值的 home 固定不變；之後進入的 local 仍可能
                // 佔用較高實體槽，不能只看 Call 當下可見的 local 數。
                work_charge(work, storage.len(), proto.id, pc)?;
                let mut local_floor = 0usize;
                for local in storage {
                    if local.start_pc as usize >= live_end || live_start >= local.end_pc as usize {
                        continue;
                    }
                    let home =
                        official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, pc)?;
                    local_floor = local_floor.max(usize::from(home) + 1);
                }
                frontier = frontier.max(local_floor.checked_add(current).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "fixed Call local 前綴數溢位",
                    )
                })?);
            }
            // 固定 Call 的 home 在整段 IR 中不搬動。跨 Call 的值即使在
            // Call 前已有局部值結束，出生時仍須避開當時同時存活的槽。
            for (register, range) in span.iter().enumerate() {
                if !crosses_call(register, range) || range.0 >= pc {
                    continue;
                }
                let birth = range.0;
                let after_birth = birth.checked_add(1).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "fixed Call 出生後 PC 溢位",
                    )
                })?;
                let scan = span
                    .len()
                    .checked_mul(pending.len().checked_add(1).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "fixed Call 出生掃描 work 溢位",
                        )
                    })?)
                    .and_then(|units| units.checked_add(locals.len()))
                    .and_then(|units| units.checked_add(storage.len()))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "fixed Call 出生掃描 work 溢位",
                        )
                    })?;
                work_charge(work, scan, proto.id, pc)?;
                let active_birth = active_local_frontier(birth)?;
                let live_birth = span
                    .iter()
                    .enumerate()
                    .filter(|(other, range)| {
                        let (start, end) = **range;
                        mapped[*other] == u8::MAX
                            && *other != usize::from(proto.frame.environment.0)
                            && *other != usize::from(proto.global_environment.0)
                            && *other != usize::from(base.0)
                            && !pending
                                .iter()
                                .any(|entry| usize::from(entry.register.0) == *other)
                            && start <= birth
                            && after_birth < end
                            && live_at_pc(span, protected, live_at, *other, after_birth)
                    })
                    .count();
                frontier = frontier.max(active_birth.checked_add(live_birth).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "fixed Call 出生前綴數溢位",
                    )
                })?);
            }
            let retained = frontier.checked_sub(active).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "fixed Call 出生前綴低於 active local",
                )
            })?;
            if !pending.is_empty() && call_within_backward_edge(proto, pc, work)? {
                retained.max(fixed_pending_birth_retained(
                    active,
                    pending,
                    mapped,
                    span,
                    protected,
                    live_at,
                    base,
                    proto.frame.environment,
                    proto.global_environment,
                    locals.len(),
                    storage.len(),
                    active_local_frontier,
                    proto.id,
                    pc,
                    work,
                )?)
            } else {
                retained
            }
        };
        let first_slot = active
            .checked_add(retained)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native temporary 保留前綴超出 stack",
                )
            })?;
        let call_base = first_slot
            .checked_add(u16::try_from(pending.len()).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native temporary 數超出 stack",
                )
            })?)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native temporary call base 溢位",
                )
            })?;
        let terminal = chain_terminal.unwrap_or(pc);
        let root = if open_chain {
            match proto.instructions[terminal].instruction {
                Instruction::Call { base, .. } | Instruction::TailCall { base, .. } => base,
                _ => unreachable!("strict open Call terminal 必為 Call 或 TailCall"),
            }
        } else {
            base
        };
        let offset = base.0.checked_sub(root.0).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc,
                "native temporary open Call root 無效",
            )
        })?;
        if open_chain {
            let terminal_pending = if matches!(
                proto.instructions[terminal].instruction,
                Instruction::Call { .. }
            ) {
                let terminal_pc = InstructionOffset(u32::try_from(terminal).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "open Call terminal PC 超出範圍",
                    )
                })?);
                debug
                    .temporaries_at(proto.id, terminal_pc)
                    .map_or(0, <[_]>::len)
            } else {
                0
            };
            if pending.len() != terminal_pending + usize::from(offset) {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "open Call 鏈缺少完整 pending prefix",
                ));
            }
        }
        let window_start = call_base.checked_sub(offset).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native temporary Call window 起點溢位",
            )
        })?;
        let window_width = scratch_width_at(proto, pc, work)?;
        let window_end = window_start.checked_add(window_width).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native temporary Call window 終點溢位",
            )
        })?;
        if (!open_chain && window_start < call_base) || window_end > 255 {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native temporary Call window 與 pending slot 衝突",
            ));
        }
        calls.push(TemporaryCallLayout {
            pc,
            first_slot,
            window_start,
            window_width,
            window_end,
            call_base,
            open_chain,
        });
    }
    // 僅相鄰 open Call 鏈共用動態結果窗口；各成員原有下界不可降低。
    let mut chain_start = 0;
    while chain_start < calls.len() {
        let start_pc = calls[chain_start].pc;
        let terminal = if calls[chain_start].open_chain {
            strict_open_call_terminal(proto, start_pc, work)?
        } else {
            None
        };
        let Some(terminal) = terminal else {
            chain_start += 1;
            continue;
        };
        let mut chain_end = chain_start;
        while chain_end < calls.len() && calls[chain_end].pc <= terminal {
            work_charge(work, 1, proto.id, calls[chain_end].pc)?;
            let expected_pc = start_pc
                .checked_add(chain_end - chain_start)
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        start_pc,
                        "open Call 鏈 PC 溢位",
                    )
                })?;
            if !calls[chain_end].open_chain || calls[chain_end].pc != expected_pc {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    calls[chain_end].pc,
                    "open Call 鏈的 temporary 佈局不連續",
                ));
            }
            chain_end += 1;
        }
        if calls[chain_end - 1].pc != terminal {
            return Err(error(
                OfficialExportErrorKind::Unsupported,
                proto.id,
                start_pc,
                "open Call 鏈缺少 terminal temporary 佈局",
            ));
        }
        let mut common_frontier = 0u16;
        let mut incompatible_ordinal = false;
        for left in chain_start..chain_end {
            common_frontier = common_frontier.max(calls[left].first_slot);
            let left_pc = InstructionOffset(u32::try_from(calls[left].pc).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    calls[left].pc,
                    "open Call temporary PC 超出範圍",
                )
            })?);
            let left_pending = debug.temporaries_at(proto.id, left_pc).unwrap_or(&[]);
            for right in left + 1..chain_end {
                let right_pc = InstructionOffset(u32::try_from(calls[right].pc).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        calls[right].pc,
                        "open Call temporary PC 超出範圍",
                    )
                })?);
                let right_pending = debug.temporaries_at(proto.id, right_pc).unwrap_or(&[]);
                let comparisons = left_pending
                    .len()
                    .checked_mul(right_pending.len())
                    .and_then(|count| count.checked_add(1))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            calls[right].pc,
                            "open Call temporary 比對 work 溢位",
                        )
                    })?;
                work_charge(work, comparisons, proto.id, calls[right].pc)?;
                for first in left_pending {
                    for second in right_pending {
                        if first.register == second.register && first.ordinal != second.ordinal {
                            incompatible_ordinal = true;
                        }
                    }
                }
            }
        }
        if incompatible_ordinal {
            return Err(error(
                OfficialExportErrorKind::Unsupported,
                proto.id,
                start_pc,
                "open Call 鏈 temporary ordinal 衝突",
            ));
        }
        for call in &mut calls[chain_start..chain_end] {
            work_charge(work, 1, proto.id, call.pc)?;
            let shift = common_frontier
                .checked_sub(call.first_slot)
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        call.pc,
                        "open Call 鏈共同前綴低於下界",
                    )
                })?;
            call.first_slot = common_frontier;
            call.call_base = call.call_base.checked_add(shift).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    call.pc,
                    "open Call 共用 call base 超出 stack",
                )
            })?;
            call.window_start = call.window_start.checked_add(shift).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    call.pc,
                    "open Call 共用 window 起點超出 stack",
                )
            })?;
            call.window_end = call.window_end.checked_add(shift).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    call.pc,
                    "open Call 共用 window 終點超出 stack",
                )
            })?;
            if call.window_end > 255 {
                return Err(error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    call.pc,
                    "open Call 共用 window 超出 stack",
                ));
            }
        }
        chain_start = chain_end;
    }
    Ok(calls)
}

/// 原始 register 的值經單一 Move 交給外層固定 Call 時，容許兩者共用同一官方槽。
/// 證明只接受無分支的連續區間；其餘情形仍交由保守 live span 衝突檢查拒絕。
fn pending_move_relay_alias(
    instructions: &[BytecodeInstruction],
    register_count: u16,
    id: ProtoId,
    call_pc: usize,
    source: Register,
    candidate: Register,
    locals: &[NativeLocal],
    work: &mut OfficialWorkBudget,
) -> Result<Option<(usize, usize)>, OfficialExportError> {
    let access = |pc: usize, register| {
        register_access(&instructions[pc].instruction, register, register_count)
    };
    let mut definition = None;
    for pc in (0..call_pc).rev() {
        work_charge(work, 1, id, pc)?;
        let (_, write, possible_write, _) = access(pc, source);
        if possible_write {
            return Ok(None);
        }
        if write {
            definition = Some(pc);
            break;
        }
    }
    let Some(definition) = definition else {
        return Ok(None);
    };
    let mut relay = None;
    for pc in definition..instructions.len() {
        work_charge(work, 1, id, pc)?;
        let instruction = &instructions[pc].instruction;
        let (source_read, source_write, source_possible, source_close) = access(pc, source);
        if pc > definition && pc <= call_pc && (source_write || source_possible || source_close) {
            return Ok(None);
        }
        if pc == call_pc && source_read {
            return Ok(None);
        }
        if pc <= call_pc {
            continue;
        }
        if source_write || source_possible || source_close {
            return Ok(None);
        }
        if source_read {
            if let Instruction::Move { dest, src } = instruction {
                if *src == source && *dest != source {
                    relay = Some((pc, *dest));
                }
            }
            break;
        }
    }
    let Some((relay, destination)) = relay else {
        return Ok(None);
    };
    for pc in definition..relay {
        work_charge(work, 1, id, pc)?;
        let (dest_read, dest_write, dest_possible, dest_close) = access(pc, destination);
        let (candidate_read, candidate_write, candidate_possible, candidate_close) =
            access(pc, candidate);
        if dest_read
            || dest_write
            || dest_possible
            || dest_close
            || candidate_read
            || candidate_write
            || candidate_possible
            || candidate_close
        {
            return Ok(None);
        }
    }
    let mut consumer = None;
    for pc in relay + 1..instructions.len() {
        work_charge(work, 1, id, pc)?;
        let instruction = &instructions[pc].instruction;
        let (source_read, source_write, source_possible, source_close) = access(pc, source);
        let (dest_read, dest_write, dest_possible, dest_close) = access(pc, destination);
        if source_read || source_write || source_possible || source_close {
            return Ok(None);
        }
        if dest_possible || dest_close || (dest_write && !dest_read) {
            return Ok(None);
        }
        if dest_read {
            let fixed_consumer = matches!(instruction,
                Instruction::Call { base, arg_count, result_mode: ResultMode::Fixed(_), .. }
                    if *arg_count != u16::MAX && destination.0 >= base.0
                        && destination.0 - base.0 <= *arg_count)
                || matches!(instruction,
                    Instruction::TailCall { base, arg_count, .. }
                        if *arg_count != u16::MAX && destination.0 >= base.0
                            && destination.0 - base.0 <= *arg_count);
            let open_consumer = if let Instruction::Call {
                base,
                arg_count,
                result_mode: ResultMode::All,
            } = instruction
            {
                let mut next = pc + 1;
                while matches!(
                    instructions.get(next).map(|entry| &entry.instruction),
                    Some(Instruction::Call {
                        arg_count: u16::MAX,
                        result_mode: ResultMode::All,
                        ..
                    })
                ) {
                    work_charge(work, 1, id, next)?;
                    next += 1;
                }
                *arg_count != u16::MAX
                    && candidate == destination
                    && destination.0 >= base.0
                    && destination.0 <= base.0.saturating_add(*arg_count)
                    && matches!(
                        instructions.get(next).map(|entry| &entry.instruction),
                        Some(
                            Instruction::Call {
                                arg_count: u16::MAX,
                                ..
                            } | Instruction::TailCall {
                                arg_count: u16::MAX,
                                ..
                            }
                        )
                    )
            } else {
                false
            };
            let dynamic_consumer = pc > 0
                && candidate == destination
                && matches!(instruction,
                    Instruction::Call { base, arg_count: u16::MAX, .. }
                        | Instruction::TailCall { base, arg_count: u16::MAX, .. }
                        if matches!(instructions[pc - 1].instruction,
                            Instruction::Call { base: producer_base, result_mode: ResultMode::All, .. }
                                if destination.0 >= base.0 && destination.0 < producer_base.0));
            if fixed_consumer || open_consumer || dynamic_consumer {
                consumer = Some(pc);
            }
            break;
        }
    }
    let Some(consumer) = consumer else {
        return Ok(None);
    };
    let future_local = if candidate == destination {
        false
    } else {
        let copy_pc = consumer + 1;
        let Some(copy) = instructions.get(copy_pc) else {
            return Ok(None);
        };
        if !matches!(instructions[consumer].instruction,
            Instruction::Call { base, result_mode: ResultMode::Fixed(count), .. }
                if base == destination && count > 0)
            || !matches!(copy.instruction,
                Instruction::Move { dest, src } if dest == candidate && src == destination)
            || !locals.iter().any(|local| {
                local.register == candidate
                    && local.initialized_pc as usize == copy_pc
                    && local.end_pc as usize > copy_pc
            })
        {
            return Ok(None);
        }
        for pc in relay..=consumer {
            work_charge(work, 1, id, pc)?;
            let (read, write, possible_write, close) = access(pc, candidate);
            if read || write || possible_write || close {
                return Ok(None);
            }
        }
        true
    };
    for pc in definition..consumer {
        work_charge(work, 1, id, pc)?;
        if matches!(
            instructions[pc].instruction,
            Instruction::Jump { .. }
                | Instruction::JumpIfFalse { .. }
                | Instruction::NumericForPrepare { .. }
                | Instruction::NumericForNext { .. }
                | Instruction::Return { .. }
                | Instruction::TailCall { .. }
        ) {
            return Ok(None);
        }
    }
    for (pc, entry) in instructions.iter().enumerate() {
        work_charge(work, 1, id, pc)?;
        let targets = match &entry.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                [Some(target.0 as usize), None]
            }
            Instruction::NumericForPrepare { exit, .. } => [Some(exit.0 as usize), None],
            Instruction::NumericForNext { target, exit, .. } => {
                [Some(target.0 as usize), Some(exit.0 as usize)]
            }
            _ => [None, None],
        };
        if targets
            .into_iter()
            .flatten()
            .any(|target| definition <= target && target <= consumer)
        {
            return Ok(None);
        }
    }
    let mut cleared = false;
    for pc in consumer + 1..instructions.len() {
        work_charge(work, 1, id, pc)?;
        let instruction = &instructions[pc].instruction;
        let (source_read, source_write, source_possible, source_close) = access(pc, source);
        let (dest_read, dest_write, dest_possible, dest_close) = access(pc, destination);
        if source_read || source_possible || source_close || dest_possible || dest_close {
            return Ok(None);
        }
        if cleared {
            if dest_read
                || ((source_write || dest_write)
                    && !matches!(instruction, Instruction::LoadNil { .. }))
            {
                return Ok(None);
            }
        } else if source_write || dest_write {
            if !matches!(instruction, Instruction::LoadNil { .. })
                || (source_write && !dest_write)
                || dest_read
            {
                return Ok(None);
            }
            cleared = true;
        }
    }
    Ok((candidate == destination || future_local).then_some((relay, consumer)))
}

fn pending_open_result_local_alias(
    instructions: &[BytecodeInstruction],
    register_count: u16,
    id: ProtoId,
    call_pc: usize,
    source: Register,
    candidate: Register,
    locals: &[NativeLocal],
    work: &mut OfficialWorkBudget,
) -> Result<Option<usize>, OfficialExportError> {
    let access = |pc: usize, register| {
        register_access(&instructions[pc].instruction, register, register_count)
    };
    let mut terminal = None;
    for pc in call_pc + 1..instructions.len() {
        work_charge(work, 1, id, pc)?;
        if let Instruction::Call {
            base,
            arg_count: u16::MAX,
            result_mode: ResultMode::Fixed(count),
        } = instructions[pc].instruction
        {
            if count > 0
                && source.0 >= base.0
                && source.0 - base.0 < count
                && pc > 0
                && matches!(
                    instructions[pc - 1].instruction,
                    Instruction::Call {
                        result_mode: ResultMode::All,
                        ..
                    }
                )
            {
                terminal = Some((pc, base, count));
                break;
            }
        }
        let (_, write, possible_write, close) = access(pc, source);
        let (candidate_read, candidate_write, candidate_possible, candidate_close) =
            access(pc, candidate);
        if write
            || possible_write
            || close
            || candidate_read
            || candidate_write
            || candidate_possible
            || candidate_close
        {
            return Ok(None);
        }
    }
    let Some((terminal_pc, base, count)) = terminal else {
        return Ok(None);
    };
    let copy_start = terminal_pc + 1;
    let Some(copy_end) = copy_start.checked_add(usize::from(count)) else {
        return Ok(None);
    };
    if copy_end > instructions.len() {
        return Ok(None);
    }
    let source_index = usize::from(source.0 - base.0);
    let mut first_slot = None;
    for index in 0..usize::from(count) {
        let pc = copy_start + index;
        work_charge(work, 1, id, pc)?;
        let Some(expected_source) = base.0.checked_add(index as u16) else {
            return Ok(None);
        };
        let Instruction::Move { dest, src } = instructions[pc].instruction else {
            return Ok(None);
        };
        if src.0 != expected_source || (index == source_index && dest != candidate) {
            return Ok(None);
        }
        let Some(local) = locals.iter().find(|local| local.register == dest) else {
            return Ok(None);
        };
        work_charge(work, locals.len(), id, pc)?;
        if local.initialized_pc as usize != pc
            || (local.start_pc as usize) < pc
            || (local.end_pc as usize) <= pc
        {
            return Ok(None);
        }
        let first = *first_slot.get_or_insert(local.slot);
        if usize::from(local.slot) != usize::from(first) + index {
            return Ok(None);
        }
    }
    work_charge(work, instructions.len(), id, terminal_pc)?;
    for (pc, entry) in instructions.iter().enumerate() {
        let targets = match &entry.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                [Some(target.0 as usize), None]
            }
            Instruction::NumericForPrepare { exit, .. } => [Some(exit.0 as usize), None],
            Instruction::NumericForNext { target, exit, .. } => {
                [Some(target.0 as usize), Some(exit.0 as usize)]
            }
            _ => [None, None],
        };
        if targets
            .into_iter()
            .flatten()
            .any(|target| call_pc <= target && target < copy_end)
        {
            return Ok(None);
        }
        if pc < copy_end {
            continue;
        }
        let (read, write, possible_write, close) = access(pc, source);
        let (_, candidate_write, candidate_possible, candidate_close) = access(pc, candidate);
        if read || possible_write || close {
            return Ok(None);
        }
        if write
            && (!matches!(entry.instruction, Instruction::LoadNil { .. })
                || candidate_write
                || candidate_possible
                || candidate_close)
        {
            return Ok(None);
        }
    }
    Ok(Some(copy_end))
}

/// open Call 的動態結果可覆蓋已死亡的固定值；證明只接受到下一次定義或
/// 函式退出前無讀取、無分支的區間。
#[cfg(test)]
fn dead_after_open_call(
    proto: &BytecodePrototype,
    call_pc: usize,
    register: Register,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    dead_after_open_call_with_pending(proto, call_pc, register, false, work)
}

fn dead_after_open_call_with_pending(
    proto: &BytecodePrototype,
    call_pc: usize,
    register: Register,
    gathered_pending: bool,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let producer_base = match proto.instructions[call_pc].instruction {
        Instruction::Call {
            base,
            result_mode: ResultMode::All,
            ..
        } => base,
        _ => return Ok(false),
    };
    let Some(terminal) = strict_open_call_terminal(proto, call_pc, work)? else {
        return Ok(false);
    };
    let mut end = proto.instructions.len();
    for pc in call_pc + 1..proto.instructions.len() {
        work_charge(work, 1, proto.id, pc)?;
        let instruction = &proto.instructions[pc].instruction;
        // 相鄰 terminal 從 Call 前綴讀取已 gather 的 pending；舊 home
        // 即使被 producer 的開放結果覆寫，也不影響這次讀取。
        if gathered_pending
            && pc == terminal
            && terminal == call_pc + 1
            && register.0 < producer_base.0
            && matches!(instruction, Instruction::Call {
                base, arg_count: u16::MAX, result_mode: ResultMode::Fixed(0),
            } if *base == register)
        {
            continue;
        }
        if pc <= terminal && register.0 >= producer_base.0 {
            match instruction {
                Instruction::Call {
                    base,
                    arg_count: u16::MAX,
                    result_mode: ResultMode::Fixed(results),
                } if register.0 >= base.0 && register.0 - base.0 < *results => {
                    // terminal 已消耗開放引數並覆寫此槽；後續讀取屬於新結果。
                    end = pc;
                    break;
                }
                Instruction::Call {
                    arg_count: u16::MAX,
                    ..
                } => continue,
                Instruction::TailCall {
                    arg_count: u16::MAX,
                    ..
                } => {
                    end = pc;
                    break;
                }
                _ => {}
            }
        }
        let (read, write, possible_write, close) =
            register_access(instruction, register, proto.register_count);
        if read || possible_write || close {
            return Ok(false);
        }
        if matches!(
            instruction,
            Instruction::Jump { .. }
                | Instruction::JumpIfFalse { .. }
                | Instruction::NumericForPrepare { .. }
                | Instruction::NumericForNext { .. }
        ) {
            return Ok(false);
        }
        if write
            || matches!(
                instruction,
                Instruction::Return { .. } | Instruction::TailCall { .. }
            )
        {
            end = pc;
            break;
        }
    }
    work_charge(work, proto.instructions.len(), proto.id, call_pc)?;
    for entry in &proto.instructions {
        let targets = match &entry.instruction {
            Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. } => {
                [Some(target.0 as usize), None]
            }
            Instruction::NumericForPrepare { exit, .. } => [Some(exit.0 as usize), None],
            Instruction::NumericForNext { target, exit, .. } => {
                [Some(target.0 as usize), Some(exit.0 as usize)]
            }
            _ => [None, None],
        };
        if targets
            .into_iter()
            .flatten()
            .any(|target| call_pc < target && target <= end)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn dead_after_gathered_pending_open_call(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    call: &TemporaryCallLayout,
    register: usize,
    work: &mut OfficialWorkBudget,
) -> Result<bool, OfficialExportError> {
    let pending = module
        .native_debug()
        .and_then(|debug| debug.temporaries_at(proto.id, InstructionOffset(call.pc as u32)))
        .unwrap_or(&[]);
    work_charge(work, pending.len(), proto.id, call.pc)?;
    let prefix = pending
        .iter()
        .find(|temporary| usize::from(temporary.register.0) == register)
        .and_then(|temporary| temporary.ordinal.checked_sub(1))
        .and_then(|ordinal| call.first_slot.checked_add(ordinal));
    let gathered_pending = if let Some(prefix) = prefix {
        pending_call_prefix_home(module, proto, call, register, prefix, work)?
    } else {
        false
    };
    dead_after_open_call_with_pending(
        proto,
        call.pc,
        Register(register as u16),
        gathered_pending,
        work,
    )
}

/// 由 P05 local storage 與 guest register 存取區間配置實體槽；每個暫存槽
/// 在保守的 first..last 區間內獨占，因此回邊也不會覆蓋仍可讀的值。
fn compact_map_base_bytes(
    proto: &BytecodePrototype,
    storage_count: usize,
    call_count: usize,
    temporary_count: usize,
    cleanup_count: usize,
    numeric_count: usize,
) -> Result<usize, OfficialExportError> {
    let registers = usize::from(proto.register_count);
    let instructions = proto.instructions.len();
    let register_bytes = registers
        .checked_mul(
            size_of::<u8>() * 2
                + size_of::<(usize, usize)>()
                + size_of::<(usize, usize, usize)>()
                + size_of::<(u8, usize, usize)>()
                + size_of::<LiveRow>()
                // owner_next 以至多兩倍的實際容量保守計費。
                + size_of::<usize>() * 2,
        )
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<usize>>()))
        .and_then(|bytes| bytes.checked_add(255 * size_of::<usize>()))
        .and_then(|bytes| {
            storage_count
                .checked_mul(size_of::<(u8, usize, usize)>())
                .and_then(|extra| bytes.checked_add(extra))
        });
    let instruction_bytes = instructions
        .checked_mul(size_of::<usize>() * 6 + 4 + size_of::<u16>())
        .and_then(|bytes| bytes.checked_add(size_of::<usize>()))
        .and_then(|bytes| bytes.checked_add(size_of::<Vec<(usize, [u8; 32])>>()));
    register_bytes
        .and_then(|bytes| instruction_bytes.and_then(|extra| bytes.checked_add(extra)))
        .and_then(|bytes| {
            call_count
                .checked_mul(size_of::<TemporaryCallLayout>() + size_of::<(usize, bool)>())
                .and_then(|extra| bytes.checked_add(extra))
        })
        .and_then(|bytes| {
            cleanup_count
                .checked_mul(size_of::<(usize, [u8; 32])>())
                .and_then(|extra| bytes.checked_add(extra))
        })
        .and_then(|bytes| {
            temporary_count
                .checked_mul(size_of::<(u8, usize, usize)>() * 2 + size_of::<PendingRelayPair>())
                .and_then(|extra| bytes.checked_add(extra))
        })
        .and_then(|bytes| {
            // 稀疏 Next 索引常駐；proof 的 visited/worklist 取兩倍
            // try_reserve_exact 實際容量上界，一次性納入 peak。
            numeric_count
                .checked_mul(2)
                .and_then(|n| n.checked_mul(size_of::<NumericOwnedNext>()))
                .and_then(|extra| bytes.checked_add(extra))
        })
        .and_then(|bytes| {
            if numeric_count == 0 {
                Some(bytes)
            } else {
                instructions
                    .checked_mul(2)
                    .and_then(|n| n.checked_mul(size_of::<u32>() + 1))
                    .and_then(|extra| bytes.checked_add(extra))
            }
        })
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native mapping peak 大小溢位",
            )
        })
}

fn numeric_local_aliases(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    numeric: &[NumericPair],
    anonymous_vararg_slot: Option<u8>,
    profile: LuaProfile,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<NumericAlias>, OfficialExportError> {
    let mut aliases = Vec::new();
    aliases.try_reserve_exact(numeric.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "numeric local alias 配置失敗",
        )
    })?;
    let Some(debug) = module.native_debug() else {
        return Ok(aliases);
    };
    let Some(locals) = debug
        .prototype(proto.id)
        .map(|entry| entry.locals.as_slice())
    else {
        return Ok(aliases);
    };
    let Some(storage) = debug.storage_for(proto.id) else {
        return Ok(aliases);
    };
    let width = if profile == LuaProfile::Lua54 { 3 } else { 2 };
    for pair in numeric {
        let body_offset = InstructionOffset(u32::try_from(pair.body_pc).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pair.body_pc,
                "numeric local alias PC 超出範圍",
            )
        })?);
        let child_work = module
            .module()
            .prototypes
            .iter()
            .try_fold(0usize, |total, child| {
                total
                    .checked_add(child.upvalues.len())
                    .and_then(|total| total.checked_add(proto.instructions.len()))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pair.prepare_pc,
                            "numeric local alias child 工作量溢位",
                        )
                    })
            })?;
        work_charge(
            work,
            proto
                .instructions
                .len()
                .checked_mul(3)
                .and_then(|units| units.checked_add(locals.len()))
                .and_then(|units| units.checked_add(storage.len()))
                .and_then(|units| units.checked_add(numeric.len()))
                .and_then(|units| units.checked_add(child_work))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pair.prepare_pc,
                        "numeric local alias 工作量溢位",
                    )
                })?,
            proto.id,
            pair.prepare_pc,
        )?;
        let Some(local) = locals.iter().find(|local| {
            local.register == pair.visible
                && local.start_pc as usize <= pair.body_pc
                && local.end_pc as usize > pair.next_pc
        }) else {
            continue;
        };
        let Some(Instruction::LoadNil {
            start: anchor,
            count: 1,
        }) = proto
            .instructions
            .get(pair.body_pc)
            .map(|entry| &entry.instruction)
        else {
            continue;
        };
        let anchor = *anchor;
        // body 前的讀取不會觀察到被省略的 nil 寫入，除非後續控制流程回跳到 prepare 前。
        let reenters_before_prepare = proto.instructions[pair.prepare_pc..].iter().any(|entry| {
            let targets = match entry.instruction {
                Instruction::Jump { target }
                | Instruction::JumpIfFalse { target, .. }
                | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            targets
                .into_iter()
                .flatten()
                .any(|target| (target.0 as usize) < pair.prepare_pc)
        });
        let mut later_read = false;
        if proto.instructions[pair.body_pc].close_path.is_some()
            || !debug.is_non_counted_pc(proto.id, body_offset)
            || proto
                .binding_registers
                .iter()
                .any(|(_, register)| *register == anchor)
            || proto.instructions.iter().enumerate().any(|(pc, entry)| {
                pc != pair.body_pc && {
                    let (read, write, maybe_write, close) =
                        register_access(&entry.instruction, anchor, proto.register_count);
                    if pc > pair.next_pc && read {
                        later_read = true;
                    }
                    numeric_alias_anchor_observed(
                        pc,
                        pair.prepare_pc,
                        pair.next_pc,
                        read,
                        close,
                        reenters_before_prepare,
                    ) || ((write || maybe_write) && pair.prepare_pc <= pc && pc <= pair.next_pc)
                }
            })
            || numeric.iter().any(|other| {
                other.prepare_pc != pair.prepare_pc
                    && other.prepare_pc <= pair.next_pc
                    && pair.prepare_pc <= other.next_pc
            })
            || proto.instructions[pair.prepare_pc..=pair.next_pc]
                .iter()
                .any(|entry| {
                    matches!(
                        entry.instruction,
                        Instruction::Call { .. }
                            | Instruction::TailCall { .. }
                            | Instruction::Vararg { .. }
                    )
                })
        {
            continue;
        }
        if later_read && !numeric_alias_later_reads_defined(proto, pair.body_pc, anchor, work)? {
            continue;
        }
        let tuple =
            official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, pair.prepare_pc)?;
        let Some(last_slot) = tuple.checked_add(width).filter(|slot| *slot < 255) else {
            continue;
        };
        if storage.iter().any(|other| {
            other.register != pair.visible
                && other.start_pc as usize <= pair.next_pc
                && other.end_pc as usize > pair.prepare_pc
                && official_storage_slot(
                    other.slot,
                    anonymous_vararg_slot,
                    proto.id,
                    pair.prepare_pc,
                )
                .is_ok_and(|slot| tuple <= slot && slot <= last_slot)
        }) {
            continue;
        }
        // 同一 child prototype 的捕獲來源槽固定；跨 alias scope 建立時沿用舊佈局。
        if module.module().prototypes.iter().any(|child| {
            child.parent == Some(proto.id)
                && child.upvalues.iter().any(|upvalue| {
                    matches!(&upvalue.source, BytecodeUpvalueSource::ParentLocal(binding) if *binding == local.binding)
                })
                && proto.instructions.iter().enumerate().any(|(pc, entry)| {
                    matches!(entry.instruction, Instruction::Closure { proto: id, .. } if id == child.id)
                        && !(pair.body_pc <= pc && pc <= pair.next_pc)
                })
        }) {
            continue;
        }
        let share_nil_slot = numeric_alias_shared_home_eligible(
            proto,
            anchor,
            &module.module().prototypes,
            locals,
            storage,
            debug.temporaries_for(proto.id).unwrap_or(&[]),
            debug.initializer_temporaries_for(proto.id).unwrap_or(&[]),
            work,
        )?;
        aliases.push(NumericAlias {
            visible: pair.visible,
            prepare_pc: pair.prepare_pc,
            body_pc: pair.body_pc,
            next_pc: pair.next_pc,
            tuple,
            width,
            anchor,
            share_nil_slot,
            preserve_mapped_home: later_read,
        });
    }
    Ok(aliases)
}

fn compact_register_map(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    numeric: &[NumericPair],
    numeric_blocks: u16,
    anonymous_vararg_slot: Option<u8>,
    profile: LuaProfile,
    env_upvalue: Option<u16>,
    bitmap_limit: usize,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<
    (
        Vec<u8>,
        Vec<u8>,
        Vec<(usize, usize)>,
        Vec<LiveRow>,
        u16,
        Vec<u16>,
        Vec<u16>,
        Vec<(usize, [u8; 32])>,
        u8,
        Vec<NumericAlias>,
    ),
    OfficialExportError,
> {
    let debug = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id));
    let storage = module
        .native_debug()
        .and_then(|debug| debug.storage_for(proto.id))
        .unwrap_or(&[]);
    let aliases =
        numeric_local_aliases(module, proto, numeric, anonymous_vararg_slot, profile, work)?;
    let fixed_count = storage.len() + usize::from(anonymous_vararg_slot.is_some());
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    let call_count = if debug.is_some() {
        proto
            .instructions
            .iter()
            .filter(|entry| {
                matches!(entry.instruction, Instruction::Call { .. })
                    || matches!(
                        entry.instruction,
                        Instruction::TailCall {
                            arg_count: u16::MAX,
                            ..
                        }
                    )
            })
            .count()
    } else {
        0
    };
    let temporary_count = module
        .native_debug()
        .and_then(|debug| debug.temporaries_for(proto.id))
        .map_or(0, <[_]>::len);
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    // 每個 cleanup 都是 Fixed(0) Call 緊後唯一的 LoadNil；PC 依掃描順序遞增。
    let cleanup_count = (0..proto.instructions.len())
        .filter(|&pc| call_cleanup_range(proto, pc).is_some())
        .count();
    if compact_map_base_bytes(
        proto,
        fixed_count,
        call_count,
        temporary_count,
        cleanup_count,
        numeric.len(),
    )? > limits.max_allocated_bytes
    {
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
        let official_slot = official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, 0)?;
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
        if *slot != u8::MAX && *slot != official_slot {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                0,
                "native local register 對應衝突",
            ));
        }
        *slot = official_slot;
    }
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
        if let Some((_, register)) = proto.named_vararg {
            let slot = mapped.get_mut(usize::from(register.0)).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    0,
                    "native named vararg register 不存在",
                )
            })?;
            *slot = u8::try_from(proto.parameter_count).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native named vararg slot 超限",
                )
            })?;
        }
    }
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
    let owned_next = numeric_owned_next_pairs(module, proto, numeric, &mapped, work)?;
    let live_at = extend_live_spans(proto, &mapped, &mut span, &owned_next, bitmap_limit, work)?;
    let mut fixed = u16::from(debug.map_or(0, |entry| entry.max_active_locals));
    if debug.is_none() {
        fixed = proto
            .parameter_count
            .checked_add(u16::from(proto.named_vararg.is_some()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "native named vararg fixed slot 溢位",
                )
            })?;
    }
    if anonymous_vararg_slot.is_some() {
        fixed = fixed.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "匿名 vararg fixed slot 溢位",
            )
        })?;
    }
    // 未別名化的數值控制值先於 Call 窗口；C callee 可在參數後推入值。
    let low_tuple_base =
        (debug.is_some() && !numeric.is_empty() && aliases.is_empty()).then_some(fixed);
    let call_layouts = temporary_call_layouts(
        module,
        proto,
        anonymous_vararg_slot,
        numeric,
        low_tuple_base,
        &mapped,
        &span,
        &protected,
        &live_at,
        work,
    )?;
    let profile_stack_limit = if matches!(profile, LuaProfile::Lua54) {
        254
    } else {
        255
    };
    fixed = fixed.max(
        call_layouts
            .iter()
            .map(|layout| layout.window_end)
            .max()
            .unwrap_or(0),
    );
    if !aliases.is_empty() {
        fixed = fixed
            .checked_add(numeric_blocks.checked_mul(3).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "numeric local 控制槽溢位",
                )
            })?)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "numeric local 佈局溢位",
                )
            })?;
    }
    if let Some(env) = mapped.get_mut(usize::from(proto.frame.environment.0)) {
        // 上限槽仍需留給實際值；邊界上的 environment cache 交由 interval allocator 安置。
        if *env == u8::MAX && fixed < profile_stack_limit {
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
        } else if *env == u8::MAX && fixed > profile_stack_limit {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native environment slot 超限",
            ));
        }
    }
    let tuple_base = low_tuple_base.unwrap_or(fixed);
    let (shared_nil_slot, alias_slots) = numeric_alias_nil_slots(&aliases, proto.id, work)?;
    let tuple_end = tuple_base
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
                "native numeric tuple 溢位",
            )
        })?;
    let temp_base = fixed
        .max(tuple_end)
        .checked_add(u16::try_from(alias_slots).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native temp base 溢位",
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
    let mut relay_reservations = Vec::new();
    relay_reservations
        .try_reserve_exact(temporary_count)
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native relay 保留區配置失敗",
            )
        })?;
    let mut relay_pairs: Vec<PendingRelayPair> = Vec::new();
    relay_pairs
        .try_reserve_exact(temporary_count)
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native relay 配對配置失敗",
            )
        })?;
    if let Some(debug) = module.native_debug() {
        // pending 的 home 由後續區間配置器決定；固定 local 仍沿用其槽。
        let all_temporaries = debug.temporaries_for(proto.id).unwrap_or(&[]);
        work_charge(work, all_temporaries.len(), proto.id, 0)?;
        for temporary in all_temporaries {
            let register = usize::from(temporary.register.0);
            let slot = mapped[register];
            if slot == u8::MAX {
                continue;
            }
            work_charge(work, mapped.len(), proto.id, temporary.call_pc.0 as usize)?;
            let original_end = span[register].1;
            let mut relay_end = None;
            let mut relay_pair = None;
            for (other, &other_slot) in mapped.iter().enumerate() {
                if other != register
                    && slot == other_slot
                    && span[register].0 < span[other].1
                    && span[other].0 < original_end
                {
                    let mut reverse_pair = false;
                    let mut terminal = None;
                    for &pair in &relay_pairs {
                        work_charge(work, 1, proto.id, temporary.call_pc.0 as usize)?;
                        if pair.source != Register(other as u16)
                            || pair.destination != temporary.register
                            || pair.slot != slot
                        {
                            continue;
                        }
                        if terminal.is_none() {
                            terminal = strict_open_call_terminal(
                                proto,
                                temporary.call_pc.0 as usize,
                                work,
                            )?;
                            if let Some(end) = terminal {
                                let plan_calls = module
                                    .official_execution()
                                    .map_or(&[][..], |plan| plan.calls());
                                work_charge(
                                    work,
                                    plan_calls.len(),
                                    proto.id,
                                    temporary.call_pc.0 as usize,
                                )?;
                                if plan_calls.iter().any(|call| {
                                    call.prototype == proto.id && call.call_pc.0 as usize == end
                                }) {
                                    terminal = None;
                                }
                            }
                        }
                        if pending_relay_reverse_revisit(
                            pair,
                            Register(other as u16),
                            temporary.register,
                            slot,
                            temporary.call_pc.0 as usize,
                            terminal,
                            span[other],
                            span[register],
                            &relay_reservations,
                        ) {
                            reverse_pair = true;
                            break;
                        }
                    }
                    if reverse_pair {
                        continue;
                    }
                    let proof_end = if let Some((relay, consumer)) = pending_move_relay_alias(
                        &proto.instructions,
                        proto.register_count,
                        proto.id,
                        temporary.call_pc.0 as usize,
                        temporary.register,
                        Register(other as u16),
                        &debug
                            .prototype(proto.id)
                            .map_or(&[][..], |entry| &entry.locals),
                        work,
                    )? {
                        if let Instruction::Move { dest, .. } =
                            proto.instructions[relay].instruction
                        {
                            if dest == Register(other as u16) {
                                let pair = PendingRelayPair {
                                    source: temporary.register,
                                    destination: dest,
                                    move_pc: relay,
                                    consumer_pc: consumer,
                                    slot,
                                };
                                if relay_pair.is_some_and(|prior: PendingRelayPair| {
                                    prior.source != pair.source
                                        || prior.destination != pair.destination
                                        || prior.move_pc != pair.move_pc
                                        || prior.consumer_pc != pair.consumer_pc
                                        || prior.slot != pair.slot
                                }) {
                                    return Err(error(
                                        OfficialExportErrorKind::Unsupported,
                                        proto.id,
                                        temporary.call_pc.0 as usize,
                                        "native temporary relay 配對衝突",
                                    ));
                                }
                                relay_pair = Some(pair);
                            }
                        }
                        Some(relay + 1)
                    } else {
                        pending_open_result_local_alias(
                            &proto.instructions,
                            proto.register_count,
                            proto.id,
                            temporary.call_pc.0 as usize,
                            temporary.register,
                            Register(other as u16),
                            &debug
                                .prototype(proto.id)
                                .map_or(&[][..], |entry| &entry.locals),
                            work,
                        )?
                    };
                    if let Some(end) = proof_end {
                        if relay_end.is_some_and(|prior| prior != end) {
                            return Err(error(
                                OfficialExportErrorKind::Unsupported,
                                proto.id,
                                temporary.call_pc.0 as usize,
                                "native temporary relay 次序衝突",
                            ));
                        }
                        relay_end = Some(end);
                    } else {
                        return Err(error(
                            OfficialExportErrorKind::Unsupported,
                            proto.id,
                            temporary.call_pc.0 as usize,
                            "native temporary 與固定 register 生命週期衝突",
                        ));
                    }
                }
            }
            if let Some(end) = relay_end {
                span[register].1 = end;
                relay_reservations.push((slot, end, original_end));
                if let Some(pair) = relay_pair {
                    relay_pairs.push(pair);
                }
            }
        }
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
        .try_reserve_exact(
            count
                .checked_add(fixed_count)
                .and_then(|count| count.checked_add(relay_reservations.len()))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        0,
                        "native fixed interval 數溢位",
                    )
                })?,
        )
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
        mapped.len().checked_add(fixed_count).ok_or_else(|| {
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
        let slot = official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, 0)?;
        fixed_intervals.push((slot, local.start_pc as usize, local.end_pc as usize));
    }
    fixed_intervals.extend_from_slice(&relay_reservations);
    if let Some(slot) = anonymous_vararg_slot {
        fixed_intervals.push((slot, 0, proto.instructions.len()));
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
    let environment = usize::from(proto.frame.environment.0);
    let env_cache_eligible = if env_upvalue.is_some()
        && proto.frame.environment == proto.global_environment
        && protected.get(environment) == Some(&0)
        && span
            .get(environment)
            .is_some_and(|entry| entry.0 != usize::MAX)
    {
        work_charge(
            work,
            storage
                .len()
                .checked_add(module.module().prototypes.len())
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        0,
                        "environment cache alias work 溢位",
                    )
                })?,
            proto.id,
            0,
        )?;
        !storage
            .iter()
            .any(|local| usize::from(local.register.0) == environment)
            && !module
                .module()
                .prototypes
                .iter()
                .any(|child| child.parent == Some(proto.id))
    } else {
        false
    };
    let fixed_env_interval = if env_cache_eligible && mapped[environment] != u8::MAX {
        work_charge(work, fixed_intervals.len(), proto.id, 0)?;
        let interval = (
            mapped[environment],
            span[environment].0,
            span[environment].1,
        );
        (fixed_intervals
            .iter()
            .filter(|&&entry| entry == interval)
            .count()
            == 1)
            .then_some(interval)
    } else {
        None
    };
    let mut dead_open_cache = Vec::new();
    work_charge(work, call_layouts.len(), proto.id, 0)?;
    dead_open_cache
        .try_reserve_exact(call_layouts.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native open Call dead proof 配置失敗",
            )
        })?;
    dead_open_cache.resize(call_layouts.len(), (usize::MAX, false));
    let mut slot_end = [0usize; 255];
    let mut slot_head = [usize::MAX; 255];
    let mut owner_next = Vec::new();
    owner_next.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "native slot owner 配置失敗",
        )
    })?;
    let owner_capacity_limit = count.checked_mul(2).ok_or_else(|| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native slot owner 容量溢位",
        )
    })?;
    if owner_next.capacity() > owner_capacity_limit {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native slot owner 實際容量超過預檢上限",
        ));
    }
    owner_next.resize(count, usize::MAX);
    work_charge(
        work,
        count.checked_add(255).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native slot owner 初始化 work 溢位",
            )
        })?,
        proto.id,
        0,
    )?;
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
        let mut local_handoff = None;
        let mut conflicting_handoff = false;
        if let Some(debug) = module.native_debug() {
            let temporaries = debug.temporaries_for(proto.id).unwrap_or(&[]);
            let locals = &debug
                .prototype(proto.id)
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        start,
                        "native handoff 缺少 prototype debug",
                    )
                })?
                .locals;
            work_charge(work, locals.len(), proto.id, start)?;
            for local in locals {
                let copy_pc = local.initialized_pc as usize;
                if copy_pc < start
                    || copy_pc >= end
                    || !matches!(proto.instructions.get(copy_pc).map(|entry| &entry.instruction),
                        Some(Instruction::Move { dest, src })
                            if *dest == local.register && usize::from(src.0) == register)
                {
                    continue;
                }
                work_charge(work, temporaries.len(), proto.id, copy_pc)?;
                for temporary in temporaries {
                    if usize::from(temporary.register.0) != register
                        || temporary.call_pc.0 as usize >= copy_pc
                    {
                        continue;
                    }
                    if let Some(copy_end) = pending_open_result_local_alias(
                        &proto.instructions,
                        proto.register_count,
                        proto.id,
                        temporary.call_pc.0 as usize,
                        temporary.register,
                        local.register,
                        locals,
                        work,
                    )? {
                        let home = official_storage_slot(
                            local.slot,
                            anonymous_vararg_slot,
                            proto.id,
                            copy_pc,
                        )?;
                        let proof = (home, copy_pc, copy_end);
                        if local_handoff.is_some_and(|prior| prior != proof) {
                            conflicting_handoff = true;
                        } else {
                            local_handoff = Some(proof);
                        }
                    }
                }
            }
        }
        if conflicting_handoff {
            local_handoff = None;
        }
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
        let mut candidate_ok = |candidate_register: usize,
                                candidate_start: usize,
                                candidate_end: usize,
                                slot: u16,
                                check_prior: bool,
                                work: &mut OfficialWorkBudget|
         -> Result<bool, OfficialExportError> {
            work_charge(work, 1, proto.id, candidate_start)?;
            if slot >= fixed.max(tuple_end) && slot < temp_base {
                return Ok(false);
            }
            if slot >= tuple_base && slot < tuple_end {
                work_charge(work, numeric.len(), proto.id, candidate_start)?;
                if numeric.iter().any(|pair| {
                    let first = usize::from(tuple_base) + usize::from(pair.block) * 4;
                    first <= usize::from(slot)
                        && usize::from(slot) < first + 4
                        && candidate_start <= pair.next_pc
                        && pair.prepare_pc < candidate_end
                }) {
                    return Ok(false);
                }
            }
            work_charge(work, aliases.len(), proto.id, candidate_start)?;
            if aliases.iter().any(|alias| {
                candidate_start <= alias.next_pc
                    && alias.prepare_pc < candidate_end
                    && u16::from(alias.tuple) <= slot
                    && slot <= u16::from(alias.tuple) + u16::from(alias.width)
            }) {
                return Ok(false);
            }
            let (call_first, call_end) = call_layout_range(
                &call_layouts,
                candidate_start,
                candidate_end,
                proto.id,
                work,
            )?;
            work_charge(work, call_end - call_first, proto.id, candidate_start)?;
            let mut owns_open_prefix = false;
            for (offset, call) in call_layouts[call_first..call_end].iter().enumerate() {
                let call_index = call_first + offset;
                if !live_at_pc(&span, &protected, &live_at, candidate_register, call.pc) {
                    continue;
                }
                let survives =
                    live_at_pc(&span, &protected, &live_at, candidate_register, call.pc + 1);
                if !call.open_chain && slot >= call.call_base && survives {
                    let result_written = matches!(proto.instructions[call.pc].instruction,
                        Instruction::Call { base, result_mode: ResultMode::Fixed(results), .. }
                            if candidate_register >= usize::from(base.0)
                                && candidate_register - usize::from(base.0) < usize::from(results));
                    let call_pc = InstructionOffset(u32::try_from(call.pc).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            call.pc,
                            "固定 Call pending PC 超出範圍",
                        )
                    })?);
                    let pending = module
                        .native_debug()
                        .and_then(|debug| debug.temporaries_at(proto.id, call_pc))
                        .unwrap_or(&[]);
                    work_charge(work, pending.len(), proto.id, call.pc)?;
                    if !result_written
                        && !pending
                            .iter()
                            .any(|entry| usize::from(entry.register.0) == candidate_register)
                    {
                        return Ok(false);
                    }
                }
                let open_all_base = if call.open_chain {
                    match proto.instructions[call.pc].instruction {
                        Instruction::Call {
                            base,
                            result_mode: ResultMode::All,
                            ..
                        } => Some(base),
                        _ => None,
                    }
                } else {
                    None
                };
                // 只對未固定、未受保護的 home 用 CFG 證明舊值在 All
                // 之後必先被改寫；同一 register/Call 跨候選槽僅證明一次。
                let dead_open = if open_all_base.is_some()
                    && slot >= call.call_base
                    && survives
                    && protected[candidate_register] == 0
                {
                    let cached = &mut dead_open_cache[call_index];
                    if cached.0 != candidate_register {
                        *cached = (
                            candidate_register,
                            dead_after_gathered_pending_open_call(
                                module,
                                proto,
                                call,
                                candidate_register,
                                work,
                            )?,
                        );
                    }
                    cached.1
                } else {
                    false
                };
                // All 結果可覆寫窗口末端以上的槽。受保護或仍存活的 home
                // 必須在 call base 以下；callee/result 本身由 Call 寫入。
                if open_all_base.is_some_and(|base| usize::from(base.0) != candidate_register)
                    && slot >= call.call_base
                    && (survives || protected[candidate_register] != 0)
                    && !dead_open
                {
                    return Ok(false);
                }
                if !call.open_chain && call.first_slot <= slot && slot < call.call_base {
                    let call_pc = InstructionOffset(u32::try_from(call.pc).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            call.pc,
                            "固定 Call pending PC 超出範圍",
                        )
                    })?);
                    let pending = module
                        .native_debug()
                        .and_then(|debug| debug.temporaries_at(proto.id, call_pc))
                        .unwrap_or(&[]);
                    work_charge(work, pending.len(), proto.id, call.pc)?;
                    let ordinal = slot - call.first_slot + 1;
                    let own = pending.iter().any(|temporary| {
                        usize::from(temporary.register.0) == candidate_register
                            && temporary.ordinal == ordinal
                    });
                    if !own && protected[candidate_register] != 0 {
                        return Ok(false);
                    }
                }
                if !(call.window_start <= slot && slot < call.window_end) {
                    continue;
                }
                // 相鄰 producer 的 pending callee 已在此槽；動態 consumer
                // 於同槽讀取後使舊值死亡，不能把它誤判為窗口占用衝突。
                if !survives
                    && call.open_chain
                    && slot == call.call_base
                    && call.window_start == call.call_base
                    && call_index > 0
                {
                    let producer = &call_layouts[call_index - 1];
                    if producer.pc + 1 == call.pc
                        && producer.open_chain
                        && strict_open_call_terminal(proto, producer.pc, work)? == Some(call.pc)
                        && pending_call_prefix_home(
                            module,
                            proto,
                            producer,
                            candidate_register,
                            slot,
                            work,
                        )?
                    {
                        continue;
                    }
                }
                if pending_call_prefix_home(module, proto, call, candidate_register, slot, work)? {
                    owns_open_prefix = true;
                    continue;
                }
                if let Instruction::TailCall {
                    base,
                    arg_count: u16::MAX,
                    result_mode: ResultMode::All,
                } = proto.instructions[call.pc].instruction
                {
                    // 動態尾呼叫仍在自己的 call base 讀取 callee；此槽在
                    // frame 交接後不再有存活值，不應當成一般 Call 結果窗排除。
                    if call.open_chain
                        && candidate_register == usize::from(base.0)
                        && slot == call.call_base
                        && !survives
                        && protected[candidate_register] == 0
                    {
                        continue;
                    }
                }
                let Instruction::Call {
                    base,
                    arg_count,
                    result_mode,
                } = proto.instructions[call.pc].instruction
                else {
                    return Ok(false);
                };
                let relative = candidate_register.checked_sub(usize::from(base.0));
                let is_result = match result_mode {
                    ResultMode::Fixed(results) => {
                        relative.is_some_and(|offset| offset < usize::from(results))
                    }
                    ResultMode::All => relative == Some(0),
                };
                let dying_input = (arg_count != u16::MAX
                    && relative.is_some_and(|offset| offset <= usize::from(arg_count))
                    || arg_count == u16::MAX
                        && matches!(result_mode, ResultMode::Fixed(0))
                        && relative == Some(0)
                        && slot == call.call_base)
                    && !survives
                    && protected[candidate_register] == 0;
                if !is_result && !dying_input && !(dead_open && slot >= call.call_base) {
                    return Ok(false);
                }
            }
            let env_alias = env_cache_eligible
                && candidate_register != environment
                && mapped[environment] != u8::MAX
                && u16::from(mapped[environment]) == slot
                && candidate_start > span[environment].0
                && owns_open_prefix
                && environment_cache_pending_alias_safe(
                    module,
                    proto,
                    candidate_start,
                    candidate_end,
                    &span,
                    &protected,
                    &live_at,
                    work,
                )?;
            if check_prior && slot_end[usize::from(slot)] > candidate_start {
                let mut owner = slot_head[usize::from(slot)];
                while owner != usize::MAX {
                    work_charge(work, 1, proto.id, candidate_start)?;
                    if owner != candidate_register
                        && !(env_alias && owner == environment)
                        && mapped_owner_interferes(
                            proto,
                            &span,
                            &protected,
                            &live_at,
                            &owned_next,
                            candidate_register,
                            owner,
                            work,
                        )?
                    {
                        return Ok(false);
                    }
                    owner = owner_next[owner];
                }
            }
            let fixed = &fixed_intervals
                [fixed_boundaries[usize::from(slot)]..fixed_boundaries[usize::from(slot) + 1]];
            work_charge(work, fixed.len(), proto.id, candidate_start)?;
            for &(_, fixed_start, fixed_end) in fixed {
                if fixed_start >= candidate_end || candidate_start >= fixed_end {
                    continue;
                }
                if env_alias && fixed_env_interval == Some((slot as u8, fixed_start, fixed_end)) {
                    continue;
                }
                if local_handoff.is_some_and(|(home, copy_pc, copy_end)| {
                    u16::from(home) == slot
                        && fixed_start == copy_pc
                        && fixed_end >= copy_end
                        && candidate_register == register
                }) {
                    continue;
                }
                if protected[candidate_register] != 0 {
                    return Ok(false);
                }
                let overlap_start = candidate_start.max(fixed_start);
                let overlap_end = candidate_end.min(fixed_end);
                let register_id = Register(candidate_register as u16);
                for pc in overlap_start..overlap_end {
                    // CFG 的 live-in 位元不含純寫入指令；寫入也不得覆蓋
                    // 此時佔用 fixed slot 的局部值或 relay。
                    work_charge(work, 8, proto.id, pc)?;
                    let (_, writes) =
                        numeric_native_access(proto, pc, register_id, &owned_next, work)?;
                    if writes
                        && !suppressed_ordinary_load_nil_write(
                            proto,
                            debug,
                            &mapped,
                            &aliases,
                            &span,
                            &protected,
                            &live_at,
                            candidate_register,
                            slot as u8,
                            pc,
                            work,
                        )?
                        || live_at_pc(&span, &protected, &live_at, candidate_register, pc)
                    {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        };
        let mut chosen = None;
        for slot in floor..255u16 {
            let ok = candidate_ok(register, start, end, slot, true, work)?;
            if ok {
                chosen = Some(slot);
                break;
            }
        }
        let mut relocation = None;
        let mut scan_work = 0usize;
        if chosen.is_none() && protected[register] == 0 {
            // 僅搬走與目前值實際干涉的 owner；舊鏈中的歷史死值仍可留原槽。
            for old_slot in floor..255u16 {
                scan_work += 1;
                let head = slot_head[usize::from(old_slot)];
                if head == usize::MAX || slot_end[usize::from(old_slot)] <= start {
                    continue;
                }
                let old_ok = candidate_ok(register, start, end, old_slot, false, work)?;
                if !old_ok {
                    continue;
                }
                let mut owner = head;
                let mut has_conflict = false;
                let mut protected_conflict = false;
                while owner != usize::MAX {
                    scan_work += 1;
                    if mapped_owner_interferes(
                        proto,
                        &span,
                        &protected,
                        &live_at,
                        &owned_next,
                        register,
                        owner,
                        work,
                    )? {
                        has_conflict = true;
                        if protected[owner] != 0 {
                            protected_conflict = true;
                            break;
                        }
                    }
                    owner = owner_next[owner];
                }
                if !has_conflict || protected_conflict {
                    continue;
                }
                for new_slot in 0..255u16 {
                    if new_slot == old_slot {
                        scan_work += 1;
                        continue;
                    }
                    let mut owner = head;
                    let mut fits = true;
                    while owner != usize::MAX {
                        scan_work += 1;
                        let conflicts = mapped_owner_interferes(
                            proto,
                            &span,
                            &protected,
                            &live_at,
                            &owned_next,
                            register,
                            owner,
                            work,
                        )?;
                        let owner_ok = if conflicts {
                            let (owner_start, owner_end) = span[owner];
                            owner != register
                                && protected[owner] == 0
                                && candidate_ok(
                                    owner,
                                    owner_start,
                                    owner_end,
                                    new_slot,
                                    true,
                                    work,
                                )?
                        } else {
                            true
                        };
                        if !owner_ok {
                            fits = false;
                            break;
                        }
                        owner = owner_next[owner];
                    }
                    if fits {
                        relocation = Some((old_slot, new_slot));
                        chosen = Some(old_slot);
                        break;
                    }
                }
                if relocation.is_some() {
                    break;
                }
            }
        }
        drop(candidate_ok);
        work_charge(work, scan_work, proto.id, start)?;
        if let Some((old_slot, new_slot)) = relocation {
            // 搬移集合經逐 owner 與新槽原鏈的活性、Call 窗與固定槽檢查。
            let mut owner = slot_head[usize::from(old_slot)];
            let mut kept_head = usize::MAX;
            let mut kept_tail = usize::MAX;
            let mut moved_head = usize::MAX;
            let mut moved_tail = usize::MAX;
            let mut kept_end = 0usize;
            let mut moved_end = 0usize;
            while owner != usize::MAX {
                work_charge(work, 1, proto.id, start)?;
                let next = owner_next[owner];
                let conflicts = mapped_owner_interferes(
                    proto,
                    &span,
                    &protected,
                    &live_at,
                    &owned_next,
                    register,
                    owner,
                    work,
                )?;
                owner_next[owner] = usize::MAX;
                if conflicts {
                    mapped[owner] = new_slot as u8;
                    moved_end = moved_end.max(span[owner].1);
                    if moved_head == usize::MAX {
                        moved_head = owner;
                    } else {
                        owner_next[moved_tail] = owner;
                    }
                    moved_tail = owner;
                } else {
                    kept_end = kept_end.max(span[owner].1);
                    if kept_head == usize::MAX {
                        kept_head = owner;
                    } else {
                        owner_next[kept_tail] = owner;
                    }
                    kept_tail = owner;
                }
                owner = next;
            }
            owner_next[moved_tail] = slot_head[usize::from(new_slot)];
            slot_head[usize::from(new_slot)] = moved_head;
            slot_end[usize::from(new_slot)] = slot_end[usize::from(new_slot)].max(moved_end);
            slot_head[usize::from(old_slot)] = kept_head;
            slot_end[usize::from(old_slot)] = kept_end;
            high = high.max(new_slot + 1);
        }
        let slot = chosen.ok_or_else(|| {
            #[cfg(feature = "std")]
            eprintln!(
                "native slot failure proto={} register={} start={} end={} protected={} floor={} fixed={} tuple_end={} temp_base={} high={} occupied={} fixed_intervals={} overlapping_calls={} max_call_window={}",
                proto.id.0,
                register,
                start,
                end,
                protected[register],
                floor,
                fixed,
                tuple_end,
                temp_base,
                high,
                slot_head.iter().filter(|&&head| head != usize::MAX).count(),
                fixed_intervals.len(),
                call_layouts.iter().filter(|call| start <= call.pc && call.pc < end).count(),
                call_layouts.iter().map(|call| call.window_end).max().unwrap_or(0),
            );
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                start,
                "native 同時活躍 register 超過官方 stack",
            )
        })?;
        slot_end[usize::from(slot)] = slot_end[usize::from(slot)].max(end);
        owner_next[register] = slot_head[usize::from(slot)];
        slot_head[usize::from(slot)] = register;
        if protected[register] != 0 {
            protected_slot_end[usize::from(slot)] = protected_slot_end[usize::from(slot)].max(end);
        }
        mapped[register] = slot as u8;
        high = high.max(slot + 1);
    }
    if let Some(debug) = module.native_debug() {
        for call in &call_layouts {
            let call_pc = InstructionOffset(u32::try_from(call.pc).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    call.pc,
                    "native temporary PC 超出範圍",
                )
            })?);
            let pending = debug.temporaries_at(proto.id, call_pc).unwrap_or(&[]);
            work_charge(work, pending.len(), proto.id, call.pc)?;
            if !call.open_chain && !pending.is_empty() {
                work_charge(
                    work,
                    mapped.len().checked_mul(pending.len() + 1).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            call.pc,
                            "固定 Call pending 驗證 work 溢位",
                        )
                    })?,
                    proto.id,
                    call.pc,
                )?;
                for (register, &home) in mapped.iter().enumerate() {
                    if home == u8::MAX
                        || u16::from(home) < call.first_slot
                        || u16::from(home) >= call.call_base
                        || span[register].0 > call.pc
                        || span[register].1 <= call.pc
                    {
                        continue;
                    }
                    let ordinal = u16::from(home) - call.first_slot + 1;
                    let own = pending.iter().any(|temporary| {
                        usize::from(temporary.register.0) == register
                            && temporary.ordinal == ordinal
                    });
                    if !own && protected[register] != 0 {
                        return Err(error(
                            OfficialExportErrorKind::Unsupported,
                            proto.id,
                            call.pc,
                            "固定 Call pending 前綴與受保護 home 衝突",
                        ));
                    }
                }
            }
            for temporary in pending {
                if mapped
                    .get(usize::from(temporary.register.0))
                    .copied()
                    .filter(|slot| *slot != u8::MAX)
                    .is_none()
                {
                    return Err(error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        call.pc,
                        "native temporary home 未配置",
                    ));
                }
            }
        }
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
        let selected_call = call_layouts.iter().find(|call| call.pc == pc);
        work_charge(work, call_layouts.len(), proto.id, pc)?;
        let end = if selected_call.is_some_and(|call| call.open_chain) {
            pc
        } else if matches!(
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
        let mut top = anonymous_vararg_slot.map_or(0, |slot| u16::from(slot) + 1);
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
                    let slot =
                        official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, at)?;
                    top = top.max(u16::from(slot) + 1);
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
        if let Some(call) = selected_call {
            if end != pc || width != call.window_width {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "native Call temporary window 與 open chain 衝突",
                ));
            }
            let (base, arg_count, result_mode, tail) = match proto.instructions[pc].instruction {
                Instruction::Call {
                    base,
                    arg_count,
                    result_mode,
                } => (base, arg_count, result_mode, false),
                Instruction::TailCall {
                    base,
                    arg_count,
                    result_mode,
                } if call.open_chain => (base, arg_count, result_mode, true),
                _ => {
                    return Err(error(
                        OfficialExportErrorKind::InvalidPrototype,
                        proto.id,
                        pc,
                        "native Call 佈局 PC 無 Call",
                    ));
                }
            };
            work_charge(work, mapped.len(), proto.id, pc)?;
            for (register, &slot) in mapped.iter().enumerate() {
                let result_written = !tail
                    && (matches!(result_mode, ResultMode::Fixed(results)
                    if register >= usize::from(base.0)
                        && register - usize::from(base.0) < usize::from(results))
                        || matches!(result_mode, ResultMode::All)
                            && register == usize::from(base.0));
                let destructive_start = if call.open_chain {
                    call.call_base
                } else {
                    call.window_start
                };
                let destructive_end = if call.open_chain && matches!(result_mode, ResultMode::All) {
                    255
                } else {
                    call.window_end
                };
                if slot != u8::MAX
                    && destructive_start <= u16::from(slot)
                    && u16::from(slot) < destructive_end
                    && live_at_pc(&span, &protected, &live_at, register, pc)
                    && (live_at_pc(&span, &protected, &live_at, register, pc + 1)
                        || protected[register] != 0)
                    && !result_written
                {
                    if call.open_chain
                        && matches!(result_mode, ResultMode::All)
                        && u16::from(slot) >= call.window_end
                        && environment_cache_chain_safe(
                            proto,
                            pc,
                            Register(register as u16),
                            env_upvalue.is_some(),
                            work,
                        )?
                    {
                        let pending_env = if let Some(debug) = module.native_debug() {
                            let terminal =
                                strict_open_call_terminal(proto, pc, work)?.ok_or_else(|| {
                                    error(
                                        OfficialExportErrorKind::InvalidPrototype,
                                        proto.id,
                                        pc,
                                        "environment cache 缺開放呼叫終點",
                                    )
                                })?;
                            let mut found = false;
                            for at in pc..=terminal {
                                let call_pc =
                                    InstructionOffset(u32::try_from(at).map_err(|_| {
                                        error(
                                            OfficialExportErrorKind::LimitExceeded,
                                            proto.id,
                                            at,
                                            "environment cache PC 超限",
                                        )
                                    })?);
                                let pending =
                                    debug.temporaries_at(proto.id, call_pc).unwrap_or(&[]);
                                work_charge(work, pending.len(), proto.id, at)?;
                                found |= pending
                                    .iter()
                                    .any(|entry| entry.register == proto.global_environment);
                            }
                            found
                        } else {
                            false
                        };
                        if !pending_env
                            && environment_cache_slot_exclusive(
                                &fixed_intervals,
                                slot,
                                pc,
                                proto.id,
                                work,
                            )?
                        {
                            continue;
                        }
                    }
                    if call.open_chain
                        && matches!(result_mode, ResultMode::All)
                        && dead_after_gathered_pending_open_call(
                            module, proto, call, register, work,
                        )?
                    {
                        continue;
                    }
                    return Err(error(
                        OfficialExportErrorKind::Unsupported,
                        proto.id,
                        pc,
                        "native Call window 與活躍固定 register 衝突",
                    ));
                }
            }
            let gather_base = if call.open_chain
                && matches!(result_mode, ResultMode::All)
                && arg_count != u16::MAX
            {
                open_root_base(proto, pc, work)?
            } else {
                base
            };
            let gathered = if arg_count == u16::MAX {
                0
            } else {
                arg_count
                    .checked_add(1)
                    .and_then(|count| count.checked_add(base.0 - gather_base.0))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            pc,
                            "native Call gather 數溢位",
                        )
                    })?
            };
            let scattered = match (tail, result_mode) {
                (true, _) => 0,
                (_, ResultMode::Fixed(count)) => count,
                (_, ResultMode::All) => 0,
            };
            let spare = (top..255)
                .find(|slot| *slot < call.window_start || *slot >= call.window_end)
                .map(|slot| slot as u8);
            let candidate = u8::try_from(call.window_start).map_err(|_| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "native Call window 起點超出 stack",
                )
            })?;
            let gather_plan = parallel_copy_plan(
                &mapped,
                gather_base,
                gathered,
                candidate,
                true,
                spare,
                proto.id,
                pc,
                work,
            )?;
            let scatter_plan = parallel_copy_plan(
                &mapped, base, scattered, candidate, false, spare, proto.id, pc, work,
            )?;
            let (Some(gather_plan), Some(scatter_plan)) = (gather_plan, scatter_plan) else {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "native Call window 無安全 gather/scatter",
                ));
            };
            // 只有搬移計畫真的使用備用槽時，才把它計入官方 maxstack。
            let spare = spare.filter(|slot| {
                gather_plan.moves[..gather_plan.len]
                    .iter()
                    .chain(&scatter_plan.moves[..scatter_plan.len])
                    .any(|&(dest, src)| dest == *slot || src == *slot)
            });
            scratch[pc] = call.window_start;
            parallel_spare[pc] = spare.map_or(NO_SPARE_SLOT, u16::from);
            max_stack = max_stack
                .max(top)
                .max(call.window_end)
                .max(spare.map_or(0, |slot| u16::from(slot) + 1));
            pc += 1;
            continue;
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
                if let Some(slot) = anonymous_vararg_slot {
                    immutable[usize::from(slot)] = true;
                }
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
                for register in 0..span.len() {
                    let active = live_at_pc(&span, &protected, &live_at, register, pc);
                    let survives = live_at_pc(&span, &protected, &live_at, register, pc + 1);
                    let result_written = register >= usize::from(guest.0)
                        && register - usize::from(guest.0) < usize::from(scattered);
                    if protected[register] != 0
                        && active
                        && mapped[register] != u8::MAX
                        && !(is_vararg && result_written)
                    {
                        immutable[usize::from(mapped[register])] = true;
                    }
                    if is_call && active && mapped[register] != u8::MAX {
                        if protected[register] != 0 || survives && !result_written {
                            call_floor = call_floor.max(u16::from(mapped[register]) + 1);
                        }
                    }
                    if is_vararg && active && mapped[register] != u8::MAX {
                        if !result_written && (survives || protected[register] != 0) {
                            immutable[usize::from(mapped[register])] = true;
                        }
                    }
                }
                for local in storage {
                    if local.start_pc as usize <= pc && pc < local.end_pc as usize {
                        let slot =
                            official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, pc)?;
                        let result_written = is_vararg
                            && local.register.0 >= guest.0
                            && local.register.0 - guest.0 < scattered;
                        if !result_written {
                            immutable[usize::from(slot)] = true;
                        }
                        if is_call {
                            call_floor = call_floor.max(u16::from(slot) + 1);
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
    // Lua 5.4 的 luaK_checkstack 在 newstack >= MAXREGS(255) 時拒絕；
    // Lua 5.5 的 MAX_FSTACK(255) 則允許等於上限。
    if max_stack > profile_stack_limit {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native maxstack 超過 profile 上限",
        ));
    }
    let max_stack = u8::try_from(max_stack).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native maxstack 超過 255",
        )
    })?;
    let mut call_cleanup_slots = Vec::new();
    call_cleanup_slots
        .try_reserve_exact(cleanup_count)
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                proto.id,
                0,
                "native call cleanup 佈局配置失敗",
            )
        })?;
    if call_cleanup_slots.capacity() > cleanup_count {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            0,
            "native call cleanup 實際容量超過預檢上限",
        ));
    }
    for pc in 0..proto.instructions.len() {
        let Some((first, end)) = call_cleanup_range(proto, pc) else {
            continue;
        };
        work_charge(
            work,
            count
                .checked_mul(2)
                .and_then(|units| units.checked_add(storage.len()))
                .and_then(|units| {
                    numeric
                        .len()
                        .checked_mul(4)
                        .and_then(|numeric_units| units.checked_add(numeric_units))
                })
                .and_then(|units| units.checked_add(255))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native call cleanup work 溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        let mut occupied = [false; 255];
        if let Some(slot) = anonymous_vararg_slot {
            occupied[usize::from(slot)] = true;
        }
        for (register, &(start, last)) in span.iter().enumerate() {
            let slot = mapped[register];
            if (register < first || register >= end) && start <= pc && pc < last && slot != u8::MAX
            {
                occupied[usize::from(slot)] = true;
            }
        }
        for local in storage {
            let register = usize::from(local.register.0);
            if (register < first || register >= end)
                && (local.start_pc as usize) <= pc
                && pc < local.end_pc as usize
            {
                let official_slot =
                    official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, pc)?;
                let slot = occupied
                    .get_mut(usize::from(official_slot))
                    .ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            proto.id,
                            pc,
                            "native call cleanup local slot 超出官方 stack",
                        )
                    })?;
                *slot = true;
            }
        }
        if let Some(debug) = module
            .native_debug()
            .and_then(|debug| debug.prototype(proto.id))
        {
            work_charge(work, debug.locals.len(), proto.id, pc)?;
            for local in &debug.locals {
                let register = usize::from(local.register.0);
                if (register < first || register >= end)
                    && local.initialized_pc as usize <= pc
                    && pc < local.end_pc as usize
                {
                    let slot =
                        official_storage_slot(local.slot, anonymous_vararg_slot, proto.id, pc)?;
                    occupied[usize::from(slot)] = true;
                }
            }
        }
        for pair in numeric {
            if pair.prepare_pc <= pc && pc <= pair.next_pc {
                let base = usize::from(tuple_base) + usize::from(pair.block) * 4;
                let slots = occupied.get_mut(base..base + 4).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native call cleanup numeric tuple 超出官方 stack",
                    )
                })?;
                slots.fill(true);
            }
        }
        call_cleanup_slots.push((pc, [0u8; 32]));
        let selected = &mut call_cleanup_slots
            .last_mut()
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    proto.id,
                    pc,
                    "native call cleanup 稀疏索引遺失",
                )
            })?
            .1;
        for &slot in &mapped[first..end] {
            if slot != u8::MAX && !occupied[usize::from(slot)] {
                cleanup_slot_set(selected, slot);
            }
        }
        let call_pc = pc - 1;
        let Instruction::Call { arg_count, .. } = proto.instructions[call_pc].instruction else {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc,
                "native call cleanup 缺前置 Call",
            ));
        };
        let scratch_first = usize::from(scratch[call_pc]);
        let scratch_end = if arg_count == u16::MAX {
            usize::from(max_stack)
        } else {
            scratch_first
                .checked_add(usize::from(arg_count) + 1)
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "native call cleanup scratch 溢位",
                    )
                })?
        };
        if scratch_end > usize::from(max_stack) {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "native call cleanup scratch 超出官方 stack",
            ));
        }
        for slot in scratch_first..scratch_end {
            if !occupied[slot] {
                cleanup_slot_set(selected, slot as u8);
            }
        }
        let spare = parallel_spare[call_pc];
        if spare < u16::from(max_stack) && !occupied[usize::from(spare)] {
            cleanup_slot_set(selected, spare as u8);
        }
    }
    work_charge(work, aliases.len(), proto.id, 0)?;
    if aliases
        .iter()
        .any(|alias| alias.preserve_mapped_home && mapped[usize::from(alias.anchor.0)] == u8::MAX)
    {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            proto.id,
            0,
            "numeric alias 後讀 home 缺少實體配置",
        ));
    }
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
    // 有後讀的 anchor 保留 allocator home，讓既有 Call/scratch/cleanup 版圖一致；
    // 其餘 nil home 才在 bitmap 建好後改映，不能漏清理存活的可達值。
    let mut private_nil_slot = usize::from(shared_nil_slot);
    work_charge(
        work,
        aliases
            .len()
            .checked_mul(aliases.len().checked_add(1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "numeric CFG nil slot 配置工作量溢位",
                )
            })?)
            .and_then(|units| units.checked_mul(2))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    0,
                    "numeric CFG nil slot 配置工作量溢位",
                )
            })?,
        proto.id,
        0,
    )?;
    for (index, alias) in aliases.iter().enumerate() {
        if numeric_alias_preserves_mapped_home(&aliases, alias.anchor) {
            continue;
        }
        // 同一 guest anchor 的分類由全函式效果決定，重複 alias 沿用首次 home。
        if !alias.share_nil_slot
            && aliases[..index]
                .iter()
                .any(|earlier| !earlier.share_nil_slot && earlier.anchor == alias.anchor)
        {
            continue;
        }
        let offset = if alias.share_nil_slot {
            0
        } else {
            let offset = private_nil_slot;
            private_nil_slot = private_nil_slot.checked_add(1).ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    alias.body_pc,
                    "numeric CFG nil slot 數溢位",
                )
            })?;
            offset
        };
        let slot = numeric_blocks
            .checked_mul(4)
            .and_then(|size| tuple_base.checked_add(size))
            .and_then(|slot| {
                u16::try_from(offset)
                    .ok()
                    .and_then(|offset| slot.checked_add(offset))
            })
            .and_then(|slot| u8::try_from(slot).ok())
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    alias.body_pc,
                    "numeric CFG nil slot 超限",
                )
            })?;
        mapped[usize::from(alias.anchor.0)] = slot;
    }
    Ok((
        mapped,
        protected,
        span,
        live_at,
        tuple_base,
        scratch,
        parallel_spare,
        call_cleanup_slots,
        max_stack,
        aliases,
    ))
}

fn layout(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    root: bool,
    profile: LuaProfile,
    numeric: &[NumericPair],
    numeric_blocks: u16,
    bitmap_limit: usize,
    work: &mut OfficialWorkBudget,
    limits: &OfficialChunkLimits,
) -> Result<Layout, OfficialExportError> {
    let anonymous_vararg_slot = anonymous_vararg_slot(proto, profile)?;
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
    let (
        mapped,
        protected,
        span,
        live_at,
        tuple_base,
        scratch,
        parallel_spare,
        call_cleanup_slots,
        max_stack,
        numeric_aliases,
    ) = compact_register_map(
        module,
        proto,
        numeric,
        numeric_blocks,
        anonymous_vararg_slot,
        profile,
        env_upvalue,
        bitmap_limit,
        limits,
        work,
    )?;
    Ok(Layout {
        anonymous_vararg_slot,
        tuple_base,
        scratch,
        parallel_spare,
        call_cleanup_slots,
        max_stack,
        guest_upvalue_offset,
        env_upvalue,
        mapped,
        protected,
        span,
        live_at,
        numeric_aliases,
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
        let next_total = self.total_instructions.checked_add(1).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                self.id,
                pc,
                "官方指令數溢位",
            )
        })?;
        if next_total > self.limits.max_instructions {
            return Err(error(
                OfficialExportErrorKind::LimitExceeded,
                self.id,
                pc,
                "官方指令數超限",
            ));
        }
        if self.code.len() >= self.max_words {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                self.id,
                pc,
                "native 指令數超出預付額度",
            ));
        }
        *self.total_instructions = next_total;
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

fn used_parallel_spare(plan: &ParallelMoves, marker: u16) -> Option<u8> {
    if !plan.used_spare {
        return None;
    }
    u8::try_from(marker).ok().filter(|slot| *slot < 255)
}

fn parallel_plan_words(plan: &ParallelMoves, marker: u16) -> usize {
    plan.len + usize::from(used_parallel_spare(plan, marker).is_some())
}

// 沿用既有平行搬移的「無讀者才寫目的槽、循環經備用槽」順序；
// 固定 Call 額外需要非連續的借位 home，故接收實體槽配對。
fn parallel_slot_pairs_plan(
    source: &[u8; 512],
    destination: &[u8; 512],
    len: usize,
    spare: Option<u8>,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<ParallelMoves>, OfficialExportError> {
    let mut sources = *source;
    let mut pending = [false; 512];
    let mut destination_seen = [false; 255];
    let mut readers = [0u16; 256];
    let mut plan = ParallelMoves {
        moves: [(0, 0); 512],
        len: 0,
        used_spare: false,
    };
    let mut remaining = 0usize;
    work_charge(work, len, id, pc)?;
    for index in 0..len {
        let src = sources[index];
        let dest = destination[index];
        if src == u8::MAX || dest == u8::MAX || destination_seen[usize::from(dest)] {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                pc,
                "固定 Call pending 搬移槽無效或重疊",
            ));
        }
        destination_seen[usize::from(dest)] = true;
        if src != dest {
            pending[index] = true;
            remaining += 1;
            readers[usize::from(src)] += 1;
        }
    }
    if let Some(spare) = spare {
        work_charge(work, len, id, pc)?;
        if (0..len).any(|index| source[index] == spare || destination[index] == spare) {
            return Ok(None);
        }
    }
    while remaining > 0 {
        work_charge(work, len, id, pc)?;
        if let Some(index) =
            (0..len).find(|&index| pending[index] && readers[usize::from(destination[index])] == 0)
        {
            let src = sources[index];
            plan.push(destination[index], src, id, pc)?;
            readers[usize::from(src)] -= 1;
            pending[index] = false;
            remaining -= 1;
            continue;
        }
        let Some(spare) = spare else { return Ok(None) };
        if readers[usize::from(spare)] != 0 {
            return Ok(None);
        }
        work_charge(work, len, id, pc)?;
        let index = pending[..len]
            .iter()
            .position(|item| *item)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    pc,
                    "固定 Call pending 待搬移集合無效",
                )
            })?;
        let saved = destination[index];
        plan.push(spare, saved, id, pc)?;
        plan.used_spare = true;
        work_charge(work, len, id, pc)?;
        for index in 0..len {
            if pending[index] && sources[index] == saved {
                sources[index] = spare;
                readers[usize::from(saved)] -= 1;
                readers[usize::from(spare)] += 1;
            }
        }
    }
    Ok(Some(plan))
}

// Call 的一般 gather/scatter 備用槽可能落在額外的 pending 前綴中。
// 對這一組實際配對先檢查；無法借用時仍讓無循環配對由原 planner 完成。
fn fixed_pending_spare_for_pairs(
    marker: u16,
    source: &[u8; 512],
    destination: &[u8; 512],
    len: usize,
    id: ProtoId,
    pc: usize,
    work: &mut OfficialWorkBudget,
) -> Result<Option<u8>, OfficialExportError> {
    let Some(spare) = (marker < 255).then_some(marker as u8) else {
        return Ok(None);
    };
    work_charge(work, len, id, pc)?;
    Ok((0..len)
        .all(|index| source[index] != spare && destination[index] != spare)
        .then_some(spare))
}

// 固定 Call 的 pending 值在官方 ABI 中位於 callee 以下。借用 pending
// 搬出後騰空的 home 存放其他跨 Call 活值，返回時逆向搬回。
fn fixed_call_pending_moves(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    pc: usize,
    gather: bool,
    work: &mut OfficialWorkBudget,
) -> Result<Option<(ParallelMoves, Option<u8>)>, OfficialExportError> {
    let Instruction::Call {
        base,
        arg_count,
        result_mode: ResultMode::Fixed(results),
    } = proto.instructions[pc].instruction
    else {
        return Ok(None);
    };
    if arg_count == u16::MAX {
        return Ok(None);
    }
    let call_pc = InstructionOffset(u32::try_from(pc).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "固定 Call pending PC 超出範圍",
        )
    })?);
    let Some(debug) = module.native_debug() else {
        return Ok(None);
    };
    let pending: &[NativeTemporary] = debug.temporaries_at(proto.id, call_pc).unwrap_or(&[]);
    if pending.is_empty() {
        return Ok(None);
    }
    if let Some(plan) = module
        .official_execution()
        .filter(|plan| plan.is_native_builtin())
    {
        work_charge(work, plan.calls().len(), proto.id, pc)?;
        if plan.call(proto.id, call_pc).is_some() {
            return Ok(None);
        }
    }
    if pending.len() > 255 {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "固定 Call pending 數超出 stack",
        ));
    }
    let count = u16::try_from(pending.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::LimitExceeded,
            proto.id,
            pc,
            "固定 Call pending 數超出 stack",
        )
    })?;
    let call_base = *meta.scratch.get(pc).ok_or_else(|| {
        error(
            OfficialExportErrorKind::InvalidPrototype,
            proto.id,
            pc,
            "固定 Call 缺少 scratch",
        )
    })?;
    let first = call_base
        .checked_sub(count)
        .and_then(|slot| u8::try_from(slot).ok())
        .filter(|slot| usize::from(*slot) + pending.len() <= 255)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "固定 Call pending 前綴超出 stack",
            )
        })?;
    let last = usize::from(first) + pending.len();
    let mut homes = [u8::MAX; 255];
    let mut outside = [u8::MAX; 255];
    let mut outside_count = 0usize;
    work_charge(work, pending.len(), proto.id, pc)?;
    for (index, temporary) in pending.iter().enumerate() {
        if usize::from(temporary.ordinal) != index + 1 {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                proto.id,
                pc,
                "固定 Call pending ordinal 無效",
            ));
        }
        let home = meta.register(temporary.register, proto.id, pc)?;
        if meta.protected[usize::from(temporary.register.0)] != 0
            && usize::from(home) != usize::from(first) + index
        {
            return Err(error(
                OfficialExportErrorKind::Unsupported,
                proto.id,
                pc,
                "受保護 pending home 無法與官方前綴分離",
            ));
        }
        homes[index] = home;
        if usize::from(home) < usize::from(first) || usize::from(home) >= last {
            outside[outside_count] = home;
            outside_count += 1;
        }
    }
    let mut displaced = [false; 255];
    let mut outside_occupied = [false; 255];
    let scan_work = meta
        .mapped
        .len()
        .checked_mul(pending.len().checked_add(2).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "固定 Call 前綴掃描 work 溢位",
            )
        })?)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "固定 Call 前綴掃描 work 溢位",
            )
        })?;
    work_charge(work, scan_work, proto.id, pc)?;
    for (register, &home) in meta.mapped.iter().enumerate() {
        let slot = usize::from(home);
        if home == u8::MAX
            || !live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc)
            || pending
                .iter()
                .any(|temporary| usize::from(temporary.register.0) == register)
        {
            continue;
        }
        let survives = live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc + 1)
            || meta.protected[register] != 0;
        if slot < usize::from(first) || slot >= last {
            if survives {
                outside_occupied[slot] = true;
            }
            continue;
        }
        let result_written = register >= usize::from(base.0)
            && register - usize::from(base.0) < usize::from(results);
        if !result_written && survives {
            if meta.protected[register] != 0 {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "受保護 home 無法借用固定 Call 前綴",
                ));
            }
            let ordinal = slot - usize::from(first);
            if homes[ordinal] == home {
                return Err(error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "固定 Call pending 原位 home 與其他活值重疊",
                ));
            }
            displaced[ordinal] = true;
        }
    }
    let mut borrowed_homes = [u8::MAX; 255];
    let mut borrowed_count = 0usize;
    let mut borrowed_seen = [false; 255];
    let window_end = call_base
        .checked_add(scratch_width_at(proto, pc, work)?)
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                pc,
                "固定 Call 借位窗口溢位",
            )
        })?;
    work_charge(work, outside_count, proto.id, pc)?;
    for &home in &outside[..outside_count] {
        let slot = usize::from(home);
        if !(call_base <= u16::from(home) && u16::from(home) < window_end)
            && !outside_occupied[slot]
            && !borrowed_seen[slot]
        {
            borrowed_seen[slot] = true;
            borrowed_homes[borrowed_count] = home;
            borrowed_count += 1;
        }
    }
    let mut source = [0u8; 512];
    let mut destination = [0u8; 512];
    let mut len = 0usize;
    for (index, &home) in homes[..pending.len()].iter().enumerate() {
        source[len] = if gather { home } else { first + index as u8 };
        destination[len] = if gather { first + index as u8 } else { home };
        len += 1;
    }
    let mut borrowed = 0usize;
    work_charge(work, pending.len(), proto.id, pc)?;
    for (index, occupied) in displaced[..pending.len()].iter().enumerate() {
        if !occupied {
            continue;
        }
        let borrowed_home = *borrowed_homes
            .get(borrowed)
            .filter(|home| **home != u8::MAX)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::Unsupported,
                    proto.id,
                    pc,
                    "固定 Call pending 沒有可借用的騰空 home",
                )
            })?;
        let prefix_slot = first + index as u8;
        source[len] = if gather { prefix_slot } else { borrowed_home };
        destination[len] = if gather { borrowed_home } else { prefix_slot };
        len += 1;
        borrowed += 1;
    }
    let marker = meta.parallel_spare[pc];
    let spare =
        fixed_pending_spare_for_pairs(marker, &source, &destination, len, proto.id, pc, work)?;
    let mut plan = parallel_slot_pairs_plan(&source, &destination, len, spare, proto.id, pc, work)?;
    let mut cleanup_spare = plan
        .as_ref()
        .and_then(|plan| used_parallel_spare(plan, marker));
    if plan.is_none() {
        // 一般 Call gather 沒有循環時不會保留 spare；pending 的 home 卻
        // 可能與官方前綴互換。只借用已計入 maxstack、且此 Call 前後無活值的槽。
        let scan = meta
            .mapped
            .len()
            .checked_add(usize::from(meta.max_stack))
            .and_then(|units| units.checked_add(len.checked_mul(2)?))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "固定 Call 備用槽掃描 work 溢位",
                )
            })?;
        work_charge(work, scan, proto.id, pc)?;
        let mut occupied = [false; 255];
        for (register, &home) in meta.mapped.iter().enumerate() {
            if home != u8::MAX
                && (live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc)
                    || live_at_pc(&meta.span, &meta.protected, &meta.live_at, register, pc + 1))
            {
                occupied[usize::from(home)] = true;
            }
        }
        let (numeric, _) = numeric_pairs(proto, work)?;
        let numeric_scan = usize::from(meta.max_stack)
            .saturating_sub(usize::from(window_end))
            .checked_mul(numeric.len())
            .and_then(|units| units.checked_mul(meta.numeric_aliases.len().checked_add(1)?))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "固定 Call 備用槽 numeric work 溢位",
                )
            })?;
        work_charge(work, numeric_scan, proto.id, pc)?;
        if let Some(extra) = (window_end..u16::from(meta.max_stack)).find(|&slot| {
            let slot = slot as u8;
            !occupied[usize::from(slot)]
                && meta.anonymous_vararg_slot != Some(slot)
                && !numeric.iter().any(|pair| {
                    if !(pair.prepare_pc <= pc && pc <= pair.next_pc) {
                        return false;
                    }
                    let first = meta
                        .numeric_aliases
                        .iter()
                        .find(|alias| alias.body_pc == pair.body_pc)
                        .map_or(
                            usize::from(meta.tuple_base) + usize::from(pair.block) * 4,
                            |alias| usize::from(alias.tuple),
                        );
                    first <= usize::from(slot) && usize::from(slot) < first + 4
                })
                && (0..len).all(|index| source[index] != slot && destination[index] != slot)
        }) {
            plan = parallel_slot_pairs_plan(
                &source,
                &destination,
                len,
                Some(extra as u8),
                proto.id,
                pc,
                work,
            )?;
            if let Some(ref selected) = plan {
                // 備用槽只在搬移循環期間借用；完成後必須清掉暫存的 GC root。
                cleanup_spare = used_parallel_spare(selected, extra);
            }
        }
    }
    plan.map(|plan| Some((plan, cleanup_spare))).ok_or_else(|| {
        error(
            OfficialExportErrorKind::Unsupported,
            proto.id,
            pc,
            "固定 Call pending 無安全平行搬移",
        )
    })
}

fn emit_fixed_call_pending_moves(
    builder: &mut Builder<'_>,
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    pc: usize,
    gather: bool,
) -> Result<(), OfficialExportError> {
    if let Some((plan, cleanup_spare)) =
        fixed_call_pending_moves(module, proto, meta, pc, gather, builder.work)?
    {
        emit_parallel_plan(builder, &plan, cleanup_spare, pc)?;
    }
    Ok(())
}

fn emit_parallel_plan(
    builder: &mut Builder<'_>,
    plan: &ParallelMoves,
    cleanup_spare: Option<u8>,
    pc: usize,
) -> Result<(), OfficialExportError> {
    for &(dest, src) in &plan.moves[..plan.len] {
        builder.push(abc(0, dest, src, 0, false), pc)?;
    }
    if let Some(spare) = cleanup_spare {
        // 搬移後的複本不是活值，須在下一個 opcode 前移除 GC root。
        builder.push(abc(8, spare, 0, 0, false), pc)?;
    }
    Ok(())
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
        emit_parallel_plan(
            builder,
            &plan,
            used_parallel_spare(&plan, meta.parallel_spare[pc]),
            pc,
        )?;
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
        emit_parallel_plan(
            builder,
            &plan,
            used_parallel_spare(&plan, meta.parallel_spare[pc]),
            pc,
        )?;
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

fn preflight_native_fusion_arrays(
    stats: &mut NativePreflight,
    instructions: usize,
    numeric: usize,
    limits: &OfficialChunkLimits,
    id: ProtoId,
) -> Result<(), OfficialExportError> {
    stats.bytes(numeric, size_of::<DirectNumericInit>(), limits, id)?;
    stats.bytes(instructions / 4, size_of::<DirectConstCopy>(), limits, id)?;
    stats.bytes(
        instructions,
        size_of::<Option<CompareBranchFusion>>(),
        limits,
        id,
    )?;
    stats.bytes(
        instructions,
        size_of::<Option<TerminalCompareFusion>>(),
        limits,
        id,
    )?;
    stats.bytes(
        instructions,
        size_of::<Option<EnvFieldFusion>>(),
        limits,
        id,
    )?;
    stats.bytes(
        instructions,
        size_of::<Option<LoopExitNilFusion>>(),
        limits,
        id,
    )?;
    stats.bytes(instructions, size_of::<(usize, usize)>(), limits, id)?;
    stats.bytes(instructions, size_of::<Option<usize>>(), limits, id)?;
    Ok(())
}

fn preflight_numeric_control_names(
    stats: &mut NativePreflight,
    control_locals: usize,
    limits: &OfficialChunkLimits,
    id: ProtoId,
) -> Result<(), OfficialExportError> {
    for _ in 0..control_locals {
        stats.string(NUMERIC_CONTROL_LOCAL, limits, id)?;
    }
    Ok(())
}

fn native_opcode_words(
    module: &VerifiedModule,
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
        Instruction::LoadNil { count, .. } => {
            if call_cleanup_range(proto, pc).is_some() {
                work_charge(work, 32, proto.id, pc)?;
                cleanup_slots_at(&meta.call_cleanup_slots, proto, pc, work)?
                    .iter()
                    .map(|byte| byte.count_ones() as usize)
                    .sum()
            } else {
                usize::from(*count)
            }
        }
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
            let gather_start = if *arg_count != u16::MAX && matches!(result_mode, ResultMode::All) {
                open_root_base(proto, pc, work)?
            } else {
                *base
            };
            let gathered = if *arg_count == u16::MAX {
                0usize
            } else {
                usize::from(base.0.checked_sub(gather_start.0).ok_or_else(|| {
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
                    gather_start,
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
                .map_or(gathered, |plan| {
                    parallel_plan_words(&plan, meta.parallel_spare[pc])
                })
            } else {
                gathered
            };
            let scattered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                planned_copy(meta, *base, scatter_count, 0, false, proto.id, pc, work)?
                    .map_or(scattered, |plan| {
                        parallel_plan_words(&plan, meta.parallel_spare[pc])
                    })
            } else {
                scattered
            };
            let pending_before = fixed_call_pending_moves(module, proto, meta, pc, true, work)?
                .map_or(0, |(plan, spare)| plan.len + usize::from(spare.is_some()));
            let pending_after = fixed_call_pending_moves(module, proto, meta, pc, false, work)?
                .map_or(0, |(plan, spare)| plan.len + usize::from(spare.is_some()));
            1usize
                .checked_add(gathered)
                .and_then(|words| words.checked_add(scattered))
                .and_then(|words| words.checked_add(pending_before))
                .and_then(|words| words.checked_add(pending_after))
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
                    .map_or(gathered, |plan| {
                        parallel_plan_words(&plan, meta.parallel_spare[pc])
                    })
            } else {
                gathered
            };
            1 + gathered
        }
        Instruction::Vararg { base, result_mode } => match result_mode {
            ResultMode::Fixed(count) => {
                let scattered = if meta.parallel_spare[pc] != NO_PARALLEL_COPY {
                    planned_copy(meta, *base, *count, 0, false, proto.id, pc, work)?
                        .map_or(usize::from(*count), |plan| {
                            parallel_plan_words(&plan, meta.parallel_spare[pc])
                        })
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
                    .map_or(usize::from(*count), |plan| {
                        parallel_plan_words(&plan, meta.parallel_spare[pc])
                    })
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
) -> Result<(usize, Option<u32>), OfficialExportError> {
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
            .checked_add(native_opcode_words(module, groups, proto, meta, pc, work)?)
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
    let end_line = native_missing_end_line(module, proto, work)?;
    let words = words
        .checked_add(usize::from(end_line.is_some()))
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                proto.instructions.len(),
                "native 末行返回指令數溢位",
            )
        })?;
    Ok((words, end_line))
}

fn native_missing_end_line(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    work: &mut OfficialWorkBudget,
) -> Result<Option<u32>, OfficialExportError> {
    if proto.parent.is_none()
        || !matches!(
            proto.instructions.last().map(|entry| &entry.instruction),
            Some(
                Instruction::Return { .. }
                    | Instruction::TailCall { .. }
                    | Instruction::Jump { .. }
            )
        )
    {
        return Ok(None);
    }
    let Some(entry) = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id))
    else {
        return Ok(None);
    };
    work_charge(work, entry.lines.len(), proto.id, proto.instructions.len())?;
    Ok((!entry.lines.contains(&entry.last_line_defined)).then_some(entry.last_line_defined))
}

fn preflight_native_prototype(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    root: bool,
    profile: LuaProfile,
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
    stats.bytes(numeric_count, size_of::<NumericAlias>(), limits, proto.id)?;
    if numeric_count > 0 && module.native_debug().is_some() {
        stats.bytes(
            proto.instructions.len(),
            2 * (1 + size_of::<u32>()),
            limits,
            proto.id,
        )?;
    }
    preflight_native_fusion_arrays(
        stats,
        proto.instructions.len(),
        numeric_count,
        limits,
        proto.id,
    )?;
    let storage_count = module
        .native_debug()
        .and_then(|debug| debug.storage_for(proto.id))
        .map_or(0, |storage| storage.len());
    let anonymous_vararg_slot = anonymous_vararg_slot(proto, profile)?;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    work_charge(work, proto.instructions.len(), proto.id, 0)?;
    let cleanup_count = (0..proto.instructions.len())
        .filter(|&pc| call_cleanup_range(proto, pc).is_some())
        .count();
    let storage_total = storage_count + usize::from(anonymous_vararg_slot.is_some());
    let call_count = if module.native_debug().is_some() {
        proto
            .instructions
            .iter()
            .filter(|entry| {
                matches!(entry.instruction, Instruction::Call { .. })
                    || matches!(
                        entry.instruction,
                        Instruction::TailCall {
                            arg_count: u16::MAX,
                            ..
                        }
                    )
            })
            .count()
    } else {
        0
    };
    let temporary_count = module
        .native_debug()
        .and_then(|debug| debug.temporaries_for(proto.id))
        .map_or(0, <[_]>::len);
    let map_base = compact_map_base_bytes(
        proto,
        storage_total,
        call_count,
        temporary_count,
        cleanup_count,
        numeric_count,
    )?;
    stats.bytes(1, map_base, limits, proto.id)?;
    let bitmap_limit = limits.max_allocated_bytes - stats.allocated_bytes;
    let (numeric, numeric_blocks) = numeric_pairs(proto, work)?;
    let meta = layout(
        module,
        proto,
        root,
        profile,
        &numeric,
        numeric_blocks,
        bitmap_limit,
        work,
        limits,
    )?;
    let bitmap_bytes = meta.live_at.iter().try_fold(0usize, |total, row| {
        let capacity = match row {
            LiveRow::Uncomputed => 0,
            LiveRow::Bits { bytes, .. } => bytes.capacity(),
        };
        total.checked_add(capacity).ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                proto.id,
                0,
                "native CFG live snapshot 大小溢位",
            )
        })
    })?;
    stats.bytes(1, bitmap_bytes, limits, proto.id)?;
    let (words, _) = native_word_count(module, &close_groups, proto, &meta, root, work)?;
    NativePreflight::add(
        &mut stats.instructions,
        words,
        // 上界包含稍後合併的指令；實際上限由 Builder::push 逐條檢查。
        usize::MAX,
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
            let control_locals = meta
                .numeric_aliases
                .iter()
                .try_fold(0usize, |count, alias| {
                    count.checked_add(usize::from(alias.width)).ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            proto.id,
                            alias.body_pc,
                            "numeric debug local 數溢位",
                        )
                    })
                })?;
            stats.bytes(words, size_of::<u32>(), limits, proto.id)?;
            stats.bytes(words, size_of::<i8>(), limits, proto.id)?;
            stats.bytes(words, size_of::<OfficialAbsLine>(), limits, proto.id)?;
            let total_locals = entry
                .locals
                .len()
                .checked_add(usize::from(meta.anonymous_vararg_slot.is_some()))
                .and_then(|count| count.checked_add(control_locals))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        0,
                        "numeric debug local 數溢位",
                    )
                })?;
            stats.bytes(total_locals, size_of::<OfficialLocal>(), limits, proto.id)?;
            stats.bytes(upvalues, size_of::<Option<Vec<u8>>>(), limits, proto.id)?;
            work_charge(
                work,
                entry
                    .locals
                    .len()
                    .checked_add(entry.upvalue_names.len())
                    .and_then(|count| {
                        count.checked_add(usize::from(meta.anonymous_vararg_slot.is_some()))
                    })
                    .and_then(|count| count.checked_add(control_locals))
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
            preflight_numeric_control_names(stats, control_locals, limits, proto.id)?;
            if meta.anonymous_vararg_slot.is_some() {
                stats.string(ANONYMOUS_VARARG_LOCAL, limits, proto.id)?;
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
        preflight_native_prototype(
            module,
            child,
            false,
            profile,
            strip,
            depth + 1,
            limits,
            work,
            stats,
        )?;
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
                        work_charge(work, parent_proto.instructions.len(), proto.id, 0)?;
                        let mut source = None;
                        for (pc, instruction) in parent_proto.instructions.iter().enumerate() {
                            if !matches!(
                                instruction.instruction,
                                Instruction::Closure { proto: child, .. } if child == proto.id
                            ) {
                                continue;
                            }
                            let slot = parent_layout.register(register, parent_proto.id, pc)?;
                            if source.is_some_and(|previous| previous != slot) {
                                return Err(error(
                                    OfficialExportErrorKind::InvalidPrototype,
                                    proto.id,
                                    pc,
                                    "同一 child 的 parent local 捕獲槽不一致",
                                ));
                            }
                            source = Some(slot);
                        }
                        (
                            true,
                            match source {
                                Some(slot) => slot,
                                None => parent_layout.register(register, proto.id, 0)?,
                            },
                        )
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

fn compare_branch_fusions(
    module: &VerifiedModule,
    proto: &BytecodePrototype,
    meta: &Layout,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<Option<CompareBranchFusion>>, OfficialExportError> {
    let count = proto.instructions.len();
    let mut result = Vec::new();
    result.try_reserve_exact(count).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            proto.id,
            0,
            "比較分支配置失敗",
        )
    })?;
    work_charge(work, count, proto.id, 0)?;
    result.resize(count, None);
    let Some(debug) = module
        .native_debug()
        .and_then(|debug| debug.prototype(proto.id))
    else {
        return Ok(result);
    };
    for pc in 0..count.saturating_sub(2) {
        let Instruction::BinaryOp {
            dest,
            op,
            left,
            right,
        } = &proto.instructions[pc].instruction
        else {
            continue;
        };
        let Some((opcode, swap, invert)) = comparison_opcode(op) else {
            continue;
        };
        let Instruction::Move { dest: phi, src } = proto.instructions[pc + 1].instruction else {
            continue;
        };
        let Instruction::JumpIfFalse { condition, target } = proto.instructions[pc + 2].instruction
        else {
            continue;
        };
        let phi_slot = meta.register(phi, proto.id, pc)?;
        let left_slot = meta.register(*left, proto.id, pc)?;
        let right_slot = meta.register(*right, proto.id, pc)?;
        if phi_slot == right_slot {
            continue;
        }
        if phi_slot == left_slot {
            // 左運算元若是緊鄰載入的匿名常數，條件比較讀完即可讓 phi 共槽。
            // 仍須排除跳入比較、後續讀取及 close，避免覆蓋存活值。
            let Some(load_pc) = pc.checked_sub(1) else {
                continue;
            };
            if !matches!(proto.instructions[load_pc].instruction,
                Instruction::LoadConst { dest, .. } if dest == *left)
                || debug.lines.get(load_pc) != debug.lines.get(pc)
                || proto
                    .binding_registers
                    .iter()
                    .any(|(_, register)| register == left)
                || debug.locals.iter().any(|local| local.register == *left)
            {
                continue;
            }
            work_charge(
                work,
                count.checked_mul(2).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "比較共槽工作量溢位",
                    )
                })?,
                proto.id,
                pc,
            )?;
            let enters_compare = proto.instructions.iter().any(|entry| {
                let targets = match entry.instruction {
                    Instruction::Jump { target }
                    | Instruction::JumpIfFalse { target, .. }
                    | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                    Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                    _ => [None, None],
                };
                targets
                    .into_iter()
                    .flatten()
                    .any(|target| target.0 as usize == pc)
            });
            let (reads_later, closes_later) = proto.instructions.iter().skip(pc + 1).fold(
                (false, false),
                |(read_seen, close_seen), entry| {
                    let (read, _, _, close) =
                        register_access(&entry.instruction, *left, proto.register_count);
                    (read_seen || read, close_seen || close)
                },
            );
            if enters_compare
                || closes_later
                || (reads_later && generation_live_after_consumer(proto, meta, *left, pc))
            {
                continue;
            }
        }
        let end = target.0 as usize;
        if src != *dest
            || condition != *dest
            || phi == *dest
            || phi == *left
            || phi == *right
            || *dest == *left
            || *dest == *right
            || end <= pc + 3
            || end > count
            || phi == proto.frame.environment
            || *dest == proto.frame.environment
            || !matches!(proto.instructions[end - 1].instruction, Instruction::Move { dest, .. } if dest == phi)
            || proto.instructions[pc..=pc + 2]
                .iter()
                .any(|entry| entry.close_path.is_some())
            || debug.lines.get(pc) != debug.lines.get(pc + 1)
            || debug.lines.get(pc) != debug.lines.get(pc + 2)
        {
            continue;
        }
        work_charge(
            work,
            count
                .checked_mul(3)
                .and_then(|n| n.checked_add(debug.locals.len()))
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        proto.id,
                        pc,
                        "比較分支工作量溢位",
                    )
                })?,
            proto.id,
            pc,
        )?;
        if proto
            .binding_registers
            .iter()
            .any(|(_, register)| *register == *dest || *register == phi)
            || debug.locals.iter().any(|local| {
                ((local.register == *dest || local.register == phi)
                    && local.start_pc as usize <= end
                    && local.end_pc as usize > pc)
                    || [pc + 1, pc + 2].contains(&(local.start_pc as usize))
                    || [pc + 1, pc + 2].contains(&(local.initialized_pc as usize))
                    || [pc + 1, pc + 2].contains(&(local.end_pc as usize))
            })
        {
            continue;
        }
        let enters_skipped_pc = proto.instructions.iter().any(|entry| {
            let targets = match entry.instruction {
                Instruction::Jump { target }
                | Instruction::JumpIfFalse { target, .. }
                | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            targets.into_iter().flatten().any(|target| {
                let target = target.0 as usize;
                target == pc + 1 || target == pc + 2
            })
        });
        let enters_rhs = proto.instructions.iter().any(|entry| {
            let targets = match entry.instruction {
                Instruction::Jump { target }
                | Instruction::JumpIfFalse { target, .. }
                | Instruction::NumericForPrepare { exit: target, .. } => [Some(target), None],
                Instruction::NumericForNext { target, exit, .. } => [Some(target), Some(exit)],
                _ => [None, None],
            };
            targets.into_iter().flatten().any(|target| {
                let target = target.0 as usize;
                pc + 3 <= target && target < end
            })
        });
        if enters_skipped_pc || enters_rhs {
            continue;
        }
        let mut safe_rhs = true;
        // 只預扣實際會走訪的 RHS 區間與後續 dest 掃描，仍涵蓋每個
        // RHS 指令對所有 register 的最壞情況檢查。
        let rhs_entries = end - (pc + 3);
        let later_entries = count - (pc + 3);
        let scan_work = rhs_entries
            .checked_mul(usize::from(proto.register_count) + 1)
            .and_then(|units| units.checked_add(later_entries))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    proto.id,
                    pc,
                    "比較別名工作量溢位",
                )
            })?;
        work_charge(work, scan_work, proto.id, pc)?;
        for offset in pc + 3..end {
            let entry = &proto.instructions[offset];
            let (phi_read, phi_write, phi_possible, phi_close) =
                register_access(&entry.instruction, phi, proto.register_count);
            if entry.close_path.is_some()
                || matches!(
                    entry.instruction,
                    Instruction::Jump { .. }
                        | Instruction::JumpIfFalse { .. }
                        | Instruction::NumericForPrepare { .. }
                        | Instruction::NumericForNext { .. }
                        | Instruction::Return { .. }
                        | Instruction::TailCall { .. }
                )
                || phi_read
                || phi_close
                || phi_possible
                || (offset != end - 1 && phi_write)
            {
                safe_rhs = false;
                break;
            }
            for register in 0..proto.register_count {
                let register = Register(register);
                if register == phi
                    || !register_access(&entry.instruction, register, proto.register_count).0
                {
                    continue;
                }
                if meta.register(register, proto.id, offset)? == phi_slot {
                    safe_rhs = false;
                    break;
                }
            }
            if !safe_rhs {
                break;
            }
        }
        let (dest_reads_later, dest_closes_later) = proto.instructions.iter().skip(pc + 3).fold(
            (false, false),
            |(read_seen, close_seen), entry| {
                let (read, _, _, close) =
                    register_access(&entry.instruction, *dest, proto.register_count);
                (read_seen || read, close_seen || close)
            },
        );
        if !safe_rhs
            || dest_closes_later
            || (dest_reads_later && generation_live_after_consumer(proto, meta, *dest, pc + 2))
        {
            continue;
        }
        let (left, right) = if swap {
            (*right, *left)
        } else {
            (*left, *right)
        };
        result[pc] = Some(CompareBranchFusion {
            phi,
            target,
            opcode,
            left,
            right,
            invert,
        });
    }
    Ok(result)
}

fn stripped_native_header_lines(
    entries: &[NativePrototypeDebug],
    id: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<(u32, u32), OfficialExportError> {
    for entry in entries {
        work_charge(work, 1, id, 0)?;
        if entry.prototype == id {
            return Ok((entry.line_defined, entry.last_line_defined));
        }
    }
    Ok((0, 0))
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
    let meta = layout(
        module,
        proto,
        root,
        profile,
        &numeric,
        numeric_blocks,
        limits.max_allocated_bytes,
        work,
        limits,
    )?;
    let (word_limit, end_line) =
        native_word_count(module, &close_groups, proto, &meta, root, work)?;
    verify_bare_close_layout(module, proto, &meta, &close_groups, work, limits)?;
    for pair in &mut numeric {
        pair.tuple = if let Some(alias) = meta
            .numeric_aliases
            .iter()
            .find(|alias| alias.body_pc == pair.body_pc)
        {
            alias.tuple
        } else {
            meta.tuple_base
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
                })?
        };
    }
    let direct_inits = direct_numeric_inits(module, proto, &meta, &numeric, work)?;
    let direct_copies = direct_const_copies(module, proto, &meta, work)?;
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
    let mut compare_fusions = compare_branch_fusions(module, proto, &meta, work)?;
    let terminal_fusions = terminal_compare_fusions(
        proto,
        &meta,
        module.native_debug().and_then(|debug| debug.prototype(id)),
        &compare_fusions,
        work,
    )?;
    work_charge(work, compare_fusions.len(), id, 0)?;
    for (pc, plan) in compare_fusions.iter_mut().enumerate() {
        let Some(fusion) = plan else { continue };
        let terminal_pc = fusion.target.0 as usize - 2;
        if terminal_fusions[terminal_pc].is_some() {
            continue;
        }
        let phi = meta.register(fusion.phi, id, pc)?;
        if phi == meta.register(fusion.left, id, pc)?
            || phi == meta.register(fusion.right, id, pc)?
        {
            // 非終端路徑會先寫 LOADFALSE；共槽時須保留原比較結果實體化。
            *plan = None;
        }
    }
    let env_fusions = env_field_fusions(module, proto, &meta, work)?;
    let exit_nil_fusions = loop_exit_nil_fusions(module, proto, &meta, &numeric, profile, work)?;
    let debug_entry = if strip {
        None
    } else {
        module.native_debug().and_then(|debug| debug.prototype(id))
    };
    let (line_defined, last_line_defined) = if strip {
        if let Some(debug) = module.native_debug() {
            stripped_native_header_lines(debug.prototypes(), id, work)?
        } else {
            (0, 0)
        }
    } else {
        debug_entry.map_or((0, 0), |entry| {
            (entry.line_defined, entry.last_line_defined)
        })
    };
    let reserve_words = word_limit.min(limits.max_instructions.saturating_sub(*total_instructions));
    let mut code = Vec::new();
    code.try_reserve_exact(reserve_words).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            id,
            0,
            "native 指令預付配置失敗",
        )
    })?;
    let mut lines = Vec::new();
    if debug_entry.is_some() {
        lines.try_reserve_exact(reserve_words).map_err(|_| {
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
        max_words: reserve_words,
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
    let mut conditional_false_jumps: Vec<(usize, usize)> = Vec::new();
    conditional_false_jumps
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "條件短路 patch 配置失敗",
            )
        })?;
    let mut conditional_false_blocks = Vec::new();
    conditional_false_blocks
        .try_reserve_exact(proto.instructions.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "條件短路位置配置失敗",
            )
        })?;
    conditional_false_blocks.resize(proto.instructions.len(), None);
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
    work_charge(
        builder.work,
        direct_inits
            .len()
            .checked_mul(proto.instructions.len())
            .and_then(|count| count.checked_mul(3))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "numeric direct lookup 工作量溢位",
                )
            })?,
        id,
        0,
    )?;
    for (pc, entry) in proto.instructions.iter().enumerate() {
        let r = |register| meta.register(register, id, pc);
        if let Some((pair_index, pair)) = numeric
            .iter()
            .enumerate()
            .find(|(_, pair)| pair.body_pc == pc)
        {
            // 官方 FORLOOP 回邊先更新可見變數；一般 RVLU goto 直接進入 body PC。
            numeric_entry[pair_index] = builder.code.len();
            if !meta
                .numeric_aliases
                .iter()
                .any(|alias| alias.body_pc == pair.body_pc)
            {
                let source = pair.tuple + if profile == LuaProfile::Lua54 { 3 } else { 2 };
                builder.push(abc(0, r(pair.visible)?, source, 0, false), pc)?;
            }
        }
        anchors.push(builder.code.len());
        let (reads_env, writes_env) = environment_access(proto, pc, &meta, builder.work)?;
        if reads_env && env_fusions[pc].is_none() {
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
                let direct_move = direct_inits
                    .iter()
                    .any(|plan| (0..3).any(|offset| pc == plan.first_load_pc + offset * 2 + 1))
                    || direct_copies
                        .iter()
                        .any(|plan| pc == plan.first_pc + 1 || pc == plan.first_pc + 2);
                if (pc == 0 || compare_fusions[pc - 1].is_none())
                    && (pc == 0 || terminal_fusions[pc - 1].is_none())
                    && !direct_move
                {
                    builder.push(abc(0, r(*dest)?, r(*src)?, 0, false), pc)?;
                    if entry.close_path.is_some() {
                        let destination = r(*dest)?;
                        builder.push(abc(55, destination, 0, 0, false), pc)?;
                    }
                }
            }
            Instruction::LoadConst { dest, constant } => {
                if env_fusions
                    .get(pc + 1)
                    .is_some_and(|fusion| fusion.is_some())
                {
                    continue;
                }
                let direct_slot = direct_inits
                    .iter()
                    .find_map(|plan| {
                        (0..3).find_map(|offset| {
                            (pc == plan.first_load_pc + offset * 2)
                                .then_some(plan.tuple + offset as u8)
                        })
                    })
                    .or_else(|| {
                        direct_copies
                            .iter()
                            .find_map(|plan| (pc == plan.first_pc).then_some(plan.slot))
                    });
                let destination = direct_slot.map(Ok).unwrap_or_else(|| r(*dest))?;
                if constant.0 <= 131_071 {
                    builder.push(abx(3, destination, constant.0), pc)?;
                } else {
                    builder.push(abc(4, destination, 0, 0, false), pc)?;
                    builder.push(ax(extra_opcode(profile), constant.0), pc)?;
                }
            }
            Instruction::LoadNil { start, count } => {
                if let Some(fusion) = exit_nil_fusions[pc] {
                    builder.push(abc(8, fusion.first_slot, fusion.count, 0, false), pc)?;
                } else if pc > 0 && exit_nil_fusions[pc - 1].is_some() {
                    // 兩個必要清槽與其間已證實死亡的槽已由前一個 LOADNIL 清除。
                } else if meta
                    .numeric_aliases
                    .iter()
                    .any(|alias| alias.body_pc == pc && alias.anchor == *start && *count == 1)
                {
                    // CFG label 的 nil 在下一次可觀察讀取前已被確定覆寫；
                    // 無後讀者使用 nil home，有後讀者保留原 allocator home。
                } else if call_cleanup_range(proto, pc).is_some() {
                    work_charge(builder.work, 255, id, pc)?;
                    let cleanup =
                        cleanup_slots_at(&meta.call_cleanup_slots, proto, pc, builder.work)?;
                    let mut slot = 0usize;
                    while slot <= 254 {
                        if !cleanup_slot_contains(cleanup, slot as u8) {
                            slot += 1;
                            continue;
                        }
                        let start = slot;
                        while slot <= 254 && cleanup_slot_contains(cleanup, slot as u8) {
                            slot += 1;
                        }
                        let first = u8::try_from(start).map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "call cleanup 起點超限",
                            )
                        })?;
                        let count = u8::try_from(slot - start - 1).map_err(|_| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "call cleanup 長度超限",
                            )
                        })?;
                        builder.push(abc(8, first, count, 0, false), pc)?;
                    }
                } else {
                    let mut occupied = [0u8; 32];
                    let debug = module.native_debug().and_then(|debug| debug.prototype(id));
                    if let Some(debug) = debug {
                        work_charge(builder.work, debug.locals.len(), id, pc)?;
                        let end = usize::from(start.0) + usize::from(*count);
                        for local in &debug.locals {
                            let register = usize::from(local.register.0);
                            if (register < usize::from(start.0) || register >= end)
                                && local.initialized_pc as usize <= pc
                                && pc < local.end_pc as usize
                            {
                                cleanup_slot_set(&mut occupied, r(local.register)?);
                            }
                        }
                    }
                    if *count > 1 {
                        let end = usize::from(start.0)
                            .checked_add(usize::from(*count))
                            .ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "LoadNil occupied 範圍溢位",
                                )
                            })?;
                        let per_register =
                            meta.numeric_aliases.len().checked_add(1).ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "LoadNil occupied work 溢位",
                                )
                            })?;
                        work_charge(
                            builder.work,
                            meta.mapped.len().checked_mul(per_register).ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "LoadNil occupied work 溢位",
                                )
                            })?,
                            id,
                            pc,
                        )?;
                        for register in 0..meta.mapped.len() {
                            if usize::from(start.0) <= register && register < end
                                || meta.protected[register] != 0
                                || !matches!(meta.live_at.get(register), Some(LiveRow::Bits { .. }))
                                || !live_at_pc(
                                    &meta.span,
                                    &meta.protected,
                                    &meta.live_at,
                                    register,
                                    pc,
                                )
                                || !live_at_pc(
                                    &meta.span,
                                    &meta.protected,
                                    &meta.live_at,
                                    register,
                                    pc + 1,
                                )
                            {
                                continue;
                            }
                            let register = Register(u16::try_from(register).map_err(|_| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "LoadNil occupied register 超限",
                                )
                            })?);
                            cleanup_slot_set(&mut occupied, r(register)?);
                        }
                    }
                    let mut dead_temporary = true;
                    let mut cleared = [0u8; 32];
                    for offset in 0..*count {
                        let register = start.0.checked_add(offset).ok_or_else(|| {
                            error(
                                OfficialExportErrorKind::LimitExceeded,
                                id,
                                pc,
                                "LoadNil register 溢位",
                            )
                        })?;
                        let register = Register(register);
                        if proto
                            .binding_registers
                            .iter()
                            .any(|(_, bound)| *bound == register)
                            || debug.is_some_and(|debug| {
                                debug.locals.iter().any(|local| {
                                    local.register == register
                                        && local.initialized_pc as usize <= pc
                                        && pc < local.end_pc as usize
                                })
                            })
                        {
                            dead_temporary = false;
                        }
                        let slot = r(register)?;
                        if !cleanup_slot_contains(&occupied, slot)
                            && !nil_after_direct_const_copy(
                                proto,
                                &meta,
                                &direct_copies,
                                &direct_inits,
                                &exit_nil_fusions,
                                &numeric,
                                pc,
                                slot,
                                builder.work,
                            )?
                        {
                            cleanup_slot_set(&mut cleared, slot);
                        }
                    }
                    if dead_temporary {
                        work_charge(builder.work, 255, id, pc)?;
                        let mut slot = 0usize;
                        while slot <= 254 {
                            if !cleanup_slot_contains(&cleared, slot as u8) {
                                slot += 1;
                                continue;
                            }
                            let first = slot;
                            while slot <= 254 && cleanup_slot_contains(&cleared, slot as u8) {
                                slot += 1;
                            }
                            builder.push(
                                abc(8, first as u8, (slot - first - 1) as u8, 0, false),
                                pc,
                            )?;
                        }
                    } else {
                        for offset in 0..*count {
                            let register = start.0.checked_add(offset).ok_or_else(|| {
                                error(
                                    OfficialExportErrorKind::LimitExceeded,
                                    id,
                                    pc,
                                    "LoadNil register 溢位",
                                )
                            })?;
                            let slot = r(Register(register))?;
                            if !cleanup_slot_contains(&occupied, slot)
                                && !nil_after_direct_const_copy(
                                    proto,
                                    &meta,
                                    &direct_copies,
                                    &direct_inits,
                                    &exit_nil_fusions,
                                    &numeric,
                                    pc,
                                    slot,
                                    builder.work,
                                )?
                            {
                                builder.push(abc(8, slot, 0, 0, false), pc)?;
                            }
                        }
                    }
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
                if let Some(fusion) = env_fusions[pc] {
                    let upvalue = u8::try_from(meta.env_upvalue.ok_or_else(|| {
                        error(
                            OfficialExportErrorKind::InvalidPrototype,
                            id,
                            pc,
                            "環境欄位缺 upvalue",
                        )
                    })?)
                    .map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            pc,
                            "環境欄位 upvalue 超限",
                        )
                    })?;
                    builder.push(abc(11, r(*dest)?, upvalue, fusion.field, false), pc)?;
                } else {
                    builder.push(abc(12, r(*dest)?, r(*table)?, r(*key)?, false), pc)?;
                }
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
                if let Some(fusion) = compare_fusions[pc] {
                    if fusion.target.0 >= 2
                        && terminal_fusions[(fusion.target.0 as usize) - 2].is_some()
                    {
                        // 比較為 false 時直接跳至終端 false block；true 時略過
                        // 這個 JMP，自然落入 RHS。條件 opcode 後仍緊接 JMP。
                        let words = chained_compare_words(
                            fusion.opcode,
                            r(fusion.left)?,
                            r(fusion.right)?,
                            fusion.invert,
                            id,
                            pc,
                        )?;
                        builder.push(words[0], pc)?;
                        conditional_false_jumps
                            .push((builder.code.len(), fusion.target.0 as usize - 2));
                        builder.push(words[1], pc)?;
                    } else {
                        builder.push(abc(5, r(fusion.phi)?, 0, 0, false), pc)?;
                        builder.push(
                            abc(
                                fusion.opcode,
                                r(fusion.left)?,
                                r(fusion.right)?,
                                0,
                                fusion.invert,
                            ),
                            pc,
                        )?;
                    }
                } else if let Some(fusion) = terminal_fusions[pc] {
                    let words = terminal_compare_words(
                        fusion.opcode,
                        r(fusion.left)?,
                        r(fusion.right)?,
                        r(fusion.phi)?,
                        fusion.invert,
                        id,
                        pc,
                    )?;
                    builder.push(words[0], pc)?;
                    builder.push(words[1], pc)?;
                    conditional_false_blocks[pc] = Some(builder.code.len());
                    // LFALSESKIP 設 false 並跳過下一個 LOADTRUE；比較與可能的
                    // metamethod 錯誤仍先於 phi 寫入。
                    builder.push(words[2], pc)?;
                    builder.push(words[3], pc)?;
                } else if let Some((opcode, event)) = arithmetic {
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
                } else if let Some((opcode, swap, invert)) = comparison_opcode(op) {
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
                if pc >= 2 && compare_fusions[pc - 2].is_some() {
                    if !(target.0 >= 2 && terminal_fusions[(target.0 as usize) - 2].is_some()) {
                        patches.push((builder.code.len(), *target));
                        builder.push(jump(0, id, pc)?, pc)?;
                    }
                } else {
                    builder.push(abc(66, r(*condition)?, 0, 0, false), pc)?;
                    patches.push((builder.code.len(), *target));
                    builder.push(jump(0, id, pc)?, pc)?;
                }
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
                    emit_fixed_call_pending_moves(&mut builder, module, proto, &meta, pc, true)?;
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
                    emit_fixed_call_pending_moves(&mut builder, module, proto, &meta, pc, false)?;
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
                    let first = r(*base)?;
                    builder.push(abc(54, first, 0, 0, false), pc)?;
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
                if !direct_inits.iter().any(|plan| plan.prepare_pc == pc) {
                    for (offset, source) in [*control, *limit, *step].iter().enumerate() {
                        builder
                            .push(abc(0, pair.tuple + offset as u8, r(*source)?, 0, false), pc)?;
                    }
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
                if pair.exit.0 as usize != pc + 1 {
                    patches.push((builder.code.len(), pair.exit));
                    builder.push(jump(0, id, pc)?, pc)?;
                }
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
    work_charge(builder.work, conditional_false_jumps.len(), id, 0)?;
    for (at, terminal_pc) in conditional_false_jumps {
        let destination = conditional_false_blocks
            .get(terminal_pc)
            .copied()
            .flatten()
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    terminal_pc,
                    "條件短路 false block 不存在",
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
                    "條件短路 jump 距離溢位",
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
    if let Some(end_line) = end_line {
        if !matches!(
            builder.code.last().map(|word| word & 0x7f),
            Some(56 | 69..=72)
        ) {
            return Err(error(
                OfficialExportErrorKind::InvalidPrototype,
                id,
                proto.instructions.len(),
                "native 末行前缺少終止指令",
            ));
        }
        builder.push(abc(71, 0, 0, 0, false), proto.instructions.len())?;
        if let Some(line) = builder.lines.last_mut() {
            *line = end_line;
        }
    }
    let debug = if let Some(entry) = debug_entry {
        let (line_info, abs_line_info) =
            native_line_info(id, &builder.lines, entry.line_defined, builder.work)?;
        let mut locals = Vec::new();
        let control_locals = meta
            .numeric_aliases
            .iter()
            .try_fold(0usize, |count, alias| {
                count.checked_add(usize::from(alias.width)).ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        alias.body_pc,
                        "numeric debug local 數溢位",
                    )
                })
            })?;
        let total_locals = entry
            .locals
            .len()
            .checked_add(usize::from(meta.anonymous_vararg_slot.is_some()))
            .and_then(|count| count.checked_add(control_locals))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "numeric debug local 數溢位",
                )
            })?;
        locals.try_reserve_exact(total_locals).map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "native official locals 配置失敗",
            )
        })?;
        for local in &entry.locals {
            work_charge(builder.work, 1, id, local.start_pc as usize)?;
            let parameter = u16::from(local.slot) < proto.parameter_count
                && local.register.0 == u16::from(local.slot) + 1
                && local.initialized_pc == 0
                && local.start_pc == 0;
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
            let mut alias_end_pc = None;
            if let Some(alias) = meta.numeric_aliases.iter().find(|alias| {
                alias.visible == local.register
                    && local.start_pc as usize <= alias.body_pc
                    && local.end_pc as usize > alias.next_pc
            }) {
                let start_pc = source_pc(u32::try_from(alias.prepare_pc).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        alias.prepare_pc,
                        "numeric debug 起點溢位",
                    )
                })?)?;
                let end_pc = source_pc(u32::try_from(alias.next_pc + 1).map_err(|_| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        alias.next_pc,
                        "numeric debug 終點溢位",
                    )
                })?)?;
                alias_end_pc = Some(end_pc);
                work_charge(builder.work, usize::from(alias.width), id, alias.body_pc)?;
                for _ in 0..alias.width {
                    locals.push(OfficialLocal {
                        name: Some(copy_slice(NUMERIC_CONTROL_LOCAL, id, builder.work)?),
                        start_pc,
                        end_pc,
                    });
                }
            }
            locals.push(OfficialLocal {
                name: Some(copy_slice(&local.name, id, builder.work)?),
                start_pc: if parameter {
                    0
                } else {
                    source_pc(local.start_pc)?
                },
                end_pc: if let Some(end_pc) = alias_end_pc {
                    end_pc
                } else {
                    source_pc(local.end_pc)?
                },
            });
        }
        if meta.anonymous_vararg_slot.is_some() {
            let position = usize::from(proto.parameter_count);
            if position > locals.len() {
                return Err(error(
                    OfficialExportErrorKind::InvalidPrototype,
                    id,
                    0,
                    "匿名 vararg 前缺少參數 debug local",
                ));
            }
            work_charge(builder.work, locals.len() - position + 1, id, 0)?;
            locals.insert(
                position,
                OfficialLocal {
                    name: Some(copy_slice(ANONYMOUS_VARARG_LOCAL, id, builder.work)?),
                    start_pc: 1,
                    end_pc: u32::try_from(builder.code.len()).map_err(|_| {
                        error(
                            OfficialExportErrorKind::LimitExceeded,
                            id,
                            0,
                            "匿名 vararg debug local PC 溢位",
                        )
                    })?,
                },
            );
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
        line_defined,
        last_line_defined,
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
    preflight_native_prototype(
        module,
        root,
        true,
        profile,
        strip,
        1,
        limits,
        work,
        &mut preflight,
    )?;
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

    #[test]
    fn stripped_header_lines_preserve_span_and_charge_lookup() {
        let entry = |id, line_defined, last_line_defined| NativePrototypeDebug {
            prototype: ProtoId(id),
            line_defined,
            last_line_defined,
            lines: Vec::new(),
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            max_active_locals: 0,
        };
        let entries = [entry(0, 1, 9), entry(1, 5, 5)];
        let mut short = OfficialWorkBudget::new(1);
        assert_eq!(
            stripped_native_header_lines(&entries, ProtoId(1), &mut short)
                .expect_err("第二筆 metadata 掃描須收費")
                .kind,
            OfficialExportErrorKind::WorkExhausted,
        );
        let mut exact = OfficialWorkBudget::new(2);
        assert_eq!(
            stripped_native_header_lines(&entries, ProtoId(1), &mut exact).unwrap(),
            (5, 5),
        );
        assert_eq!(exact.remaining(), 0);
    }

    #[test]
    fn numeric_alias_prior_read_requires_no_reentry_and_prior_close_always_rejects() {
        assert!(!numeric_alias_anchor_observed(
            5, 10, 12, true, false, false
        ));
        assert!(numeric_alias_anchor_observed(5, 10, 12, true, false, true));
        assert!(numeric_alias_anchor_observed(5, 10, 12, false, true, false));
        assert!(numeric_alias_anchor_observed(
            10, 10, 12, true, false, false
        ));
        assert!(!numeric_alias_anchor_observed(
            13, 10, 12, true, false, false
        ));
        assert!(numeric_alias_anchor_observed(
            13, 10, 12, false, true, false
        ));
    }

    #[test]
    fn native_preflight_charges_fusion_arrays_and_numeric_control_names() {
        let defaults = OfficialChunkLimits::default();
        let mut stats = NativePreflight::default();
        preflight_native_fusion_arrays(&mut stats, 9, 1, &defaults, ProtoId(0)).unwrap();
        preflight_numeric_control_names(&mut stats, 3, &defaults, ProtoId(0)).unwrap();
        let expected_arrays = size_of::<DirectNumericInit>()
            + 2 * size_of::<DirectConstCopy>()
            + 9 * (size_of::<Option<CompareBranchFusion>>()
                + size_of::<Option<TerminalCompareFusion>>()
                + size_of::<Option<EnvFieldFusion>>()
                + size_of::<Option<LoopExitNilFusion>>()
                + size_of::<(usize, usize)>()
                + size_of::<Option<usize>>());
        assert_eq!(
            stats.allocated_bytes,
            expected_arrays + 3 * NUMERIC_CONTROL_LOCAL.len()
        );
        assert_eq!(stats.strings, 3);
        assert_eq!(stats.string_bytes, 3 * NUMERIC_CONTROL_LOCAL.len());

        let mut tight = defaults.clone();
        tight.max_allocated_bytes = stats.allocated_bytes - 1;
        let mut bounded = NativePreflight::default();
        preflight_native_fusion_arrays(&mut bounded, 9, 1, &tight, ProtoId(0)).unwrap();
        assert_eq!(
            preflight_numeric_control_names(&mut bounded, 3, &tight, ProtoId(0))
                .expect_err("少一 byte 必須拒絕")
                .kind,
            OfficialExportErrorKind::LimitExceeded,
        );
        tight.max_allocated_bytes = stats.allocated_bytes;
        bounded = NativePreflight::default();
        preflight_native_fusion_arrays(&mut bounded, 9, 1, &tight, ProtoId(0)).unwrap();
        preflight_numeric_control_names(&mut bounded, 3, &tight, ProtoId(0)).unwrap();

        tight.max_strings = 2;
        bounded = NativePreflight::default();
        assert_eq!(
            preflight_numeric_control_names(&mut bounded, 3, &tight, ProtoId(0))
                .expect_err("第三個控制 local 名稱必須計數")
                .kind,
            OfficialExportErrorKind::LimitExceeded,
        );
        tight.max_strings = defaults.max_strings;
        tight.max_total_string_bytes = 3 * NUMERIC_CONTROL_LOCAL.len() - 1;
        bounded = NativePreflight::default();
        assert_eq!(
            preflight_numeric_control_names(&mut bounded, 3, &tight, ProtoId(0))
                .expect_err("控制 local 名稱總 byte 必須計數")
                .kind,
            OfficialExportErrorKind::LimitExceeded,
        );
    }

    #[test]
    fn terminal_compare_fusion_requires_single_anonymous_result_consumer() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::BinaryOp {
                dest: Register(5),
                op: BinaryOperation::Less,
                left: Register(1),
                right: Register(2),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(5),
            },
            Instruction::Return {
                base: Register(3),
                result_mode: ResultMode::Fixed(1),
            },
        ]);
        let layout = Layout {
            anonymous_vararg_slot: None,
            tuple_base: 0,
            scratch: Vec::new(),
            parallel_spare: Vec::new(),
            call_cleanup_slots: Vec::new(),
            max_stack: 9,
            guest_upvalue_offset: 0,
            env_upvalue: None,
            mapped: (0..9).collect(),
            protected: vec![0; usize::from(proto.register_count)],
            span: vec![(0, proto.instructions.len()); usize::from(proto.register_count)],
            live_at: (0..usize::from(proto.register_count))
                .map(|_| LiveRow::Uncomputed)
                .collect(),
            numeric_aliases: Vec::new(),
        };
        let mut first = vec![None; proto.instructions.len()];
        first[0] = Some(CompareBranchFusion {
            phi: Register(3),
            target: InstructionOffset(8),
            opcode: 58,
            left: Register(1),
            right: Register(2),
            invert: false,
        });
        let mut debug = NativePrototypeDebug {
            prototype: ProtoId(0),
            line_defined: 1,
            last_line_defined: 1,
            lines: vec![1; proto.instructions.len()],
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            max_active_locals: 0,
        };
        let check = |proto: &BytecodePrototype, debug: &NativePrototypeDebug| {
            terminal_compare_fusions(
                proto,
                &layout,
                Some(debug),
                &first,
                &mut OfficialWorkBudget::new(10_000),
            )
            .unwrap()[6]
                .is_some()
        };
        assert!(check(&proto, &debug));
        proto.binding_registers.push((
            super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 1,
            },
            Register(5),
        ));
        assert!(
            !check(&proto, &debug),
            "具名結果必須走保留 materialization 的路徑"
        );
        proto.binding_registers.clear();
        proto.instructions[8].instruction = Instruction::Move {
            dest: Register(6),
            src: Register(5),
        };
        assert!(
            !check(&proto, &debug),
            "額外讀取 terminal 結果必須走 fallback"
        );
        proto.instructions[8].instruction = Instruction::Return {
            base: Register(3),
            result_mode: ResultMode::Fixed(1),
        };
        debug.lines[7] = 2;
        assert!(!check(&proto, &debug), "跨來源行的 Move 必須保留");
        debug.lines[7] = 1;
        debug.locals.push(NativeLocal {
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 2,
            },
            register: Register(5),
            slot: 5,
            initialized_pc: 6,
            start_pc: 6,
            end_pc: 9,
            name: b"result".to_vec(),
        });
        assert!(!check(&proto, &debug), "debug local 的結果槽必須保留");
        debug.locals.clear();
        proto.instructions[3].instruction = Instruction::Jump {
            target: InstructionOffset(7),
        };
        assert!(!check(&proto, &debug), "外部入邊不可略過終端結果的定義");
    }

    fn relay_instructions(instructions: Vec<Instruction>) -> Vec<BytecodeInstruction> {
        let span = super::super::codec::BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        instructions
            .into_iter()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect()
    }

    fn relay_fixture() -> Vec<Instruction> {
        vec![
            Instruction::LoadNil {
                start: Register(2),
                count: 2,
            },
            Instruction::NewTable { dest: Register(3) },
            Instruction::Call {
                base: Register(5),
                arg_count: 0,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Move {
                dest: Register(2),
                src: Register(3),
            },
            Instruction::Call {
                base: Register(2),
                arg_count: 0,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::Return {
                base: Register(2),
                result_mode: ResultMode::Fixed(1),
            },
        ]
    }

    fn relay_proof(instructions: Vec<Instruction>, call_pc: usize) -> Option<usize> {
        pending_move_relay_alias(
            &relay_instructions(instructions),
            8,
            ProtoId(0),
            call_pc,
            Register(3),
            Register(2),
            &[],
            &mut OfficialWorkBudget::new(10_000),
        )
        .unwrap()
        .map(|(relay, _)| relay)
    }

    #[test]
    fn pending_relay_proof_accepts_straight_move_to_fixed_call() {
        assert_eq!(relay_proof(relay_fixture(), 2), Some(3));
    }

    #[test]
    fn pending_relay_proof_requires_adjacent_open_producer_for_dynamic_consumer() {
        let mut open = relay_fixture();
        open[3] = Instruction::Move {
            dest: Register(4),
            src: Register(3),
        };
        open[4] = Instruction::Call {
            base: Register(5),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        open[5] = Instruction::TailCall {
            base: Register(4),
            arg_count: u16::MAX,
            result_mode: ResultMode::All,
        };
        let prove = |instructions: Vec<Instruction>| {
            pending_move_relay_alias(
                &relay_instructions(instructions),
                8,
                ProtoId(0),
                2,
                Register(3),
                Register(4),
                &[],
                &mut OfficialWorkBudget::new(10_000),
            )
            .unwrap()
            .map(|(relay, _)| relay)
        };
        assert_eq!(prove(open.clone()), Some(3));
        open.insert(
            5,
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
        );
        assert_eq!(prove(open), None);
    }

    #[test]
    fn pending_relay_proof_accepts_fixed_prefix_below_open_producer() {
        let mut instructions = relay_fixture();
        instructions[2] = Instruction::Call {
            base: Register(7),
            arg_count: 0,
            result_mode: ResultMode::Fixed(0),
        };
        instructions[3] = Instruction::Move {
            dest: Register(5),
            src: Register(3),
        };
        instructions[4] = Instruction::Call {
            base: Register(6),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        instructions[5] = Instruction::TailCall {
            base: Register(4),
            arg_count: u16::MAX,
            result_mode: ResultMode::All,
        };
        let prove = |instructions: Vec<Instruction>| {
            pending_move_relay_alias(
                &relay_instructions(instructions),
                8,
                ProtoId(0),
                2,
                Register(3),
                Register(5),
                &[],
                &mut OfficialWorkBudget::new(10_000),
            )
            .unwrap()
        };
        assert_eq!(prove(instructions.clone()), Some((3, 5)));
        instructions[5] = Instruction::TailCall {
            base: Register(6),
            arg_count: u16::MAX,
            result_mode: ResultMode::All,
        };
        assert_eq!(prove(instructions), None);
    }

    #[test]
    fn pending_relay_reverse_revisit_requires_same_pair_and_open_consumer() {
        let pair = PendingRelayPair {
            source: Register(15),
            destination: Register(19),
            move_pc: 21,
            consumer_pc: 27,
            slot: 0,
        };
        let reservations = [(0, 22, 22)];
        let revisit =
            |source, destination, slot, call_pc, terminal, source_span, destination_span| {
                pending_relay_reverse_revisit(
                    pair,
                    source,
                    destination,
                    slot,
                    call_pc,
                    terminal,
                    source_span,
                    destination_span,
                    &reservations,
                )
            };
        assert!(revisit(
            Register(15),
            Register(19),
            0,
            26,
            Some(27),
            (16, 22),
            (21, 28)
        ));
        assert!(!revisit(
            Register(15),
            Register(20),
            0,
            26,
            Some(27),
            (16, 22),
            (21, 28)
        ));
        assert!(!revisit(
            Register(15),
            Register(19),
            0,
            25,
            Some(28),
            (16, 22),
            (21, 28)
        ));
        assert!(!revisit(
            Register(15),
            Register(19),
            0,
            26,
            Some(27),
            (16, 23),
            (21, 28)
        ));
        assert!(!revisit(
            Register(15),
            Register(19),
            1,
            26,
            Some(27),
            (16, 22),
            (21, 28)
        ));
    }

    #[test]
    fn pending_relay_proof_rejects_destination_read_or_write_while_source_is_live() {
        let mut read = relay_fixture();
        read.insert(
            2,
            Instruction::Move {
                dest: Register(6),
                src: Register(2),
            },
        );
        assert_eq!(relay_proof(read, 3), None);
        let mut write = relay_fixture();
        write.insert(
            2,
            Instruction::LoadNil {
                start: Register(2),
                count: 1,
            },
        );
        assert_eq!(relay_proof(write, 3), None);
    }

    #[test]
    fn pending_relay_proof_rejects_nonrelay_branch_loop_and_simultaneous_use() {
        let mut nonrelay = relay_fixture();
        nonrelay[3] = Instruction::Move {
            dest: Register(6),
            src: Register(3),
        };
        assert_eq!(relay_proof(nonrelay, 2), None);

        let mut branch = relay_fixture();
        branch.insert(
            2,
            Instruction::JumpIfFalse {
                condition: Register(7),
                target: InstructionOffset(3),
            },
        );
        assert_eq!(relay_proof(branch, 3), None);

        let mut looped = relay_fixture();
        looped.insert(
            5,
            Instruction::Jump {
                target: InstructionOffset(1),
            },
        );
        assert_eq!(relay_proof(looped, 2), None);

        let mut simultaneous = relay_fixture();
        simultaneous.insert(
            4,
            Instruction::Move {
                dest: Register(6),
                src: Register(3),
            },
        );
        assert_eq!(relay_proof(simultaneous, 2), None);
    }

    fn result_local(source: Register, slot: u8, initialized_pc: u32) -> NativeLocal {
        NativeLocal {
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: u32::from(slot),
            },
            register: source,
            slot,
            initialized_pc,
            start_pc: initialized_pc,
            end_pc: 10,
            name: b"result".to_vec(),
        }
    }

    fn open_result_local_fixture() -> Vec<Instruction> {
        vec![
            Instruction::LoadNil {
                start: Register(2),
                count: 3,
            },
            Instruction::NewTable { dest: Register(3) },
            Instruction::Call {
                base: Register(7),
                arg_count: 0,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Call {
                base: Register(4),
                arg_count: 0,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::Move {
                dest: Register(2),
                src: Register(3),
            },
            Instruction::LoadNil {
                start: Register(3),
                count: 2,
            },
            Instruction::Return {
                base: Register(2),
                result_mode: ResultMode::Fixed(1),
            },
        ]
    }

    fn open_result_local_proof(
        instructions: Vec<Instruction>,
        locals: &[NativeLocal],
    ) -> Option<usize> {
        pending_open_result_local_alias(
            &relay_instructions(instructions),
            9,
            ProtoId(0),
            2,
            Register(3),
            Register(2),
            locals,
            &mut OfficialWorkBudget::new(100_000),
        )
        .unwrap()
    }

    #[test]
    fn pending_open_result_local_alias_accepts_straight_handoff() {
        let local = result_local(Register(2), 0, 5);
        assert_eq!(
            open_result_local_proof(open_result_local_fixture(), &[local]),
            Some(6)
        );
        let mut two = open_result_local_fixture();
        two[4] = Instruction::Call {
            base: Register(3),
            arg_count: u16::MAX,
            result_mode: ResultMode::Fixed(2),
        };
        two.insert(
            6,
            Instruction::Move {
                dest: Register(6),
                src: Register(4),
            },
        );
        assert_eq!(
            open_result_local_proof(
                two,
                &[
                    result_local(Register(2), 0, 5),
                    result_local(Register(6), 1, 6),
                ]
            ),
            Some(7)
        );
    }

    #[test]
    fn pending_open_result_local_alias_rejects_early_or_wrong_handoff() {
        let mut early = result_local(Register(2), 0, 4);
        assert_eq!(
            open_result_local_proof(open_result_local_fixture(), &[early.clone()]),
            None
        );
        early.initialized_pc = 5;
        early.start_pc = 5;
        let mut nonadjacent = open_result_local_fixture();
        nonadjacent.insert(
            5,
            Instruction::LoadNil {
                start: Register(8),
                count: 1,
            },
        );
        assert_eq!(open_result_local_proof(nonadjacent, &[early.clone()]), None);
        let mut wrong_source = open_result_local_fixture();
        wrong_source[5] = Instruction::Move {
            dest: Register(2),
            src: Register(4),
        };
        assert_eq!(
            open_result_local_proof(wrong_source, &[early.clone()]),
            None
        );
        let mut later_read = open_result_local_fixture();
        later_read.insert(
            6,
            Instruction::Move {
                dest: Register(8),
                src: Register(3),
            },
        );
        assert_eq!(open_result_local_proof(later_read, &[early.clone()]), None);
        let mut branch = open_result_local_fixture();
        branch[0] = Instruction::Jump {
            target: InstructionOffset(4),
        };
        assert_eq!(open_result_local_proof(branch, &[early]), None);
    }

    fn dead_open_fixture(instructions: Vec<Instruction>) -> BytecodePrototype {
        let span = super::super::codec::BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        BytecodePrototype {
            id: ProtoId(0),
            function: 0,
            parent: None,
            span,
            register_count: 9,
            parameter_count: 0,
            is_variadic: false,
            named_vararg: None,
            frame: super::super::FrameLayout {
                register_limit: 9,
                initial_top: Register(0),
                dynamic_top: Register(0),
                return_base: Register(0),
                environment: Register(0),
                environment_source: EnvironmentSource::RootExternal,
                registers_start_as_nil: true,
            },
            global_environment: Register(0),
            global_environment_binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 0,
            },
            binding_registers: Vec::new(),
            constants: Vec::new(),
            upvalues: Vec::new(),
            instructions: relay_instructions(instructions),
            close_paths: Vec::new(),
        }
    }

    fn producer_generation_test_layout(proto: &BytecodePrototype) -> Layout {
        let registers = usize::from(proto.register_count);
        let mut span = vec![(0, proto.instructions.len()); registers];
        let mut work = OfficialWorkBudget::new(100_000);
        let live_at = extend_live_spans(
            proto,
            &vec![u8::MAX; registers],
            &mut span,
            &[],
            usize::MAX,
            &mut work,
        )
        .unwrap();
        Layout {
            anonymous_vararg_slot: None,
            tuple_base: 0,
            scratch: Vec::new(),
            parallel_spare: Vec::new(),
            call_cleanup_slots: Vec::new(),
            max_stack: 9,
            guest_upvalue_offset: 0,
            env_upvalue: None,
            mapped: (0..registers as u8).collect(),
            protected: vec![0; registers],
            span,
            live_at,
            numeric_aliases: Vec::new(),
        }
    }

    #[test]
    fn direct_numeric_init_reused_temporary_requires_def_on_every_path() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::Move {
                dest: Register(1),
                src: Register(5),
            },
            Instruction::JumpIfFalse {
                condition: Register(2),
                target: InstructionOffset(5),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(1),
            },
            Instruction::Jump {
                target: InstructionOffset(6),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(2),
            },
            Instruction::Move {
                dest: Register(6),
                src: Register(5),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let check = |proto: &BytecodePrototype| {
            generation_live_after_consumer(
                proto,
                &producer_generation_test_layout(proto),
                Register(5),
                1,
            )
        };
        assert!(
            !check(&proto),
            "後代讀取若每條路徑先有確定定義，可省略初始化暫存 home"
        );
        proto.instructions[5].instruction = Instruction::LoadNil {
            start: Register(7),
            count: 1,
        };
        assert!(check(&proto), "分支漏掉定義時仍須保留原暫存值");
        proto.instructions[5].instruction = Instruction::LoadConst {
            dest: Register(5),
            constant: super::super::ConstId(2),
        };
        proto.instructions[3].instruction = Instruction::Move {
            dest: Register(5),
            src: Register(5),
        };
        assert!(check(&proto), "同一指令先讀後寫不能證明舊值已死亡");
        proto.instructions[3].instruction = Instruction::Vararg {
            base: Register(5),
            result_mode: ResultMode::All,
        };
        assert!(check(&proto), "動態結果不能當作確定覆寫");
    }

    #[test]
    fn env_field_key_reuse_requires_redefinition_and_never_skips_close() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::GetTable {
                dest: Register(6),
                table: Register(0),
                key: Register(5),
            },
            Instruction::JumpIfFalse {
                condition: Register(2),
                target: InstructionOffset(5),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(1),
            },
            Instruction::Jump {
                target: InstructionOffset(6),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(2),
            },
            Instruction::Move {
                dest: Register(7),
                src: Register(5),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let observed = |proto: &BytecodePrototype| {
            env_field_key_observed_later(
                proto,
                &producer_generation_test_layout(proto),
                Register(5),
                1,
            )
        };
        assert!(!observed(&proto), "後續 key 讀取在每條路徑上先重新定義");
        proto.instructions[5].instruction = Instruction::LoadNil {
            start: Register(7),
            count: 1,
        };
        assert!(observed(&proto), "漏定義的分支必須保留原 key home");
        proto.instructions[5].instruction = Instruction::LoadConst {
            dest: Register(5),
            constant: super::super::ConstId(2),
        };
        proto.instructions[3].instruction = Instruction::Move {
            dest: Register(5),
            src: Register(5),
        };
        assert!(observed(&proto), "先讀後寫不能證明 key 死亡");
        proto.instructions[3].instruction = Instruction::LoadConst {
            dest: Register(5),
            constant: super::super::ConstId(1),
        };
        proto.instructions[7].instruction = Instruction::Close {
            base: Register(5),
            count: 1,
        };
        assert!(
            observed(&proto),
            "後續 close 即使發生於重新定義之後也須保留原路徑"
        );
    }

    #[test]
    fn loop_exit_nil_gap_requires_dead_identified_unobservable_homes() {
        let mut proto = dead_open_fixture(vec![
            Instruction::NumericForPrepare {
                control: Register(1),
                limit: Register(2),
                step: Register(3),
                visible: Register(4),
                exit: InstructionOffset(3),
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::NumericForNext {
                control: Register(1),
                limit: Register(2),
                step: Register(3),
                visible: Register(4),
                target: InstructionOffset(1),
                exit: InstructionOffset(3),
            },
            Instruction::LoadNil {
                start: Register(7),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(4),
                count: 1,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let pair = NumericPair {
            prepare_pc: 0,
            next_pc: 2,
            body_pc: 1,
            tuple: 1,
            block: 0,
            visible: Register(4),
            exit: InstructionOffset(3),
        };
        let mut debug = NativePrototypeDebug {
            prototype: ProtoId(0),
            line_defined: 1,
            last_line_defined: 1,
            lines: vec![1; proto.instructions.len()],
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            max_active_locals: 0,
        };
        let safe = |proto: &BytecodePrototype,
                    meta: &Layout,
                    debug: &NativePrototypeDebug,
                    budget: u64| {
            loop_exit_nil_gap_safe(
                proto,
                meta,
                debug,
                &[pair],
                &pair,
                LuaProfile::Lua54,
                3,
                1,
                7,
                &mut OfficialWorkBudget::new(budget),
            )
        };
        let mut meta = producer_generation_test_layout(&proto);
        assert!(
            safe(&proto, &meta, &debug, 100_000).unwrap(),
            "結束的 numeric tuple 與已死的已識別 home 可一起清除"
        );
        assert_eq!(
            safe(&proto, &meta, &debug, 1).unwrap_err().kind,
            OfficialExportErrorKind::WorkExhausted
        );
        meta.mapped[5] = u8::MAX;
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "未知私有槽不能擴大清除"
        );
        meta.mapped[5] = 5;
        meta.protected[5] = 1;
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "捕獲或受保護 home 不得清除"
        );
        meta.protected[5] = 0;
        debug.locals.push(NativeLocal {
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 1,
            },
            register: Register(5),
            slot: 5,
            initialized_pc: 0,
            start_pc: 0,
            end_pc: 5,
            name: b"kept".to_vec(),
        });
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "可觀察 local 不得清除"
        );
        debug.locals.clear();
        proto.instructions[5].instruction = Instruction::Move {
            dest: Register(8),
            src: Register(5),
        };
        meta = producer_generation_test_layout(&proto);
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "後續讀取前未定義的 home 不得清除"
        );
        proto.instructions[5].instruction = Instruction::LoadConst {
            dest: Register(5),
            constant: super::super::ConstId(0),
        };
        let span = proto.instructions[5].span;
        proto.instructions.push(BytecodeInstruction {
            instruction: Instruction::Move {
                dest: Register(8),
                src: Register(5),
            },
            span,
            close_path: None,
        });
        meta = producer_generation_test_layout(&proto);
        assert!(
            safe(&proto, &meta, &debug, 100_000).unwrap(),
            "後續讀取前確定重定義的 home 可一起清除"
        );
        proto.instructions.pop();
        proto.instructions[5].instruction = Instruction::Close {
            base: Register(5),
            count: 1,
        };
        meta = producer_generation_test_layout(&proto);
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "後續 close 不得清除"
        );
        proto.instructions[5].instruction = Instruction::Jump {
            target: InstructionOffset(3),
        };
        meta = producer_generation_test_layout(&proto);
        assert!(
            !safe(&proto, &meta, &debug, 100_000).unwrap(),
            "外部入邊不得使用 tuple 死亡證明"
        );
        proto.instructions[5].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(0),
        };
        meta = producer_generation_test_layout(&proto);
        let active_other = NumericPair {
            prepare_pc: 1,
            body_pc: 2,
            next_pc: 5,
            tuple: 2,
            ..pair
        };
        assert!(
            !loop_exit_nil_gap_safe(
                &proto,
                &meta,
                &debug,
                &[pair, active_other],
                &pair,
                LuaProfile::Lua54,
                3,
                1,
                7,
                &mut OfficialWorkBudget::new(100_000)
            )
            .unwrap(),
            "其他仍活躍的 numeric tuple 不得清除"
        );
        meta.mapped[4] = u8::MAX;
        assert!(
            !loop_exit_nil_gap_safe(
                &proto,
                &meta,
                &debug,
                &[pair],
                &pair,
                LuaProfile::Lua55,
                3,
                1,
                5,
                &mut OfficialWorkBudget::new(100_000)
            )
            .unwrap(),
            "Lua55 較窄的 tuple 不得誤認第四槽"
        );
    }

    #[test]
    fn compare_fusion_reused_result_and_left_slot_require_def_on_every_path() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::BinaryOp {
                dest: Register(6),
                op: BinaryOperation::Less,
                left: Register(5),
                right: Register(2),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(6),
            },
            Instruction::JumpIfFalse {
                condition: Register(6),
                target: InstructionOffset(6),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(1),
            },
            Instruction::LoadConst {
                dest: Register(6),
                constant: super::super::ConstId(2),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(3),
            },
            Instruction::LoadConst {
                dest: Register(6),
                constant: super::super::ConstId(4),
            },
            Instruction::Move {
                dest: Register(7),
                src: Register(5),
            },
            Instruction::Move {
                dest: Register(8),
                src: Register(6),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let check = |proto: &BytecodePrototype, register, consumer| {
            generation_live_after_consumer(
                proto,
                &producer_generation_test_layout(proto),
                register,
                consumer,
            )
        };
        assert!(!check(&proto, Register(5), 1), "共槽左值後續先重新定義");
        assert!(
            !check(&proto, Register(6), 3),
            "比較結果在分支兩側先重新定義"
        );
        proto.instructions[6].instruction = Instruction::LoadNil {
            start: Register(7),
            count: 1,
        };
        assert!(check(&proto, Register(5), 1), "左值在跳躍側漏定義不能共槽");
        proto.instructions[7].instruction = Instruction::LoadNil {
            start: Register(7),
            count: 1,
        };
        assert!(
            check(&proto, Register(6), 3),
            "結果在分支合流前漏定義不能省略"
        );
    }

    #[test]
    fn terminal_compare_fusion_allows_only_redefined_later_result() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::BinaryOp {
                dest: Register(5),
                op: BinaryOperation::Less,
                left: Register(1),
                right: Register(2),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(5),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::Move {
                dest: Register(6),
                src: Register(5),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let mut first = vec![None; proto.instructions.len()];
        first[0] = Some(CompareBranchFusion {
            phi: Register(3),
            target: InstructionOffset(8),
            opcode: 58,
            left: Register(1),
            right: Register(2),
            invert: false,
        });
        let debug = NativePrototypeDebug {
            prototype: ProtoId(0),
            line_defined: 1,
            last_line_defined: 1,
            lines: vec![1; proto.instructions.len()],
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            max_active_locals: 0,
        };
        let check = |proto: &BytecodePrototype| {
            terminal_compare_fusions(
                proto,
                &producer_generation_test_layout(proto),
                Some(&debug),
                &first,
                &mut OfficialWorkBudget::new(10_000),
            )
            .unwrap()[6]
                .is_some()
        };
        assert!(
            check(&proto),
            "後代確定定義前沒有讀取時可融合 terminal 比較"
        );
        proto.instructions[8].instruction = Instruction::Move {
            dest: Register(5),
            src: Register(5),
        };
        assert!(!check(&proto), "先讀後寫仍須保留結果 home");
        proto.instructions[8].instruction = Instruction::Close {
            base: Register(5),
            count: 1,
        };
        assert!(!check(&proto), "後續 close 必須觀察原 home");
    }

    #[test]
    fn fused_compare_words_preserve_short_circuit_and_terminal_boolean_paths() {
        let execute = |code: &[u32], first: bool, terminal: bool| {
            let mut pc = 0usize;
            let mut rhs_seen = false;
            let mut value = None;
            let mut steps = 0;
            while pc < code.len() {
                steps += 1;
                assert!(steps <= 8, "融合比較不得產生回邊");
                let word = code[pc];
                match (word & 0x7f) as u8 {
                    58 => {
                        let predicate = if pc == 0 { first } else { terminal };
                        if pc != 0 {
                            rhs_seen = true;
                        }
                        pc += if predicate == ((word >> 15) & 1 != 0) {
                            1
                        } else {
                            2
                        };
                    }
                    56 => {
                        let offset = i64::from(word >> 7) - 16_777_215;
                        pc = usize::try_from(pc as i64 + 1 + offset).unwrap();
                    }
                    8 => {
                        rhs_seen = true;
                        pc += 1;
                    }
                    6 => {
                        value = Some(false);
                        pc += 2;
                    }
                    7 => {
                        value = Some(true);
                        pc += 1;
                    }
                    opcode => panic!("非預期的融合 opcode {opcode}"),
                }
            }
            (value.expect("融合比較必須寫入布林結果"), rhs_seen)
        };
        for first_invert in [false, true] {
            for terminal_invert in [false, true] {
                let first = chained_compare_words(58, 1, 2, first_invert, ProtoId(0), 0).unwrap();
                let terminal =
                    terminal_compare_words(58, 3, 4, 5, terminal_invert, ProtoId(0), 3).unwrap();
                let mut code = vec![
                    first[0],
                    first[1],
                    abc(8, 6, 0, 0, false),
                    terminal[0],
                    terminal[1],
                    terminal[2],
                    terminal[3],
                ];
                let false_block = 5i64;
                code[1] = jump(false_block - 2, ProtoId(0), 1).unwrap();
                assert_eq!(code[1] & 0x7f, 56, "比較後須緊接 JMP");
                assert_eq!(code[4] & 0x7f, 56, "終端比較後須緊接 JMP");
                assert_eq!([code[5] & 0x7f, code[6] & 0x7f], [6, 7]);
                for first_predicate in [false, true] {
                    for terminal_predicate in [false, true] {
                        let (value, rhs_seen) = execute(&code, first_predicate, terminal_predicate);
                        let first_value = first_predicate ^ first_invert;
                        let terminal_value = terminal_predicate ^ terminal_invert;
                        assert_eq!(rhs_seen, first_value, "false 短路不得求值 RHS");
                        assert_eq!(
                            value,
                            first_value && terminal_value,
                            "true/false 終端結果必須正確"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn numeric_alias_later_read_requires_def_on_every_cfg_path() {
        let mut proto = dead_open_fixture(vec![
            Instruction::Move {
                dest: Register(8),
                src: Register(6),
            },
            Instruction::NumericForPrepare {
                control: Register(1),
                limit: Register(2),
                step: Register(3),
                visible: Register(4),
                exit: InstructionOffset(4),
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::NumericForNext {
                control: Register(1),
                limit: Register(2),
                step: Register(3),
                visible: Register(4),
                target: InstructionOffset(2),
                exit: InstructionOffset(4),
            },
            Instruction::JumpIfFalse {
                condition: Register(1),
                target: InstructionOffset(8),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::BinaryOp {
                dest: Register(6),
                op: BinaryOperation::Less,
                left: Register(2),
                right: Register(5),
            },
            Instruction::Move {
                dest: Register(7),
                src: Register(6),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let check = |proto: &BytecodePrototype| {
            let mut work = OfficialWorkBudget::new(10_000);
            numeric_alias_later_reads_defined(proto, 2, Register(6), &mut work).unwrap()
        };
        assert!(
            check(&proto),
            "body nil 不得當作新定義；後續比較結果的確定寫入才保護讀取"
        );
        proto.instructions[4].instruction = Instruction::JumpIfFalse {
            condition: Register(1),
            target: InstructionOffset(7),
        };
        assert!(!check(&proto), "分支跳過定義仍會觀察舊 nil");
        proto.instructions[4].instruction = Instruction::JumpIfFalse {
            condition: Register(1),
            target: InstructionOffset(8),
        };
        proto.instructions[6].instruction = Instruction::Move {
            dest: Register(6),
            src: Register(6),
        };
        assert!(!check(&proto), "同一指令須先讀取再寫入");
        proto.instructions[6].instruction = Instruction::Vararg {
            base: Register(6),
            result_mode: ResultMode::All,
        };
        assert!(!check(&proto), "動態可能寫入不能截斷未定義路徑");
        proto.instructions[6].instruction = Instruction::Close {
            base: Register(6),
            count: 1,
        };
        assert!(!check(&proto), "關閉會觀察原 home");
        proto.instructions[6].instruction = Instruction::BinaryOp {
            dest: Register(6),
            op: BinaryOperation::Less,
            left: Register(2),
            right: Register(5),
        };
        proto.instructions[8].instruction = Instruction::Jump {
            target: InstructionOffset(0),
        };
        assert!(!check(&proto), "回入 prepare 前的讀取不得被後續定義掩蓋");
        let mut no_work = OfficialWorkBudget::new(0);
        assert_eq!(
            numeric_alias_later_reads_defined(&proto, 2, Register(6), &mut no_work)
                .expect_err("CFG proof 必須計費")
                .kind,
            OfficialExportErrorKind::WorkExhausted
        );
    }

    #[test]
    fn numeric_alias_later_read_keeps_allocator_home_without_private_nil_slot() {
        let alias = |anchor, share_nil_slot, preserve_mapped_home| NumericAlias {
            visible: Register(4),
            prepare_pc: 1,
            body_pc: 2,
            next_pc: 3,
            tuple: 1,
            width: 3,
            anchor: Register(anchor),
            share_nil_slot,
            preserve_mapped_home,
        };
        let aliases = [
            alias(6, false, true),
            alias(6, false, false),
            alias(7, true, false),
            alias(8, false, false),
            alias(8, false, false),
        ];
        let mut work = OfficialWorkBudget::new(10_000);
        assert_eq!(
            numeric_alias_nil_slots(&aliases, ProtoId(0), &mut work).unwrap(),
            (true, 2),
            "同 guest 的後讀沿用 allocator home；共用 nil 與一個私有 home 各計一次"
        );
        assert!(numeric_alias_preserves_mapped_home(&aliases, Register(6)));
        assert!(!numeric_alias_preserves_mapped_home(&aliases, Register(8)));
        let mut no_work = OfficialWorkBudget::new(0);
        assert_eq!(
            numeric_alias_nil_slots(&aliases, ProtoId(0), &mut no_work)
                .expect_err("分類掃描須計費")
                .kind,
            OfficialExportErrorKind::WorkExhausted
        );
    }

    #[test]
    fn numeric_nil_alias_shares_only_whole_function_nil_writes() {
        let source = vec![
            Instruction::LoadNil {
                start: Register(2),
                count: 1,
            },
            Instruction::LoadNil {
                start: Register(2),
                count: 1,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ];
        let mut proto = dead_open_fixture(source);
        let check = |proto: &BytecodePrototype| {
            let mut work = OfficialWorkBudget::new(10_000);
            numeric_alias_nil_only(proto, Register(2), &mut work).unwrap()
        };
        assert!(check(&proto), "匿名 nil anchor 全函式只寫 nil 才能共槽");
        let eligible = |proto: &BytecodePrototype,
                        locals: &[NativeLocal],
                        pending: &[NativeTemporary],
                        initializer: &[NativeInitializerTemporary]| {
            let mut work = OfficialWorkBudget::new(10_000);
            numeric_alias_shared_home_eligible(
                proto,
                Register(2),
                std::slice::from_ref(proto),
                locals,
                &[],
                pending,
                initializer,
                &mut work,
            )
            .unwrap()
        };
        assert!(eligible(&proto, &[], &[], &[]));
        let pending = [NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(1),
            ordinal: 1,
            register: Register(2),
        }];
        assert!(!eligible(&proto, &[], &pending, &[]), "pending 不可共享");
        let initializer = [NativeInitializerTemporary {
            prototype: ProtoId(0),
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 1,
            },
            register: Register(2),
            slot: 1,
            start_pc: 0,
            end_pc: 1,
        }];
        assert!(
            !eligible(&proto, &[], &[], &initializer),
            "initializer synthetic slot 不可共享"
        );
        let local = [NativeLocal {
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 1,
            },
            register: Register(2),
            slot: 1,
            initialized_pc: 0,
            start_pc: 0,
            end_pc: 2,
            name: b"x".to_vec(),
        }];
        assert!(
            !eligible(&proto, &local, &[], &[]),
            "local/capture 不可共享"
        );
        let mut child = proto.clone();
        child.id = ProtoId(1);
        child.parent = Some(proto.id);
        child.frame.environment_source = EnvironmentSource::ParentFrame {
            parent: proto.id,
            register: Register(2),
        };
        let prototypes = [proto.clone(), child.clone()];
        let mut work = OfficialWorkBudget::new(10_000);
        assert!(
            !numeric_alias_shared_home_eligible(
                &proto,
                Register(2),
                &prototypes,
                &[],
                &[],
                &[],
                &[],
                &mut work
            )
            .unwrap(),
            "child ParentFrame(anchor) 可觀測 nil home，不能共槽"
        );
        child.frame.environment_source = EnvironmentSource::ParentFrame {
            parent: proto.id,
            register: Register(3),
        };
        let mut work = OfficialWorkBudget::new(10_000);
        assert!(
            numeric_alias_shared_home_eligible(
                &proto,
                Register(2),
                &[proto.clone(), child],
                &[],
                &[],
                &[],
                &[],
                &mut work
            )
            .unwrap(),
            "child 捕獲其他 register 不應阻止 nil anchor 共槽"
        );
        let mut work = OfficialWorkBudget::new(0);
        assert_eq!(
            numeric_alias_shared_home_eligible(
                &proto,
                Register(2),
                &prototypes,
                &[],
                &[],
                &[],
                &[],
                &mut work
            )
            .expect_err("child metadata 掃描須計費")
            .kind,
            OfficialExportErrorKind::WorkExhausted
        );
        proto.instructions[0].instruction = Instruction::Move {
            dest: Register(8),
            src: Register(2),
        };
        assert!(!check(&proto), "Prepare 前即使不回跳，原 home 讀取仍需專槽");
        proto.instructions[0].instruction = Instruction::Move {
            dest: Register(2),
            src: Register(1),
        };
        assert!(!check(&proto), "Prepare 前非 nil Move 不能共享");
        proto.instructions[0].instruction = Instruction::LoadNil {
            start: Register(2),
            count: 1,
        };
        proto.instructions[1].instruction = Instruction::LoadConst {
            dest: Register(2),
            constant: super::super::ConstId(0),
        };
        assert!(!check(&proto), "Next 後非 nil LoadConst 不能共享");
        proto.instructions[1].instruction = Instruction::Call {
            base: Register(2),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        assert!(!check(&proto), "動態可能覆寫不能當成 nil");
        proto.instructions[1].instruction = Instruction::Close {
            base: Register(2),
            count: 1,
        };
        assert!(!check(&proto), "Close 可能觀察原 home");
        let mut no_work = OfficialWorkBudget::new(0);
        assert_eq!(
            numeric_alias_nil_only(&proto, Register(2), &mut no_work)
                .expect_err("alias proof 必須計費")
                .kind,
            OfficialExportErrorKind::WorkExhausted
        );
    }

    #[test]
    fn numeric_tuple_owned_next_requires_cfg_and_unobserved_original_home() {
        let proto = dead_open_fixture(vec![
            Instruction::Move {
                dest: Register(2),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(1),
            },
            Instruction::NumericForPrepare {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(5),
                exit: InstructionOffset(7),
            },
            Instruction::LoadNil {
                start: Register(6),
                count: 1,
            },
            Instruction::Jump {
                target: InstructionOffset(6),
            },
            Instruction::NumericForNext {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(5),
                target: InstructionOffset(4),
                exit: InstructionOffset(7),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let pair = NumericPair {
            prepare_pc: 3,
            next_pc: 6,
            body_pc: 4,
            tuple: 0,
            block: 0,
            visible: Register(5),
            exit: InstructionOffset(7),
        };
        let debug = NativePrototypeDebug {
            prototype: ProtoId(0),
            line_defined: 0,
            last_line_defined: 0,
            lines: Vec::new(),
            locals: Vec::new(),
            upvalue_names: Vec::new(),
            max_active_locals: 0,
        };
        let mut mapped = [u8::MAX; 9];
        mapped[0] = 0;
        let prove = |proto: &BytecodePrototype,
                     pairs: &[NumericPair],
                     debug: &NativePrototypeDebug,
                     pending: &[NativeTemporary],
                     child: &[Register]| {
            let mut seen = vec![0u8; proto.instructions.len()];
            let mut queue = Vec::with_capacity(proto.instructions.len());
            let mut work = OfficialWorkBudget::new(1_000_000);
            numeric_pair_tuple_owned(
                proto,
                &pair,
                pairs,
                &mapped,
                debug,
                &[],
                pending,
                &[],
                child,
                &mut seen,
                &mut queue,
                &mut work,
            )
            .unwrap()
        };
        assert!(prove(&proto, &[pair], &debug, &[], &[]));
        let owned = [NumericOwnedNext {
            next_pc: 6,
            control: Register(2),
            limit: Register(3),
            step: Register(4),
        }];
        let mut work = OfficialWorkBudget::new(1_000_000);
        assert_eq!(static_register_access(&proto, 6, Register(2)), (true, true));
        for register in [Register(2), Register(3), Register(4)] {
            assert_eq!(
                numeric_native_access(&proto, 6, register, &owned, &mut work).unwrap(),
                (false, false),
                "僅已證明 Next 的 tuple-owned 原 home 可忽略"
            );
            assert_eq!(
                numeric_native_access(&proto, 6, register, &[], &mut work).unwrap(),
                static_register_access(&proto, 6, register),
                "沒有 proof 須保留原 IR read/write"
            );
        }
        let mut owned_spans = [(usize::MAX, 0usize); 9];
        owned_spans[3] = (1, 7);
        let mut raw_spans = owned_spans;
        let mut live_work = OfficialWorkBudget::new(1_000_000);
        let owned_live = extend_live_spans(
            &proto,
            &mapped,
            &mut owned_spans,
            &owned,
            64,
            &mut live_work,
        )
        .unwrap();
        let raw_live =
            extend_live_spans(&proto, &mapped, &mut raw_spans, &[], 64, &mut live_work).unwrap();
        let protected = [0u8; 9];
        assert!(
            live_at_pc(&owned_spans, &protected, &owned_live, 3, 3),
            "Prepare 仍必須讀原 limit"
        );
        assert!(
            !live_at_pc(&owned_spans, &protected, &owned_live, 3, 5),
            "tuple 接管後原 limit 在 body 不再因 Next 假讀而活躍"
        );
        assert!(
            live_at_pc(&raw_spans, &protected, &raw_live, 3, 5),
            "未證明時 Next 原始讀取仍延長生命期"
        );
        let mut later = proto.clone();
        later.instructions[7].instruction = Instruction::Return {
            base: Register(2),
            result_mode: ResultMode::Fixed(1),
        };
        assert!(
            !prove(&later, &[pair], &debug, &[], &[]),
            "Next 後仍觀察 control 時不可用 tuple-only effect"
        );
        later.instructions[7].instruction = Instruction::LoadNil {
            start: Register(2),
            count: 1,
        };
        later
            .instructions
            .push(super::super::codec::BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(2),
                    result_mode: ResultMode::Fixed(1),
                },
                span: later.span,
                close_path: None,
            });
        assert!(
            prove(&later, &[pair], &debug, &[], &[]),
            "出口後確定重定義可截斷原 home"
        );
        let mut body_read = proto.clone();
        body_read.instructions[4].instruction = Instruction::Move {
            dest: Register(6),
            src: Register(3),
        };
        assert!(
            !prove(&body_read, &[pair], &debug, &[], &[]),
            "body 讀 limit 須保留原 home"
        );
        body_read.instructions[4].instruction = Instruction::Move {
            dest: Register(3),
            src: Register(6),
        };
        assert!(
            !prove(&body_read, &[pair], &debug, &[], &[]),
            "body 改 limit 會與 tuple 分歧"
        );
        body_read.instructions[4].instruction = Instruction::Close {
            base: Register(4),
            count: 1,
        };
        assert!(
            !prove(&body_read, &[pair], &debug, &[], &[]),
            "body Close step 不可忽略"
        );
        let mut external = proto.clone();
        external.instructions[0].instruction = Instruction::Jump {
            target: InstructionOffset(4),
        };
        assert!(
            !prove(&external, &[pair], &debug, &[], &[]),
            "外部跳入 body 會繞過 Prepare"
        );
        let mut alternate_exit = proto.clone();
        alternate_exit.instructions[4].instruction = Instruction::JumpIfFalse {
            condition: Register(6),
            target: InstructionOffset(8),
        };
        alternate_exit
            .instructions
            .push(super::super::codec::BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(2),
                    result_mode: ResultMode::Fixed(1),
                },
                span: alternate_exit.span,
                close_path: None,
            });
        assert!(
            !prove(&alternate_exit, &[pair], &debug, &[], &[]),
            "body 其他出口的 control 後讀不可漏掉"
        );
        let overlapping = NumericPair {
            prepare_pc: 4,
            next_pc: 5,
            ..pair
        };
        assert!(
            !prove(&proto, &[pair, overlapping], &debug, &[], &[]),
            "沒有有效 Prepare/Next 配對的重疊 pair 須拒絕"
        );
        let mut nested = dead_open_fixture(vec![
            Instruction::Move {
                dest: Register(2),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(1),
            },
            Instruction::NumericForPrepare {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(5),
                exit: InstructionOffset(12),
            },
            Instruction::Move {
                dest: Register(6),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(7),
                src: Register(1),
            },
            Instruction::Move {
                dest: Register(8),
                src: Register(1),
            },
            Instruction::NumericForPrepare {
                control: Register(6),
                limit: Register(7),
                step: Register(8),
                visible: Register(9),
                exit: InstructionOffset(10),
            },
            Instruction::LoadNil {
                start: Register(10),
                count: 1,
            },
            Instruction::NumericForNext {
                control: Register(6),
                limit: Register(7),
                step: Register(8),
                visible: Register(9),
                target: InstructionOffset(8),
                exit: InstructionOffset(10),
            },
            Instruction::LoadNil {
                start: Register(11),
                count: 1,
            },
            Instruction::NumericForNext {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(5),
                target: InstructionOffset(4),
                exit: InstructionOffset(12),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        nested.register_count = 12;
        nested.frame.register_limit = 12;
        let (nested_pairs, nested_blocks) =
            numeric_pairs(&nested, &mut OfficialWorkBudget::new(1_000_000)).unwrap();
        assert_eq!(nested_blocks, 2, "同時活躍的內外 pair 須有獨立 tuple block");
        let mut nested_mapped = [u8::MAX; 12];
        nested_mapped[0] = 0;
        let check_nested = |proto: &BytecodePrototype, pairs: &[NumericPair]| {
            let mut seen = vec![0u8; proto.instructions.len()];
            let mut queue = Vec::with_capacity(proto.instructions.len());
            let mut work = OfficialWorkBudget::new(1_000_000);
            numeric_pair_tuple_owned(
                proto,
                &pairs[0],
                pairs,
                &nested_mapped,
                &debug,
                &[],
                &[],
                &[],
                &[],
                &mut seen,
                &mut queue,
                &mut work,
            )
            .unwrap()
        };
        assert!(
            check_nested(&nested, &nested_pairs),
            "有效且獨立的嚴格巢狀 pair 可由各自 tuple 接管"
        );
        let mut shared_block = nested_pairs.clone();
        shared_block[1].block = shared_block[0].block;
        assert!(
            !check_nested(&nested, &shared_block),
            "共 block 的巢狀 pair 不可共享 tuple"
        );
        let mut shared_guest = nested.clone();
        shared_guest.instructions[7].instruction = Instruction::NumericForPrepare {
            control: Register(2),
            limit: Register(7),
            step: Register(8),
            visible: Register(9),
            exit: InstructionOffset(10),
        };
        shared_guest.instructions[9].instruction = Instruction::NumericForNext {
            control: Register(2),
            limit: Register(7),
            step: Register(8),
            visible: Register(9),
            target: InstructionOffset(8),
            exit: InstructionOffset(10),
        };
        let (shared_pairs, _) =
            numeric_pairs(&shared_guest, &mut OfficialWorkBudget::new(1_000_000)).unwrap();
        assert!(
            !check_nested(&shared_guest, &shared_pairs),
            "共用 control guest 的巢狀 pair 不可移除原 home 存取"
        );
        let mut crossing = nested.clone();
        crossing.instructions[7].instruction = Instruction::NumericForPrepare {
            control: Register(6),
            limit: Register(7),
            step: Register(8),
            visible: Register(9),
            exit: InstructionOffset(14),
        };
        crossing.instructions[9].instruction = Instruction::Jump {
            target: InstructionOffset(13),
        };
        crossing
            .instructions
            .push(super::super::codec::BytecodeInstruction {
                instruction: Instruction::NumericForNext {
                    control: Register(6),
                    limit: Register(7),
                    step: Register(8),
                    visible: Register(9),
                    target: InstructionOffset(8),
                    exit: InstructionOffset(14),
                },
                span: crossing.span,
                close_path: None,
            });
        crossing
            .instructions
            .push(super::super::codec::BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
                span: crossing.span,
                close_path: None,
            });
        let (crossing_pairs, _) =
            numeric_pairs(&crossing, &mut OfficialWorkBudget::new(1_000_000)).unwrap();
        assert!(
            !check_nested(&crossing, &crossing_pairs),
            "交錯 pair 即使使用不同 guest 與 block 仍須拒絕"
        );
        let pending = [NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(5),
            ordinal: 1,
            register: Register(2),
        }];
        assert!(
            !prove(&proto, &[pair], &debug, &pending, &[]),
            "pending 仍要求原 home"
        );
        assert!(
            !prove(&proto, &[pair], &debug, &[], &[Register(4)]),
            "child ParentFrame 捕獲仍要求原 home"
        );
        let mut local_debug = debug.clone();
        local_debug.locals.push(NativeLocal {
            binding: super::super::codec::BytecodeBindingId {
                function: 0,
                ordinal: 1,
            },
            register: Register(2),
            slot: 0,
            initialized_pc: 0,
            start_pc: 0,
            end_pc: 8,
            name: b"control".to_vec(),
        });
        assert!(
            !prove(&proto, &[pair], &local_debug, &[], &[]),
            "debug local slot 不可丟失原 home"
        );
        let mut seen = vec![0u8; proto.instructions.len()];
        let mut queue = Vec::with_capacity(proto.instructions.len());
        let mut short = OfficialWorkBudget::new(0);
        assert_eq!(
            numeric_pair_tuple_owned(
                &proto,
                &pair,
                &[pair],
                &mapped,
                &debug,
                &[],
                &[],
                &[],
                &[],
                &mut seen,
                &mut queue,
                &mut short
            )
            .expect_err("CFG proof 必須計費")
            .kind,
            OfficialExportErrorKind::WorkExhausted
        );
    }

    #[test]
    fn ordinary_load_nil_ignores_only_suppressed_dead_temporary_write() {
        let mut proto = dead_open_fixture(vec![
            Instruction::LoadNil {
                start: Register(2),
                count: 3,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        let mut debug = NativePrototypeDebug {
            prototype: ProtoId(0),
            line_defined: 0,
            last_line_defined: 0,
            lines: Vec::new(),
            locals: vec![NativeLocal {
                binding: super::super::codec::BytecodeBindingId {
                    function: 0,
                    ordinal: 1,
                },
                register: Register(7),
                slot: 4,
                initialized_pc: 0,
                start_pc: 0,
                end_pc: 2,
                name: b"kept".to_vec(),
            }],
            upvalue_names: Vec::new(),
            max_active_locals: 1,
        };
        let mut mapped = [u8::MAX; 9];
        mapped[3] = 4;
        mapped[7] = 4;
        let mut spans = [(usize::MAX, 0); 9];
        spans[3] = (0, 2);
        let protected = [0u8; 9];
        let mut rows: Vec<LiveRow> = (0..9).map(|_| LiveRow::Uncomputed).collect();
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: Vec::new(),
        };
        let check = |proto: &BytecodePrototype,
                     debug: Option<&NativePrototypeDebug>,
                     mapped: &[u8],
                     aliases: &[NumericAlias],
                     rows: &[LiveRow]| {
            let mut work = OfficialWorkBudget::new(1000);
            suppressed_ordinary_load_nil_write(
                proto, debug, mapped, aliases, &spans, &protected, rows, 3, 4, 0, &mut work,
            )
            .unwrap()
        };
        assert!(
            check(&proto, Some(&debug), &mapped, &[], &rows),
            "已初始化 local 的實體槽使 dead temporary 清除被 emitter 抑制"
        );
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0001],
        };
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "candidate live-in 不得忽略清除"
        );
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0010],
        };
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "candidate live-out 不得忽略清除"
        );
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: Vec::new(),
        };
        assert!(
            !check(&proto, None, &mapped, &[], &rows),
            "缺 debug 不得猜測 occupied slot"
        );
        debug.locals[0].initialized_pc = 1;
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "尚未初始化的 local 不佔用此槽"
        );
        debug.locals[0].initialized_pc = 0;
        debug.locals[0].end_pc = 0;
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "已離域的 local 不佔用此槽"
        );
        debug.locals[0].end_pc = 2;
        debug.locals[0].register = Register(4);
        mapped[4] = 4;
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "clear guest 範圍內的 local 不屬於 emitter occupied 集合"
        );
        debug.locals[0].register = Register(7);
        mapped[7] = u8::MAX;
        assert!(
            !check(&proto, Some(&debug), &mapped, &[], &rows),
            "沒有可確定實體槽的 local 不得放行"
        );
        let alias = [NumericAlias {
            visible: Register(7),
            prepare_pc: 0,
            body_pc: 0,
            next_pc: 1,
            tuple: 3,
            width: 1,
            anchor: Register(7),
            share_nil_slot: false,
            preserve_mapped_home: false,
        }];
        assert!(
            check(&proto, Some(&debug), &mapped, &alias, &rows),
            "occupied 判斷須使用與 Layout 相同的 numeric alias home"
        );
        proto.instructions[0].instruction = Instruction::Move {
            dest: Register(3),
            src: Register(2),
        };
        assert!(
            !check(&proto, Some(&debug), &mapped, &alias, &rows),
            "非 LoadNil 寫入不得省略"
        );
        proto.instructions[0].instruction = Instruction::LoadNil {
            start: Register(3),
            count: 1,
        };
        assert!(
            !check(&proto, Some(&debug), &mapped, &alias, &rows),
            "單槽特殊路徑維持保守拒絕"
        );
    }

    #[test]
    fn ordinary_load_nil_future_numeric_tuple_keeps_prior_cleanup_proof() {
        let mut proto = dead_open_fixture(vec![
            Instruction::Call {
                base: Register(2),
                arg_count: 0,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::LoadNil {
                start: Register(2),
                count: 7,
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(5),
            },
            Instruction::Move {
                dest: Register(1),
                src: Register(4),
            },
            Instruction::LoadNil {
                start: Register(4),
                count: 2,
            },
            Instruction::NumericForPrepare {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(6),
                exit: InstructionOffset(9),
            },
            Instruction::LoadNil {
                start: Register(7),
                count: 1,
            },
            Instruction::NumericForNext {
                control: Register(2),
                limit: Register(3),
                step: Register(4),
                visible: Register(6),
                target: InstructionOffset(7),
                exit: InstructionOffset(9),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        proto.constants.push(BytecodeConstant::Integer(0));
        let mut meta = producer_generation_test_layout(&proto);
        let mut cleared = [0u8; 32];
        cleanup_slot_set(&mut cleared, 4);
        cleanup_slot_set(&mut cleared, 5);
        meta.call_cleanup_slots.push((1, cleared));
        let copies = [DirectConstCopy {
            first_pc: 2,
            slot: 1,
        }];
        let exits = vec![None; proto.instructions.len()];
        let future = NumericPair {
            prepare_pc: 6,
            body_pc: 7,
            next_pc: 8,
            tuple: 4,
            block: 0,
            visible: Register(6),
            exit: InstructionOffset(9),
        };
        let check = |proto: &BytecodePrototype, meta: &Layout, pairs: &[NumericPair], slot| {
            let mut work = OfficialWorkBudget::new(100_000);
            nil_after_direct_const_copy(
                proto,
                meta,
                &copies,
                &[],
                &exits,
                pairs,
                5,
                slot,
                &mut work,
            )
            .unwrap()
        };
        assert!(
            check(&proto, &meta, &[future], 4),
            "未來才開始的 tuple 不得阻擋已清 nil 的 first temporary"
        );
        assert!(
            check(&proto, &meta, &[future], 5),
            "未來才開始的 tuple 不得阻擋已清 nil 的 middle temporary"
        );
        meta.numeric_aliases.push(NumericAlias {
            visible: Register(6),
            prepare_pc: 6,
            body_pc: 7,
            next_pc: 8,
            tuple: 4,
            width: 4,
            anchor: Register(7),
            share_nil_slot: false,
            preserve_mapped_home: false,
        });
        assert!(
            check(&proto, &meta, &[future], 4),
            "未來 alias 同樣不應否定先前實際清理"
        );

        let active = NumericPair {
            prepare_pc: 5,
            ..future
        };
        assert!(
            !check(&proto, &meta, &[active], 4),
            "已開始的 tuple 仍須保守保留清理"
        );
        meta.numeric_aliases[0].prepare_pc = 5;
        assert!(
            !check(&proto, &meta, &[future], 4),
            "已開始的 alias 仍須保守保留清理"
        );
        meta.numeric_aliases[0].prepare_pc = 6;
        meta.call_cleanup_slots[0].1[0] &= !(1 << 4);
        assert!(
            !check(&proto, &meta, &[future], 4),
            "先前 cleanup 未實際清此槽時不可略過"
        );
        cleanup_slot_set(&mut meta.call_cleanup_slots[0].1, 4);
        proto.instructions[9].instruction = Instruction::Jump {
            target: InstructionOffset(5),
        };
        assert!(
            !check(&proto, &meta, &[future], 4),
            "跳入目前清槽可繞過先前 cleanup"
        );
    }

    #[test]
    fn ordinary_load_nil_skips_only_proven_prior_call_cleanup_slots() {
        let mut proto = dead_open_fixture(vec![
            Instruction::Call {
                base: Register(2),
                arg_count: 0,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::LoadNil {
                start: Register(2),
                count: 7,
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: super::super::ConstId(0),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(5),
            },
            Instruction::Move {
                dest: Register(1),
                src: Register(4),
            },
            Instruction::LoadNil {
                start: Register(4),
                count: 2,
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
        ]);
        proto.constants.push(BytecodeConstant::Integer(0));
        let mut meta = producer_generation_test_layout(&proto);
        let mut cleared = [0u8; 32];
        cleanup_slot_set(&mut cleared, 4);
        cleanup_slot_set(&mut cleared, 5);
        meta.call_cleanup_slots.push((1, cleared));
        let copies = [DirectConstCopy {
            first_pc: 2,
            slot: 1,
        }];
        let mut exits = vec![None; proto.instructions.len()];
        let check = |proto: &BytecodePrototype,
                     meta: &Layout,
                     copies: &[DirectConstCopy],
                     exits: &[Option<LoopExitNilFusion>],
                     slot| {
            let mut work = OfficialWorkBudget::new(100_000);
            nil_after_direct_const_copy(proto, meta, copies, &[], exits, &[], 5, slot, &mut work)
                .unwrap()
        };
        assert!(check(&proto, &meta, &copies, &exits, 4));
        assert!(check(&proto, &meta, &copies, &exits, 5));
        meta.call_cleanup_slots[0].1[0] &= !(1 << 5);
        assert!(
            !check(&proto, &meta, &copies, &exits, 5),
            "先前 cleanup 未實際發出的槽不可省"
        );
        cleanup_slot_set(&mut meta.call_cleanup_slots[0].1, 5);
        let overwritten = [DirectConstCopy {
            first_pc: 2,
            slot: 4,
        }];
        assert!(
            !check(&proto, &meta, &overwritten, &exits, 4),
            "最終 LOADK 寫入的槽不可省"
        );
        proto.instructions[6].instruction = Instruction::Jump {
            target: InstructionOffset(2),
        };
        assert!(
            !check(&proto, &meta, &copies, &exits, 4),
            "跳入 LOADK 可繞過先前 cleanup"
        );
        proto.instructions[6].instruction = Instruction::Jump {
            target: InstructionOffset(5),
        };
        assert!(
            !check(&proto, &meta, &copies, &exits, 4),
            "跳入目前 LoadNil 亦可繞過先前 cleanup"
        );
        proto.instructions[6].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(0),
        };
        exits[1] = Some(LoopExitNilFusion {
            first_slot: 2,
            count: 1,
        });
        assert!(
            !check(&proto, &meta, &copies, &exits, 4),
            "先前 cleanup 若走其他融合發碼不可假定已清該槽"
        );
        exits[1] = None;
        meta.protected[4] = 1;
        assert!(
            !check(&proto, &meta, &copies, &exits, 4),
            "捕獲或受保護的實體槽須保留清理"
        );
    }

    #[test]
    fn open_call_frontier_reserves_unmapped_callee_home_once() {
        let pending = [NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(0),
            ordinal: 1,
            register: Register(2),
        }];
        let mut mapped = [u8::MAX; 9];
        let check = |current, open, pending: &[NativeTemporary], base, mapped: &[u8]| {
            let mut work = OfficialWorkBudget::new(1000);
            open_call_frontier_with_callee(
                current,
                open,
                pending,
                base,
                mapped,
                Register(0),
                Register(0),
                ProtoId(0),
                0,
                &mut work,
            )
        };
        assert_eq!(check(7, true, &pending, Register(3), &mapped).unwrap(), 8);
        assert_eq!(check(7, false, &pending, Register(3), &mapped).unwrap(), 7);
        assert_eq!(check(7, true, &[], Register(3), &mapped).unwrap(), 7);
        mapped[3] = 4;
        assert_eq!(check(7, true, &pending, Register(3), &mapped).unwrap(), 7);
        mapped[3] = u8::MAX;
        assert_eq!(check(7, true, &pending, Register(2), &mapped).unwrap(), 7);
        assert_eq!(check(7, true, &pending, Register(0), &mapped).unwrap(), 7);
        let mut spans = [(usize::MAX, 0); 9];
        spans[3] = (5, 11);
        assert!(unmapped_callee_alive_at_birth(true, &spans, Register(3), 5));
        assert!(unmapped_callee_alive_at_birth(
            true,
            &spans,
            Register(3),
            10
        ));
        assert!(!unmapped_callee_alive_at_birth(
            true,
            &spans,
            Register(3),
            4
        ));
        assert!(!unmapped_callee_alive_at_birth(
            true,
            &spans,
            Register(3),
            11
        ));
        assert!(!unmapped_callee_alive_at_birth(
            false,
            &spans,
            Register(3),
            7
        ));
        assert_eq!(
            check(usize::MAX, true, &pending, Register(3), &mapped)
                .expect_err("frontier + callee 不得溢位")
                .kind,
            OfficialExportErrorKind::LimitExceeded,
        );
    }

    #[test]
    fn fixed_pending_pair_spare_filters_collisions_without_losing_moves() {
        let mut source = [0u8; 512];
        let mut destination = [0u8; 512];
        source[0] = 1;
        destination[0] = 3;
        let mut work = OfficialWorkBudget::new(10_000);
        let spare =
            fixed_pending_spare_for_pairs(3, &source, &destination, 1, ProtoId(0), 0, &mut work)
                .unwrap();
        assert_eq!(spare, None, "單一搬移的目的槽不可當備用槽");
        let plan =
            parallel_slot_pairs_plan(&source, &destination, 1, spare, ProtoId(0), 0, &mut work)
                .unwrap()
                .expect("無循環搬移不需要備用槽");
        assert_eq!(&plan.moves[..plan.len], &[(3, 1)]);

        source[1] = 2;
        destination[1] = 4;
        let spare =
            fixed_pending_spare_for_pairs(4, &source, &destination, 2, ProtoId(0), 0, &mut work)
                .unwrap();
        assert_eq!(spare, None, "多筆無循環搬移也不可誤借目的槽");
        assert!(
            parallel_slot_pairs_plan(&source, &destination, 2, spare, ProtoId(0), 0, &mut work,)
                .unwrap()
                .is_some()
        );
        assert!(
            parallel_slot_pairs_plan(&source, &destination, 2, Some(4), ProtoId(0), 0, &mut work,)
                .unwrap()
                .is_none(),
            "原 planner 對明確錯誤 spare 仍須拒絕"
        );

        destination[0] = 2;
        destination[1] = 1;
        let spare =
            fixed_pending_spare_for_pairs(1, &source, &destination, 2, ProtoId(0), 0, &mut work)
                .unwrap();
        assert_eq!(spare, None);
        assert!(
            parallel_slot_pairs_plan(&source, &destination, 2, spare, ProtoId(0), 0, &mut work,)
                .unwrap()
                .is_none(),
            "真正循環沒有安全 spare 仍須拒絕"
        );
        let spare =
            fixed_pending_spare_for_pairs(3, &source, &destination, 2, ProtoId(0), 0, &mut work)
                .unwrap();
        let plan =
            parallel_slot_pairs_plan(&source, &destination, 2, spare, ProtoId(0), 0, &mut work)
                .unwrap()
                .expect("合法 spare 能保存循環中的原值");
        assert_eq!(used_parallel_spare(&plan, 3), Some(3));
        let mut values = [0u8; 256];
        values[1] = 11;
        values[2] = 22;
        for &(dest, src) in &plan.moves[..plan.len] {
            values[usize::from(dest)] = values[usize::from(src)];
        }
        assert_eq!((values[1], values[2]), (22, 11));
        let limits = OfficialChunkLimits::default();
        let mut total_instructions = 0;
        let mut work = OfficialWorkBudget::new(10_000);
        let mut builder = Builder {
            id: ProtoId(0),
            limits: &limits,
            work: &mut work,
            total_instructions: &mut total_instructions,
            max_words: plan.len + 1,
            code: Vec::new(),
            source_lines: None,
            lines: Vec::new(),
        };
        emit_parallel_plan(&mut builder, &plan, used_parallel_spare(&plan, 3), 0).unwrap();
        assert_eq!(builder.code.len(), plan.len + 1);
        assert_eq!(builder.code.last().copied(), Some(abc(8, 3, 0, 0, false)));
        assert_eq!(*builder.total_instructions, plan.len + 1);
    }

    #[test]
    fn fixed_result_marker_cycle_clears_temporary_gc_root_and_counts_words() {
        let proto = dead_open_fixture(vec![
            Instruction::Call {
                base: Register(0),
                arg_count: 1,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::LoadNil {
                start: Register(0),
                count: 2,
            },
        ]);
        assert_eq!(call_cleanup_range(&proto, 1), None);

        let mut work = OfficialWorkBudget::new(10_000);
        let plan = parallel_copy_plan(
            &[1, 0],
            Register(0),
            2,
            0,
            true,
            Some(2),
            ProtoId(0),
            0,
            &mut work,
        )
        .unwrap()
        .expect("循環搬移須使用 marker");
        let spare = used_parallel_spare(&plan, 2);
        assert_eq!(spare, Some(2));
        assert_eq!(parallel_plan_words(&plan, 2), plan.len + 1);
        let direct = parallel_copy_plan(
            &[0, 1],
            Register(0),
            2,
            0,
            true,
            Some(2),
            ProtoId(0),
            0,
            &mut work,
        )
        .unwrap()
        .expect("原位值不需借用 marker");
        assert_eq!(used_parallel_spare(&direct, 2), None);
        assert_eq!(parallel_plan_words(&direct, 2), direct.len);
        let work_before = work.remaining();
        let limits = OfficialChunkLimits::default();
        let mut total_instructions = 0;
        let mut builder = Builder {
            id: ProtoId(0),
            limits: &limits,
            work: &mut work,
            total_instructions: &mut total_instructions,
            max_words: plan.len + 1,
            code: Vec::new(),
            source_lines: None,
            lines: Vec::new(),
        };
        emit_parallel_plan(&mut builder, &plan, spare, 0).unwrap();
        assert_eq!(builder.code.len(), parallel_plan_words(&plan, 2));
        assert_eq!(*builder.total_instructions, builder.code.len());
        assert_eq!(
            work_before - builder.work.remaining(),
            (plan.len + 1) as u64
        );
        let mut slots = [Some(11), Some(22), None];
        for &word in &builder.code {
            let destination = ((word >> 7) & 0xff) as usize;
            match word & 0x7f {
                0 => slots[destination] = slots[((word >> 16) & 0xff) as usize],
                8 => {
                    assert_eq!((word >> 16) & 0xff, 0);
                    slots[destination] = None;
                }
                opcode => panic!("非預期平行搬移 opcode {opcode}"),
            }
        }
        assert_eq!(slots, [Some(22), Some(11), None]);
    }

    #[test]
    fn fixed_call_pending_birth_reserves_only_proven_frontier() {
        let mut pending = [NativeTemporary {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(10),
            ordinal: 1,
            register: Register(2),
        }];
        let mut mapped = [u8::MAX; 8];
        let mut spans = [(usize::MAX, 0); 8];
        spans[2] = (5, 13);
        spans[3] = (6, 12);
        spans[4] = (5, 11);
        spans[5] = (5, 9);
        let check = |pending: &[NativeTemporary],
                     mapped: &[u8],
                     spans: &[(usize, usize)],
                     live_at: &[LiveRow],
                     max_work: u64| {
            let mut work = OfficialWorkBudget::new(max_work);
            fixed_pending_birth_retained(
                12,
                pending,
                mapped,
                spans,
                &[0; 8],
                live_at,
                Register(3),
                Register(0),
                Register(0),
                12,
                12,
                |_| Ok(12),
                ProtoId(0),
                10,
                &mut work,
            )
        };
        let mut live_at: Vec<LiveRow> = (0..spans.len()).map(|_| LiveRow::Uncomputed).collect();
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            2,
            "pending 出生後兩個仍活躍的值須高於 active floor"
        );
        live_at[4] = LiveRow::Bits {
            base_pc: 8,
            bytes: vec![1],
        };
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            1,
            "寬 span 中的值若未在出生後存活，不得墊高 pending 前綴"
        );
        live_at[4] = LiveRow::Uncomputed;
        spans[5] = (5, 6);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            1,
            "出生指令讀完即死的 operand 不佔下一 PC 前綴"
        );
        spans[5] = (4, 6);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            1,
            "較早出生但恰於此指令死亡的值也不佔前綴"
        );
        spans[5] = (5, 7);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            2,
            "出生後下一 PC 仍活躍的值須保留"
        );
        spans[5] = (5, 9);
        spans[3] = (5, 12);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            3,
            "callee 恰在 pending 出生時已存在且跨至 Call 也佔槽"
        );
        spans[3] = (4, 12);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            3,
            "callee 在 pending 出生前已生且未固定時也佔槽"
        );
        spans[3] = (6, 12);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            2,
            "callee 在 pending 出生後才產生時不得預留出生槽"
        );
        assert_eq!(
            check(&[], &mapped, &spans, &live_at, 10_000).unwrap(),
            0,
            "空 pending 不提高 fixed Call 前綴"
        );
        pending[0].register = Register(6);
        spans[6] = (5, 11);
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            0,
            "未跨 Call 的 pending 不觸發出生峰掃描"
        );
        pending[0].register = Register(2);
        spans[6] = (usize::MAX, 0);
        mapped[4] = 1;
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 10_000).unwrap(),
            1,
            "既有 mapped home 不重算為未映射前綴"
        );
        mapped[4] = u8::MAX;
        assert_eq!(
            check(&pending, &mapped, &spans, &live_at, 1)
                .expect_err("超出預付 work 必須拒絕")
                .kind,
            OfficialExportErrorKind::WorkExhausted,
        );
    }

    #[test]
    fn dying_gettable_key_and_plain_move_source_share_new_home_only_at_boundary() {
        let mut proto = dead_open_fixture(vec![
            Instruction::GetTable {
                dest: Register(3),
                table: Register(1),
                key: Register(2),
            },
            Instruction::Return {
                base: Register(3),
                result_mode: ResultMode::Fixed(1),
            },
        ]);
        let mut spans = [(usize::MAX, 0); 9];
        spans[2] = (0, 2);
        spans[3] = (0, 2);
        let mut rows: Vec<LiveRow> = (0..9).map(|_| LiveRow::Uncomputed).collect();
        rows[2] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0001],
        };
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0010],
        };
        let mut protected = [0u8; 9];
        let check = |proto: &BytecodePrototype, rows: &[LiveRow], protected: &[u8]| {
            let mut work = OfficialWorkBudget::new(1000);
            mapped_owner_interferes(proto, &spans, protected, rows, &[], 3, 2, &mut work).unwrap()
        };
        assert!(
            !check(&proto, &rows, &protected),
            "GetTable 必須先讀已死亡 key，再覆寫同一實體槽"
        );
        rows[2] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0011],
        };
        assert!(check(&proto, &rows, &protected), "key 存活出邊不得重疊");
        rows[2] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0001],
        };
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0011],
        };
        assert!(check(&proto, &rows, &protected), "dest 存活入邊不得重疊");
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0010],
        };
        protected[2] = 1;
        assert!(check(&proto, &rows, &protected), "受保護 key 不得共享");
        protected[2] = 0;
        protected[3] = 1;
        assert!(check(&proto, &rows, &protected), "受保護 dest 不得共享");
        protected[3] = 0;
        proto.instructions[0].instruction = Instruction::Move {
            dest: Register(3),
            src: Register(2),
        };
        assert!(
            !check(&proto, &rows, &protected),
            "普通 Move 先讀已死亡 src，再覆寫同一實體槽"
        );
        rows[2] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0011],
        };
        assert!(
            check(&proto, &rows, &protected),
            "Move src 存活出邊不得重疊"
        );
        rows[2] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0001],
        };
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0011],
        };
        assert!(
            check(&proto, &rows, &protected),
            "Move dest 存活入邊不得重疊"
        );
        rows[3] = LiveRow::Bits {
            base_pc: 0,
            bytes: vec![0b0000_0010],
        };
        protected[2] = 1;
        assert!(check(&proto, &rows, &protected), "受保護 Move src 不得共享");
        protected[2] = 0;
        proto.instructions[0].instruction = Instruction::UnaryOp {
            dest: Register(3),
            op: UnaryOperation::Not,
            src: Register(2),
        };
        assert!(check(&proto, &rows, &protected), "其他讀寫指令不在白名單");
        proto.instructions[0].instruction = Instruction::GetTable {
            dest: Register(3),
            table: Register(2),
            key: Register(1),
        };
        assert!(
            check(&proto, &rows, &protected),
            "table input 不在 key 白名單"
        );
    }

    #[test]
    fn sparse_live_rows_distinguish_empty_unknown_and_byte_aligned_base() {
        let spans = [(0, 17); 3];
        let protected = [0; 3];
        let rows = [
            LiveRow::Uncomputed,
            LiveRow::Bits {
                base_pc: 8,
                bytes: vec![0b0000_0010],
            },
            LiveRow::Bits {
                base_pc: 0,
                bytes: Vec::new(),
            },
        ];
        assert!(live_at_pc(&spans, &protected, &rows, 0, 7));
        assert!(!live_at_pc(&spans, &protected, &rows, 1, 7));
        assert!(!live_at_pc(&spans, &protected, &rows, 1, 8));
        assert!(live_at_pc(&spans, &protected, &rows, 1, 9));
        assert!(!live_at_pc(&spans, &protected, &rows, 1, 10));
        assert!(!live_at_pc(&spans, &protected, &rows, 2, 9));
        assert!(!live_at_pc(&spans, &protected, &rows, 0, 17));
    }

    #[test]
    fn sparse_live_snapshot_preserves_cfg_and_exact_payload_limit() {
        let proto = dead_open_fixture(vec![
            Instruction::LoadNil {
                start: Register(1),
                count: 2,
            },
            Instruction::Jump {
                target: InstructionOffset(3),
            },
            Instruction::Move {
                dest: Register(1),
                src: Register(1),
            },
            Instruction::JumpIfFalse {
                condition: Register(1),
                target: InstructionOffset(2),
            },
            Instruction::Return {
                base: Register(1),
                result_mode: ResultMode::Fixed(1),
            },
        ]);
        let mut mapped = vec![u8::MAX; usize::from(proto.register_count)];
        mapped[3] = 0;
        let mut spans = vec![(usize::MAX, 0); mapped.len()];
        spans[1] = (0, proto.instructions.len());
        spans[2] = (0, 1);
        spans[3] = (0, proto.instructions.len());
        let mut work = OfficialWorkBudget::new(1_000_000);
        let rows = extend_live_spans(&proto, &mapped, &mut spans, &[], 1, &mut work)
            .expect("一個 bitmap byte 應足以儲存完整 CFG 存活結果");
        let protected = vec![0; mapped.len()];
        assert!(!live_at_pc(&spans, &protected, &rows, 1, 0));
        for pc in 1..=4 {
            assert!(live_at_pc(&spans, &protected, &rows, 1, pc), "pc={pc}");
        }
        assert!(!live_at_pc(&spans, &protected, &rows, 2, 0));
        assert!(live_at_pc(&spans, &protected, &rows, 3, 2));
        assert!(matches!(&rows[1], LiveRow::Bits { base_pc: 0, bytes }
            if bytes.as_slice() == [0b0001_1110]));
        assert!(matches!(&rows[2], LiveRow::Bits { bytes, .. } if bytes.is_empty()));
        assert!(matches!(&rows[3], LiveRow::Uncomputed));

        let mut work = OfficialWorkBudget::new(1_000_000);
        let mut spans = vec![(usize::MAX, 0); mapped.len()];
        spans[1] = (0, proto.instructions.len());
        spans[2] = (0, 1);
        spans[3] = (0, proto.instructions.len());
        assert_eq!(
            extend_live_spans(&proto, &mapped, &mut spans, &[], 0, &mut work)
                .expect_err("少一個 bitmap byte 必須拒絕")
                .kind,
            OfficialExportErrorKind::LimitExceeded,
        );
    }

    #[test]
    fn call_layout_range_includes_left_and_excludes_right_pc() {
        let calls = [2, 5, 9, 15].map(|pc| TemporaryCallLayout {
            pc,
            first_slot: 0,
            window_start: 0,
            window_width: 0,
            window_end: 0,
            call_base: 0,
            open_chain: false,
        });
        for (start, end, expected) in [
            (0, 2, (0, 0)),
            (2, 3, (0, 1)),
            (5, 9, (1, 2)),
            (9, 15, (2, 3)),
            (5, 5, (1, 1)),
            (16, 20, (4, 4)),
        ] {
            let mut work = OfficialWorkBudget::new(100);
            assert_eq!(
                call_layout_range(&calls, start, end, ProtoId(0), &mut work).unwrap(),
                expected
            );
        }
        let mut work = OfficialWorkBudget::new(0);
        assert_eq!(
            call_layout_range(&[], 0, 20, ProtoId(0), &mut work).unwrap(),
            (0, 0)
        );
        assert_eq!(
            call_layout_range(&calls, 0, 20, ProtoId(0), &mut work)
                .expect_err("二分 probe 前須先扣 work")
                .kind,
            OfficialExportErrorKind::WorkExhausted,
        );
    }

    #[test]
    fn sparse_live_snapshot_packs_computed_nonzero_byte_base() {
        let mut instructions = vec![
            Instruction::LoadNil {
                start: Register(7),
                count: 1
            };
            11
        ];
        instructions.push(Instruction::LoadNil {
            start: Register(1),
            count: 1,
        });
        instructions.push(Instruction::Return {
            base: Register(1),
            result_mode: ResultMode::Fixed(1),
        });
        let proto = dead_open_fixture(instructions);
        let mapped = vec![u8::MAX; usize::from(proto.register_count)];
        let mut spans = vec![(usize::MAX, 0); mapped.len()];
        spans[1] = (11, 13);
        let mut work = OfficialWorkBudget::new(1_000_000);
        let rows = extend_live_spans(&proto, &mapped, &mut spans, &[], 1, &mut work).unwrap();
        assert!(matches!(&rows[1], LiveRow::Bits { base_pc: 8, bytes }
            if bytes.as_slice() == [0b0001_0000]));
        let protected = vec![0; mapped.len()];
        assert!(!live_at_pc(&spans, &protected, &rows, 1, 11));
        assert!(live_at_pc(&spans, &protected, &rows, 1, 12));
    }

    #[test]
    fn strict_open_call_chain_rejects_gap_cleanup_jump_and_wrong_consumer() {
        let chain = vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 0,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::All,
            },
            Instruction::TailCall {
                base: Register(2),
                arg_count: u16::MAX,
                result_mode: ResultMode::All,
            },
        ];
        let prove = |instructions| {
            strict_open_call_terminal(
                &dead_open_fixture(instructions),
                0,
                &mut OfficialWorkBudget::new(10_000),
            )
        };
        assert_eq!(prove(chain.clone()).unwrap(), Some(2));

        let mut gap = chain.clone();
        gap.insert(
            1,
            Instruction::LoadNil {
                start: Register(7),
                count: 1,
            },
        );
        assert_eq!(prove(gap.clone()).unwrap(), None);
        assert_eq!(
            open_chain_end(
                &dead_open_fixture(gap),
                0,
                &mut OfficialWorkBudget::new(10_000)
            )
            .unwrap_err()
            .kind,
            OfficialExportErrorKind::Unsupported
        );

        let mut cleanup = chain.clone();
        cleanup.insert(
            1,
            Instruction::Close {
                base: Register(7),
                count: 1,
            },
        );
        assert_eq!(
            prove(cleanup).unwrap_err().kind,
            OfficialExportErrorKind::Unsupported
        );

        let mut jump = chain.clone();
        jump.push(Instruction::Jump {
            target: InstructionOffset(1),
        });
        assert_eq!(
            prove(jump).unwrap_err().kind,
            OfficialExportErrorKind::Unsupported
        );

        let mut wrong = chain;
        wrong[2] = Instruction::TailCall {
            base: Register(2),
            arg_count: 1,
            result_mode: ResultMode::All,
        };
        assert_eq!(prove(wrong.clone()).unwrap(), None);
        assert_eq!(
            open_chain_end(
                &dead_open_fixture(wrong),
                0,
                &mut OfficialWorkBudget::new(10_000)
            )
            .unwrap_err()
            .kind,
            OfficialExportErrorKind::Unsupported
        );
    }

    #[test]
    fn environment_cache_open_chain_requires_physical_upvalue_and_exact_register() {
        let fixture = dead_open_fixture(vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 0,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Return {
                base: Register(7),
                result_mode: ResultMode::Fixed(1),
            },
        ]);
        let check = |candidate, physical| {
            environment_cache_chain_safe(
                &fixture,
                0,
                candidate,
                physical,
                &mut OfficialWorkBudget::new(100_000),
            )
            .unwrap()
        };
        assert!(check(Register(0), true));
        assert!(!check(Register(0), false));
        assert!(!check(Register(7), true));
    }

    #[test]
    fn environment_cache_open_chain_rejects_semantic_use_gap_close_and_jump() {
        let chain = vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 0,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::Move {
                dest: Register(7),
                src: Register(0),
            },
            Instruction::Return {
                base: Register(7),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        let check = |instructions: Vec<Instruction>, producer_pc| {
            environment_cache_chain_safe(
                &dead_open_fixture(instructions),
                producer_pc,
                Register(0),
                true,
                &mut OfficialWorkBudget::new(100_000),
            )
        };
        assert_eq!(check(chain.clone(), 0).unwrap(), true);

        let mut read = chain.clone();
        read[0] = Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        assert_eq!(check(read, 0).unwrap(), false);

        let mut gap = chain.clone();
        gap.insert(
            1,
            Instruction::LoadNil {
                start: Register(0),
                count: 1,
            },
        );
        assert_eq!(check(gap, 0).unwrap(), false);

        let mut close = chain.clone();
        close.insert(
            1,
            Instruction::Close {
                base: Register(0),
                count: 1,
            },
        );
        assert_eq!(
            check(close, 0).unwrap_err().kind,
            OfficialExportErrorKind::Unsupported
        );

        let mut jump = chain;
        jump.insert(
            0,
            Instruction::Jump {
                target: InstructionOffset(2),
            },
        );
        assert_eq!(
            check(jump, 1).unwrap_err().kind,
            OfficialExportErrorKind::Unsupported
        );
    }

    #[test]
    fn environment_cache_slot_rejects_alias_local_and_relay_occupants() {
        let id = ProtoId(0);
        let check = |intervals: &[(u8, usize, usize)]| {
            environment_cache_slot_exclusive(
                intervals,
                5,
                3,
                id,
                &mut OfficialWorkBudget::new(100_000),
            )
            .unwrap()
        };
        let env = (5, 0, 10);
        assert!(check(&[env]));
        assert!(!check(&[]));
        for occupied in [(5, 1, 9), (5, 3, 4), (5, 0, 10)] {
            assert!(!check(&[env, occupied]));
        }
        assert!(check(&[env, (5, 4, 9), (6, 0, 10)]));
    }

    #[test]
    fn open_call_dead_value_proof_accepts_consumed_dynamic_tail_only() {
        let instructions = vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 1,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(1),
            },
            Instruction::LoadNil {
                start: Register(5),
                count: 1,
            },
            Instruction::Return {
                base: Register(2),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        let check = |instructions| {
            dead_after_open_call(
                &dead_open_fixture(instructions),
                0,
                Register(5),
                &mut OfficialWorkBudget::new(100_000),
            )
            .unwrap()
        };
        assert!(check(instructions.clone()));
        let mut later_read = instructions.clone();
        later_read.insert(
            2,
            Instruction::Move {
                dest: Register(8),
                src: Register(5),
            },
        );
        assert!(!check(later_read));
        let mut jump_in = instructions;
        jump_in.insert(
            0,
            Instruction::Jump {
                target: InstructionOffset(2),
            },
        );
        assert!(
            dead_after_open_call(
                &dead_open_fixture(jump_in),
                1,
                Register(5),
                &mut OfficialWorkBudget::new(100_000),
            )
            .is_err()
        );
    }

    #[test]
    fn open_call_dead_value_proof_distinguishes_terminal_results_from_old_arguments() {
        let instructions = vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 1,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(4),
            },
            Instruction::Move {
                dest: Register(8),
                src: Register(5),
            },
            Instruction::Return {
                base: Register(8),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        let check = |instructions| {
            dead_after_open_call(
                &dead_open_fixture(instructions),
                0,
                Register(5),
                &mut OfficialWorkBudget::new(100_000),
            )
            .unwrap()
        };
        assert!(check(instructions.clone()));
        let mut unmodified_argument = instructions;
        unmodified_argument[1] = Instruction::Call {
            base: Register(3),
            arg_count: u16::MAX,
            result_mode: ResultMode::Fixed(2),
        };
        assert!(!check(unmodified_argument));
    }

    #[test]
    fn gathered_pending_open_call_allows_dead_home_but_not_later_read() {
        let instructions = vec![
            Instruction::Call {
                base: Register(4),
                arg_count: 2,
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(3),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::LoadNil {
                start: Register(3),
                count: 1,
            },
            Instruction::Return {
                base: Register(2),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        let check = |instructions, gathered| {
            dead_after_open_call_with_pending(
                &dead_open_fixture(instructions),
                0,
                Register(3),
                gathered,
                &mut OfficialWorkBudget::new(100_000),
            )
            .unwrap()
        };
        assert!(!check(instructions.clone(), false));
        assert!(check(instructions.clone(), true));
        let mut later_read = instructions;
        later_read.insert(
            2,
            Instruction::Move {
                dest: Register(8),
                src: Register(3),
            },
        );
        assert!(!check(later_read, true));
    }

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
    fn fixed_call_slot_pairs_preserve_cycles_fanout_and_spare_absence() {
        fn run_pairs(
            sources: &[u8],
            destinations: &[u8],
            spare: Option<u8>,
            original: &[i32],
            visible: usize,
        ) -> Option<(Vec<i32>, usize)> {
            assert_eq!(sources.len(), destinations.len());
            let mut source_slots = [0u8; 512];
            let mut destination_slots = [0u8; 512];
            source_slots[..sources.len()].copy_from_slice(sources);
            destination_slots[..destinations.len()].copy_from_slice(destinations);
            let mut work = OfficialWorkBudget::new(10_000);
            let plan = parallel_slot_pairs_plan(
                &source_slots,
                &destination_slots,
                sources.len(),
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
            values.truncate(visible);
            Some((values, plan.len))
        }
        assert_eq!(
            run_pairs(&[0, 1], &[1, 0], Some(2), &[10, 20, 0], 2),
            Some((vec![20, 10], 3)),
        );
        assert_eq!(
            run_pairs(&[0, 1, 2], &[1, 2, 0], Some(3), &[10, 20, 30, 0], 3),
            Some((vec![30, 10, 20], 4)),
        );
        assert_eq!(
            run_pairs(&[0, 0], &[1, 2], Some(3), &[10, 20, 30, 0], 3),
            Some((vec![10, 10, 10], 2)),
        );
        assert_eq!(
            run_pairs(&[1, 2], &[0, 1], None, &[10, 20, 30], 3),
            Some((vec![20, 30, 30], 2)),
        );
        assert_eq!(run_pairs(&[0, 1], &[1, 0], None, &[10, 20], 2), None);
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
