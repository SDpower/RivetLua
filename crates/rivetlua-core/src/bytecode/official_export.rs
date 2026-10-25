//! 將 P05 已驗證模組輸出為 Lua 5.4.9／5.5.1 官方 binary chunk。

use alloc::vec::Vec;
use rivetlua_alloc::{AllocationRecovery, GlobalAllocation, ReserveError, StateAllocator};

use super::official::{
    OfficialAbsLine, OfficialChunk, OfficialChunkErrorKind, OfficialChunkLimits, OfficialConstant,
    OfficialDebug, OfficialLocal, OfficialPrototype,
    encode_official_chunk_metered_with_recovery,
};
use super::codec::{BytecodeVec, RetainedVec, Scratch};
use super::official_translation::OfficialWorkBudget;
use super::{LuaProfile, ProtoId, VerifiedModule};
use core::mem::size_of;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialExportErrorKind {
    ProfileMismatch,
    InvalidPrototype,
    Unsupported,
    LimitExceeded,
    AllocationFailed,
    WorkExhausted,
    Codec,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialExportError {
    pub kind: OfficialExportErrorKind,
    pub prototype: ProtoId,
    pub pc: usize,
    pub detail: &'static str,
}

impl core::fmt::Display for OfficialExportError {
    fn fmt(&self, output: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            output,
            "原型 {} PC {}：{}",
            self.prototype.0, self.pc, self.detail
        )
    }
}

impl core::error::Error for OfficialExportError {}

#[derive(Debug)]
pub enum OfficialExportRecoveryError<E> {
    Export(OfficialExportError),
    Reserve(ReserveError<E>),
}

pub(super) fn error(
    kind: OfficialExportErrorKind,
    prototype: ProtoId,
    pc: usize,
    detail: &'static str,
) -> OfficialExportError {
    OfficialExportError {
        kind,
        prototype,
        pc,
        detail,
    }
}

pub(super) fn work_charge(
    work: &mut OfficialWorkBudget,
    units: usize,
    prototype: ProtoId,
    pc: usize,
) -> Result<(), OfficialExportError> {
    work.charge(units, prototype, pc).map_err(|_| {
        error(
            OfficialExportErrorKind::WorkExhausted,
            prototype,
            pc,
            "官方輸出 work 額度耗盡",
        )
    })
}

pub(super) fn copy_slice<T: Copy>(
    source: &[T],
    prototype: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<T>, OfficialExportError> {
    let bytes = source
        .len()
        .checked_mul(core::mem::size_of::<T>())
        .ok_or_else(|| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                prototype,
                0,
                "複製大小溢位",
            )
        })?;
    work_charge(work, bytes, prototype, 0)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(source.len()).map_err(|_| {
        error(
            OfficialExportErrorKind::AllocationFailed,
            prototype,
            0,
            "官方來源複製配置失敗",
        )
    })?;
    copy.extend_from_slice(source);
    Ok(copy)
}

pub(super) fn copy_slice_with_recovery<T: Copy, R: AllocationRecovery>(
    source: &[T],
    prototype: ProtoId,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<RetainedVec<T>, OfficialExportError> {
    let bytes = source.len().checked_mul(size_of::<T>()).ok_or_else(|| {
        error(OfficialExportErrorKind::LimitExceeded, prototype, 0, "複製大小溢位")
    })?;
    work_charge(work, bytes, prototype, 0)?;
    let mut copy = scratch.vec();
    scratch.reserve_exact(&mut copy, source.len()).map_err(|_| {
        error(OfficialExportErrorKind::AllocationFailed, prototype, 0, "官方來源複製配置失敗")
    })?;
    copy.extend_from_slice(source);
    scratch.retain(copy).map_err(|_| {
        error(OfficialExportErrorKind::AllocationFailed, prototype, 0, "官方來源 owner 配置失敗")
    })
}

fn copy_optional_bytes_with_recovery<R: AllocationRecovery>(
    source: Option<&[u8]>,
    prototype: ProtoId,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<Option<RetainedVec<u8>>, OfficialExportError> {
    source.map(|bytes| copy_slice_with_recovery(bytes, prototype, work, scratch)).transpose()
}

fn copy_optional_bytes(
    source: Option<&[u8]>,
    prototype: ProtoId,
    work: &mut OfficialWorkBudget,
) -> Result<Option<Vec<u8>>, OfficialExportError> {
    source
        .map(|bytes| copy_slice(bytes, prototype, work))
        .transpose()
}

#[derive(Default)]
struct ExportStats {
    state_owned: bool,
    prototypes: usize,
    instructions: usize,
    constants: usize,
    upvalues: usize,
    debug_entries: usize,
    strings: usize,
    string_bytes: usize,
    copy_bytes: usize,
}

impl ExportStats {
    fn add(
        value: &mut usize,
        amount: usize,
        maximum: usize,
        id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        *value = value
            .checked_add(amount)
            .filter(|total| *total <= maximum)
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "官方輸出資源上限或整數溢位",
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
                "複製大小溢位",
            )
        })?;
        Self::add(&mut self.copy_bytes, amount, limits.max_allocated_bytes, id)
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
                "官方字串超限",
            ));
        }
        Self::add(&mut self.strings, 1, limits.max_strings, id)?;
        Self::add(
            &mut self.string_bytes,
            bytes.len(),
            limits.max_total_string_bytes,
            id,
        )?;
        self.bytes(bytes.len(), 1, limits, id)?;
        if self.state_owned {
            self.bytes(1, StateAllocator::shared_block_size::<BytecodeVec<u8>>(), limits, id)?;
        }
        Ok(())
    }
}

fn scan_prototype(
    source: &OfficialPrototype,
    root_source: Option<&[u8]>,
    strip: bool,
    depth: usize,
    limits: &OfficialChunkLimits,
    stats: &mut ExportStats,
    work: &mut OfficialWorkBudget,
    id: ProtoId,
) -> Result<(), OfficialExportError> {
    work_charge(work, 1, id, 0)?;
    if depth > limits.max_depth {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            id,
            0,
            "官方子樹深度超限",
        ));
    }
    ExportStats::add(&mut stats.prototypes, 1, limits.max_prototypes, id)?;
    if stats.state_owned {
        stats.bytes(
            if strip { 4 } else { 8 },
            StateAllocator::shared_block_size::<BytecodeVec<u8>>(),
            limits,
            id,
        )?;
    }
    ExportStats::add(
        &mut stats.instructions,
        source.code.len(),
        limits.max_instructions,
        id,
    )?;
    ExportStats::add(
        &mut stats.constants,
        source.constants.len(),
        limits.max_constants,
        id,
    )?;
    ExportStats::add(
        &mut stats.upvalues,
        source.upvalues.len(),
        limits.max_upvalues,
        id,
    )?;
    stats.bytes(source.code.len(), size_of::<u32>(), limits, id)?;
    stats.bytes(
        source.constants.len(),
        size_of::<OfficialConstant>(),
        limits,
        id,
    )?;
    stats.bytes(
        source.upvalues.len(),
        size_of::<super::official::OfficialUpvalue>(),
        limits,
        id,
    )?;
    stats.bytes(source.children.len(), size_of::<ProtoId>(), limits, id)?;
    work_charge(work, source.constants.len(), id, 0)?;
    for constant in &source.constants {
        if let OfficialConstant::String { bytes, .. } = constant {
            stats.string(bytes, limits, id)?;
        }
    }
    if !strip {
        let debug = &source.debug;
        let count = debug
            .line_info
            .len()
            .checked_add(debug.abs_line_info.len())
            .and_then(|count| count.checked_add(debug.locals.len()))
            .and_then(|count| count.checked_add(debug.upvalue_names.len()))
            .ok_or_else(|| {
                error(
                    OfficialExportErrorKind::LimitExceeded,
                    id,
                    0,
                    "debug 數量溢位",
                )
            })?;
        ExportStats::add(
            &mut stats.debug_entries,
            count,
            limits.max_debug_entries,
            id,
        )?;
        stats.bytes(debug.line_info.len(), size_of::<i8>(), limits, id)?;
        stats.bytes(
            debug.abs_line_info.len(),
            size_of::<OfficialAbsLine>(),
            limits,
            id,
        )?;
        stats.bytes(debug.locals.len(), size_of::<OfficialLocal>(), limits, id)?;
        stats.bytes(
            debug.upvalue_names.len(),
            size_of::<Option<RetainedVec<u8>>>(),
            limits,
            id,
        )?;
        if let Some(bytes) = root_source.or(source.source.as_deref()) {
            stats.string(bytes, limits, id)?;
        }
        work_charge(
            work,
            debug
                .locals
                .len()
                .checked_add(debug.upvalue_names.len())
                .ok_or_else(|| {
                    error(
                        OfficialExportErrorKind::LimitExceeded,
                        id,
                        0,
                        "debug 掃描 work 溢位",
                    )
                })?,
            id,
            0,
        )?;
        for local in &debug.locals {
            if let Some(bytes) = local.name.as_deref() {
                stats.string(bytes, limits, id)?;
            }
        }
        for name in &debug.upvalue_names {
            if let Some(bytes) = name.as_deref() {
                stats.string(bytes, limits, id)?;
            }
        }
    }
    work_charge(work, source.children.len(), id, 0)?;
    Ok(())
}

fn copy_prototype_with_recovery<R: AllocationRecovery>(
    source: &OfficialPrototype,
    root_source: Option<&[u8]>,
    strip: bool,
    id: ProtoId,
    selected: ProtoId,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<OfficialPrototype, OfficialExportError> {
    work_charge(work, 1, id, 0)?;
    let code = copy_slice_with_recovery(&source.code, id, work, scratch)?;
    let upvalues = copy_slice_with_recovery(&source.upvalues, id, work, scratch)?;
    let mut constants = scratch.vec();
    scratch
        .reserve_exact(&mut constants, source.constants.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "常數配置失敗",
            )
        })?;
    for constant in &source.constants {
        work_charge(work, 1, id, 0)?;
        constants.push(match constant {
            OfficialConstant::Nil => OfficialConstant::Nil,
            OfficialConstant::Boolean(value) => OfficialConstant::Boolean(*value),
            OfficialConstant::Integer(value) => OfficialConstant::Integer(*value),
            OfficialConstant::Number(value) => OfficialConstant::Number(*value),
            OfficialConstant::String { bytes, long } => OfficialConstant::String {
                bytes: copy_slice_with_recovery(bytes, id, work, scratch)?,
                long: *long,
            },
        });
    }
    let mut children = scratch.vec();
    scratch
        .reserve_exact(&mut children, source.children.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "child 配置失敗",
            )
        })?;
    for child in &source.children {
        children.push(ProtoId(child.0.checked_sub(selected.0).ok_or_else(|| {
            error(OfficialExportErrorKind::InvalidPrototype, id, 0, "child prototype 順序不符")
        })?));
    }
    let (source_name, debug) = if strip {
        (None, OfficialDebug::default())
    } else {
        let mut locals = scratch.vec();
        scratch
            .reserve_exact(&mut locals, source.debug.locals.len())
            .map_err(|_| {
                error(
                    OfficialExportErrorKind::AllocationFailed,
                    id,
                    0,
                    "local debug 配置失敗",
                )
            })?;
        for local in &source.debug.locals {
            locals.push(OfficialLocal {
                name: copy_optional_bytes_with_recovery(local.name.as_deref(), id, work, scratch)?,
                start_pc: local.start_pc,
                end_pc: local.end_pc,
            });
        }
        let mut upvalue_names = scratch.vec();
        scratch
            .reserve_exact(&mut upvalue_names, source.debug.upvalue_names.len())
            .map_err(|_| {
                error(
                    OfficialExportErrorKind::AllocationFailed,
                    id,
                    0,
                    "upvalue 名稱配置失敗",
                )
            })?;
        for name in &source.debug.upvalue_names {
            upvalue_names.push(copy_optional_bytes_with_recovery(name.as_deref(), id, work, scratch)?);
        }
        let source_name = copy_optional_bytes_with_recovery(root_source.or(source.source.as_deref()), id, work, scratch)?;
        let debug = OfficialDebug {
            line_info: copy_slice_with_recovery(&source.debug.line_info, id, work, scratch)?,
            abs_line_info: copy_slice_with_recovery::<OfficialAbsLine, _>(&source.debug.abs_line_info, id, work, scratch)?,
            locals: scratch.retain(locals).map_err(|_| error(OfficialExportErrorKind::AllocationFailed, id, 0, "local owner 配置失敗"))?,
            upvalue_names: scratch.retain(upvalue_names).map_err(|_| error(OfficialExportErrorKind::AllocationFailed, id, 0, "upvalue name owner 配置失敗"))?,
        };
        (source_name, debug)
    };
    Ok(OfficialPrototype {
        source: source_name,
        line_defined: source.line_defined,
        last_line_defined: source.last_line_defined,
        num_params: source.num_params,
        flags: source.flags,
        max_stack_size: source.max_stack_size,
        code,
        constants: scratch.retain(constants).map_err(|_| error(OfficialExportErrorKind::AllocationFailed, id, 0, "constant owner 配置失敗"))?,
        upvalues,
        children: scratch.retain(children).map_err(|_| error(OfficialExportErrorKind::AllocationFailed, id, 0, "child owner 配置失敗"))?,
        debug,
    })
}

fn push_cursor<T, R: AllocationRecovery>(
    values: &mut BytecodeVec<T>,
    value: T,
    stats: &mut ExportStats,
    limits: &OfficialChunkLimits,
    id: ProtoId,
    scratch: &mut Scratch<'_, R>,
) -> Result<(), OfficialExportError> {
    if values.len() == values.capacity() {
        let additional = values.capacity().max(1);
        stats.bytes(additional, size_of::<T>(), limits, id)?;
        let previous = values.capacity();
        scratch.reserve_exact(values, additional).map_err(|_| {
            error(OfficialExportErrorKind::AllocationFailed, id, 0, "prototype cursor 配置失敗")
        })?;
        stats.bytes(values.capacity() - previous - additional, size_of::<T>(), limits, id)?;
    }
    values.push(value);
    Ok(())
}

/// 輸出的是函式原型，不含執行中的 upvalue 值、stack 或 coroutine。
pub fn emit_official_chunk(
    module: &VerifiedModule,
    selected: ProtoId,
    profile: LuaProfile,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<u8>, OfficialExportError> {
    let mut recovery = GlobalAllocation;
    let bytes = emit_official_chunk_with_recovery(module, selected, profile, strip, limits, work, &mut recovery)
        .map_err(|failure| match failure {
            OfficialExportRecoveryError::Export(error) => error,
            OfficialExportRecoveryError::Reserve(ReserveError::Recovery(never)) => match never {},
            OfficialExportRecoveryError::Reserve(_) => {
                error(OfficialExportErrorKind::AllocationFailed, selected, 0, "官方輸出配置失敗")
            }
        })?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).map_err(|_| {
        error(OfficialExportErrorKind::AllocationFailed, selected, 0, "官方輸出配置失敗")
    })?;
    output.extend_from_slice(&bytes);
    Ok(output)
}

pub fn emit_official_chunk_with_recovery<R: AllocationRecovery>(
    module: &VerifiedModule,
    selected: ProtoId,
    profile: LuaProfile,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    recovery: &mut R,
) -> Result<BytecodeVec<u8>, OfficialExportRecoveryError<R::Error>> {
    let mut scratch = Scratch::new(recovery);
    let result = emit_official_chunk_inner(module, selected, profile, strip, limits, work, &mut scratch);
    result.map_err(|error| match scratch.take_refusal() {
        Some(refusal) => OfficialExportRecoveryError::Reserve(refusal),
        None => OfficialExportRecoveryError::Export(error),
    })
}

fn emit_official_chunk_inner<R: AllocationRecovery>(
    module: &VerifiedModule,
    selected: ProtoId,
    profile: LuaProfile,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<BytecodeVec<u8>, OfficialExportError> {
    if module.profile() != profile {
        return Err(error(
            OfficialExportErrorKind::ProfileMismatch,
            selected,
            0,
            "輸出 profile 不符",
        ));
    }
    work_charge(work, module.module().prototypes.len(), selected, 0)?;
    if !module
        .module()
        .prototypes
        .iter()
        .any(|proto| proto.id == selected)
    {
        return Err(error(
            OfficialExportErrorKind::InvalidPrototype,
            selected,
            0,
            "prototype 不存在",
        ));
    }
    work_charge(work, 1, selected, 0)?;
    if limits.max_bytes < 32 {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            selected,
            0,
            "官方輸出 bytes 上限過小",
        ));
    }
    let encode_limits = *limits;
    let chunk = if let Some(artifact) = module.official_artifact() {
        work_charge(work, selected.0 as usize + 1, selected, 0)?;
        let source = artifact.prototype(selected).ok_or_else(|| {
            error(
                OfficialExportErrorKind::InvalidPrototype,
                selected,
                0,
                "artifact prototype 不存在",
            )
        })?;
        work_charge(work, selected.0 as usize + 1, selected, 0)?;
        let source_name = artifact.effective_source(selected);
        let mut stats = ExportStats {
            state_owned: scratch.recovery().allocator().is_lua(),
            ..ExportStats::default()
        };
        stats.bytes(1, size_of::<OfficialChunk>(), limits, selected)?;
        let mut pending = scratch.vec();
        let mut order = scratch.vec();
        push_cursor(&mut pending, (selected, 1usize), &mut stats, limits, selected, scratch)?;
        while let Some((id, depth)) = pending.pop() {
            if Some(id.0 as usize) != (selected.0 as usize).checked_add(order.len()) {
                return Err(error(OfficialExportErrorKind::InvalidPrototype, id, 0, "artifact 前序 ID 不連續"));
            }
            let node = artifact.prototype(id).ok_or_else(|| {
                error(OfficialExportErrorKind::InvalidPrototype, id, 0, "artifact child 不存在")
            })?;
            scan_prototype(node, if id == selected { source_name } else { None }, strip, depth, limits, &mut stats, work, id)?;
            push_cursor(&mut order, (id, depth), &mut stats, limits, id, scratch)?;
            for &child in node.children.iter().rev() {
                let child_depth = depth.checked_add(1).ok_or_else(|| {
                    error(OfficialExportErrorKind::LimitExceeded, id, 0, "prototype 深度溢位")
                })?;
                push_cursor(&mut pending, (child, child_depth), &mut stats, limits, id, scratch)?;
            }
        }
        stats.bytes(order.len(), size_of::<OfficialPrototype>(), limits, selected)?;
        if stats.state_owned {
            stats.bytes(1, StateAllocator::shared_block_size::<BytecodeVec<OfficialPrototype>>(), limits, selected)?;
        }
        let root_upvalues = u8::try_from(source.upvalues.len()).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                selected,
                0,
                "官方 root upvalue 超過 u8",
            )
        })?;
        let mut prototypes = scratch.vec();
        scratch.reserve_exact(&mut prototypes, order.len()).map_err(|_| {
            error(OfficialExportErrorKind::AllocationFailed, selected, 0, "prototype arena 配置失敗")
        })?;
        for &(id, _) in &order {
            let node = artifact.prototype(id).ok_or_else(|| {
                error(OfficialExportErrorKind::InvalidPrototype, id, 0, "artifact child 不存在")
            })?;
            prototypes.push(copy_prototype_with_recovery(
                node,
                if id == selected { source_name } else { None },
                strip,
                id,
                selected,
                work,
                scratch,
            )?);
        }
        OfficialChunk {
            profile,
            root_upvalues,
            main: ProtoId(0),
            prototypes: scratch.retain(prototypes).map_err(|_| {
                error(OfficialExportErrorKind::AllocationFailed, selected, 0, "prototype arena owner 配置失敗")
            })?,
        }
    } else if module
        .official_execution()
        .is_some_and(|plan| !plan.is_native_builtin())
    {
        return Err(error(
            OfficialExportErrorKind::Unsupported,
            selected,
            0,
            "無可信來源的合成 P05 plan 不可輸出",
        ));
    } else {
        super::official_native::emit_native_chunk_with_recovery(scratch, module, selected, profile, strip, limits, work)?
    };
    encode_official_chunk_metered_with_recovery(&chunk, strip, &encode_limits, work, scratch).map_err(|codec| {
        let kind = match codec.kind {
            OfficialChunkErrorKind::WorkExhausted => OfficialExportErrorKind::WorkExhausted,
            OfficialChunkErrorKind::LimitExceeded | OfficialChunkErrorKind::Overflow => {
                OfficialExportErrorKind::LimitExceeded
            }
            OfficialChunkErrorKind::AllocationFailed => OfficialExportErrorKind::AllocationFailed,
            _ => OfficialExportErrorKind::Codec,
        };
        error(kind, selected, codec.offset, codec.detail)
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum Dump54PreparePolicy {
    RequireLuaCompilerOutput,
    PreservePrivateExtension,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct Dump54Footprint {
    pub retained_bytes: usize,
    pub preparation_work: u64,
    pub temporary_bytes_bound: usize,
}

#[doc(hidden)]
pub struct Dump54Prepared {
    pub plan: Dump54Plan,
    footprint: Dump54Footprint,
}

impl Dump54Prepared {
    pub fn footprint(&self) -> Dump54Footprint {
        self.footprint
    }
}

struct Dump54Entry {
    source: ProtoId,
    parent: Option<ProtoId>,
    ordinal: usize,
    body: Option<OfficialPrototype>,
    body_error: Option<OfficialExportError>,
    incoming: Option<RetainedVec<super::official::OfficialUpvalue>>,
    incoming_error: Option<OfficialExportError>,
}

#[doc(hidden)]
pub struct Dump54Plan {
    official: bool,
    entries: RetainedVec<Dump54Entry>,
    source_index: RetainedVec<(ProtoId, usize)>,
}

impl Dump54Plan {
    fn entry(&self, source: ProtoId) -> Result<&Dump54Entry, OfficialExportError> {
        let slot = self.source_index
            .binary_search_by_key(&source, |(id, _)| *id)
            .map_err(|_| error(OfficialExportErrorKind::InvalidPrototype, source, 0,
                "dump54 來源原型不存在"))?;
        self.entries.get(self.source_index[slot].1)
            .filter(|entry| entry.source == source)
            .ok_or_else(|| error(
            OfficialExportErrorKind::InvalidPrototype, source, 0,
            "dump54 來源索引不符"))
    }

    fn body<'a>(
        &'a self,
        module: &'a VerifiedModule,
        source: ProtoId,
    ) -> Result<&'a OfficialPrototype, OfficialExportError> {
        let entry = self.entry(source)?;
        if let Some(failure) = &entry.body_error {
            return Err(failure.clone());
        }
        if self.official {
            return module.official_artifact()
                .and_then(|artifact| artifact.prototype(source))
                .ok_or_else(|| error(OfficialExportErrorKind::InvalidPrototype,
                    source, 0, "dump54 artifact 原型不存在"));
        }
        entry.body.as_ref().ok_or_else(|| error(
            OfficialExportErrorKind::InvalidPrototype, source, 0,
            "dump54 native body 不存在"))
    }

    fn upvalues<'a>(
        &'a self,
        module: &'a VerifiedModule,
        source: ProtoId,
        selected: ProtoId,
    ) -> Result<&'a [super::official::OfficialUpvalue], OfficialExportError> {
        let entry = self.entry(source)?;
        if source != selected {
            if let Some(failure) = &entry.incoming_error {
                return Err(failure.clone());
            }
            if let Some(incoming) = &entry.incoming {
                return Ok(incoming);
            }
        }
        Ok(&self.body(module, source)?.upvalues)
    }

    fn retained_bytes(&self) -> Option<usize> {
        let mut total = self.entries.retained_bytes()?
            .checked_add(self.source_index.retained_bytes()?)?;
        for entry in &self.entries {
            if let Some(body) = &entry.body {
                total = total.checked_add(body.retained_backing_bytes()?)?;
            }
            if let Some(incoming) = &entry.incoming {
                total = total.checked_add(incoming.retained_bytes()?)?;
            }
        }
        Some(total)
    }
}



/// selected 使用來源 BytecodePrototype.id，與官方 arena ordinal 分屬不同域。
#[doc(hidden)]
pub fn prepare_dump54_plan_with_recovery<R: AllocationRecovery>(
    module: &VerifiedModule,
    policy: Dump54PreparePolicy,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    recovery: &mut R,
) -> Result<Dump54Prepared, OfficialExportRecoveryError<R::Error>> {
    let mut scratch = Scratch::new(recovery);
    let result = prepare_dump54_plan_inner(module, policy, limits, work, &mut scratch);
    result.map_err(|failure| match scratch.take_refusal() {
        Some(refusal) => OfficialExportRecoveryError::Reserve(refusal),
        None => OfficialExportRecoveryError::Export(failure),
    })
}

fn dump54_index_work(
    work: &mut OfficialWorkBudget, count: usize, multiplier: usize,
    id: ProtoId,
) -> Result<(), OfficialExportError> {
    let levels = usize::BITS as usize
        - count.saturating_sub(1).leading_zeros() as usize;
    let units = count.checked_mul(levels.max(1))
        .and_then(|units| units.checked_mul(multiplier))
        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
            id, 0, "dump54 索引工作量溢位"))?;
    work_charge(work, units, id, 0)
}

fn prepare_dump54_plan_inner<R: AllocationRecovery>(
    module: &VerifiedModule,
    policy: Dump54PreparePolicy,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<Dump54Prepared, OfficialExportError> {
    let root = module.module().prototypes.first()
        .map_or(ProtoId(0), |proto| proto.id);
    if module.profile() != LuaProfile::Lua54 {
        return Err(error(OfficialExportErrorKind::ProfileMismatch, root, 0,
            "dump54 profile 不符"));
    }
    let count = module.module().prototypes.len();
    let metadata_bytes = count.checked_mul(size_of::<Dump54Entry>())
        .and_then(|bytes| bytes.checked_add(
            count.checked_mul(size_of::<(ProtoId, usize)>())?))
        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded, root, 0,
            "dump54 plan 索引大小溢位"))?;
    let child_order_bytes = count.checked_mul(size_of::<usize>())
        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded, root, 0,
            "dump54 child 索引大小溢位"))?;
    if metadata_bytes.checked_add(child_order_bytes)
        .is_none_or(|bytes| bytes > limits.max_allocated_bytes)
    {
        return Err(error(OfficialExportErrorKind::LimitExceeded, root, 0,
            "dump54 plan 索引超過配置額度"));
    }
    let start_work = work.consumed();
    work_charge(work, count, root, 0)?;
    let mut entries = scratch.vec();
    scratch.reserve_exact(&mut entries, count).map_err(|_| error(
        OfficialExportErrorKind::AllocationFailed, root, 0, "dump54 entry 配置失敗"))?;
    let mut source_index = scratch.vec();
    scratch.reserve_exact(&mut source_index, count).map_err(|_| error(
        OfficialExportErrorKind::AllocationFailed, root, 0, "dump54 ID 索引配置失敗"))?;
    for (index, proto) in module.module().prototypes.iter().enumerate() {
        entries.push(Dump54Entry {
            source: proto.id,
            parent: proto.parent,
            ordinal: 0,
            body: None,
            body_error: None,
            incoming: None,
            incoming_error: None,
        });
        source_index.push((proto.id, index));
    }
    dump54_index_work(work, count, 4, root)?;
    source_index.sort_unstable_by_key(|(id, _)| *id);
    if source_index.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(error(OfficialExportErrorKind::InvalidPrototype, root, 0,
            "dump54 來源 ID 重複"));
    }
    let mut child_counts = scratch.vec();
    scratch.reserve_exact(&mut child_counts, count).map_err(|_| error(
        OfficialExportErrorKind::AllocationFailed, root, 0,
        "dump54 child ordinal 配置失敗"))?;
    for _ in 0..count { child_counts.push(0usize); }
    for (index, proto) in module.module().prototypes.iter().enumerate() {
        if let Some(parent) = proto.parent {
            let slot = source_index.binary_search_by_key(&parent, |(id, _)| *id)
                .map_err(|_| error(OfficialExportErrorKind::InvalidPrototype,
                    proto.id, 0, "dump54 parent 不存在"))?;
            let parent_index = source_index[slot].1;
            entries[index].ordinal = child_counts[parent_index];
            child_counts[parent_index] = child_counts[parent_index]
                .checked_add(1).ok_or_else(|| error(
                    OfficialExportErrorKind::LimitExceeded, parent, 0,
                    "dump54 child ordinal 溢位"))?;
        }
    }
    let official = module.official_artifact().is_some();
    let mut temporary_bytes_bound = metadata_bytes
        .checked_add(child_counts.capacity().checked_mul(size_of::<usize>())
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 child 索引大小溢位"))?)
        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
            root, 0, "dump54 暫存大小溢位"))?;
    if temporary_bytes_bound > limits.max_allocated_bytes {
        return Err(error(OfficialExportErrorKind::LimitExceeded,
            root, 0, "dump54 暫存超過配置額度"));
    }
    if let Some(artifact) = module.official_artifact() {
        if artifact.profile() != LuaProfile::Lua54 {
            return Err(error(OfficialExportErrorKind::ProfileMismatch, root, 0,
                "dump54 artifact profile 不符"));
        }
        for proto in &module.module().prototypes {
            if artifact.prototype(proto.id).is_none() {
                return Err(error(OfficialExportErrorKind::InvalidPrototype,
                    proto.id, 0, "dump54 artifact 來源對照不存在"));
            }
        }
    } else if module.official_execution()
        .is_some_and(|plan| !plan.is_native_builtin())
    {
        let failure = error(OfficialExportErrorKind::Unsupported, root, 0,
            "無可信來源的合成 P05 plan 不可輸出");
        if policy == Dump54PreparePolicy::RequireLuaCompilerOutput {
            return Err(failure);
        }
        for entry in &mut entries {
            entry.body_error = Some(failure.clone());
        }
    } else {
        let children_len = child_counts.iter().try_fold(0usize, |total, count| {
            total.checked_add(*count)
        }).ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
            root, 0, "dump54 child 數量溢位"))?;
        let closure_count = module.module().prototypes.iter().try_fold(
            0usize, |total, proto| total.checked_add(proto.instructions.iter()
                .filter(|entry| matches!(entry.instruction,
                    super::Instruction::Closure { .. }))
                .count()))
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 closure site 數量溢位"))?;
        let binding_count = module.module().prototypes.iter().try_fold(
            0usize, |total, proto| total.checked_add(proto.binding_registers.len()))
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 binding 數量溢位"))?;
        let graph_bytes = count.checked_add(1)
            .and_then(|n| n.checked_mul(size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(
                children_len.checked_mul(size_of::<usize>())?))
            .and_then(|bytes| bytes.checked_add(
                count.checked_mul(size_of::<bool>())?))
            .and_then(|bytes| bytes.checked_add(closure_count.checked_mul(
                size_of::<super::official_native::Dump54ClosureSite>())?))
            .and_then(|bytes| bytes.checked_add(binding_count.checked_mul(
                size_of::<super::official_native::Dump54Binding>())?))
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 child 圖索引大小溢位"))?;
        let native_index_bytes = count.checked_mul(
            size_of::<Option<ProtoId>>()
                .checked_add(size_of::<Option<super::official_native::Layout>>())
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    root, 0, "dump54 lowering 暫存大小溢位"))?)
            .and_then(|bytes| bytes.checked_add(graph_bytes))
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 lowering 暫存大小溢位"))?;
        if temporary_bytes_bound.checked_add(native_index_bytes)
            .is_none_or(|bytes| bytes > limits.max_allocated_bytes)
        {
            return Err(error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 lowering 暫存超過配置額度"));
        }
        let mut child_offsets = scratch.vec();
        scratch.reserve_exact(&mut child_offsets, count + 1).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 child offset 配置失敗"))?;
        child_offsets.push(0usize);
        for &child_count in &child_counts {
            child_offsets.push(child_offsets.last().copied().unwrap_or(0)
                .checked_add(child_count).ok_or_else(|| error(
                    OfficialExportErrorKind::LimitExceeded, root, 0,
                    "dump54 child offset 溢位"))?);
        }
        let mut child_indices = scratch.vec();
        scratch.reserve_exact(&mut child_indices, children_len).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 child index 配置失敗"))?;
        child_indices.resize(children_len, 0usize);
        for (index, entry) in entries.iter().enumerate() {
            let Some(parent) = entry.parent else { continue };
            let slot = source_index.binary_search_by_key(&parent, |(id, _)| *id)
                .map_err(|_| error(OfficialExportErrorKind::InvalidPrototype,
                    entry.source, 0, "dump54 parent 不存在"))?;
            let parent_index = source_index[slot].1;
            let child_slot = child_offsets[parent_index].checked_add(entry.ordinal)
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    entry.source, 0, "dump54 child ordinal 溢位"))?;
            *child_indices.get_mut(child_slot).ok_or_else(|| error(
                OfficialExportErrorKind::InvalidPrototype, entry.source, 0,
                "dump54 child ordinal 無效"))? = index;
        }
        let mut closure_sites = scratch.vec();
        scratch.reserve_exact(&mut closure_sites, closure_count).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 closure site 配置失敗"))?;
        for proto in &module.module().prototypes {
            work_charge(work, proto.instructions.len(), proto.id, 0)?;
            for (pc, entry) in proto.instructions.iter().enumerate() {
                if let super::Instruction::Closure { proto: child, .. } = entry.instruction {
                    closure_sites.push(super::official_native::Dump54ClosureSite {
                        parent: proto.id, child, pc,
                    });
                }
            }
        }
        dump54_index_work(work, closure_count, 2, root)?;
        closure_sites.sort_unstable_by_key(|site| (site.parent, site.child, site.pc));
        let mut binding_sites = scratch.vec();
        scratch.reserve_exact(&mut binding_sites, binding_count).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 binding 索引配置失敗"))?;
        for proto in &module.module().prototypes {
            work_charge(work, proto.binding_registers.len(), proto.id, 0)?;
            for (ordinal, &(id, register)) in proto.binding_registers.iter().enumerate() {
                binding_sites.push(super::official_native::Dump54Binding {
                    parent: proto.id, id, ordinal, register,
                });
            }
        }
        dump54_index_work(work, binding_count, 2, root)?;
        binding_sites.sort_unstable_by_key(|site| {
            (site.parent, site.id.function, site.id.ordinal, site.ordinal)
        });
        let env_needed = super::official_native::dump54_environment_needs(
            scratch, module, &source_index, &child_offsets, &child_indices, work)?;
        let mut source_to_official = scratch.vec();
        scratch.reserve_exact(&mut source_to_official, count).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 native 來源對照配置失敗"))?;
        for proto in &module.module().prototypes {
            source_to_official.push(Some(proto.id));
        }
        let mut layouts = scratch.vec();
        scratch.reserve_exact(&mut layouts, count).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 layout cursor 配置失敗"))?;
        for _ in 0..count {
            layouts.push(None);
        }
        temporary_bytes_bound = temporary_bytes_bound
            .checked_add(child_offsets.capacity().checked_mul(size_of::<usize>())
                .and_then(|bytes| bytes.checked_add(child_indices.capacity()
                    .checked_mul(size_of::<usize>())?))
                .and_then(|bytes| bytes.checked_add(env_needed.capacity()
                    .checked_mul(size_of::<bool>())?))
                .and_then(|bytes| bytes.checked_add(closure_sites.capacity()
                    .checked_mul(size_of::<super::official_native::Dump54ClosureSite>())?))
                .and_then(|bytes| bytes.checked_add(binding_sites.capacity()
                    .checked_mul(size_of::<super::official_native::Dump54Binding>())?))
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    root, 0, "dump54 圖索引大小溢位"))?)
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 圖索引大小溢位"))?
            .checked_add(source_to_official.capacity()
                .checked_mul(size_of::<Option<ProtoId>>())
                .and_then(|bytes| bytes.checked_add(layouts.capacity()
                    .checked_mul(size_of::<Option<super::official_native::Layout>>())?))
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    root, 0, "dump54 lowering 暫存大小溢位"))?)
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 lowering 暫存大小溢位"))?;
        if temporary_bytes_bound > limits.max_allocated_bytes {
            return Err(error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 lowering 暫存超過配置額度"));
        }
        let outer_temporary = temporary_bytes_bound;
        let mut layout_backing = 0usize;
        let mut retained_backing = 0usize;
        for (index, proto) in module.module().prototypes.iter().enumerate() {
            let mut total_instructions = 0usize;
            let committed = outer_temporary.checked_add(layout_backing)
                .and_then(|bytes| bytes.checked_add(retained_backing))
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    proto.id, 0, "dump54 準備 peak 溢位"))?;
            let mut body_limits = *limits;
            body_limits.max_allocated_bytes = limits.max_allocated_bytes
                .checked_sub(committed).ok_or_else(|| error(
                    OfficialExportErrorKind::LimitExceeded, proto.id, 0,
                    "dump54 準備 peak 超限"))?;
            let children = super::official_native::NativeChildren::indexed(
                &module.module().prototypes, proto.id,
                &child_indices[child_offsets[index]..child_offsets[index + 1]],
                &source_index);
            match super::official_native::lower_dump54_body(
                scratch, module, proto, children, env_needed[index],
                &body_limits, work,
                &source_to_official, &mut total_instructions)
            {
                Ok((body, layout, temporary)) => {
                    retained_backing = retained_backing
                        .checked_add(body.retained_backing_bytes().ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, proto.id, 0,
                            "dump54 body retained 大小溢位"))?)
                        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 retained 大小溢位"))?;
                    layout_backing = layout_backing
                        .checked_add(layout.temporary_backing_bytes().ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, proto.id, 0,
                            "dump54 layout 暫存大小溢位"))?)
                        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 layout 暫存大小溢位"))?;
                    let peak = outer_temporary.checked_add(layout_backing)
                        .and_then(|bytes| bytes.checked_add(temporary))
                        .and_then(|bytes| bytes.checked_add(retained_backing))
                        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 準備 peak 溢位"))?;
                    if peak > limits.max_allocated_bytes {
                        return Err(error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 準備 peak 超限"));
                    }
                    entries[index].body = Some(body);
                    layouts[index] = Some(layout);
                    temporary_bytes_bound = temporary_bytes_bound
                        .max(outer_temporary + layout_backing + temporary);
                }
                Err(failure) if failure.kind == OfficialExportErrorKind::Unsupported
                    && policy == Dump54PreparePolicy::PreservePrivateExtension =>
                {
                    entries[index].body_error = Some(failure);
                }
                Err(failure) => return Err(failure),
            }
        }
        let mut incoming_backing = 0usize;
        for (index, proto) in module.module().prototypes.iter().enumerate() {
            let Some(parent_id) = proto.parent else { continue };
            if entries[index].body_error.is_some() { continue; }
            let parent_index = source_index.binary_search_by_key(
                &parent_id, |(id, _)| *id)
                .map_err(|_| error(OfficialExportErrorKind::InvalidPrototype,
                    proto.id, 0, "dump54 parent 來源不存在"))?;
            let parent_index = source_index[parent_index].1;
            let (Some(layout), Some(parent_layout)) =
                (layouts[index].as_ref(), layouts[parent_index].as_ref())
            else {
                entries[index].incoming_error = Some(entries[parent_index]
                    .body_error.clone().unwrap_or_else(|| error(
                        OfficialExportErrorKind::Unsupported, proto.id, 0,
                        "parent 無可用 incoming layout")));
                continue;
            };
            let parent = &module.module().prototypes[parent_index];
            let key = (parent_id, proto.id);
            let first_site = closure_sites.partition_point(|site| {
                (site.parent, site.child) < key
            });
            let last_site = closure_sites.partition_point(|site| {
                (site.parent, site.child) <= key
            });
            let first_binding = binding_sites.partition_point(|site| {
                site.parent < parent_id
            });
            let last_binding = binding_sites.partition_point(|site| {
                site.parent <= parent_id
            });
            let committed = outer_temporary.checked_add(layout_backing)
                .and_then(|bytes| bytes.checked_add(retained_backing))
                .and_then(|bytes| bytes.checked_add(incoming_backing))
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    proto.id, 0, "dump54 incoming peak 溢位"))?;
            let remaining = limits.max_allocated_bytes.checked_sub(committed)
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    proto.id, 0, "dump54 incoming peak 超限"))?;
            match super::official_native::dump54_incoming_upvalues(
                scratch, module, proto, layout, parent, parent_layout,
                &closure_sites[first_site..last_site],
                &binding_sites[first_binding..last_binding],
                work, remaining)
            {
                Ok(incoming) => {
                    incoming_backing = incoming_backing
                        .checked_add(incoming.retained_bytes().ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, proto.id, 0,
                            "dump54 incoming retained 大小溢位"))?)
                        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 incoming retained 大小溢位"))?;
                    if incoming_backing > limits.max_allocated_bytes - committed {
                        return Err(error(OfficialExportErrorKind::LimitExceeded,
                            proto.id, 0, "dump54 incoming retained 超限"));
                    }
                    entries[index].incoming = Some(incoming);
                }
                Err(failure) if failure.kind == OfficialExportErrorKind::Unsupported
                    && policy == Dump54PreparePolicy::PreservePrivateExtension =>
                {
                    entries[index].incoming_error = Some(failure);
                }
                Err(failure) => return Err(failure),
            }
        }
    }
    let mut live_bytes = entries.capacity().checked_mul(size_of::<Dump54Entry>())
        .and_then(|bytes| bytes.checked_add(source_index.capacity()
            .checked_mul(size_of::<(ProtoId, usize)>())?))
        .and_then(|bytes| bytes.checked_add(child_counts.capacity()
            .checked_mul(size_of::<usize>())?))
        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
            root, 0, "dump54 plan live 大小溢位"))?;
    for entry in &entries {
        if let Some(body) = &entry.body {
            live_bytes = live_bytes.checked_add(body.retained_backing_bytes()
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    entry.source, 0, "dump54 body retained 大小溢位"))?)
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    entry.source, 0, "dump54 plan live 大小溢位"))?;
        }
        if let Some(incoming) = &entry.incoming {
            live_bytes = live_bytes.checked_add(incoming.retained_bytes()
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    entry.source, 0, "dump54 incoming retained 大小溢位"))?)
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    entry.source, 0, "dump54 plan live 大小溢位"))?;
        }
    }
    if scratch.recovery().allocator().is_lua() {
        live_bytes = live_bytes.checked_add(
            StateAllocator::shared_block_size::<BytecodeVec<Dump54Entry>>())
            .and_then(|bytes| bytes.checked_add(
                StateAllocator::shared_block_size::<BytecodeVec<(ProtoId, usize)>>()))
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                root, 0, "dump54 plan owner 大小溢位"))?;
    }
    if live_bytes > limits.max_allocated_bytes {
        return Err(error(OfficialExportErrorKind::LimitExceeded,
            root, 0, "dump54 plan owner 超過配置額度"));
    }
    let plan = Dump54Plan {
        official,
        entries: scratch.retain(entries).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 entry owner 配置失敗"))?,
        source_index: scratch.retain(source_index).map_err(|_| error(
            OfficialExportErrorKind::AllocationFailed, root, 0,
            "dump54 ID owner 配置失敗"))?,
    };
    let retained_bytes = plan.retained_bytes().ok_or_else(|| error(
        OfficialExportErrorKind::LimitExceeded, root, 0,
        "dump54 retained 大小溢位"))?;
    if retained_bytes > limits.max_allocated_bytes {
        return Err(error(OfficialExportErrorKind::LimitExceeded, root, 0,
            "dump54 retained 超過配置額度"));
    }
    Ok(Dump54Prepared {
        plan,
        footprint: Dump54Footprint {
            retained_bytes,
            preparation_work: work.consumed().saturating_sub(start_work),
            temporary_bytes_bound,
        },
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Dump54Phase {
    Header, IntegerSentinel, NumberSentinel, RootUpvalues,
    SourceSize, SourceData, FirstLine, LastLine, Params, Flags, Stack,
    CodeCount, Code, ConstantCount, ConstantTag, ConstantValue,
    ConstantStringData, UpvalueCount, Upvalue, ChildCount, Children,
    LineCount, Lines, AbsCount, AbsPc, AbsLine,
    LocalCount, LocalNameSize, LocalNameData, LocalStart, LocalEnd,
    UpvalueNameCount, UpvalueNameSize, UpvalueNameData, Finish, Done,
}

#[doc(hidden)]
pub enum Dump54Piece<'a> {
    Borrowed(&'a [u8]),
    Inline { bytes: [u8; 16], len: u8 },
}

impl Dump54Piece<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Inline { bytes, len } => &bytes[..usize::from(*len)],
        }
    }
}

fn dump54_inline(bytes: &[u8]) -> Dump54Piece<'static> {
    let mut out = [0u8; 16];
    out[..bytes.len()].copy_from_slice(bytes);
    Dump54Piece::Inline { bytes: out, len: bytes.len() as u8 }
}

fn dump54_varint(mut value: u64) -> Dump54Piece<'static> {
    let mut bytes = [0u8; 16];
    let mut start = 15usize;
    bytes[start] = (value as u8 & 0x7f) | 0x80;
    value >>= 7;
    while value != 0 {
        start -= 1;
        bytes[start] = value as u8 & 0x7f;
        value >>= 7;
    }
    let len = 16 - start;
    bytes.copy_within(start.., 0);
    Dump54Piece::Inline { bytes, len: len as u8 }
}

fn dump54_size(value: usize, id: ProtoId) -> Result<Dump54Piece<'static>, OfficialExportError> {
    let value = u64::try_from(value).map_err(|_| error(
        OfficialExportErrorKind::LimitExceeded, id, 0, "dump54 size 超出 u64"))?;
    Ok(dump54_varint(value))
}

fn dump54_int(value: usize, id: ProtoId) -> Result<Dump54Piece<'static>, OfficialExportError> {
    if value > (i32::MAX as usize - 128) {
        return Err(error(OfficialExportErrorKind::LimitExceeded,
            id, 0, "dump54 int 超出官方範圍"));
    }
    dump54_size(value, id)
}

fn dump54_string_size(
    bytes: Option<&[u8]>,
    id: ProtoId,
) -> Result<Dump54Piece<'static>, OfficialExportError> {
    let size = match bytes {
        Some(bytes) => bytes.len().checked_add(1).ok_or_else(|| error(
            OfficialExportErrorKind::LimitExceeded, id, 0,
            "dump54 字串大小溢位"))?,
        None => 0,
    };
    dump54_size(size, id)
}

/// 固定大小 cursor；selected 與 current 均為來源原型 ID。
#[doc(hidden)]
pub struct Dump54Cursor {
    selected: ProtoId,
    current: ProtoId,
    strip: bool,
    phase: Dump54Phase,
    index: usize,
    depth: usize,
    entered_prototypes: usize,
}

impl Dump54Cursor {
    pub fn new(selected: ProtoId, strip: bool) -> Self {
        Self { selected, current: selected, strip,
            phase: Dump54Phase::Header, index: 0,
            depth: 1, entered_prototypes: 0 }
    }

    fn source<'a>(
        &self,
        module: &'a VerifiedModule,
        plan: &'a Dump54Plan,
        body: &'a OfficialPrototype,
    ) -> Option<&'a [u8]> {
        if self.strip { return None; }
        if self.current == self.selected {
            if let Some(artifact) = module.official_artifact() {
                return artifact.effective_source(self.selected)
                    .or(body.source.as_deref());
            }
            return Some(module.native_debug()
                .map_or(&b"=RivetLua"[..], |debug| debug.source_name()));
        }
        if plan.official { body.source.as_deref() } else { None }
    }

    pub fn next<'a>(
        &mut self,
        module: &'a VerifiedModule,
        plan: &'a Dump54Plan,
    ) -> Result<Option<Dump54Piece<'a>>, OfficialExportError> {
        loop {
            if self.phase == Dump54Phase::Done { return Ok(None); }
            let id = self.current;
            let body = plan.body(module, id)?;
            match self.phase {
                Dump54Phase::Header => {
                    self.phase = Dump54Phase::IntegerSentinel;
                    return Ok(Some(Dump54Piece::Borrowed(
                        b"\x1bLua\x54\0\x19\x93\r\n\x1a\n\x04\x08\x08")));
                }
                Dump54Phase::IntegerSentinel => {
                    self.phase = Dump54Phase::NumberSentinel;
                    return Ok(Some(dump54_inline(&0x5678i64.to_le_bytes())));
                }
                Dump54Phase::NumberSentinel => {
                    self.phase = Dump54Phase::RootUpvalues;
                    return Ok(Some(dump54_inline(&370.5f64.to_le_bytes())));
                }
                Dump54Phase::RootUpvalues => {
                    let count = plan.upvalues(module, self.selected, self.selected)?.len();
                    let count = u8::try_from(count).map_err(|_| error(
                        OfficialExportErrorKind::LimitExceeded, self.selected, 0,
                        "dump54 root upvalue 超出 u8"))?;
                    self.phase = Dump54Phase::SourceSize;
                    return Ok(Some(dump54_inline(&[count])));
                }
                Dump54Phase::SourceSize => {
                    let source = self.source(module, plan, body);
                    self.entered_prototypes = self.entered_prototypes
                        .checked_add(1).ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, id, 0,
                            "dump54 prototype 數溢位"))?;
                    self.phase = Dump54Phase::SourceData;
                    return Ok(Some(dump54_string_size(source, id)?));
                }
                Dump54Phase::SourceData => {
                    let source = self.source(module, plan, body);
                    self.phase = Dump54Phase::FirstLine;
                    if let Some(bytes) = source.filter(|bytes| !bytes.is_empty()) {
                        return Ok(Some(Dump54Piece::Borrowed(bytes)));
                    }
                }
                Dump54Phase::FirstLine => {
                    self.phase = Dump54Phase::LastLine;
                    return Ok(Some(dump54_int(body.line_defined as usize, id)?));
                }
                Dump54Phase::LastLine => {
                    self.phase = Dump54Phase::Params;
                    return Ok(Some(dump54_int(body.last_line_defined as usize, id)?));
                }
                Dump54Phase::Params => {
                    self.phase = Dump54Phase::Flags;
                    return Ok(Some(dump54_inline(&[body.num_params])));
                }
                Dump54Phase::Flags => {
                    self.phase = Dump54Phase::Stack;
                    return Ok(Some(dump54_inline(&[body.flags])));
                }
                Dump54Phase::Stack => {
                    self.phase = Dump54Phase::CodeCount;
                    return Ok(Some(dump54_inline(&[body.max_stack_size])));
                }
                Dump54Phase::CodeCount => {
                    self.phase = Dump54Phase::Code;
                    self.index = 0;
                    return Ok(Some(dump54_int(body.code.len(), id)?));
                }
                Dump54Phase::Code => {
                    if let Some(word) = body.code.get(self.index) {
                        self.index += 1;
                        return Ok(Some(dump54_inline(&word.to_le_bytes())));
                    }
                    self.phase = Dump54Phase::ConstantCount;
                }
                Dump54Phase::ConstantCount => {
                    self.phase = Dump54Phase::ConstantTag;
                    self.index = 0;
                    return Ok(Some(dump54_int(body.constants.len(), id)?));
                }
                Dump54Phase::ConstantTag => {
                    let Some(constant) = body.constants.get(self.index) else {
                        self.phase = Dump54Phase::UpvalueCount;
                        continue;
                    };
                    let tag = match constant {
                        OfficialConstant::Nil => 0,
                        OfficialConstant::Boolean(false) => 1,
                        OfficialConstant::Boolean(true) => 17,
                        OfficialConstant::Integer(_) => 3,
                        OfficialConstant::Number(_) => 19,
                        OfficialConstant::String { long: false, .. } => 4,
                        OfficialConstant::String { long: true, .. } => 20,
                    };
                    self.phase = Dump54Phase::ConstantValue;
                    return Ok(Some(dump54_inline(&[tag])));
                }
                Dump54Phase::ConstantValue => {
                    let constant = body.constants.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 常數索引不符"))?;
                    match constant {
                        OfficialConstant::Nil | OfficialConstant::Boolean(_) => {
                            self.index += 1;
                            self.phase = Dump54Phase::ConstantTag;
                        }
                        OfficialConstant::Integer(value) => {
                            self.index += 1;
                            self.phase = Dump54Phase::ConstantTag;
                            return Ok(Some(dump54_inline(&value.to_le_bytes())));
                        }
                        OfficialConstant::Number(value) => {
                            self.index += 1;
                            self.phase = Dump54Phase::ConstantTag;
                            return Ok(Some(dump54_inline(&value.to_le_bytes())));
                        }
                        OfficialConstant::String { bytes, .. } => {
                            self.phase = Dump54Phase::ConstantStringData;
                            return Ok(Some(dump54_string_size(Some(bytes.as_slice()), id)?));
                        }
                    }
                }
                Dump54Phase::ConstantStringData => {
                    let bytes = match body.constants.get(self.index) {
                        Some(OfficialConstant::String { bytes, .. }) => bytes.as_slice(),
                        _ => return Err(error(OfficialExportErrorKind::InvalidPrototype,
                            id, self.index, "dump54 字串常數狀態不符")),
                    };
                    self.index += 1;
                    self.phase = Dump54Phase::ConstantTag;
                    if !bytes.is_empty() {
                        return Ok(Some(Dump54Piece::Borrowed(bytes)));
                    }
                }
                Dump54Phase::UpvalueCount => {
                    let count = plan.upvalues(module, id, self.selected)?.len();
                    self.phase = Dump54Phase::Upvalue;
                    self.index = 0;
                    return Ok(Some(dump54_int(count, id)?));
                }
                Dump54Phase::Upvalue => {
                    let values = plan.upvalues(module, id, self.selected)?;
                    if let Some(value) = values.get(self.index) {
                        self.index += 1;
                        return Ok(Some(dump54_inline(&[
                            u8::from(value.in_stack), value.index, value.kind])));
                    }
                    self.phase = Dump54Phase::ChildCount;
                }
                Dump54Phase::ChildCount => {
                    self.phase = Dump54Phase::Children;
                    self.index = 0;
                    return Ok(Some(dump54_int(body.children.len(), id)?));
                }
                Dump54Phase::Children => {
                    if let Some(&child) = body.children.get(self.index) {
                        let entry = plan.entry(child)?;
                        if entry.parent != Some(id) || entry.ordinal != self.index {
                            return Err(error(OfficialExportErrorKind::InvalidPrototype,
                                child, 0, "dump54 child ordinal 不符"));
                        }
                        self.current = child;
                        self.depth = self.depth.checked_add(1).ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, child, 0,
                            "dump54 深度溢位"))?;
                        self.phase = Dump54Phase::SourceSize;
                        self.index = 0;
                    } else {
                        self.phase = Dump54Phase::LineCount;
                    }
                }
                Dump54Phase::LineCount => {
                    self.phase = Dump54Phase::Lines;
                    self.index = 0;
                    return Ok(Some(dump54_int(
                        if self.strip { 0 } else { body.debug.line_info.len() }, id)?));
                }
                Dump54Phase::Lines => {
                    if !self.strip {
                        if let Some(line) = body.debug.line_info.get(self.index) {
                            self.index += 1;
                            return Ok(Some(dump54_inline(&[*line as u8])));
                        }
                    }
                    self.phase = Dump54Phase::AbsCount;
                }
                Dump54Phase::AbsCount => {
                    self.phase = Dump54Phase::AbsPc;
                    self.index = 0;
                    return Ok(Some(dump54_int(
                        if self.strip { 0 } else { body.debug.abs_line_info.len() }, id)?));
                }
                Dump54Phase::AbsPc => {
                    if !self.strip {
                        if let Some(abs) = body.debug.abs_line_info.get(self.index) {
                            self.phase = Dump54Phase::AbsLine;
                            return Ok(Some(dump54_int(abs.pc as usize, id)?));
                        }
                    }
                    self.phase = Dump54Phase::LocalCount;
                }
                Dump54Phase::AbsLine => {
                    let abs = body.debug.abs_line_info.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 absolute line 索引不符"))?;
                    self.index += 1;
                    self.phase = Dump54Phase::AbsPc;
                    return Ok(Some(dump54_int(abs.line as usize, id)?));
                }
                Dump54Phase::LocalCount => {
                    self.phase = Dump54Phase::LocalNameSize;
                    self.index = 0;
                    return Ok(Some(dump54_int(
                        if self.strip { 0 } else { body.debug.locals.len() }, id)?));
                }
                Dump54Phase::LocalNameSize => {
                    if !self.strip {
                        if let Some(local) = body.debug.locals.get(self.index) {
                            self.phase = Dump54Phase::LocalNameData;
                            return Ok(Some(dump54_string_size(local.name.as_deref(), id)?));
                        }
                    }
                    self.phase = Dump54Phase::UpvalueNameCount;
                }
                Dump54Phase::LocalNameData => {
                    let local = body.debug.locals.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 local 索引不符"))?;
                    self.phase = Dump54Phase::LocalStart;
                    if let Some(bytes) = local.name.as_deref().filter(|bytes| !bytes.is_empty()) {
                        return Ok(Some(Dump54Piece::Borrowed(bytes)));
                    }
                }
                Dump54Phase::LocalStart => {
                    let local = body.debug.locals.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 local 索引不符"))?;
                    self.phase = Dump54Phase::LocalEnd;
                    return Ok(Some(dump54_int(local.start_pc as usize, id)?));
                }
                Dump54Phase::LocalEnd => {
                    let local = body.debug.locals.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 local 索引不符"))?;
                    self.index += 1;
                    self.phase = Dump54Phase::LocalNameSize;
                    return Ok(Some(dump54_int(local.end_pc as usize, id)?));
                }
                Dump54Phase::UpvalueNameCount => {
                    self.phase = Dump54Phase::UpvalueNameSize;
                    self.index = 0;
                    return Ok(Some(dump54_int(
                        if self.strip { 0 } else { body.debug.upvalue_names.len() }, id)?));
                }
                Dump54Phase::UpvalueNameSize => {
                    if !self.strip {
                        if let Some(name) = body.debug.upvalue_names.get(self.index) {
                            self.phase = Dump54Phase::UpvalueNameData;
                            return Ok(Some(dump54_string_size(name.as_deref(), id)?));
                        }
                    }
                    self.phase = Dump54Phase::Finish;
                }
                Dump54Phase::UpvalueNameData => {
                    let name = body.debug.upvalue_names.get(self.index).ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, self.index,
                        "dump54 upvalue name 索引不符"))?;
                    self.index += 1;
                    self.phase = Dump54Phase::UpvalueNameSize;
                    if let Some(bytes) = name.as_deref().filter(|bytes| !bytes.is_empty()) {
                        return Ok(Some(Dump54Piece::Borrowed(bytes)));
                    }
                }
                Dump54Phase::Finish => {
                    if id == self.selected {
                        self.phase = Dump54Phase::Done;
                    } else {
                        let entry = plan.entry(id)?;
                        let parent = entry.parent.ok_or_else(|| error(
                            OfficialExportErrorKind::InvalidPrototype, id, 0,
                            "dump54 child 缺 parent"))?;
                        self.current = parent;
                        self.depth = self.depth.checked_sub(1).ok_or_else(|| error(
                            OfficialExportErrorKind::InvalidPrototype, id, 0,
                            "dump54 cursor 深度不符"))?;
                        self.index = entry.ordinal.checked_add(1).ok_or_else(|| error(
                            OfficialExportErrorKind::LimitExceeded, id, 0,
                            "dump54 child ordinal 溢位"))?;
                        self.phase = Dump54Phase::Children;
                    }
                }
                Dump54Phase::Done => return Ok(None),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub struct Dump54Preflight {
    pub encoded_bytes: usize,
    pub output_work: u64,
    pub temporary_bytes: usize,
}

struct Dump54Stats {
    prototypes: usize,
    instructions: usize,
    constants: usize,
    upvalues: usize,
    debug_entries: usize,
    strings: usize,
    string_bytes: usize,
}

impl Dump54Stats {
    fn new() -> Self {
        Self { prototypes: 0, instructions: 0, constants: 0,
            upvalues: 0, debug_entries: 0, strings: 0, string_bytes: 0 }
    }

    fn add(
        value: &mut usize, extra: usize, maximum: usize, id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        *value = value.checked_add(extra).filter(|count| *count <= maximum)
            .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                id, 0, "dump54 子樹資源上限或整數溢位"))?;
        Ok(())
    }

    fn string(
        &mut self, bytes: Option<&[u8]>, limits: &OfficialChunkLimits,
        id: ProtoId,
    ) -> Result<(), OfficialExportError> {
        let Some(bytes) = bytes else { return Ok(()); };
        if bytes.len() > limits.max_string_bytes {
            return Err(error(OfficialExportErrorKind::LimitExceeded,
                id, 0, "dump54 字串長度超限"));
        }
        Self::add(&mut self.strings, 1, limits.max_strings, id)?;
        Self::add(&mut self.string_bytes, bytes.len(),
            limits.max_total_string_bytes, id)
    }
}

impl Dump54Plan {
    /// 與 next 共用同一 cursor 文法；所有輸出額度先於第一個 writer 檢查。
    pub fn preflight(
        &self,
        module: &VerifiedModule,
        selected: ProtoId,
        strip: bool,
        limits: &OfficialChunkLimits,
        work: &mut OfficialWorkBudget,
    ) -> Result<Dump54Preflight, OfficialExportError> {
        if module.profile() != LuaProfile::Lua54 {
            return Err(error(OfficialExportErrorKind::ProfileMismatch,
                selected, 0, "dump54 profile 不符"));
        }
        self.entry(selected)?;
        let before = work.consumed();
        let mut stats = Dump54Stats::new();
        let mut cursor = Dump54Cursor::new(selected, strip);
        let mut encoded_bytes = 0usize;
        loop {
            let before_entered = cursor.entered_prototypes;
            let Some(piece) = cursor.next(module, self)? else { break };
            if cursor.entered_prototypes != before_entered {
                let id = cursor.current;
                if cursor.depth > limits.max_depth {
                    return Err(error(OfficialExportErrorKind::LimitExceeded,
                        id, 0, "dump54 子樹深度超限"));
                }
                let body = self.body(module, id)?;
                let active_upvalues = self.upvalues(module, id, selected)?;
                if active_upvalues.len() != body.upvalues.len()
                    || body.flags > 1
                    || body.max_stack_size == 0
                    || body.num_params > body.max_stack_size
                    || (body.last_line_defined != 0
                        && body.line_defined > body.last_line_defined)
                    || (!strip && !body.debug.line_info.is_empty()
                        && body.debug.line_info.len() != body.code.len())
                    || (!strip && !body.debug.upvalue_names.is_empty()
                        && body.debug.upvalue_names.len() != active_upvalues.len())
                {
                    return Err(error(OfficialExportErrorKind::InvalidPrototype,
                        id, 0, "dump54 body 或 incoming 描述不一致"));
                }
                if id != selected {
                    let parent = self.entry(id)?.parent.ok_or_else(|| error(
                        OfficialExportErrorKind::InvalidPrototype, id, 0,
                        "dump54 child 缺 parent"))?;
                    let parent_body = self.body(module, parent)?;
                    for descriptor in active_upvalues {
                        let valid = if descriptor.in_stack {
                            descriptor.index < parent_body.max_stack_size
                        } else {
                            usize::from(descriptor.index) < parent_body.upvalues.len()
                        };
                        if !valid {
                            return Err(error(OfficialExportErrorKind::InvalidPrototype,
                                id, 0, "dump54 incoming index 超出 parent"));
                        }
                    }
                }
                let inspection_units = body.constants.len()
                    .checked_add(body.children.len())
                    .and_then(|n| n.checked_add(if strip { 0 } else {
                        body.debug.locals.len() }))
                    .and_then(|n| n.checked_add(if strip { 0 } else {
                        body.debug.upvalue_names.len() }))
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                        id, 0, "dump54 掃描 work 溢位"))?;
                work_charge(work, inspection_units, id, encoded_bytes)?;
                Dump54Stats::add(&mut stats.prototypes, 1,
                    limits.max_prototypes, id)?;
                Dump54Stats::add(&mut stats.instructions, body.code.len(),
                    limits.max_instructions, id)?;
                Dump54Stats::add(&mut stats.constants, body.constants.len(),
                    limits.max_constants, id)?;
                Dump54Stats::add(&mut stats.upvalues,
                    active_upvalues.len(),
                    limits.max_upvalues, id)?;
                stats.string(cursor.source(module, self, body), limits, id)?;
                for constant in &body.constants {
                    if let OfficialConstant::String { bytes, .. } = constant {
                        stats.string(Some(bytes.as_slice()), limits, id)?;
                    }
                }
                if !strip {
                    let debug = &body.debug;
                    let count = debug.line_info.len()
                        .checked_add(debug.abs_line_info.len())
                        .and_then(|n| n.checked_add(debug.locals.len()))
                        .and_then(|n| n.checked_add(debug.upvalue_names.len()))
                        .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                            id, 0, "dump54 debug 數量溢位"))?;
                    Dump54Stats::add(&mut stats.debug_entries,
                        count, limits.max_debug_entries, id)?;
                    for local in &debug.locals {
                        stats.string(local.name.as_deref(), limits, id)?;
                    }
                    for name in &debug.upvalue_names {
                        stats.string(name.as_deref(), limits, id)?;
                    }
                }
            }
            let size = piece.as_slice().len();
            encoded_bytes = encoded_bytes.checked_add(size)
                .filter(|bytes| *bytes <= limits.max_bytes)
                .ok_or_else(|| error(OfficialExportErrorKind::LimitExceeded,
                    cursor.current, encoded_bytes, "dump54 encoded bytes 超限"))?;
            work_charge(work, size, cursor.current, encoded_bytes)?;
        }
        Ok(Dump54Preflight {
            encoded_bytes,
            output_work: work.consumed().saturating_sub(before),
            temporary_bytes: size_of::<Dump54Cursor>(),
        })
    }
}
