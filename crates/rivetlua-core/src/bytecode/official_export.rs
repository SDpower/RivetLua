//! 將 P05 已驗證模組輸出為 Lua 5.4.9／5.5.1 官方 binary chunk。

use super::official::{
    OfficialAbsLine, OfficialChunk, OfficialChunkErrorKind, OfficialChunkLimits, OfficialConstant,
    OfficialDebug, OfficialLocal, OfficialPrototype, encode_official_chunk_metered,
};
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

impl std::error::Error for OfficialExportError {}

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
        self.bytes(bytes.len(), 1, limits, id)
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
    stats.bytes(
        source.children.len(),
        size_of::<OfficialPrototype>(),
        limits,
        id,
    )?;
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
            size_of::<Option<Vec<u8>>>(),
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
    for child in &source.children {
        scan_prototype(child, None, strip, depth + 1, limits, stats, work, id)?;
    }
    Ok(())
}

fn copy_prototype(
    source: &OfficialPrototype,
    root_source: Option<&[u8]>,
    profile: LuaProfile,
    strip: bool,
    id: ProtoId,
    depth: usize,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<OfficialPrototype, OfficialExportError> {
    if depth > limits.max_depth {
        return Err(error(
            OfficialExportErrorKind::LimitExceeded,
            id,
            0,
            "官方子樹深度超限",
        ));
    }
    work_charge(work, 1, id, 0)?;
    let code = copy_slice(&source.code, id, work)?;
    let upvalues = copy_slice(&source.upvalues, id, work)?;
    let mut constants = Vec::new();
    constants
        .try_reserve_exact(source.constants.len())
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
                bytes: copy_slice(bytes, id, work)?,
                long: *long,
            },
        });
    }
    let mut children = Vec::new();
    children
        .try_reserve_exact(source.children.len())
        .map_err(|_| {
            error(
                OfficialExportErrorKind::AllocationFailed,
                id,
                0,
                "child 配置失敗",
            )
        })?;
    for child in &source.children {
        children.push(copy_prototype(
            child,
            None,
            profile,
            strip,
            id,
            depth + 1,
            limits,
            work,
        )?);
    }
    let (source_name, debug) = if strip {
        (None, OfficialDebug::default())
    } else {
        let mut locals = Vec::new();
        locals
            .try_reserve_exact(source.debug.locals.len())
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
                name: copy_optional_bytes(local.name.as_deref(), id, work)?,
                start_pc: local.start_pc,
                end_pc: local.end_pc,
            });
        }
        let mut upvalue_names = Vec::new();
        upvalue_names
            .try_reserve_exact(source.debug.upvalue_names.len())
            .map_err(|_| {
                error(
                    OfficialExportErrorKind::AllocationFailed,
                    id,
                    0,
                    "upvalue 名稱配置失敗",
                )
            })?;
        for name in &source.debug.upvalue_names {
            upvalue_names.push(copy_optional_bytes(name.as_deref(), id, work)?);
        }
        let source_name = copy_optional_bytes(root_source.or(source.source.as_deref()), id, work)?;
        let debug = OfficialDebug {
            line_info: copy_slice(&source.debug.line_info, id, work)?,
            abs_line_info: copy_slice::<OfficialAbsLine>(&source.debug.abs_line_info, id, work)?,
            locals,
            upvalue_names,
        };
        (source_name, debug)
    };
    let _ = profile;
    Ok(OfficialPrototype {
        source: source_name,
        line_defined: source.line_defined,
        last_line_defined: source.last_line_defined,
        num_params: source.num_params,
        flags: source.flags,
        max_stack_size: source.max_stack_size,
        code,
        constants,
        upvalues,
        children,
        debug,
    })
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
        let mut stats = ExportStats::default();
        stats.bytes(1, size_of::<OfficialChunk>(), limits, selected)?;
        scan_prototype(
            source,
            source_name,
            strip,
            1,
            limits,
            &mut stats,
            work,
            selected,
        )?;
        let root_upvalues = u8::try_from(source.upvalues.len()).map_err(|_| {
            error(
                OfficialExportErrorKind::LimitExceeded,
                selected,
                0,
                "官方 root upvalue 超過 u8",
            )
        })?;
        OfficialChunk {
            profile,
            root_upvalues,
            main: copy_prototype(
                source,
                source_name,
                profile,
                strip,
                selected,
                1,
                limits,
                work,
            )?,
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
        super::official_native::emit_native_chunk(module, selected, profile, strip, limits, work)?
    };
    encode_official_chunk_metered(&chunk, strip, &encode_limits, work).map_err(|codec| {
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
