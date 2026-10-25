//! Lua 5.5.1／5.4.9 官方 binary chunk 的純 Rust 結構 codec。
//! 本模組只處理可界定資源的資料格式；指令語意與 CFG 由後續轉譯階段驗證。

use alloc::vec::Vec;
use rivetlua_alloc::{AllocationRecovery, GlobalAllocation, ReserveError, StateAllocator};

use core::hash::{Hash, Hasher};
use core::mem::size_of;

use super::official_translation::OfficialWorkBudget;
use super::codec::{BytecodeVec, RetainedVec, Scratch};
use super::{LuaProfile, ProtoId};

#[cfg(feature = "std")]
type OfficialHasher = std::collections::hash_map::DefaultHasher;
// no_std 缺少 DefaultHasher；官方 chunk 的內部字串 slot 不屬於 wire 格式。
#[cfg(not(feature = "std"))]
#[allow(deprecated)]
type OfficialHasher = core::hash::SipHasher;

#[allow(deprecated)]
fn official_slot_hasher() -> OfficialHasher {
    OfficialHasher::new()
}

const SIGNATURE: &[u8] = b"\x1bLua";
const DATA: &[u8] = b"\x19\x93\r\n\x1a\n";
const INT_SENTINEL_54: i64 = 0x5678;
const INT_SENTINEL_55: i64 = -0x5678;
const INSTRUCTION_SENTINEL_55: u32 = 0x1234_5678;
const NUMBER_SENTINEL_54: f64 = 370.5;
const NUMBER_SENTINEL_55: f64 = -370.5;
const LUA54_INT_MAX: u32 = i32::MAX as u32 - 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialChunkErrorKind {
    Truncated,
    InvalidFormat,
    LimitExceeded,
    Overflow,
    AllocationFailed,
    WorkExhausted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialChunkError {
    pub kind: OfficialChunkErrorKind,
    pub offset: usize,
    pub detail: &'static str,
}

#[derive(Debug)]
pub enum OfficialChunkRecoveryError<E> {
    Chunk(OfficialChunkError),
    Reserve(ReserveError<E>),
}

impl core::fmt::Display for OfficialChunkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "官方 chunk 位移 {}：{}", self.offset, self.detail)
    }
}

impl core::error::Error for OfficialChunkError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialChunkLimits {
    pub max_bytes: usize,
    pub max_depth: usize,
    pub max_prototypes: usize,
    pub max_instructions: usize,
    pub max_constants: usize,
    pub max_upvalues: usize,
    pub max_debug_entries: usize,
    pub max_strings: usize,
    pub max_string_bytes: usize,
    pub max_total_string_bytes: usize,
    pub max_allocated_bytes: usize,
}

impl Default for OfficialChunkLimits {
    fn default() -> Self {
        Self {
            max_bytes: 32 * 1024 * 1024,
            max_depth: 64,
            max_prototypes: 8_192,
            max_instructions: 1_000_000,
            max_constants: 1_000_000,
            max_upvalues: 100_000,
            max_debug_entries: 2_000_000,
            max_strings: 100_000,
            max_string_bytes: 4 * 1024 * 1024,
            max_total_string_bytes: 16 * 1024 * 1024,
            max_allocated_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialChunk {
    pub profile: LuaProfile,
    pub root_upvalues: u8,
    pub main: ProtoId,
    pub prototypes: RetainedVec<OfficialPrototype>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialPrototype {
    pub source: Option<RetainedVec<u8>>,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub num_params: u8,
    pub flags: u8,
    pub max_stack_size: u8,
    pub code: RetainedVec<u32>,
    pub constants: RetainedVec<OfficialConstant>,
    pub upvalues: RetainedVec<OfficialUpvalue>,
    pub children: RetainedVec<ProtoId>,
    pub debug: OfficialDebug,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OfficialConstant {
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String { bytes: RetainedVec<u8>, long: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialUpvalue {
    pub in_stack: bool,
    pub index: u8,
    pub kind: u8,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OfficialDebug {
    pub line_info: RetainedVec<i8>,
    pub abs_line_info: RetainedVec<OfficialAbsLine>,
    pub locals: RetainedVec<OfficialLocal>,
    pub upvalue_names: RetainedVec<Option<RetainedVec<u8>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialAbsLine {
    pub pc: u32,
    pub line: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialLocal {
    pub name: Option<RetainedVec<u8>>,
    pub start_pc: u32,
    pub end_pc: u32,
}

impl OfficialChunk {
    pub fn root(&self) -> Option<&OfficialPrototype> {
        self.prototype(self.main)
    }

    pub fn root_mut(&mut self) -> Option<&mut OfficialPrototype> {
        let main = self.main;
        self.prototype_mut(main)
    }

    pub fn prototype(&self, id: ProtoId) -> Option<&OfficialPrototype> {
        self.prototypes.get(id.0 as usize)
    }

    pub fn prototype_mut(&mut self, id: ProtoId) -> Option<&mut OfficialPrototype> {
        self.prototypes.global_mut()?.get_mut(id.0 as usize)
    }

    pub(crate) fn rehome<R: AllocationRecovery>(
        &mut self,
        recovery: &mut R,
    ) -> Result<(), ReserveError<R::Error>> {
        if let Some(prototypes) = self.prototypes.global_mut() {
            for prototype in prototypes {
                prototype.rehome(recovery)?;
            }
        } else if !self.prototypes.is_state_for(&recovery.allocator()) {
            return Err(ReserveError::AllocatorMismatch);
        }
        self.prototypes.rehome(recovery)
    }

    pub(crate) fn retained_backing_bytes(&self) -> Option<usize> {
        let mut bytes = self.prototypes.retained_bytes()?;
        for prototype in &self.prototypes {
            bytes = bytes.checked_add(prototype.retained_backing_bytes()?)?;
        }
        Some(bytes)
    }
}

impl OfficialPrototype {
    fn empty() -> Self {
        Self {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            flags: 0,
            max_stack_size: 0,
            code: RetainedVec::default(),
            constants: RetainedVec::default(),
            upvalues: RetainedVec::default(),
            children: RetainedVec::default(),
            debug: OfficialDebug::default(),
        }
    }

    fn rehome<R: AllocationRecovery>(
        &mut self,
        recovery: &mut R,
    ) -> Result<(), ReserveError<R::Error>> {
        let allocator = recovery.allocator();
        if let Some(source) = &mut self.source {
            source.rehome(recovery)?;
        }
        if let Some(constants) = self.constants.global_mut() {
            for constant in constants {
                if let OfficialConstant::String { bytes, .. } = constant {
                    bytes.rehome(recovery)?;
                }
            }
        } else if !self.constants.is_state_for(&allocator) {
            return Err(ReserveError::AllocatorMismatch);
        }
        if let Some(locals) = self.debug.locals.global_mut() {
            for local in locals {
                if let Some(name) = &mut local.name {
                    name.rehome(recovery)?;
                }
            }
        } else if !self.debug.locals.is_state_for(&allocator) {
            return Err(ReserveError::AllocatorMismatch);
        }
        if let Some(names) = self.debug.upvalue_names.global_mut() {
            for name in names {
                if let Some(name) = name {
                    name.rehome(recovery)?;
                }
            }
        } else if !self.debug.upvalue_names.is_state_for(&allocator) {
            return Err(ReserveError::AllocatorMismatch);
        }
        self.code.rehome(recovery)?;
        self.constants.rehome(recovery)?;
        self.upvalues.rehome(recovery)?;
        self.children.rehome(recovery)?;
        self.debug.line_info.rehome(recovery)?;
        self.debug.abs_line_info.rehome(recovery)?;
        self.debug.locals.rehome(recovery)?;
        self.debug.upvalue_names.rehome(recovery)?;
        Ok(())
    }

    pub(super) fn retained_backing_bytes(&self) -> Option<usize> {
        let mut bytes = 0usize;
        if let Some(source) = &self.source {
            bytes = bytes.checked_add(source.retained_bytes()?)?;
        }
        for values in [
            self.code.retained_bytes()?,
            self.constants.retained_bytes()?,
            self.upvalues.retained_bytes()?,
            self.children.retained_bytes()?,
            self.debug.line_info.retained_bytes()?,
            self.debug.abs_line_info.retained_bytes()?,
            self.debug.locals.retained_bytes()?,
            self.debug.upvalue_names.retained_bytes()?,
        ] {
            bytes = bytes.checked_add(values)?;
        }
        for constant in &self.constants {
            if let OfficialConstant::String { bytes: value, .. } = constant {
                bytes = bytes.checked_add(value.retained_bytes()?)?;
            }
        }
        for local in &self.debug.locals {
            if let Some(name) = &local.name {
                bytes = bytes.checked_add(name.retained_bytes()?)?;
            }
        }
        for name in &self.debug.upvalue_names {
            if let Some(name) = name {
                bytes = bytes.checked_add(name.retained_bytes()?)?;
            }
        }
        Some(bytes)
    }
}

fn error(kind: OfficialChunkErrorKind, offset: usize, detail: &'static str) -> OfficialChunkError {
    OfficialChunkError {
        kind,
        offset,
        detail,
    }
}

fn meter(
    work: &mut Option<&mut OfficialWorkBudget>,
    units: usize,
    offset: usize,
) -> Result<(), OfficialChunkError> {
    if let Some(work) = work.as_deref_mut() {
        work.charge(units, ProtoId(0), offset).map_err(|_| {
            error(
                OfficialChunkErrorKind::WorkExhausted,
                offset,
                "官方編碼 work 額度耗盡",
            )
        })?;
    }
    Ok(())
}

#[derive(Default)]
struct Budget {
    allocated: usize,
    prototypes: usize,
    instructions: usize,
    constants: usize,
    upvalues: usize,
    debug_entries: usize,
    strings: usize,
    string_bytes: usize,
}

impl Budget {
    fn charge(
        used: &mut usize,
        amount: usize,
        max: usize,
        offset: usize,
        detail: &'static str,
    ) -> Result<(), OfficialChunkError> {
        *used = used
            .checked_add(amount)
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, offset, detail))?;
        if *used > max {
            return Err(error(OfficialChunkErrorKind::LimitExceeded, offset, detail));
        }
        Ok(())
    }

    fn alloc<T>(
        &mut self,
        count: usize,
        limits: &OfficialChunkLimits,
        offset: usize,
    ) -> Result<(), OfficialChunkError> {
        let bytes = count
            .checked_mul(size_of::<T>())
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, offset, "配置大小溢位"))?;
        Self::charge(
            &mut self.allocated,
            bytes,
            limits.max_allocated_bytes,
            offset,
            "配置額度超限",
        )
    }

    fn retained_owner<T, R: AllocationRecovery>(
        &mut self,
        limits: &OfficialChunkLimits,
        offset: usize,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<(), OfficialChunkError> {
        if scratch.recovery().allocator().is_lua() {
            Self::charge(
                &mut self.allocated,
                StateAllocator::shared_block_size::<BytecodeVec<T>>(),
                limits.max_allocated_bytes,
                offset,
                "retained owner 配置額度超限",
            )?;
        }
        Ok(())
    }

    fn string(
        &mut self,
        len: usize,
        limits: &OfficialChunkLimits,
        offset: usize,
    ) -> Result<(), OfficialChunkError> {
        if len > limits.max_string_bytes {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                offset,
                "單一字串超限",
            ));
        }
        Self::charge(
            &mut self.strings,
            1,
            limits.max_strings,
            offset,
            "字串數超限",
        )?;
        Self::charge(
            &mut self.string_bytes,
            len,
            limits.max_total_string_bytes,
            offset,
            "累積字串大小超限",
        )?;
        self.alloc::<u8>(len, limits, offset)
    }
}

fn vector<T>(
    count: usize,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
) -> Result<Vec<T>, OfficialChunkError> {
    budget.alloc::<T>(count, limits, offset)?;
    let mut result = Vec::new();
    result
        .try_reserve_exact(count)
        .map_err(|_| error(OfficialChunkErrorKind::AllocationFailed, offset, "配置失敗"))?;
    budget.alloc::<T>(result.capacity() - count, limits, offset)?;
    Ok(result)
}

fn bytes_owned(
    bytes: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
) -> Result<Vec<u8>, OfficialChunkError> {
    budget.string(bytes.len(), limits, offset)?;
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(|_| {
        error(
            OfficialChunkErrorKind::AllocationFailed,
            offset,
            "字串配置失敗",
        )
    })?;
    budget.alloc::<u8>(result.capacity() - bytes.len(), limits, offset)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn bytes_saved_copy(
    bytes: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
) -> Result<Vec<u8>, OfficialChunkError> {
    budget.alloc::<u8>(bytes.len(), limits, offset)?;
    let mut result = Vec::new();
    result.try_reserve_exact(bytes.len()).map_err(|_| {
        error(
            OfficialChunkErrorKind::AllocationFailed,
            offset,
            "字串索引內容配置失敗",
        )
    })?;
    budget.alloc::<u8>(result.capacity() - bytes.len(), limits, offset)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

fn vector_with_recovery<T, R: AllocationRecovery>(
    count: usize,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
    scratch: &mut Scratch<'_, R>,
) -> Result<BytecodeVec<T>, OfficialChunkError> {
    budget.alloc::<T>(count, limits, offset)?;
    let mut result = scratch.vec();
    scratch.reserve_exact(&mut result, count).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, offset, "配置失敗")
    })?;
    budget.alloc::<T>(result.capacity() - count, limits, offset)?;
    Ok(result)
}

fn bytes_owned_with_recovery<R: AllocationRecovery>(
    bytes: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
    scratch: &mut Scratch<'_, R>,
) -> Result<RetainedVec<u8>, OfficialChunkError> {
    budget.string(bytes.len(), limits, offset)?;
    let mut result = scratch.vec();
    scratch.reserve_exact(&mut result, bytes.len()).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, offset, "字串配置失敗")
    })?;
    budget.alloc::<u8>(result.capacity() - bytes.len(), limits, offset)?;
    result.extend_from_slice(bytes);
    budget.retained_owner::<u8, _>(limits, offset, scratch)?;
    scratch.retain(result).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, offset, "字串 owner 配置失敗")
    })
}

fn bytes_saved_copy_with_recovery<R: AllocationRecovery>(
    bytes: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    offset: usize,
    scratch: &mut Scratch<'_, R>,
) -> Result<BytecodeVec<u8>, OfficialChunkError> {
    budget.alloc::<u8>(bytes.len(), limits, offset)?;
    let mut result = scratch.vec();
    scratch.reserve_exact(&mut result, bytes.len()).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, offset, "字串索引內容配置失敗")
    })?;
    budget.alloc::<u8>(result.capacity() - bytes.len(), limits, offset)?;
    result.extend_from_slice(bytes);
    Ok(result)
}

pub(super) struct DecodeFrame {
    id: ProtoId,
    depth: usize,
    remaining_children: usize,
    source: Option<RetainedVec<u8>>,
    line_defined: u32,
    last_line_defined: u32,
    num_params: u8,
    flags: u8,
    max_stack_size: u8,
    code_count: usize,
    upvalue_count: usize,
    code: BytecodeVec<u32>,
    constants: BytecodeVec<OfficialConstant>,
    upvalues: BytecodeVec<OfficialUpvalue>,
    children: BytecodeVec<ProtoId>,
}

struct Reader<'a, 'r, R: AllocationRecovery> {
    bytes: &'a [u8],
    offset: usize,
    profile: LuaProfile,
    limits: &'a OfficialChunkLimits,
    budget: Budget,
    saved_strings: BytecodeVec<BytecodeVec<u8>>,
    scratch: Scratch<'r, R>,
}

impl<'a, 'r, R: AllocationRecovery> Reader<'a, 'r, R> {
    fn retain_vec<T>(
        &mut self,
        values: BytecodeVec<T>,
        detail: &'static str,
    ) -> Result<RetainedVec<T>, OfficialChunkError> {
        self.budget.retained_owner::<T, _>(self.limits, self.offset, &mut self.scratch)?;
        self.scratch.retain(values).map_err(|_| {
            error(OfficialChunkErrorKind::AllocationFailed, self.offset, detail)
        })
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], OfficialChunkError> {
        let end = self.offset.checked_add(n).ok_or_else(|| {
            error(
                OfficialChunkErrorKind::Overflow,
                self.offset,
                "讀取長度溢位",
            )
        })?;
        let slice = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| error(OfficialChunkErrorKind::Truncated, self.offset, "chunk 截斷"))?;
        self.offset = end;
        Ok(slice)
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn require_min(&self, count: usize, item_size: usize) -> Result<(), OfficialChunkError> {
        let min = count.checked_mul(item_size).ok_or_else(|| {
            error(
                OfficialChunkErrorKind::Overflow,
                self.offset,
                "計數大小溢位",
            )
        })?;
        if min > self.remaining() {
            return Err(error(
                OfficialChunkErrorKind::Truncated,
                self.offset,
                "資料不足以容納宣稱項數",
            ));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, OfficialChunkError> {
        Ok(self.read(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, OfficialChunkError> {
        let mut bytes = [0; 4];
        bytes.copy_from_slice(self.read(4)?);
        Ok(u32::from_le_bytes(bytes))
    }

    fn i32(&mut self) -> Result<i32, OfficialChunkError> {
        Ok(self.u32()? as i32)
    }

    fn i64(&mut self) -> Result<i64, OfficialChunkError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.read(8)?);
        Ok(i64::from_le_bytes(bytes))
    }

    fn f64(&mut self) -> Result<f64, OfficialChunkError> {
        let mut bytes = [0; 8];
        bytes.copy_from_slice(self.read(8)?);
        Ok(f64::from_le_bytes(bytes))
    }

    fn varint(&mut self) -> Result<u64, OfficialChunkError> {
        let mut value = 0_u64;
        for _ in 0..10 {
            let byte = self.byte()?;
            if value > (u64::MAX >> 7) {
                return Err(error(
                    OfficialChunkErrorKind::Overflow,
                    self.offset,
                    "變長整數溢位",
                ));
            }
            value = (value << 7) | u64::from(byte & 0x7f);
            let done = match self.profile {
                LuaProfile::Lua55 => byte & 0x80 == 0,
                LuaProfile::Lua54 => byte & 0x80 != 0,
            };
            if done {
                return Ok(value);
            }
        }
        Err(error(
            OfficialChunkErrorKind::Overflow,
            self.offset,
            "變長整數超過十位元組",
        ))
    }

    fn size(&mut self) -> Result<usize, OfficialChunkError> {
        usize::try_from(self.varint()?).map_err(|_| {
            error(
                OfficialChunkErrorKind::Overflow,
                self.offset,
                "長度超過平台範圍",
            )
        })
    }

    fn int(&mut self) -> Result<u32, OfficialChunkError> {
        let value = self.varint()?;
        let limit = match self.profile {
            LuaProfile::Lua55 => i32::MAX as u32,
            LuaProfile::Lua54 => LUA54_INT_MAX,
        };
        u32::try_from(value)
            .ok()
            .filter(|v| *v <= limit)
            .ok_or_else(|| {
                error(
                    OfficialChunkErrorKind::Overflow,
                    self.offset,
                    "int 超出範圍",
                )
            })
    }

    fn align4(&mut self) -> Result<(), OfficialChunkError> {
        let padding = (4 - self.offset % 4) % 4;
        self.read(padding)?;
        Ok(())
    }

    fn header(&mut self) -> Result<(), OfficialChunkError> {
        if self.read(4)? != SIGNATURE {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                0,
                "magic 不符",
            ));
        }
        let version = match self.profile {
            LuaProfile::Lua55 => 0x55,
            LuaProfile::Lua54 => 0x54,
        };
        if self.byte()? != version || self.byte()? != 0 || self.read(6)? != DATA {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "版本或格式不符",
            ));
        }
        match self.profile {
            LuaProfile::Lua55 => {
                if self.byte()? != 4
                    || self.i32()? != INT_SENTINEL_55 as i32
                    || self.byte()? != 4
                    || self.u32()? != INSTRUCTION_SENTINEL_55
                    || self.byte()? != 8
                    || self.i64()? != INT_SENTINEL_55
                    || self.byte()? != 8
                    || self.f64()? != NUMBER_SENTINEL_55
                {
                    return Err(error(
                        OfficialChunkErrorKind::InvalidFormat,
                        self.offset,
                        "5.5 數值大小或 sentinel 不符",
                    ));
                }
            }
            LuaProfile::Lua54 => {
                if self.byte()? != 4
                    || self.byte()? != 8
                    || self.byte()? != 8
                    || self.i64()? != INT_SENTINEL_54
                    || self.f64()? != NUMBER_SENTINEL_54
                {
                    return Err(error(
                        OfficialChunkErrorKind::InvalidFormat,
                        self.offset,
                        "5.4 數值大小或 sentinel 不符",
                    ));
                }
            }
        }
        Ok(())
    }

    fn string(&mut self) -> Result<Option<RetainedVec<u8>>, OfficialChunkError> {
        let size = self.size()?;
        match self.profile {
            LuaProfile::Lua54 => {
                if size == 0 {
                    return Ok(None);
                }
                let len = size - 1;
                if len > self.limits.max_string_bytes {
                    return Err(error(
                        OfficialChunkErrorKind::LimitExceeded,
                        self.offset,
                        "單一字串超限",
                    ));
                }
                self.require_min(len, 1)?;
                let bytes = self.read(len)?;
                Ok(Some(bytes_owned_with_recovery(
                    bytes,
                    &mut self.budget,
                    self.limits,
                    self.offset,
                    &mut self.scratch,
                )?))
            }
            LuaProfile::Lua55 => {
                if size == 0 {
                    let index = self.size()?;
                    if index == 0 {
                        return Ok(None);
                    }
                    let saved = self.saved_strings.get(index - 1).ok_or_else(|| {
                        error(
                            OfficialChunkErrorKind::InvalidFormat,
                            self.offset,
                            "字串參照不是既存索引",
                        )
                    })?;
                    return Ok(Some(bytes_owned_with_recovery(
                        saved,
                        &mut self.budget,
                        self.limits,
                        self.offset,
                        &mut self.scratch,
                    )?));
                }
                let len = size - 1;
                if len > self.limits.max_string_bytes {
                    return Err(error(
                        OfficialChunkErrorKind::LimitExceeded,
                        self.offset,
                        "單一字串超限",
                    ));
                }
                self.require_min(size, 1)?;
                let bytes = self.read(size)?;
                if bytes[len] != 0 {
                    return Err(error(
                        OfficialChunkErrorKind::InvalidFormat,
                        self.offset,
                        "5.5 字串缺少結尾 NUL",
                    ));
                }
                let owned = bytes_owned_with_recovery(
                    &bytes[..len], &mut self.budget, self.limits, self.offset, &mut self.scratch,
                )?;
                let saved = bytes_saved_copy_with_recovery(
                    &bytes[..len], &mut self.budget, self.limits, self.offset, &mut self.scratch,
                )?;
                if self.saved_strings.len() == self.saved_strings.capacity() {
                    return Err(error(
                        OfficialChunkErrorKind::LimitExceeded,
                        self.offset,
                        "字串索引容量不足",
                    ));
                }
                self.saved_strings.push(saved);
                Ok(Some(owned))
            }
        }
    }

    fn prototype_head(
        &mut self,
        depth: usize,
        parent: Option<(u8, usize)>,
        prototypes: &mut BytecodeVec<OfficialPrototype>,
    ) -> Result<DecodeFrame, OfficialChunkError> {
        if depth > self.limits.max_depth {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "prototype 深度超限",
            ));
        }
        Budget::charge(
            &mut self.budget.prototypes,
            1,
            self.limits.max_prototypes,
            self.offset,
            "prototype 數超限",
        )?;
        let id = ProtoId(u32::try_from(prototypes.len()).map_err(|_| {
            error(OfficialChunkErrorKind::Overflow, self.offset, "prototype ID 溢位")
        })?);
        if prototypes.len() == prototypes.capacity() {
            let additional = prototypes.capacity().max(1);
            self.budget.alloc::<OfficialPrototype>(additional, self.limits, self.offset)?;
            let previous = prototypes.capacity();
            self.scratch.reserve_exact(prototypes, additional).map_err(|_| {
                error(OfficialChunkErrorKind::AllocationFailed, self.offset, "prototype arena 配置失敗")
            })?;
            self.budget.alloc::<OfficialPrototype>(
                prototypes.capacity() - previous - additional,
                self.limits,
                self.offset,
            )?;
        }
        prototypes.push(OfficialPrototype::empty());
        let source = if self.profile == LuaProfile::Lua54 {
            self.string()?
        } else {
            None
        };
        let line_defined = self.int()?;
        let last_line_defined = self.int()?;
        let num_params = self.byte()?;
        let flags = self.byte()?;
        let max_stack_size = self.byte()?;
        if max_stack_size == 0
            || num_params > max_stack_size
            || (last_line_defined != 0 && line_defined > last_line_defined)
            || match self.profile {
                LuaProfile::Lua55 => flags & !3 != 0,
                LuaProfile::Lua54 => flags > 1,
            }
        {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "prototype signature 不符",
            ));
        }

        let code_count = self.int()? as usize;
        Budget::charge(
            &mut self.budget.instructions,
            code_count,
            self.limits.max_instructions,
            self.offset,
            "指令數超限",
        )?;
        if self.profile == LuaProfile::Lua55 {
            self.align4()?;
        }
        self.require_min(code_count, 4)?;
        let mut code = vector_with_recovery(
            code_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..code_count {
            code.push(self.u32()?);
        }

        let constant_count = self.int()? as usize;
        Budget::charge(
            &mut self.budget.constants,
            constant_count,
            self.limits.max_constants,
            self.offset,
            "常數數超限",
        )?;
        self.require_min(constant_count, 1)?;
        let mut constants = vector_with_recovery(
            constant_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..constant_count {
            let tag = self.byte()?;
            let constant = match tag {
                0 => OfficialConstant::Nil,
                1 => OfficialConstant::Boolean(false),
                17 => OfficialConstant::Boolean(true),
                3 => OfficialConstant::Integer(match self.profile {
                    LuaProfile::Lua55 => {
                        let coded = self.varint()?;
                        if coded & 1 == 0 {
                            (coded >> 1) as i64
                        } else {
                            !(coded >> 1) as i64
                        }
                    }
                    LuaProfile::Lua54 => self.i64()?,
                }),
                19 => OfficialConstant::Number(self.f64()?),
                4 | 20 => OfficialConstant::String {
                    bytes: self.string()?.ok_or_else(|| {
                        error(
                            OfficialChunkErrorKind::InvalidFormat,
                            self.offset,
                            "常數字串不可為 NULL",
                        )
                    })?,
                    long: tag == 20,
                },
                _ => {
                    return Err(error(
                        OfficialChunkErrorKind::InvalidFormat,
                        self.offset,
                        "常數 tag 不符",
                    ));
                }
            };
            constants.push(constant);
        }

        let upvalue_count = self.int()? as usize;
        if upvalue_count > u8::MAX as usize {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "單一 prototype upvalue 過多",
            ));
        }
        Budget::charge(
            &mut self.budget.upvalues,
            upvalue_count,
            self.limits.max_upvalues,
            self.offset,
            "upvalue 數超限",
        )?;
        self.require_min(upvalue_count, 3)?;
        let mut upvalues = vector_with_recovery(
            upvalue_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..upvalue_count {
            let in_stack = self.byte()?;
            let index = self.byte()?;
            let kind = self.byte()?;
            let max_kind = if self.profile == LuaProfile::Lua55 {
                3
            } else {
                2
            };
            let valid_parent = match (parent, in_stack) {
                (Some((parent_stack, _)), 1) => index < parent_stack,
                (Some((_, parent_upvalues)), 0) => usize::from(index) < parent_upvalues,
                (None, 0 | 1) => true,
                _ => false,
            };
            if in_stack > 1 || kind > max_kind || !valid_parent {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "upvalue parent index 或 kind 不符",
                ));
            }
            upvalues.push(OfficialUpvalue {
                in_stack: in_stack == 1,
                index,
                kind,
            });
        }

        let child_count = self.int()? as usize;
        if child_count
            > self
                .limits
                .max_prototypes
                .saturating_sub(self.budget.prototypes)
        {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "子 prototype 數超限",
            ));
        }
        self.require_min(child_count, 1)?;
        let children = vector_with_recovery(
            child_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        Ok(DecodeFrame {
            id,
            depth,
            source,
            line_defined,
            last_line_defined,
            num_params,
            flags,
            max_stack_size,
            code_count,
            upvalue_count,
            code,
            constants,
            upvalues,
            children,
            remaining_children: child_count,
        })
    }

    fn finish_prototype(
        &mut self,
        frame: DecodeFrame,
        prototypes: &mut BytecodeVec<OfficialPrototype>,
    ) -> Result<(), OfficialChunkError> {
        let source = if self.profile == LuaProfile::Lua55 { self.string()? } else { frame.source };
        let debug = self.debug(frame.code_count, frame.upvalue_count)?;
        prototypes[frame.id.0 as usize] = OfficialPrototype {
            source,
            line_defined: frame.line_defined,
            last_line_defined: frame.last_line_defined,
            num_params: frame.num_params,
            flags: frame.flags,
            max_stack_size: frame.max_stack_size,
            code: self.retain_vec(frame.code, "code owner 配置失敗")?,
            constants: self.retain_vec(frame.constants, "constant owner 配置失敗")?,
            upvalues: self.retain_vec(frame.upvalues, "upvalue owner 配置失敗")?,
            children: self.retain_vec(frame.children, "prototype owner 配置失敗")?,
            debug,
        };
        Ok(())
    }

    fn push_frame(&mut self, stack: &mut BytecodeVec<DecodeFrame>, frame: DecodeFrame) -> Result<(), OfficialChunkError> {
        if stack.len() == stack.capacity() {
            let additional = stack.capacity().max(1);
            self.budget.alloc::<DecodeFrame>(additional, self.limits, self.offset)?;
            let previous = stack.capacity();
            self.scratch.reserve_exact(stack, additional).map_err(|_| {
                error(OfficialChunkErrorKind::AllocationFailed, self.offset, "decode cursor 配置失敗")
            })?;
            self.budget.alloc::<DecodeFrame>(stack.capacity() - previous - additional, self.limits, self.offset)?;
        }
        stack.push(frame);
        Ok(())
    }

    fn prototypes(&mut self, prototypes: &mut BytecodeVec<OfficialPrototype>) -> Result<ProtoId, OfficialChunkError> {
        let mut stack = self.scratch.vec();
        let root = self.prototype_head(1, None, prototypes)?;
        let root_id = root.id;
        self.push_frame(&mut stack, root)?;
        while let Some(frame) = stack.last_mut() {
            if frame.remaining_children != 0 {
                frame.remaining_children -= 1;
                let depth = frame.depth.checked_add(1).ok_or_else(|| {
                    error(OfficialChunkErrorKind::Overflow, self.offset, "prototype 深度溢位")
                })?;
                let parent = Some((frame.max_stack_size, frame.upvalue_count));
                let child = self.prototype_head(depth, parent, prototypes)?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(child.id);
                }
                self.push_frame(&mut stack, child)?;
            } else {
                if let Some(done) = stack.pop() {
                    self.finish_prototype(done, prototypes)?;
                }
            }
        }
        Ok(root_id)
    }

    fn debug(
        &mut self,
        code_count: usize,
        upvalue_count: usize,
    ) -> Result<OfficialDebug, OfficialChunkError> {
        let line_count = self.int()? as usize;
        if line_count != 0 && line_count != code_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "lineinfo 數與 code 不符",
            ));
        }
        Budget::charge(
            &mut self.budget.debug_entries,
            line_count,
            self.limits.max_debug_entries,
            self.offset,
            "debug 項數超限",
        )?;
        self.require_min(line_count, 1)?;
        let mut line_info = vector_with_recovery(
            line_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..line_count {
            line_info.push(self.byte()? as i8);
        }

        let abs_count = self.int()? as usize;
        Budget::charge(
            &mut self.budget.debug_entries,
            abs_count,
            self.limits.max_debug_entries,
            self.offset,
            "debug 項數超限",
        )?;
        if self.profile == LuaProfile::Lua55 && abs_count > 0 {
            self.align4()?;
        }
        self.require_min(
            abs_count,
            if self.profile == LuaProfile::Lua55 {
                8
            } else {
                2
            },
        )?;
        let mut abs_line_info = vector_with_recovery(
            abs_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        let mut previous_pc = None;
        for _ in 0..abs_count {
            let (pc, line) = match self.profile {
                LuaProfile::Lua55 => (self.i32()?, self.i32()?),
                LuaProfile::Lua54 => (self.int()? as i32, self.int()? as i32),
            };
            if pc < 0
                || pc as usize >= code_count
                || line < 0
                || previous_pc.is_some_and(|previous| pc <= previous)
                || line_info.get(pc as usize) != Some(&-128)
            {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "絕對行號 PC 或 line 不符",
                ));
            }
            abs_line_info.push(OfficialAbsLine {
                pc: pc as u32,
                line,
            });
            previous_pc = Some(pc);
        }
        if line_info.iter().filter(|line| **line == -128).count() != abs_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "絕對行號與 marker 不符",
            ));
        }

        let local_count = self.int()? as usize;
        Budget::charge(
            &mut self.budget.debug_entries,
            local_count,
            self.limits.max_debug_entries,
            self.offset,
            "debug 項數超限",
        )?;
        self.require_min(local_count, 3)?;
        let mut locals = vector_with_recovery(
            local_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..local_count {
            let name = self.string()?;
            let start_pc = self.int()?;
            let end_pc = self.int()?;
            if start_pc > end_pc || end_pc as usize > code_count {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "local PC 範圍不符",
                ));
            }
            locals.push(OfficialLocal {
                name,
                start_pc,
                end_pc,
            });
        }

        let name_count = self.int()? as usize;
        if name_count != 0 && name_count != upvalue_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "upvalue debug name 數不符",
            ));
        }
        Budget::charge(
            &mut self.budget.debug_entries,
            name_count,
            self.limits.max_debug_entries,
            self.offset,
            "debug 項數超限",
        )?;
        self.require_min(name_count, 1)?;
        let mut upvalue_names = vector_with_recovery(
            name_count, &mut self.budget, self.limits, self.offset, &mut self.scratch,
        )?;
        for _ in 0..name_count {
            upvalue_names.push(self.string()?);
        }
        Ok(OfficialDebug {
            line_info: self.retain_vec(line_info, "line owner 配置失敗")?,
            abs_line_info: self.retain_vec(abs_line_info, "abs line owner 配置失敗")?,
            locals: self.retain_vec(locals, "local owner 配置失敗")?,
            upvalue_names: self.retain_vec(upvalue_names, "upvalue name owner 配置失敗")?,
        })
    }
}

pub fn decode_official_chunk(
    bytes: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
) -> Result<OfficialChunk, OfficialChunkError> {
    let mut recovery = GlobalAllocation;
    decode_official_chunk_with_recovery(bytes, profile, limits, &mut recovery).map_err(|failure| {
        match failure {
            OfficialChunkRecoveryError::Chunk(error) => error,
            OfficialChunkRecoveryError::Reserve(ReserveError::Recovery(never)) => match never {},
            OfficialChunkRecoveryError::Reserve(_) => {
                error(OfficialChunkErrorKind::AllocationFailed, 0, "官方 chunk 配置失敗")
            }
        }
    })
}

pub fn decode_official_chunk_with_recovery<R: AllocationRecovery>(
    bytes: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
    recovery: &mut R,
) -> Result<OfficialChunk, OfficialChunkRecoveryError<R::Error>> {
    if bytes.len() > limits.max_bytes {
        return Err(OfficialChunkRecoveryError::Chunk(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "chunk 長度超限",
        )));
    }
    let scratch = Scratch::new(recovery);
    let saved_strings = scratch.vec();
    let mut reader = Reader {
        bytes,
        offset: 0,
        profile,
        limits,
        budget: Budget::default(),
        saved_strings,
        scratch,
    };
    let result = (|| -> Result<OfficialChunk, OfficialChunkError> {
    reader.header()?;
    if profile == LuaProfile::Lua55 {
        let capacity = limits.max_strings.min(bytes.len() / 2);
        reader
            .budget
            .alloc::<BytecodeVec<u8>>(capacity, limits, reader.offset)?;
        reader
            .scratch
            .reserve_exact(&mut reader.saved_strings, capacity)
            .map_err(|_| {
                error(
                    OfficialChunkErrorKind::AllocationFailed,
                    reader.offset,
                    "字串索引配置失敗",
                )
            })?;
        reader.budget.alloc::<BytecodeVec<u8>>(
            reader.saved_strings.capacity() - capacity,
            limits,
            reader.offset,
        )?;
    }
    let root_upvalues = reader.byte()?;
    let mut prototypes = reader.scratch.vec();
    let main = reader.prototypes(&mut prototypes)?;
    if usize::from(root_upvalues) != prototypes[main.0 as usize].upvalues.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            reader.offset,
            "root upvalue 數不符",
        ));
    }
    reader.budget.retained_owner::<OfficialPrototype, _>(limits, reader.offset, &mut reader.scratch)?;
    let prototypes = reader.scratch.retain(prototypes).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, reader.offset, "prototype arena owner 配置失敗")
    })?;
    Ok(OfficialChunk {
        profile,
        root_upvalues,
        main,
        prototypes,
    })
    })();
    result.map_err(|error| match reader.scratch.take_refusal() {
        Some(refusal) => OfficialChunkRecoveryError::Reserve(refusal),
        None => OfficialChunkRecoveryError::Chunk(error),
    })
}

fn validate_string(
    value: Option<&RetainedVec<u8>>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<(), OfficialChunkError> {
    if let Some(bytes) = value {
        budget.string(bytes.len(), limits, 0)?;
        budget.alloc::<u8>(bytes.capacity() - bytes.len(), limits, 0)?;
        validate_retained_owner(bytes, budget, limits)?;
    }
    Ok(())
}

fn validate_retained_owner<T>(
    values: &RetainedVec<T>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<(), OfficialChunkError> {
    if matches!(values, RetainedVec::State(_)) {
        budget.alloc::<u8>(StateAllocator::shared_block_size::<BytecodeVec<T>>(), limits, 0)?;
    }
    Ok(())
}

fn validate_prototype(
    prototype: &OfficialPrototype,
    profile: LuaProfile,
    parent: Option<(u8, usize)>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    work: &mut Option<&mut OfficialWorkBudget>,
) -> Result<(), OfficialChunkError> {
    let debug = &prototype.debug;
    let scan_units = prototype
        .constants
        .len()
        .checked_add(prototype.upvalues.len())
        .and_then(|value| value.checked_add(prototype.children.len()))
        .and_then(|value| value.checked_add(debug.abs_line_info.len()))
        .and_then(|value| value.checked_add(debug.line_info.len()))
        .and_then(|value| value.checked_add(debug.locals.len()))
        .and_then(|value| value.checked_add(debug.upvalue_names.len()))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            error(
                OfficialChunkErrorKind::Overflow,
                0,
                "prototype 掃描 work 溢位",
            )
        })?;
    meter(work, scan_units, 0)?;
    Budget::charge(
        &mut budget.prototypes,
        1,
        limits.max_prototypes,
        0,
        "prototype 數超限",
    )?;
    if prototype.max_stack_size == 0
        || prototype.num_params > prototype.max_stack_size
        || (prototype.last_line_defined != 0
            && prototype.line_defined > prototype.last_line_defined)
        || prototype.code.len() > i32::MAX as usize
        || prototype.constants.len() > i32::MAX as usize
        || prototype.children.len() > i32::MAX as usize
        || prototype.upvalues.len() > u8::MAX as usize
        || match profile {
            LuaProfile::Lua55 => prototype.flags & !3 != 0,
            LuaProfile::Lua54 => prototype.flags > 1,
        }
    {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            0,
            "prototype signature 不符",
        ));
    }
    Budget::charge(
        &mut budget.instructions,
        prototype.code.len(),
        limits.max_instructions,
        0,
        "指令數超限",
    )?;
    budget.alloc::<u32>(prototype.code.capacity(), limits, 0)?;
    validate_retained_owner(&prototype.code, budget, limits)?;
    Budget::charge(
        &mut budget.constants,
        prototype.constants.len(),
        limits.max_constants,
        0,
        "常數數超限",
    )?;
    budget.alloc::<OfficialConstant>(prototype.constants.capacity(), limits, 0)?;
    validate_retained_owner(&prototype.constants, budget, limits)?;
    Budget::charge(
        &mut budget.upvalues,
        prototype.upvalues.len(),
        limits.max_upvalues,
        0,
        "upvalue 數超限",
    )?;
    budget.alloc::<OfficialUpvalue>(prototype.upvalues.capacity(), limits, 0)?;
    validate_retained_owner(&prototype.upvalues, budget, limits)?;
    budget.alloc::<ProtoId>(prototype.children.capacity(), limits, 0)?;
    validate_retained_owner(&prototype.children, budget, limits)?;
    validate_string(prototype.source.as_ref(), budget, limits)?;
    for constant in &prototype.constants {
        if let OfficialConstant::String { bytes, .. } = constant {
            validate_string(Some(bytes), budget, limits)?;
        }
    }
    for upvalue in &prototype.upvalues {
        let max_kind = if profile == LuaProfile::Lua55 { 3 } else { 2 };
        let valid_parent = match (parent, upvalue.in_stack) {
            (Some((parent_stack, _)), true) => upvalue.index < parent_stack,
            (Some((_, parent_upvalues)), false) => usize::from(upvalue.index) < parent_upvalues,
            (None, _) => true,
        };
        if upvalue.kind > max_kind || !valid_parent {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                0,
                "upvalue parent index 或 kind 不符",
            ));
        }
    }
    if (!debug.line_info.is_empty() && debug.line_info.len() != prototype.code.len())
        || (!debug.upvalue_names.is_empty()
            && debug.upvalue_names.len() != prototype.upvalues.len())
        || debug.abs_line_info.len() > i32::MAX as usize
        || debug.locals.len() > i32::MAX as usize
    {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            0,
            "debug 數量不符",
        ));
    }
    for count in [
        debug.line_info.len(),
        debug.abs_line_info.len(),
        debug.locals.len(),
        debug.upvalue_names.len(),
    ] {
        Budget::charge(
            &mut budget.debug_entries,
            count,
            limits.max_debug_entries,
            0,
            "debug 項數超限",
        )?;
    }
    budget.alloc::<i8>(debug.line_info.capacity(), limits, 0)?;
    validate_retained_owner(&debug.line_info, budget, limits)?;
    budget.alloc::<OfficialAbsLine>(debug.abs_line_info.capacity(), limits, 0)?;
    validate_retained_owner(&debug.abs_line_info, budget, limits)?;
    budget.alloc::<OfficialLocal>(debug.locals.capacity(), limits, 0)?;
    validate_retained_owner(&debug.locals, budget, limits)?;
    budget.alloc::<Option<RetainedVec<u8>>>(debug.upvalue_names.capacity(), limits, 0)?;
    validate_retained_owner(&debug.upvalue_names, budget, limits)?;
    let mut previous_pc = None;
    for abs in &debug.abs_line_info {
        if abs.pc as usize >= prototype.code.len()
            || abs.line < 0
            || previous_pc.is_some_and(|previous| abs.pc <= previous)
            || debug.line_info.get(abs.pc as usize) != Some(&-128)
        {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                0,
                "絕對行號 PC 或 line 不符",
            ));
        }
        previous_pc = Some(abs.pc);
    }
    if debug.line_info.iter().filter(|line| **line == -128).count() != debug.abs_line_info.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            0,
            "絕對行號與 marker 不符",
        ));
    }
    for local in &debug.locals {
        if local.start_pc > local.end_pc || local.end_pc as usize > prototype.code.len() {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                0,
                "local PC 範圍不符",
            ));
        }
        validate_string(local.name.as_ref(), budget, limits)?;
    }
    for name in &debug.upvalue_names {
        validate_string(name.as_ref(), budget, limits)?;
    }
    Ok(())
}

fn validate_chunk<R: AllocationRecovery>(
    chunk: &OfficialChunk,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    work: &mut Option<&mut OfficialWorkBudget>,
    scratch: &mut Scratch<'_, R>,
) -> Result<(), OfficialChunkError> {
    if chunk.main != ProtoId(0) || chunk.prototypes.is_empty() {
        return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "root prototype ID 不符"));
    }
    if usize::from(chunk.root_upvalues) != chunk.prototypes[0].upvalues.len() {
        return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "root upvalue 數不符"));
    }
    if chunk.prototypes[0].children.len() > chunk.prototypes.len() - 1 {
        return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "root child 數超過 arena"));
    }
    budget.alloc::<OfficialPrototype>(chunk.prototypes.capacity(), limits, 0)?;
    validate_retained_owner(&chunk.prototypes, budget, limits)?;
    let mut stack = scratch.vec();
    let capacity = chunk.prototypes.len();
    budget.alloc::<(ProtoId, usize, Option<(u8, usize)>)>(capacity, limits, 0)?;
    scratch.reserve_exact(&mut stack, capacity).map_err(|_| {
        error(OfficialChunkErrorKind::AllocationFailed, 0, "prototype 驗證暫存配置失敗")
    })?;
    budget.alloc::<(ProtoId, usize, Option<(u8, usize)>)>(stack.capacity() - capacity, limits, 0)?;
    stack.push((chunk.main, 1, None));
    let mut next = 0usize;
    while let Some((id, depth, parent)) = stack.pop() {
        if id.0 as usize != next {
            return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "prototype 前序或 parent 不符"));
        }
        if depth > limits.max_depth {
            return Err(error(OfficialChunkErrorKind::LimitExceeded, 0, "prototype 深度超限"));
        }
        let prototype = &chunk.prototypes[next];
        validate_prototype(prototype, chunk.profile, parent, budget, limits, work)?;
        next += 1;
        if stack.len().checked_add(prototype.children.len())
            .is_none_or(|frontier| frontier > chunk.prototypes.len() - next)
        {
            return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "prototype frontier 超過 arena"));
        }
        let child_depth = depth.checked_add(1).ok_or_else(|| {
            error(OfficialChunkErrorKind::Overflow, 0, "prototype 深度溢位")
        })?;
        for &child in prototype.children.iter().rev() {
            if child.0 as usize >= chunk.prototypes.len() {
                return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "child prototype ID 不符"));
            }
            stack.push((child, child_depth, Some((prototype.max_stack_size, prototype.upvalues.len()))));
        }
    }
    if next != chunk.prototypes.len() {
        return Err(error(OfficialChunkErrorKind::InvalidFormat, 0, "prototype 含未到達節點"));
    }
    Ok(())
}

fn copy_bytes(
    source: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<Vec<u8>, OfficialChunkError> {
    bytes_owned(source, budget, limits, 0)
}

fn copy_optional_bytes(
    source: Option<&[u8]>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<Option<Vec<u8>>, OfficialChunkError> {
    source
        .map(|bytes| copy_bytes(bytes, budget, limits))
        .transpose()
}

fn copy_scalars<T: Copy>(
    source: &[T],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<Vec<T>, OfficialChunkError> {
    let mut target = vector(source.len(), budget, limits, 0)?;
    target.extend_from_slice(source);
    Ok(target)
}

fn copy_prototype(
    source: &OfficialPrototype,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<OfficialPrototype, OfficialChunkError> {
    let mut constants = vector(source.constants.len(), budget, limits, 0)?;
    for constant in &source.constants {
        constants.push(match constant {
            OfficialConstant::Nil => OfficialConstant::Nil,
            OfficialConstant::Boolean(value) => OfficialConstant::Boolean(*value),
            OfficialConstant::Integer(value) => OfficialConstant::Integer(*value),
            OfficialConstant::Number(value) => OfficialConstant::Number(*value),
            OfficialConstant::String { bytes, long } => OfficialConstant::String {
                bytes: copy_bytes(bytes, budget, limits)?.into(),
                long: *long,
            },
        });
    }
    let mut locals = vector(source.debug.locals.len(), budget, limits, 0)?;
    for local in &source.debug.locals {
        locals.push(OfficialLocal {
            name: copy_optional_bytes(local.name.as_deref(), budget, limits)?.map(Into::into),
            start_pc: local.start_pc,
            end_pc: local.end_pc,
        });
    }
    let mut upvalue_names = vector(source.debug.upvalue_names.len(), budget, limits, 0)?;
    for name in &source.debug.upvalue_names {
        upvalue_names.push(copy_optional_bytes(name.as_deref(), budget, limits)?.map(Into::into));
    }
    Ok(OfficialPrototype {
        source: copy_optional_bytes(source.source.as_deref(), budget, limits)?.map(Into::into),
        line_defined: source.line_defined,
        last_line_defined: source.last_line_defined,
        num_params: source.num_params,
        flags: source.flags,
        max_stack_size: source.max_stack_size,
        code: copy_scalars(&source.code, budget, limits)?.into(),
        constants: constants.into(),
        upvalues: copy_scalars(&source.upvalues, budget, limits)?.into(),
        children: copy_scalars(&source.children, budget, limits)?.into(),
        debug: OfficialDebug {
            line_info: copy_scalars(&source.debug.line_info, budget, limits)?.into(),
            abs_line_info: copy_scalars(&source.debug.abs_line_info, budget, limits)?.into(),
            locals: locals.into(),
            upvalue_names: upvalue_names.into(),
        },
    })
}

fn copy_bytes_with_recovery<R: AllocationRecovery>(
    source: &[u8],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    scratch: &mut Scratch<'_, R>,
) -> Result<RetainedVec<u8>, OfficialChunkError> {
    bytes_owned_with_recovery(source, budget, limits, 0, scratch)
}

fn copy_optional_bytes_with_recovery<R: AllocationRecovery>(
    source: Option<&[u8]>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    scratch: &mut Scratch<'_, R>,
) -> Result<Option<RetainedVec<u8>>, OfficialChunkError> {
    source
        .map(|bytes| copy_bytes_with_recovery(bytes, budget, limits, scratch))
        .transpose()
}

fn copy_scalars_with_recovery<T: Copy, R: AllocationRecovery>(
    source: &[T],
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    scratch: &mut Scratch<'_, R>,
) -> Result<RetainedVec<T>, OfficialChunkError> {
    let mut target = vector_with_recovery(source.len(), budget, limits, 0, scratch)?;
    target.extend_from_slice(source);
    retain_with_budget(target, budget, limits, scratch)
}

fn retain_with_budget<T, R: AllocationRecovery>(
    values: BytecodeVec<T>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    scratch: &mut Scratch<'_, R>,
) -> Result<RetainedVec<T>, OfficialChunkError> {
    budget.retained_owner::<T, _>(limits, 0, scratch)?;
    scratch.retain(values).map_err(|_| error(OfficialChunkErrorKind::AllocationFailed, 0, "owner 配置失敗"))
}

fn copy_prototype_with_recovery<R: AllocationRecovery>(
    source: &OfficialPrototype,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
    scratch: &mut Scratch<'_, R>,
) -> Result<OfficialPrototype, OfficialChunkError> {
    let mut constants = vector_with_recovery(source.constants.len(), budget, limits, 0, scratch)?;
    for constant in &source.constants {
        constants.push(match constant {
            OfficialConstant::Nil => OfficialConstant::Nil,
            OfficialConstant::Boolean(value) => OfficialConstant::Boolean(*value),
            OfficialConstant::Integer(value) => OfficialConstant::Integer(*value),
            OfficialConstant::Number(value) => OfficialConstant::Number(*value),
            OfficialConstant::String { bytes, long } => OfficialConstant::String {
                bytes: copy_bytes_with_recovery(bytes, budget, limits, scratch)?,
                long: *long,
            },
        });
    }
    let mut locals = vector_with_recovery(source.debug.locals.len(), budget, limits, 0, scratch)?;
    for local in &source.debug.locals {
        locals.push(OfficialLocal {
            name: copy_optional_bytes_with_recovery(local.name.as_deref(), budget, limits, scratch)?,
            start_pc: local.start_pc,
            end_pc: local.end_pc,
        });
    }
    let mut upvalue_names = vector_with_recovery(source.debug.upvalue_names.len(), budget, limits, 0, scratch)?;
    for name in &source.debug.upvalue_names {
        upvalue_names.push(copy_optional_bytes_with_recovery(name.as_deref(), budget, limits, scratch)?);
    }
    Ok(OfficialPrototype {
        source: copy_optional_bytes_with_recovery(source.source.as_deref(), budget, limits, scratch)?,
        line_defined: source.line_defined,
        last_line_defined: source.last_line_defined,
        num_params: source.num_params,
        flags: source.flags,
        max_stack_size: source.max_stack_size,
        code: copy_scalars_with_recovery(&source.code, budget, limits, scratch)?,
        constants: retain_with_budget(constants, budget, limits, scratch)?,
        upvalues: copy_scalars_with_recovery(&source.upvalues, budget, limits, scratch)?,
        children: copy_scalars_with_recovery(&source.children, budget, limits, scratch)?,
        debug: OfficialDebug {
            line_info: copy_scalars_with_recovery(&source.debug.line_info, budget, limits, scratch)?,
            abs_line_info: copy_scalars_with_recovery(&source.debug.abs_line_info, budget, limits, scratch)?,
            locals: retain_with_budget(locals, budget, limits, scratch)?,
            upvalue_names: retain_with_budget(upvalue_names, budget, limits, scratch)?,
        },
    })
}

pub(crate) fn clone_official_chunk_checked_with_recovery<R: AllocationRecovery>(
    source: &OfficialChunk,
    limits: &OfficialChunkLimits,
    recovery: &mut R,
) -> Result<(OfficialChunk, usize), OfficialChunkRecoveryError<R::Error>> {
    let mut scratch = Scratch::new(recovery);
    let result = (|| -> Result<(OfficialChunk, usize), OfficialChunkError> {
        let mut validation = Budget::default();
        let mut no_work = None;
        validate_chunk(source, &mut validation, limits, &mut no_work, &mut scratch)?;
        let mut copy_budget = Budget::default();
        let mut prototypes = vector_with_recovery(source.prototypes.len(), &mut copy_budget, limits, 0, &mut scratch)?;
        for prototype in &source.prototypes {
            prototypes.push(copy_prototype_with_recovery(prototype, &mut copy_budget, limits, &mut scratch)?);
        }
        let prototypes = retain_with_budget(prototypes, &mut copy_budget, limits, &mut scratch)?;
        Ok((OfficialChunk { profile: source.profile, root_upvalues: source.root_upvalues, main: source.main, prototypes }, copy_budget.allocated))
    })();
    result.map_err(|error| match scratch.take_refusal() {
        Some(refusal) => OfficialChunkRecoveryError::Reserve(refusal),
        None => OfficialChunkRecoveryError::Chunk(error),
    })
}

/// 為 P05 非 wire artifact 建立受限擁有複本；呼叫端原始樹之後可任意修改。
pub(crate) fn clone_official_chunk_checked(
    source: &OfficialChunk,
    limits: &OfficialChunkLimits,
) -> Result<(OfficialChunk, usize), OfficialChunkError> {
    let mut validation = Budget::default();
    let mut no_work = None;
    let mut recovery = GlobalAllocation;
    let mut scratch = Scratch::new(&mut recovery);
    validate_chunk(source, &mut validation, limits, &mut no_work, &mut scratch)?;
    let mut copy_budget = Budget::default();
    let mut prototypes = vector(source.prototypes.len(), &mut copy_budget, limits, 0)?;
    for prototype in &source.prototypes {
        prototypes.push(copy_prototype(prototype, &mut copy_budget, limits)?);
    }
    Ok((
        OfficialChunk {
            profile: source.profile,
            root_upvalues: source.root_upvalues,
            main: source.main,
            prototypes: prototypes.into(),
        },
        copy_budget.allocated,
    ))
}

#[derive(Clone, Copy)]
struct SavedString<'a> {
    bytes: &'a [u8],
    index: u64,
}

struct StringIndex<'a> {
    slots: BytecodeVec<Option<SavedString<'a>>>,
    count: usize,
}

impl<'a> StringIndex<'a> {
    fn new<R: AllocationRecovery>(
        max_entries: usize,
        limits: &OfficialChunkLimits,
        work: &mut Option<&mut OfficialWorkBudget>,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<Self, OfficialChunkError> {
        if max_entries == 0 {
            return Ok(Self {
                slots: scratch.vec(),
                count: 0,
            });
        }
        let slot_count = max_entries
            .checked_mul(2)
            .and_then(|value| value.checked_next_power_of_two())
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, 0, "字串索引大小溢位"))?;
        let requested = slot_count
            .checked_mul(size_of::<Option<SavedString<'a>>>())
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, 0, "字串索引配置溢位"))?;
        if requested > limits.max_allocated_bytes {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                0,
                "字串索引配置超限",
            ));
        }
        meter(work, slot_count, 0)?;
        let mut slots = scratch.vec();
        scratch.reserve_exact(&mut slots, slot_count).map_err(|_| {
            error(
                OfficialChunkErrorKind::AllocationFailed,
                0,
                "字串索引配置失敗",
            )
        })?;
        if slots
            .capacity()
            .checked_mul(size_of::<Option<SavedString<'a>>>())
            .is_none_or(|actual| actual > limits.max_allocated_bytes)
        {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                0,
                "字串索引實際容量超限",
            ));
        }
        slots.resize(slot_count, None);
        Ok(Self { slots, count: 0 })
    }

    fn allocated(&self) -> usize {
        self.slots.capacity() * size_of::<Option<SavedString<'a>>>()
    }

    fn slot(
        &self,
        bytes: &[u8],
        work: &mut Option<&mut OfficialWorkBudget>,
    ) -> Result<usize, OfficialChunkError> {
        if self.slots.is_empty() {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                0,
                "字串索引容量不足",
            ));
        }
        meter(work, bytes.len(), 0)?;
        let mut hasher = official_slot_hasher();
        bytes.hash(&mut hasher);
        let mut index = hasher.finish() as usize & (self.slots.len() - 1);
        for _ in 0..self.slots.len() {
            let compare = self.slots[index].map_or(0, |saved| saved.bytes.len());
            meter(work, compare.saturating_add(1), 0)?;
            match self.slots[index] {
                Some(saved) if saved.bytes != bytes => {
                    index = (index + 1) & (self.slots.len() - 1);
                }
                _ => return Ok(index),
            }
        }
        Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "字串索引已滿",
        ))
    }

    fn lookup(
        &self,
        bytes: &[u8],
        work: &mut Option<&mut OfficialWorkBudget>,
    ) -> Result<Option<u64>, OfficialChunkError> {
        let index = self.slot(bytes, work)?;
        Ok(self.slots[index].map(|saved| saved.index))
    }

    fn insert(
        &mut self,
        bytes: &'a [u8],
        work: &mut Option<&mut OfficialWorkBudget>,
    ) -> Result<(), OfficialChunkError> {
        let index = self.slot(bytes, work)?;
        if self.slots[index].is_some() {
            return Ok(());
        }
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, 0, "字串索引數溢位"))?;
        self.slots[index] = Some(SavedString {
            bytes,
            index: self.count as u64,
        });
        Ok(())
    }
}

struct Writer<'a, 'w> {
    bytes: BytecodeVec<u8>,
    measured_len: usize,
    measuring: bool,
    base_allocated: usize,
    profile: LuaProfile,
    limits: &'a OfficialChunkLimits,
    saved_strings: StringIndex<'a>,
    work: Option<&'w mut OfficialWorkBudget>,
}

impl<'a, 'w> Writer<'a, 'w> {
    fn offset(&self) -> usize {
        if self.measuring {
            self.measured_len
        } else {
            self.bytes.len()
        }
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), OfficialChunkError> {
        let offset = self.offset();
        meter(&mut self.work, bytes.len(), offset)?;
        let end = offset
            .checked_add(bytes.len())
            .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, offset, "輸出長度溢位"))?;
        if end > self.limits.max_bytes
            || end
                .checked_add(self.saved_strings.allocated())
                .and_then(|value| value.checked_add(self.base_allocated))
                .is_none_or(|total| total > self.limits.max_allocated_bytes)
        {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                offset,
                "輸出或配置額度超限",
            ));
        }
        if self.measuring {
            self.measured_len = end;
            return Ok(());
        }
        if end > self.bytes.capacity() {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                offset,
                "預估輸出大小不符",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn byte(&mut self, value: u8) -> Result<(), OfficialChunkError> {
        self.put(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), OfficialChunkError> {
        self.put(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), OfficialChunkError> {
        self.put(&value.to_le_bytes())
    }

    fn i64(&mut self, value: i64) -> Result<(), OfficialChunkError> {
        self.put(&value.to_le_bytes())
    }

    fn f64(&mut self, value: f64) -> Result<(), OfficialChunkError> {
        self.put(&value.to_le_bytes())
    }

    fn varint(&mut self, mut value: u64) -> Result<(), OfficialChunkError> {
        let mut buffer = [0_u8; 10];
        let mut start = buffer.len() - 1;
        buffer[start] = value as u8 & 0x7f;
        value >>= 7;
        while value != 0 {
            start -= 1;
            buffer[start] = value as u8 & 0x7f;
            value >>= 7;
        }
        match self.profile {
            LuaProfile::Lua55 => {
                let end = buffer.len() - 1;
                for byte in &mut buffer[start..end] {
                    *byte |= 0x80;
                }
            }
            LuaProfile::Lua54 => buffer[buffer.len() - 1] |= 0x80,
        }
        self.put(&buffer[start..])
    }

    fn size(&mut self, value: usize) -> Result<(), OfficialChunkError> {
        self.varint(u64::try_from(value).map_err(|_| {
            error(
                OfficialChunkErrorKind::Overflow,
                self.offset(),
                "長度超出 u64 範圍",
            )
        })?)
    }

    fn int(&mut self, value: usize) -> Result<(), OfficialChunkError> {
        let limit = match self.profile {
            LuaProfile::Lua55 => i32::MAX as u32,
            LuaProfile::Lua54 => LUA54_INT_MAX,
        };
        if value > limit as usize {
            return Err(error(
                OfficialChunkErrorKind::Overflow,
                self.offset(),
                "int 超出範圍",
            ));
        }
        self.size(value)
    }

    fn align4(&mut self) -> Result<(), OfficialChunkError> {
        let padding = (4 - self.offset() % 4) % 4;
        self.put(&[0_u8; 3][..padding])
    }

    fn header(&mut self) -> Result<(), OfficialChunkError> {
        self.put(SIGNATURE)?;
        self.byte(if self.profile == LuaProfile::Lua55 {
            0x55
        } else {
            0x54
        })?;
        self.byte(0)?;
        self.put(DATA)?;
        match self.profile {
            LuaProfile::Lua55 => {
                self.byte(4)?;
                self.i32(INT_SENTINEL_55 as i32)?;
                self.byte(4)?;
                self.u32(INSTRUCTION_SENTINEL_55)?;
                self.byte(8)?;
                self.i64(INT_SENTINEL_55)?;
                self.byte(8)?;
                self.f64(NUMBER_SENTINEL_55)?;
            }
            LuaProfile::Lua54 => {
                self.byte(4)?;
                self.byte(8)?;
                self.byte(8)?;
                self.i64(INT_SENTINEL_54)?;
                self.f64(NUMBER_SENTINEL_54)?;
            }
        }
        Ok(())
    }

    fn string(&mut self, value: Option<&'a [u8]>) -> Result<(), OfficialChunkError> {
        let Some(bytes) = value else {
            self.size(0)?;
            if self.profile == LuaProfile::Lua55 {
                self.size(0)?;
            }
            return Ok(());
        };
        if self.profile == LuaProfile::Lua55 {
            if let Some(index) = self.saved_strings.lookup(bytes, &mut self.work)? {
                self.size(0)?;
                return self.varint(index);
            }
        }
        let size = bytes.len().checked_add(1).ok_or_else(|| {
            error(
                OfficialChunkErrorKind::Overflow,
                self.offset(),
                "字串大小溢位",
            )
        })?;
        self.size(size)?;
        self.put(bytes)?;
        if self.profile == LuaProfile::Lua55 {
            self.byte(0)?;
            self.saved_strings.insert(bytes, &mut self.work)?;
        }
        Ok(())
    }

    fn prototype_head(
        &mut self,
        prototype: &'a OfficialPrototype,
        strip: bool,
    ) -> Result<(), OfficialChunkError> {
        if self.profile == LuaProfile::Lua54 {
            self.string(if strip {
                None
            } else {
                prototype.source.as_deref()
            })?;
        }
        self.int(prototype.line_defined as usize)?;
        self.int(prototype.last_line_defined as usize)?;
        self.byte(prototype.num_params)?;
        self.byte(prototype.flags)?;
        self.byte(prototype.max_stack_size)?;
        self.int(prototype.code.len())?;
        if self.profile == LuaProfile::Lua55 {
            self.align4()?;
        }
        meter(&mut self.work, prototype.code.len(), 0)?;
        for instruction in &prototype.code {
            self.u32(*instruction)?;
        }
        self.int(prototype.constants.len())?;
        meter(&mut self.work, prototype.constants.len(), 0)?;
        for constant in &prototype.constants {
            match constant {
                OfficialConstant::Nil => self.byte(0)?,
                OfficialConstant::Boolean(false) => self.byte(1)?,
                OfficialConstant::Boolean(true) => self.byte(17)?,
                OfficialConstant::Integer(integer) => {
                    self.byte(3)?;
                    match self.profile {
                        LuaProfile::Lua55 => {
                            let coded = if *integer >= 0 {
                                (*integer as u64) << 1
                            } else {
                                ((!*integer) as u64) << 1 | 1
                            };
                            self.varint(coded)?;
                        }
                        LuaProfile::Lua54 => self.i64(*integer)?,
                    }
                }
                OfficialConstant::Number(number) => {
                    self.byte(19)?;
                    self.f64(*number)?;
                }
                OfficialConstant::String { bytes, long } => {
                    self.byte(if *long { 20 } else { 4 })?;
                    self.string(Some(bytes))?;
                }
            }
        }
        self.int(prototype.upvalues.len())?;
        meter(&mut self.work, prototype.upvalues.len(), 0)?;
        for upvalue in &prototype.upvalues {
            self.byte(u8::from(upvalue.in_stack))?;
            self.byte(upvalue.index)?;
            self.byte(upvalue.kind)?;
        }
        self.int(prototype.children.len())?;
        meter(&mut self.work, prototype.children.len(), 0)?;
        Ok(())
    }

    fn prototype_tail(
        &mut self,
        prototype: &'a OfficialPrototype,
        strip: bool,
    ) -> Result<(), OfficialChunkError> {
        if self.profile == LuaProfile::Lua55 {
            self.string(if strip {
                None
            } else {
                prototype.source.as_deref()
            })?;
        }
        let debug = &prototype.debug;
        let line_count = if strip { 0 } else { debug.line_info.len() };
        self.int(line_count)?;
        meter(&mut self.work, line_count, 0)?;
        for line in debug.line_info.iter().take(line_count) {
            self.byte(*line as u8)?;
        }
        let abs_count = if strip { 0 } else { debug.abs_line_info.len() };
        self.int(abs_count)?;
        if self.profile == LuaProfile::Lua55 && abs_count > 0 {
            self.align4()?;
        }
        meter(&mut self.work, abs_count, 0)?;
        for abs in debug.abs_line_info.iter().take(abs_count) {
            match self.profile {
                LuaProfile::Lua55 => {
                    self.u32(abs.pc)?;
                    self.i32(abs.line)?;
                }
                LuaProfile::Lua54 => {
                    self.int(abs.pc as usize)?;
                    self.int(abs.line as usize)?;
                }
            }
        }
        let local_count = if strip { 0 } else { debug.locals.len() };
        self.int(local_count)?;
        meter(&mut self.work, local_count, 0)?;
        for local in debug.locals.iter().take(local_count) {
            self.string(local.name.as_deref())?;
            self.int(local.start_pc as usize)?;
            self.int(local.end_pc as usize)?;
        }
        let name_count = if strip { 0 } else { debug.upvalue_names.len() };
        self.int(name_count)?;
        meter(&mut self.work, name_count, 0)?;
        for name in debug.upvalue_names.iter().take(name_count) {
            self.string(name.as_deref())?;
        }
        Ok(())
    }

    fn prototypes<R: AllocationRecovery>(
        &mut self,
        chunk: &'a OfficialChunk,
        strip: bool,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<(), OfficialChunkError> {
        let mut stack = scratch.vec();
        scratch.reserve_exact(&mut stack, chunk.prototypes.len()).map_err(|_| {
            error(OfficialChunkErrorKind::AllocationFailed, 0, "編碼 prototype cursor 配置失敗")
        })?;
        stack.push((chunk.main, 0usize, false));
        while let Some((id, child_index, entered)) = stack.last_mut() {
            let prototype = &chunk.prototypes[id.0 as usize];
            if !*entered {
                self.prototype_head(prototype, strip)?;
                *entered = true;
            } else if let Some(&child) = prototype.children.get(*child_index) {
                *child_index += 1;
                stack.push((child, 0, false));
            } else {
                self.prototype_tail(prototype, strip)?;
                stack.pop();
            }
        }
        Ok(())
    }
}

pub fn encode_official_chunk(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
) -> Result<Vec<u8>, OfficialChunkError> {
    let mut recovery = GlobalAllocation;
    let mut scratch = Scratch::new(&mut recovery);
    let bytes = encode_official_chunk_inner(chunk, strip, limits, None, &mut scratch)?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).map_err(|_| error(OfficialChunkErrorKind::AllocationFailed, 0, "輸出配置失敗"))?;
    output.extend_from_slice(&bytes);
    Ok(output)
}

pub(super) fn encode_official_chunk_metered(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<u8>, OfficialChunkError> {
    let mut recovery = GlobalAllocation;
    let mut scratch = Scratch::new(&mut recovery);
    let bytes = encode_official_chunk_inner(chunk, strip, limits, Some(work), &mut scratch)?;
    let mut output = Vec::new();
    output.try_reserve_exact(bytes.len()).map_err(|_| error(OfficialChunkErrorKind::AllocationFailed, 0, "輸出配置失敗"))?;
    output.extend_from_slice(&bytes);
    Ok(output)
}

pub(super) fn encode_official_chunk_metered_with_recovery<R: AllocationRecovery>(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
    scratch: &mut Scratch<'_, R>,
) -> Result<BytecodeVec<u8>, OfficialChunkError> {
    encode_official_chunk_inner(chunk, strip, limits, Some(work), scratch)
}

fn encode_official_chunk_inner<R: AllocationRecovery>(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
    mut work: Option<&mut OfficialWorkBudget>,
    scratch: &mut Scratch<'_, R>,
) -> Result<BytecodeVec<u8>, OfficialChunkError> {
    let mut budget = Budget::default();
    budget.alloc::<OfficialChunk>(1, limits, 0)?;
    validate_chunk(chunk, &mut budget, limits, &mut work, scratch)?;
    let remaining = limits
        .max_allocated_bytes
        .checked_sub(budget.allocated)
        .ok_or_else(|| error(OfficialChunkErrorKind::LimitExceeded, 0, "配置額度超限"))?;
    let table_limits = OfficialChunkLimits {
        max_allocated_bytes: remaining,
        ..*limits
    };
    let table_entries = if chunk.profile == LuaProfile::Lua55 {
        if strip {
            let mut total = 0usize;
            for proto in &chunk.prototypes {
                meter(&mut work, proto.constants.len().checked_add(proto.children.len()).ok_or_else(|| {
                    error(OfficialChunkErrorKind::Overflow, 0, "字串表掃描 work 溢位")
                })?, 0)?;
                total = total.checked_add(proto.constants.iter().filter(|constant| matches!(constant, OfficialConstant::String { .. })).count()).ok_or_else(|| {
                    error(OfficialChunkErrorKind::Overflow, 0, "字串表項數溢位")
                })?;
            }
            total
        } else {
            budget.strings
        }
    } else {
        0
    };
    let mut measured = Writer {
        bytes: scratch.vec(),
        measured_len: 0,
        measuring: true,
        base_allocated: budget.allocated,
        profile: chunk.profile,
        limits,
        saved_strings: StringIndex::new(table_entries, &table_limits, &mut work, scratch)?,
        work: work.as_deref_mut(),
    };
    measured.header()?;
    measured.byte(chunk.root_upvalues)?;
    measured.prototypes(chunk, strip, scratch)?;
    let output_len = measured.measured_len;
    drop(measured);

    let table = StringIndex::new(table_entries, &table_limits, &mut work, scratch)?;
    let preflight_total = budget
        .allocated
        .checked_add(table.allocated())
        .and_then(|value| value.checked_add(output_len))
        .ok_or_else(|| error(OfficialChunkErrorKind::Overflow, 0, "配置總量溢位"))?;
    if preflight_total > limits.max_allocated_bytes {
        return Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "配置額度超限",
        ));
    }
    let mut bytes = scratch.vec();
    scratch
        .reserve_exact(&mut bytes, output_len)
        .map_err(|_| error(OfficialChunkErrorKind::AllocationFailed, 0, "輸出配置失敗"))?;
    if budget
        .allocated
        .checked_add(table.allocated())
        .and_then(|value| value.checked_add(bytes.capacity()))
        .is_none_or(|total| total > limits.max_allocated_bytes)
    {
        return Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "輸出實際容量超限",
        ));
    }
    let mut writer = Writer {
        bytes,
        measured_len: 0,
        measuring: false,
        base_allocated: budget.allocated,
        profile: chunk.profile,
        limits,
        saved_strings: table,
        work,
    };
    writer.header()?;
    writer.byte(chunk.root_upvalues)?;
    writer.prototypes(chunk, strip, scratch)?;
    if writer.bytes.len() != output_len {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            writer.bytes.len(),
            "預估輸出大小不符",
        ));
    }
    Ok(writer.bytes)
}

#[cfg(test)]
mod metered_encoder_tests {
    use super::*;

    #[test]
    fn lua55_string_index_and_two_pass_encoder_obey_exact_work_boundary() {
        let limits = OfficialChunkLimits::default();
        let mut chunk = decode_official_chunk(
            include_bytes!("../../tests/official_chunk_fixtures/lua55-debug.luac"),
            LuaProfile::Lua55,
            &limits,
        )
        .unwrap();
        for index in 0..64 {
            chunk.main.constants.push(OfficialConstant::String {
                bytes: format!("shared-hash-probe-{index:03}-{}", "x".repeat(96)).into_bytes(),
                long: false,
            });
        }
        let mut unrestricted = OfficialWorkBudget::new(u64::MAX);
        let expected =
            encode_official_chunk_metered(&chunk, false, &limits, &mut unrestricted).unwrap();
        let exact = unrestricted.consumed();
        assert!(exact > expected.len() as u64);

        let mut zero = OfficialWorkBudget::new(0);
        assert_eq!(
            encode_official_chunk_metered(&chunk, false, &limits, &mut zero)
                .unwrap_err()
                .kind,
            OfficialChunkErrorKind::WorkExhausted
        );
        let mut one_below = OfficialWorkBudget::new(exact - 1);
        assert_eq!(
            encode_official_chunk_metered(&chunk, false, &limits, &mut one_below)
                .unwrap_err()
                .kind,
            OfficialChunkErrorKind::WorkExhausted
        );
        let mut exact_work = OfficialWorkBudget::new(exact);
        let actual =
            encode_official_chunk_metered(&chunk, false, &limits, &mut exact_work).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(exact_work.remaining(), 0);
    }

    #[test]
    fn encoder_retained_capacity_is_counted_once_at_allocation_boundary() {
        let defaults = OfficialChunkLimits::default();
        let decoded = decode_official_chunk(
            include_bytes!("../../tests/official_chunk_fixtures/lua54-debug.luac"),
            LuaProfile::Lua54,
            &defaults,
        )
        .unwrap();
        let original = decoded.clone();
        let mut padded = decoded.clone();
        let original_capacity = padded.main.code.capacity();
        padded.main.code.reserve_exact(2_048);
        let extra_bytes = (padded.main.code.capacity() - original_capacity) * size_of::<u32>();
        assert!(extra_bytes > 0);

        let minimum = |chunk: &OfficialChunk| {
            let mut low = 1usize;
            let mut high = defaults.max_allocated_bytes;
            while low < high {
                let mid = low + (high - low) / 2;
                let mut limits = defaults;
                limits.max_allocated_bytes = mid;
                if encode_official_chunk(chunk, false, &limits).is_ok() {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            low
        };
        let original_minimum = minimum(&original);
        let padded_minimum = minimum(&padded);
        assert_eq!(padded_minimum - original_minimum, extra_bytes);
        let mut exact = defaults;
        exact.max_allocated_bytes = padded_minimum;
        assert!(encode_official_chunk(&padded, false, &exact).is_ok());
        exact.max_allocated_bytes -= 1;
        assert_eq!(
            encode_official_chunk(&padded, false, &exact)
                .unwrap_err()
                .kind,
            OfficialChunkErrorKind::LimitExceeded
        );
    }
}
