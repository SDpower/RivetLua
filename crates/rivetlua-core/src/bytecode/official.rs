//! Lua 5.5.1／5.4.9 官方 binary chunk 的純 Rust 結構 codec。
//! 本模組只處理可界定資源的資料格式；指令語意與 CFG 由後續轉譯階段驗證。

use std::hash::{Hash, Hasher};
use std::mem::size_of;

use super::official_translation::OfficialWorkBudget;
use super::{LuaProfile, ProtoId};

const SIGNATURE: &[u8] = b"\x1bLua";
const DATA: &[u8] = b"\x19\x93\r\n\x1a\n";
const INT_SENTINEL_54: i64 = 0x5678;
const INT_SENTINEL_55: i64 = -0x5678;
const INSTRUCTION_SENTINEL_55: u32 = 0x1234_5678;
const NUMBER_SENTINEL_54: f64 = 370.5;
const NUMBER_SENTINEL_55: f64 = -370.5;
const MAX_SAFE_DEPTH: usize = 64;
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

impl std::fmt::Display for OfficialChunkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "官方 chunk 位移 {}：{}", self.offset, self.detail)
    }
}

impl std::error::Error for OfficialChunkError {}

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
    pub main: OfficialPrototype,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialPrototype {
    pub source: Option<Vec<u8>>,
    pub line_defined: u32,
    pub last_line_defined: u32,
    pub num_params: u8,
    pub flags: u8,
    pub max_stack_size: u8,
    pub code: Vec<u32>,
    pub constants: Vec<OfficialConstant>,
    pub upvalues: Vec<OfficialUpvalue>,
    pub children: Vec<OfficialPrototype>,
    pub debug: OfficialDebug,
}

#[derive(Clone, Debug, PartialEq)]
pub enum OfficialConstant {
    Nil,
    Boolean(bool),
    Integer(i64),
    Number(f64),
    String { bytes: Vec<u8>, long: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialUpvalue {
    pub in_stack: bool,
    pub index: u8,
    pub kind: u8,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct OfficialDebug {
    pub line_info: Vec<i8>,
    pub abs_line_info: Vec<OfficialAbsLine>,
    pub locals: Vec<OfficialLocal>,
    pub upvalue_names: Vec<Option<Vec<u8>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialAbsLine {
    pub pc: u32,
    pub line: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialLocal {
    pub name: Option<Vec<u8>>,
    pub start_pc: u32,
    pub end_pc: u32,
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

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
    profile: LuaProfile,
    limits: &'a OfficialChunkLimits,
    budget: Budget,
    saved_strings: Vec<Vec<u8>>,
}

impl<'a> Reader<'a> {
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

    fn string(&mut self) -> Result<Option<Vec<u8>>, OfficialChunkError> {
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
                Ok(Some(bytes_owned(
                    bytes,
                    &mut self.budget,
                    self.limits,
                    self.offset,
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
                    return Ok(Some(bytes_owned(
                        saved,
                        &mut self.budget,
                        self.limits,
                        self.offset,
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
                let owned = bytes_owned(&bytes[..len], &mut self.budget, self.limits, self.offset)?;
                let saved =
                    bytes_saved_copy(&bytes[..len], &mut self.budget, self.limits, self.offset)?;
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

    fn prototype(
        &mut self,
        depth: usize,
        parent: Option<(u8, usize)>,
    ) -> Result<OfficialPrototype, OfficialChunkError> {
        if depth > self.limits.max_depth.min(MAX_SAFE_DEPTH) {
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
        let mut code = vector(code_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut constants = vector(constant_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut upvalues = vector(upvalue_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut children = vector(child_count, &mut self.budget, self.limits, self.offset)?;
        for _ in 0..child_count {
            children.push(self.prototype(depth + 1, Some((max_stack_size, upvalue_count)))?);
        }
        let source = if self.profile == LuaProfile::Lua55 {
            self.string()?
        } else {
            source
        };
        let debug = self.debug(code_count, upvalue_count)?;
        Ok(OfficialPrototype {
            source,
            line_defined,
            last_line_defined,
            num_params,
            flags,
            max_stack_size,
            code,
            constants,
            upvalues,
            children,
            debug,
        })
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
        let mut line_info = vector(line_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut abs_line_info = vector(abs_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut locals = vector(local_count, &mut self.budget, self.limits, self.offset)?;
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
        let mut upvalue_names = vector(name_count, &mut self.budget, self.limits, self.offset)?;
        for _ in 0..name_count {
            upvalue_names.push(self.string()?);
        }
        Ok(OfficialDebug {
            line_info,
            abs_line_info,
            locals,
            upvalue_names,
        })
    }
}

pub fn decode_official_chunk(
    bytes: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
) -> Result<OfficialChunk, OfficialChunkError> {
    if bytes.len() > limits.max_bytes {
        return Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "chunk 長度超限",
        ));
    }
    let mut reader = Reader {
        bytes,
        offset: 0,
        profile,
        limits,
        budget: Budget::default(),
        saved_strings: Vec::new(),
    };
    reader.header()?;
    if profile == LuaProfile::Lua55 {
        let capacity = limits.max_strings.min(bytes.len() / 2);
        reader
            .budget
            .alloc::<Vec<u8>>(capacity, limits, reader.offset)?;
        reader
            .saved_strings
            .try_reserve_exact(capacity)
            .map_err(|_| {
                error(
                    OfficialChunkErrorKind::AllocationFailed,
                    reader.offset,
                    "字串索引配置失敗",
                )
            })?;
        reader.budget.alloc::<Vec<u8>>(
            reader.saved_strings.capacity() - capacity,
            limits,
            reader.offset,
        )?;
    }
    let root_upvalues = reader.byte()?;
    let main = reader.prototype(1, None)?;
    if usize::from(root_upvalues) != main.upvalues.len() || reader.offset != bytes.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            reader.offset,
            "root upvalue 數或結尾不符",
        ));
    }
    Ok(OfficialChunk {
        profile,
        root_upvalues,
        main,
    })
}

fn validate_string(
    value: Option<&Vec<u8>>,
    budget: &mut Budget,
    limits: &OfficialChunkLimits,
) -> Result<(), OfficialChunkError> {
    if let Some(bytes) = value {
        budget.string(bytes.len(), limits, 0)?;
        budget.alloc::<u8>(bytes.capacity() - bytes.len(), limits, 0)?;
    }
    Ok(())
}

fn validate_prototype(
    prototype: &OfficialPrototype,
    profile: LuaProfile,
    depth: usize,
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
    if depth > limits.max_depth.min(MAX_SAFE_DEPTH) {
        return Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "prototype 深度超限",
        ));
    }
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
    Budget::charge(
        &mut budget.constants,
        prototype.constants.len(),
        limits.max_constants,
        0,
        "常數數超限",
    )?;
    budget.alloc::<OfficialConstant>(prototype.constants.capacity(), limits, 0)?;
    Budget::charge(
        &mut budget.upvalues,
        prototype.upvalues.len(),
        limits.max_upvalues,
        0,
        "upvalue 數超限",
    )?;
    budget.alloc::<OfficialUpvalue>(prototype.upvalues.capacity(), limits, 0)?;
    budget.alloc::<OfficialPrototype>(prototype.children.capacity(), limits, 0)?;
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
    budget.alloc::<OfficialAbsLine>(debug.abs_line_info.capacity(), limits, 0)?;
    budget.alloc::<OfficialLocal>(debug.locals.capacity(), limits, 0)?;
    budget.alloc::<Option<Vec<u8>>>(debug.upvalue_names.capacity(), limits, 0)?;
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
    for child in &prototype.children {
        validate_prototype(
            child,
            profile,
            depth + 1,
            Some((prototype.max_stack_size, prototype.upvalues.len())),
            budget,
            limits,
            work,
        )?;
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
                bytes: copy_bytes(bytes, budget, limits)?,
                long: *long,
            },
        });
    }
    let mut locals = vector(source.debug.locals.len(), budget, limits, 0)?;
    for local in &source.debug.locals {
        locals.push(OfficialLocal {
            name: copy_optional_bytes(local.name.as_deref(), budget, limits)?,
            start_pc: local.start_pc,
            end_pc: local.end_pc,
        });
    }
    let mut upvalue_names = vector(source.debug.upvalue_names.len(), budget, limits, 0)?;
    for name in &source.debug.upvalue_names {
        upvalue_names.push(copy_optional_bytes(name.as_deref(), budget, limits)?);
    }
    let mut children = vector(source.children.len(), budget, limits, 0)?;
    for child in &source.children {
        children.push(copy_prototype(child, budget, limits)?);
    }
    Ok(OfficialPrototype {
        source: copy_optional_bytes(source.source.as_deref(), budget, limits)?,
        line_defined: source.line_defined,
        last_line_defined: source.last_line_defined,
        num_params: source.num_params,
        flags: source.flags,
        max_stack_size: source.max_stack_size,
        code: copy_scalars(&source.code, budget, limits)?,
        constants,
        upvalues: copy_scalars(&source.upvalues, budget, limits)?,
        children,
        debug: OfficialDebug {
            line_info: copy_scalars(&source.debug.line_info, budget, limits)?,
            abs_line_info: copy_scalars(&source.debug.abs_line_info, budget, limits)?,
            locals,
            upvalue_names,
        },
    })
}

/// 為 P05 非 wire artifact 建立受限擁有複本；呼叫端原始樹之後可任意修改。
pub(crate) fn clone_official_chunk_checked(
    source: &OfficialChunk,
    limits: &OfficialChunkLimits,
) -> Result<(OfficialChunk, usize), OfficialChunkError> {
    if usize::from(source.root_upvalues) != source.main.upvalues.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            0,
            "root upvalue 數不符",
        ));
    }
    let mut validation = Budget::default();
    let mut no_work = None;
    validate_prototype(
        &source.main,
        source.profile,
        1,
        None,
        &mut validation,
        limits,
        &mut no_work,
    )?;
    let mut copy_budget = Budget::default();
    let main = copy_prototype(&source.main, &mut copy_budget, limits)?;
    Ok((
        OfficialChunk {
            profile: source.profile,
            root_upvalues: source.root_upvalues,
            main,
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
    slots: Vec<Option<SavedString<'a>>>,
    count: usize,
}

impl<'a> StringIndex<'a> {
    fn new(
        max_entries: usize,
        limits: &OfficialChunkLimits,
        work: &mut Option<&mut OfficialWorkBudget>,
    ) -> Result<Self, OfficialChunkError> {
        if max_entries == 0 {
            return Ok(Self {
                slots: Vec::new(),
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
        let mut slots = Vec::new();
        slots.try_reserve_exact(slot_count).map_err(|_| {
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
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
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
    bytes: Vec<u8>,
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

    fn prototype(
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
        for child in &prototype.children {
            self.prototype(child, strip)?;
        }
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
}

pub fn encode_official_chunk(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
) -> Result<Vec<u8>, OfficialChunkError> {
    encode_official_chunk_inner(chunk, strip, limits, None)
}

pub(super) fn encode_official_chunk_metered(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
    work: &mut OfficialWorkBudget,
) -> Result<Vec<u8>, OfficialChunkError> {
    encode_official_chunk_inner(chunk, strip, limits, Some(work))
}

fn encode_official_chunk_inner(
    chunk: &OfficialChunk,
    strip: bool,
    limits: &OfficialChunkLimits,
    mut work: Option<&mut OfficialWorkBudget>,
) -> Result<Vec<u8>, OfficialChunkError> {
    if usize::from(chunk.root_upvalues) != chunk.main.upvalues.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            0,
            "root upvalue 數不符",
        ));
    }
    let mut budget = Budget::default();
    budget.alloc::<OfficialChunk>(1, limits, 0)?;
    validate_prototype(
        &chunk.main,
        chunk.profile,
        1,
        None,
        &mut budget,
        limits,
        &mut work,
    )?;
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
            fn constant_strings(
                proto: &OfficialPrototype,
                work: &mut Option<&mut OfficialWorkBudget>,
            ) -> Result<usize, OfficialChunkError> {
                meter(
                    work,
                    proto
                        .constants
                        .len()
                        .checked_add(proto.children.len())
                        .ok_or_else(|| {
                            error(OfficialChunkErrorKind::Overflow, 0, "字串表掃描 work 溢位")
                        })?,
                    0,
                )?;
                let mut total = proto
                    .constants
                    .iter()
                    .filter(|constant| matches!(constant, OfficialConstant::String { .. }))
                    .count();
                for child in &proto.children {
                    total = total
                        .checked_add(constant_strings(child, work)?)
                        .ok_or_else(|| {
                            error(OfficialChunkErrorKind::Overflow, 0, "字串表項數溢位")
                        })?;
                }
                Ok(total)
            }
            constant_strings(&chunk.main, &mut work)?
        } else {
            budget.strings
        }
    } else {
        0
    };
    let mut measured = Writer {
        bytes: Vec::new(),
        measured_len: 0,
        measuring: true,
        base_allocated: budget.allocated,
        profile: chunk.profile,
        limits,
        saved_strings: StringIndex::new(table_entries, &table_limits, &mut work)?,
        work: work.as_deref_mut(),
    };
    measured.header()?;
    measured.byte(chunk.root_upvalues)?;
    measured.prototype(&chunk.main, strip)?;
    let output_len = measured.measured_len;
    drop(measured);

    let table = StringIndex::new(table_entries, &table_limits, &mut work)?;
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
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(output_len)
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
    writer.prototype(&chunk.main, strip)?;
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
