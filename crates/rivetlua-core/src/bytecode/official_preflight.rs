//! 官方 chunk 的無配置結構預掃描，供 P13 在 decode 前預扣工作與配置。

use core::mem::size_of;

use super::official::{OfficialChunkError, OfficialChunkErrorKind, OfficialChunkLimits};
use super::official_translation::OfficialPcMap;
use super::{
    BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeInstruction, BytecodePrototype,
    BytecodeUpvalue, InstructionOffset, LuaProfile, OfficialPlanCall, OfficialPlanFrameInput,
    OfficialPlanRootBinding, OfficialPlanUpvalueMap, OfficialRvluPc, Register, VerifyLimits,
};

const SIGNATURE: &[u8] = b"\x1bLua";
const DATA: &[u8] = b"\x19\x93\r\n\x1a\n";
const LUA54_INT_MAX: u32 = i32::MAX as u32 - 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialChunkPreflight {
    /// 此值不含預掃描本身；呼叫者須在掃描前預扣 `2 * input.len() + 1`。
    pub subsequent_work: u64,
    pub temporary_bytes: usize,
    pub retained_bytes: usize,
    pub decoded_bytes: usize,
    pub prototypes: usize,
    pub instructions: usize,
    pub constants: usize,
    pub expanded_instructions: usize,
}

#[derive(Default)]
struct Stats {
    prototypes: u128,
    instructions: u128,
    constants: u128,
    upvalues: u128,
    debug_entries: u128,
    strings: u128,
    string_bytes: u128,
    saved_bytes: u128,
    max_saved_len: u128,
    saved_count: u128,
    stack_slots: u128,
    instruction_squares: u128,
    expanded_instructions: u128,
    register_slots: u128,
    binding_capacity: u128,
    binding_squares: u128,
    upvalue_squares: u128,
    close_cells: u128,
    close_binding_lookups: u128,
    numeric_dominator_work: u128,
    numeric_cfg_bytes: u128,
    plan_metered_work: u128,
    source_metered_work: u128,
    source_cfg_work: u128,
    internal_calls: u128,
    call_inputs: u128,
    source_work_bytes: u128,
}

fn error(kind: OfficialChunkErrorKind, offset: usize, detail: &'static str) -> OfficialChunkError {
    OfficialChunkError {
        kind,
        offset,
        detail,
    }
}

fn overflow(offset: usize) -> OfficialChunkError {
    error(
        OfficialChunkErrorKind::Overflow,
        offset,
        "官方預掃描計數溢位",
    )
}

fn budget_overflow(offset: usize) -> OfficialChunkError {
    error(
        OfficialChunkErrorKind::LimitExceeded,
        offset,
        "官方預掃描資源計數溢位",
    )
}

fn add(total: &mut u128, amount: u128, offset: usize) -> Result<(), OfficialChunkError> {
    *total = total
        .checked_add(amount)
        .ok_or_else(|| budget_overflow(offset))?;
    Ok(())
}

struct Scan<'a> {
    input: &'a [u8],
    offset: usize,
    profile: LuaProfile,
    limits: &'a OfficialChunkLimits,
    verify: &'a VerifyLimits,
    stats: Stats,
}

impl<'a> Scan<'a> {
    fn read(&mut self, len: usize) -> Result<&'a [u8], OfficialChunkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| overflow(self.offset))?;
        let result = self.input.get(self.offset..end).ok_or_else(|| {
            error(
                OfficialChunkErrorKind::Truncated,
                self.offset,
                "官方 chunk 截斷",
            )
        })?;
        self.offset = end;
        Ok(result)
    }

    fn byte(&mut self) -> Result<u8, OfficialChunkError> {
        Ok(self.read(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, OfficialChunkError> {
        let mut raw = [0; 4];
        raw.copy_from_slice(self.read(4)?);
        Ok(u32::from_le_bytes(raw))
    }

    fn i64(&mut self) -> Result<i64, OfficialChunkError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.read(8)?);
        Ok(i64::from_le_bytes(raw))
    }

    fn f64(&mut self) -> Result<f64, OfficialChunkError> {
        let mut raw = [0; 8];
        raw.copy_from_slice(self.read(8)?);
        Ok(f64::from_le_bytes(raw))
    }

    fn varint(&mut self) -> Result<u64, OfficialChunkError> {
        let mut result = 0_u64;
        for _ in 0..10 {
            let byte = self.byte()?;
            if result > u64::MAX >> 7 {
                return Err(overflow(self.offset));
            }
            result = (result << 7) | u64::from(byte & 0x7f);
            let done = match self.profile {
                LuaProfile::Lua55 => byte & 0x80 == 0,
                LuaProfile::Lua54 => byte & 0x80 != 0,
            };
            if done {
                return Ok(result);
            }
        }
        Err(overflow(self.offset))
    }

    fn size(&mut self) -> Result<usize, OfficialChunkError> {
        usize::try_from(self.varint()?).map_err(|_| overflow(self.offset))
    }

    fn int(&mut self) -> Result<u32, OfficialChunkError> {
        let limit = match self.profile {
            LuaProfile::Lua55 => i32::MAX as u32,
            LuaProfile::Lua54 => LUA54_INT_MAX,
        };
        u32::try_from(self.varint()?)
            .ok()
            .filter(|value| *value <= limit)
            .ok_or_else(|| overflow(self.offset))
    }

    fn count(
        &mut self,
        total: fn(&mut Stats) -> &mut u128,
        amount: usize,
        limit: usize,
    ) -> Result<(), OfficialChunkError> {
        let offset = self.offset;
        add(total(&mut self.stats), amount as u128, offset)?;
        if *total(&mut self.stats) > limit as u128 {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                offset,
                "官方 chunk 項數超限",
            ));
        }
        Ok(())
    }

    fn require_min(&self, count: usize, unit: usize) -> Result<(), OfficialChunkError> {
        let bytes = count
            .checked_mul(unit)
            .ok_or_else(|| overflow(self.offset))?;
        if bytes > self.input.len() - self.offset {
            return Err(error(
                OfficialChunkErrorKind::Truncated,
                self.offset,
                "資料不足以容納宣稱項數",
            ));
        }
        Ok(())
    }

    fn align4(&mut self) -> Result<(), OfficialChunkError> {
        self.read((4 - self.offset % 4) % 4)?;
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
            LuaProfile::Lua54 => 0x54,
            LuaProfile::Lua55 => 0x55,
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
                    || self.u32()? != (-0x5678_i32) as u32
                    || self.byte()? != 4
                    || self.u32()? != 0x1234_5678
                    || self.byte()? != 8
                    || self.i64()? != -0x5678
                    || self.byte()? != 8
                    || self.f64()? != -370.5
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
                    || self.i64()? != 0x5678
                    || self.f64()? != 370.5
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

    fn string(&mut self) -> Result<bool, OfficialChunkError> {
        let size = self.size()?;
        if self.profile == LuaProfile::Lua55 && size == 0 {
            let index = self.size()?;
            if index == 0 {
                return Ok(false);
            }
            if index as u128 > self.stats.saved_count {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "字串參照不是既存索引",
                ));
            }
            self.string_charge(self.stats.max_saved_len)?;
            return Ok(true);
        }
        if size == 0 {
            return Ok(false);
        }
        let len = size - 1;
        if len > self.limits.max_string_bytes {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "單一字串超限",
            ));
        }
        self.require_min(
            if self.profile == LuaProfile::Lua55 {
                size
            } else {
                len
            },
            1,
        )?;
        let raw = self.read(if self.profile == LuaProfile::Lua55 {
            size
        } else {
            len
        })?;
        if self.profile == LuaProfile::Lua55 {
            if raw[len] != 0 {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "5.5 字串缺少結尾 NUL",
                ));
            }
            add(&mut self.stats.saved_count, 1, self.offset)?;
            if self.stats.saved_count > self.limits.max_strings.min(self.input.len() / 2) as u128 {
                return Err(error(
                    OfficialChunkErrorKind::LimitExceeded,
                    self.offset,
                    "字串索引容量不足",
                ));
            }
            add(&mut self.stats.saved_bytes, len as u128, self.offset)?;
            self.stats.max_saved_len = self.stats.max_saved_len.max(len as u128);
        }
        self.string_charge(len as u128)?;
        Ok(true)
    }

    fn string_charge(&mut self, len: u128) -> Result<(), OfficialChunkError> {
        add(&mut self.stats.strings, 1, self.offset)?;
        add(&mut self.stats.string_bytes, len, self.offset)?;
        if self.stats.strings > self.limits.max_strings as u128
            || self.stats.string_bytes > self.limits.max_total_string_bytes as u128
        {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "字串額度超限",
            ));
        }
        Ok(())
    }

    fn prototype(
        &mut self,
        depth: usize,
        parent: Option<(u8, usize)>,
    ) -> Result<usize, OfficialChunkError> {
        if depth > self.limits.max_depth.min(64) {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "prototype 深度超限",
            ));
        }
        self.count(
            |stats| &mut stats.prototypes,
            1,
            self.limits.max_prototypes.min(self.verify.max_prototypes),
        )?;
        if self.profile == LuaProfile::Lua54 {
            self.string()?;
        }
        let line_defined = self.int()?;
        let last_line_defined = self.int()?;
        let num_params = self.byte()?;
        let flags = self.byte()?;
        let max_stack = self.byte()?;
        if max_stack == 0
            || num_params > max_stack
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
        self.count(
            |stats| &mut stats.instructions,
            code_count,
            self.limits
                .max_instructions
                .min(self.verify.max_instructions),
        )?;
        add(&mut self.stats.stack_slots, max_stack as u128, self.offset)?;
        add(
            &mut self.stats.instruction_squares,
            (code_count as u128)
                .checked_mul(code_count as u128)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        if self.profile == LuaProfile::Lua55 {
            self.align4()?;
        }
        self.require_min(code_count, 4)?;
        let code_bytes = self.read(
            code_count
                .checked_mul(4)
                .ok_or_else(|| budget_overflow(self.offset))?,
        )?;
        let mut tbc = 0_u128;
        let mut close_exits = 0_u128;
        let mut fixed_list_values = 0_u128;
        let mut concat_values = 0_u128;
        let mut maximum_list = 3_u128;
        let mut numeric = 0_u128;
        let mut internal_calls = 0_u128;
        for word in code_bytes.chunks_exact(4) {
            let word = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            match (word & 0x7f) as u8 {
                53 => add(
                    &mut concat_values,
                    u128::from((word >> 16) & 0xff),
                    self.offset,
                )?,
                55 | 75 => tbc += 1,
                54 | 69..=72 => close_exits += 1,
                74 => numeric += 1,
                78 => {
                    let count = match self.profile {
                        LuaProfile::Lua54 => (word >> 16) & 0xff,
                        LuaProfile::Lua55 => (word >> 16) & 0x3f,
                    } as u128;
                    maximum_list = maximum_list.max(count);
                    fixed_list_values += count;
                    internal_calls += 1;
                }
                80 if self.profile == LuaProfile::Lua55 && (word >> 15) & 1 != 0 => {
                    internal_calls += 1
                }
                81 | 82 if self.profile == LuaProfile::Lua55 => internal_calls += 1,
                _ => {}
            }
        }
        let n = code_count as u128;
        let stack = max_stack as u128;
        let expanded = sum(
            &[
                // 固定 lowering 的最大值是 TFORCALL 的 7 條；SETLIST
                // 的逐值複製、CONCAT 的逐值合併及 close 路徑另外計入。
                n.checked_mul(7)
                    .ok_or_else(|| budget_overflow(self.offset))?,
                fixed_list_values,
                concat_values,
                close_exits
                    .checked_mul(
                        stack
                            .checked_add(tbc)
                            .ok_or_else(|| budget_overflow(self.offset))?,
                    )
                    .ok_or_else(|| budget_overflow(self.offset))?,
                num_params as u128,
                8,
            ],
            self.offset,
        )?;
        add(&mut self.stats.expanded_instructions, expanded, self.offset)?;
        let register_count = sum(
            &[
                num_params as u128,
                maximum_list,
                numeric
                    .checked_mul(3)
                    .ok_or_else(|| budget_overflow(self.offset))?,
                stack,
                15,
            ],
            self.offset,
        )?;
        if register_count > self.verify.max_registers as u128 || register_count > u16::MAX as u128 {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "必要轉譯暫存器超過 P05 限制",
            ));
        }
        add(&mut self.stats.register_slots, register_count, self.offset)?;
        let bindings = sum(&[2, stack, tbc], self.offset)?;
        add(
            &mut self.stats.binding_capacity,
            sum(&[2, stack, n], self.offset)?,
            self.offset,
        )?;
        add(
            &mut self.stats.binding_squares,
            bindings
                .checked_mul(bindings)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        add(
            &mut self.stats.plan_metered_work,
            expanded
                .checked_mul(register_count)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        add(
            &mut self.stats.source_metered_work,
            n.checked_mul(stack + 512)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        add(
            &mut self.stats.source_cfg_work,
            // close flow 每個 PC 入 worklist 至多一次，出邊至多兩條；
            // 每次狀態比較與關閉至多走訪 TBC 深度。
            n.checked_mul(tbc + 2)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        add(
            &mut self.stats.source_work_bytes,
            n.checked_mul(
                512_u128
                    .checked_add(
                        tbc.checked_mul(64)
                            .ok_or_else(|| budget_overflow(self.offset))?,
                    )
                    .ok_or_else(|| budget_overflow(self.offset))?,
            )
            .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        add(&mut self.stats.internal_calls, internal_calls, self.offset)?;
        add(
            &mut self.stats.call_inputs,
            sum(
                &[
                    fixed_list_values,
                    internal_calls
                        .checked_mul(3)
                        .ok_or_else(|| budget_overflow(self.offset))?,
                ],
                self.offset,
            )?,
            self.offset,
        )?;
        if numeric != 0 {
            add(
                &mut self.stats.numeric_dominator_work,
                expanded
                    .checked_mul(128)
                    .ok_or_else(|| budget_overflow(self.offset))?,
                self.offset,
            )?;
            add(
                &mut self.stats.numeric_cfg_bytes,
                expanded
                    .checked_mul(768)
                    .ok_or_else(|| budget_overflow(self.offset))?,
                self.offset,
            )?;
        }
        let tbc_plus_one = tbc
            .checked_add(1)
            .ok_or_else(|| budget_overflow(self.offset))?;
        let close_cells = close_exits
            .checked_mul(tbc_plus_one)
            .and_then(|count| count.checked_mul(tbc_plus_one))
            .and_then(|count| count.checked_add(tbc))
            .ok_or_else(|| budget_overflow(self.offset))?;
        add(&mut self.stats.close_cells, close_cells, self.offset)?;
        let close_lookups = close_exits
            .checked_mul(tbc_plus_one)
            .and_then(|count| count.checked_mul(bindings))
            .ok_or_else(|| budget_overflow(self.offset))?;
        add(
            &mut self.stats.close_binding_lookups,
            close_lookups,
            self.offset,
        )?;

        let constant_count = self.int()? as usize;
        self.count(
            |stats| &mut stats.constants,
            constant_count,
            self.limits.max_constants.min(self.verify.max_constants),
        )?;
        self.require_min(constant_count, 1)?;
        for _ in 0..constant_count {
            match self.byte()? {
                0 | 1 | 17 => {}
                3 if self.profile == LuaProfile::Lua55 => {
                    self.varint()?;
                }
                3 | 19 => {
                    self.read(8)?;
                }
                4 | 20 => {
                    if !self.string()? {
                        return Err(error(
                            OfficialChunkErrorKind::InvalidFormat,
                            self.offset,
                            "常數字串不可為 NULL",
                        ));
                    }
                }
                _ => {
                    return Err(error(
                        OfficialChunkErrorKind::InvalidFormat,
                        self.offset,
                        "常數 tag 不符",
                    ));
                }
            }
        }

        let upvalue_count = self.int()? as usize;
        if upvalue_count > u8::MAX as usize
            || upvalue_count > self.verify.max_upvalues_per_prototype
        {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "upvalue 數超限",
            ));
        }
        self.count(
            |stats| &mut stats.upvalues,
            upvalue_count,
            self.limits.max_upvalues,
        )?;
        let translated_upvalues = (upvalue_count as u128)
            .checked_add(4)
            .ok_or_else(|| budget_overflow(self.offset))?;
        add(
            &mut self.stats.upvalue_squares,
            translated_upvalues
                .checked_mul(translated_upvalues)
                .ok_or_else(|| budget_overflow(self.offset))?,
            self.offset,
        )?;
        self.require_min(upvalue_count, 3)?;
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
                (Some((stack, _)), 1) => index < stack,
                (Some((_, upvalues)), 0) => (index as usize) < upvalues,
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
        }

        let child_count = self.int()? as usize;
        if child_count as u128 > self.limits.max_prototypes as u128 - self.stats.prototypes {
            return Err(error(
                OfficialChunkErrorKind::LimitExceeded,
                self.offset,
                "子 prototype 數超限",
            ));
        }
        self.require_min(child_count, 1)?;
        for _ in 0..child_count {
            self.prototype(depth + 1, Some((max_stack, upvalue_count)))?;
        }
        if self.profile == LuaProfile::Lua55 {
            self.string()?;
        }
        self.debug(code_count, upvalue_count)?;
        Ok(upvalue_count)
    }

    fn debug(&mut self, code_count: usize, upvalue_count: usize) -> Result<(), OfficialChunkError> {
        let line_count = self.int()? as usize;
        if line_count != 0 && line_count != code_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "lineinfo 數與 code 不符",
            ));
        }
        self.count(
            |stats| &mut stats.debug_entries,
            line_count,
            self.limits.max_debug_entries,
        )?;
        self.require_min(line_count, 1)?;
        let lines = self.read(line_count)?;
        let marker_count = lines.iter().filter(|line| **line == 0x80).count();
        let abs_count = self.int()? as usize;
        self.count(
            |stats| &mut stats.debug_entries,
            abs_count,
            self.limits.max_debug_entries,
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
        let mut previous_pc = None;
        for _ in 0..abs_count {
            let (pc, line) = match self.profile {
                LuaProfile::Lua55 => (self.u32()? as i32, self.u32()? as i32),
                LuaProfile::Lua54 => (self.int()? as i32, self.int()? as i32),
            };
            if pc < 0
                || pc as usize >= code_count
                || line < 0
                || previous_pc.is_some_and(|previous| pc <= previous)
                || lines.get(pc as usize) != Some(&0x80)
            {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "絕對行號 PC 或 line 不符",
                ));
            }
            previous_pc = Some(pc);
        }
        if marker_count != abs_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "絕對行號與 marker 不符",
            ));
        }
        let local_count = self.int()? as usize;
        self.count(
            |stats| &mut stats.debug_entries,
            local_count,
            self.limits.max_debug_entries,
        )?;
        self.require_min(local_count, 3)?;
        for _ in 0..local_count {
            self.string()?;
            let start = self.int()?;
            let end = self.int()?;
            if start > end || end as usize > code_count {
                return Err(error(
                    OfficialChunkErrorKind::InvalidFormat,
                    self.offset,
                    "local PC 範圍不符",
                ));
            }
        }
        let name_count = self.int()? as usize;
        if name_count != 0 && name_count != upvalue_count {
            return Err(error(
                OfficialChunkErrorKind::InvalidFormat,
                self.offset,
                "upvalue debug name 數不符",
            ));
        }
        self.count(
            |stats| &mut stats.debug_entries,
            name_count,
            self.limits.max_debug_entries,
        )?;
        self.require_min(name_count, 1)?;
        for _ in 0..name_count {
            self.string()?;
        }
        Ok(())
    }
}

fn bounded(value: u128, offset: usize) -> Result<usize, OfficialChunkError> {
    usize::try_from(value).map_err(|_| budget_overflow(offset))
}

fn mul(value: u128, factor: u128, offset: usize) -> Result<u128, OfficialChunkError> {
    value
        .checked_mul(factor)
        .ok_or_else(|| budget_overflow(offset))
}

fn sum(parts: &[u128], offset: usize) -> Result<u128, OfficialChunkError> {
    parts.iter().try_fold(0_u128, |total, part| {
        total
            .checked_add(*part)
            .ok_or_else(|| budget_overflow(offset))
    })
}

fn sort_work(items: u128, offset: usize) -> Result<u128, OfficialChunkError> {
    let levels = if items == 0 {
        0
    } else {
        u128::BITS - items.leading_zeros()
    };
    mul(items, u128::from(levels + 1) * 2, offset)
}

/// 只讀取輸入 bytes，不配置 heap。呼叫者須先預扣至少 `2*input.len() + 1`
/// 個工作單位；第二次線性額度涵蓋 code opcode 與 line marker 走訪。
pub fn preflight_official_chunk(
    input: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
    verify: &VerifyLimits,
) -> Result<OfficialChunkPreflight, OfficialChunkError> {
    if input.len() > limits.max_bytes {
        return Err(error(
            OfficialChunkErrorKind::LimitExceeded,
            0,
            "chunk 長度超限",
        ));
    }
    let mut scan = Scan {
        input,
        offset: 0,
        profile,
        limits,
        verify,
        stats: Stats::default(),
    };
    scan.header()?;
    let root_upvalues = scan.byte()? as usize;
    let root_count = scan.prototype(1, None)?;
    if root_count != root_upvalues || scan.offset != input.len() {
        return Err(error(
            OfficialChunkErrorKind::InvalidFormat,
            scan.offset,
            "root upvalue 數或結尾不符",
        ));
    }
    let s = &scan.stats;
    let offset = scan.offset;
    let p = s.prototypes;
    let i = s.instructions;
    let c = s.constants;
    let u = s.upvalues;
    let d = s.debug_entries;
    let strings = s.string_bytes;
    let saved_index = (if profile == LuaProfile::Lua55 {
        limits.max_strings.min(input.len() / 2)
    } else {
        0
    } as u128)
        .checked_mul(size_of::<Vec<u8>>() as u128)
        .ok_or_else(|| budget_overflow(offset))?;
    // Reader 各 Vec、字串內容及 Lua 5.5 saved-string index/copy。
    // Vec 的請求容量及實際 capacity 由 codec 前/後核對；2 倍供
    // try_reserve_exact 的可能額外容量，超額仍由實際 capacity gate 拒絕。
    let decoded = sum(
        &[
            mul(
                p,
                size_of::<super::official::OfficialPrototype>() as u128,
                offset,
            )?,
            mul(i, 4, offset)?,
            mul(
                c,
                size_of::<super::official::OfficialConstant>() as u128,
                offset,
            )?,
            mul(
                u,
                size_of::<super::official::OfficialUpvalue>() as u128,
                offset,
            )?,
            mul(
                d,
                size_of::<super::official::OfficialLocal>() as u128,
                offset,
            )?,
            strings,
            s.saved_bytes,
            saved_index,
        ],
        offset,
    )?;
    let decoded = sum(&[mul(decoded, 2, offset)?, 512], offset)?;
    // E_p=參數 prologue+每 op 最多 7 條固定 lowering（TFORCALL）
    // +CONCAT 逐值合併+SETLIST 固定值複製+關閉時 captured≤stack
    // 與 active≤TBC+8 條 prologue。各項按 source prototype 分別計入。
    let expanded = s.expanded_instructions;
    let close_cells = s.close_cells;
    let constants_upper = sum(&[c, mul(i, 4, offset)?, mul(p, 16, offset)?], offset)?;
    let upvalues_upper = sum(&[u, mul(p, 4, offset)?], offset)?;
    let plan = sum(
        &[
            mul(
                upvalues_upper,
                size_of::<OfficialPlanRootBinding>() as u128,
                offset,
            )?,
            mul(p, 2 * size_of::<OfficialPlanUpvalueMap>() as u128, offset)?,
            mul(
                p,
                8 * size_of::<(super::OfficialPlanBuiltin, super::UpvalueId)>() as u128,
                offset,
            )?,
            mul(p, 6 * size_of::<OfficialPlanFrameInput>() as u128, offset)?,
            mul(
                s.internal_calls,
                2 * size_of::<OfficialPlanCall>() as u128,
                offset,
            )?,
            mul(s.call_inputs, 2 * size_of::<Register>() as u128, offset)?,
        ],
        offset,
    )?;
    // 各 grow Vec 以 2 倍容量計；binding_registers 依實際
    // try_reserve_exact(2+stack+sourceI) 而不是邏輯 binding 數。
    let rvlu = sum(
        &[
            mul(
                expanded,
                2 * size_of::<BytecodeInstruction>() as u128,
                offset,
            )?,
            mul(
                constants_upper,
                2 * size_of::<BytecodeConstant>() as u128,
                offset,
            )?,
            mul(
                upvalues_upper,
                2 * size_of::<BytecodeUpvalue>() as u128,
                offset,
            )?,
            mul(p, 2 * size_of::<BytecodePrototype>() as u128, offset)?,
            mul(p, 2 * size_of::<(u32, super::ProtoId)>() as u128, offset)?,
            mul(
                s.binding_capacity,
                2 * size_of::<(BytecodeBindingId, Register)>() as u128,
                offset,
            )?,
            mul(i, 2 * size_of::<BytecodeClosePath>() as u128, offset)?,
            mul(
                close_cells,
                2 * (size_of::<BytecodeBindingId>() + size_of::<Register>()) as u128,
                offset,
            )?,
            mul(strings, 2, offset)?,
            plan,
        ],
        offset,
    )?;
    // artifact 持有 source clone、I→E／E→I PC maps、每 source PC line。
    let artifact = sum(
        &[
            decoded,
            mul(
                i,
                2 * (size_of::<Option<InstructionOffset>>() + size_of::<Option<u32>>()) as u128,
                offset,
            )?,
            mul(expanded, 2 * size_of::<OfficialRvluPc>() as u128, offset)?,
            mul(p, 2 * size_of::<OfficialPcMap>() as u128, offset)?,
            512,
        ],
        offset,
    )?;
    let retained = sum(&[rvlu, artifact], offset)?;
    // decode、source clone、RVLU module、CFG/close/plan/verifier 暫存同時
    // 存在的保守峰值；輸入 LoadBuffer 由 P13 獨立持有及計帳。
    // NumericFor dominance 至多 N 個指令加 N 個 gate；保留舊、新 DFS
    // stack 並以 2 倍 grow capacity 逐容器計 byte/N：gates 16；edges
    // header/內層 48/64；predecessors 48/112；visited 2；postorder 16；
    // 舊 stack 64；order 16；idom 32；dominator_children 48/96；entry/exit
    // 各 16；新 stack 128，合計 722N。獨立預付 768E，兩階段核對實際
    // 容量；其餘 256E 不拿來抵扣 numeric helper。
    let access_entries = sum(
        &[expanded, s.call_inputs, mul(s.internal_calls, 4, offset)?],
        offset,
    )?;
    let temporary = sum(
        &[
            decoded,
            retained,
            // source_work_bytes=Σn(512+64t)：opcode/data/CFG 前後繼、
            // close flow 與 Rc node、numeric tuple、patch、side Call 暫存。
            s.source_work_bytes,
            // 256E：一般 module verifier 的 metadata、NumericFor pair map、
            // 非 numeric CFG states/worklist，以及 lowering 的短期索引。
            mul(expanded, 256, offset)?,
            s.numeric_cfg_bytes,
            // 32R：P05 sensitive register 與 register-key 暫存。
            mul(s.register_slots, 32, offset)?,
            // 32 inputs：side、candidate 與 final Call input Vec 的重疊峰值。
            mul(s.call_inputs, 32, offset)?,
            // 2A：P05 allowed_reads tuple 的實際 grow capacity 上界。
            mul(
                access_entries,
                2 * size_of::<(usize, usize, u16)>() as u128,
                offset,
            )?,
            // 64H：close active/path 建立與 clone 的暫存 binding/register。
            mul(close_cells, 64, offset)?,
        ],
        offset,
    )?;
    // 先前 prescan 工作由 caller 單獨預扣；下列是 Reader、P05 source
    // preflight/clone/CFG、module verifier、official plan 與 artifact copy。
    let plan_call_checks = s
        .internal_calls
        .checked_mul(sum(
            &[expanded, s.binding_capacity, mul(p, 24, offset)?],
            offset,
        )?)
        .ok_or_else(|| budget_overflow(offset))?;
    let work = sum(
        &[
            mul(input.len() as u128, 3, offset)?,
            mul(strings, 8, offset)?,
            mul(sum(&[i, c, u, d, p], offset)?, 16, offset)?,
            s.source_metered_work,
            mul(s.source_cfg_work, 8, offset)?,
            mul(s.plan_metered_work, 2, offset)?,
            mul(s.binding_squares, 4, offset)?,
            mul(s.upvalue_squares, 4, offset)?,
            mul(s.close_binding_lookups, 8, offset)?,
            mul(close_cells, 16, offset)?,
            s.numeric_dominator_work,
            mul(expanded, 32, offset)?,
            sort_work(access_entries, offset)?,
            sort_work(s.register_slots, offset)?,
            mul(constants_upper, 8, offset)?,
            mul(
                p.checked_mul(p).ok_or_else(|| budget_overflow(offset))?,
                32,
                offset,
            )?,
            mul(
                p.checked_mul(expanded)
                    .ok_or_else(|| budget_overflow(offset))?,
                8,
                offset,
            )?,
            plan_call_checks,
        ],
        offset,
    )?;
    let retained_bytes = bounded(retained, offset)?;
    let temporary_bytes = bounded(temporary, offset)?;
    let work = u64::try_from(work).map_err(|_| budget_overflow(offset))?;
    Ok(OfficialChunkPreflight {
        subsequent_work: work,
        temporary_bytes,
        retained_bytes,
        decoded_bytes: bounded(decoded, offset)?,
        prototypes: bounded(p, offset)?,
        instructions: bounded(i, offset)?,
        constants: bounded(c, offset)?,
        expanded_instructions: bounded(expanded, offset)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::official::{
        OfficialChunk, OfficialDebug, OfficialPrototype, decode_official_chunk,
        encode_official_chunk,
    };
    use crate::bytecode::official_translation::{
        OfficialWorkBudget, translate_official_chunk_with_work,
    };
    use crate::verified_module_allocation_bytes;

    #[test]
    fn official_preflight_bounds_small_decode_translation_and_rejects_hostile_counts() {
        for (profile, bytes) in [
            (
                LuaProfile::Lua54,
                include_bytes!("../../tests/official_chunk_fixtures/lua54-debug.luac").as_slice(),
            ),
            (
                LuaProfile::Lua55,
                include_bytes!("../../tests/official_chunk_fixtures/lua55-debug.luac").as_slice(),
            ),
        ] {
            let limits = OfficialChunkLimits::default();
            let verify = VerifyLimits::default();
            let stats = preflight_official_chunk(bytes, profile, &limits, &verify).unwrap();
            let mut decode_limits = limits;
            decode_limits.max_allocated_bytes = stats.decoded_bytes;
            let decoded = decode_official_chunk(bytes, profile, &decode_limits).unwrap();
            let mut work = OfficialWorkBudget::new(stats.subsequent_work);
            let translated =
                translate_official_chunk_with_work(&decoded, &verify, &mut work).unwrap();
            assert!(work.consumed() <= stats.subsequent_work);
            assert!(
                verified_module_allocation_bytes(translated.verified()).unwrap()
                    <= stats.retained_bytes
            );

            let mut count_limited = limits;
            count_limited.max_instructions = 1;
            assert_eq!(
                preflight_official_chunk(bytes, profile, &count_limited, &verify)
                    .unwrap_err()
                    .kind,
                OfficialChunkErrorKind::LimitExceeded
            );
            let mut string_limited = limits;
            string_limited.max_string_bytes = 0;
            assert_eq!(
                preflight_official_chunk(bytes, profile, &string_limited, &verify)
                    .unwrap_err()
                    .kind,
                OfficialChunkErrorKind::LimitExceeded
            );
            let mut scan = Scan {
                input: bytes,
                offset: 0,
                profile,
                limits: &limits,
                verify: &verify,
                stats: Stats::default(),
            };
            scan.header().unwrap();
            scan.byte().unwrap();
            if profile == LuaProfile::Lua54 {
                scan.string().unwrap();
            }
            scan.int().unwrap();
            scan.int().unwrap();
            scan.byte().unwrap();
            scan.byte().unwrap();
            scan.byte().unwrap();
            let mut overflowing = bytes[..scan.offset].to_vec();
            overflowing
                .extend_from_slice(&[if profile == LuaProfile::Lua54 { 0 } else { 128 }; 10]);
            assert_eq!(
                preflight_official_chunk(&overflowing, profile, &limits, &verify)
                    .unwrap_err()
                    .kind,
                OfficialChunkErrorKind::Overflow
            );
        }
    }

    #[test]
    fn official_preflight_counts_long_concat_expansion_in_both_profiles() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let source = OfficialChunk {
                profile,
                root_upvalues: 0,
                main: OfficialPrototype {
                    source: None,
                    line_defined: 0,
                    last_line_defined: 0,
                    num_params: 0,
                    flags: 0,
                    max_stack_size: 255,
                    code: vec![53 | (255 << 16), 71],
                    constants: vec![],
                    upvalues: vec![],
                    children: vec![],
                    debug: OfficialDebug::default(),
                },
            };
            let limits = OfficialChunkLimits::default();
            let verify = VerifyLimits::default();
            let bytes = encode_official_chunk(&source, false, &limits).unwrap();
            let stats = preflight_official_chunk(&bytes, profile, &limits, &verify).unwrap();
            let mut decode_limits = limits;
            decode_limits.max_allocated_bytes = stats.decoded_bytes;
            let decoded = decode_official_chunk(&bytes, profile, &decode_limits).unwrap();
            let mut work = OfficialWorkBudget::new(stats.subsequent_work);
            let translated =
                translate_official_chunk_with_work(&decoded, &verify, &mut work).unwrap();
            assert!(
                translated.verified().module().prototypes[0]
                    .instructions
                    .len()
                    >= 256
            );
            assert!(work.consumed() <= stats.subsequent_work);
            assert!(
                verified_module_allocation_bytes(translated.verified()).unwrap()
                    <= stats.retained_bytes
            );
        }
    }

    #[test]
    #[ignore = "需明示固定的 P15 db.lua 官方 chunk 路徑"]
    fn p15_db_preflight_formula_diagnostic() {
        let path = std::env::var_os("RIVETLUA_P15_DB_CHUNK").expect("官方 chunk 路徑");
        let bytes = std::fs::read(path).unwrap();
        let limits = OfficialChunkLimits::default();
        let verify = VerifyLimits::default();
        let mut scan = Scan {
            input: &bytes,
            offset: 0,
            profile: LuaProfile::Lua55,
            limits: &limits,
            verify: &verify,
            stats: Stats::default(),
        };
        scan.header().unwrap();
        let roots = scan.byte().unwrap();
        assert_eq!(scan.prototype(1, None).unwrap(), roots as usize);
        assert_eq!(scan.offset, bytes.len());
        let stats = &scan.stats;
        let result = preflight_official_chunk(&bytes, LuaProfile::Lua55, &limits, &verify).unwrap();
        eprintln!(
            "p15 db stats instruction_squares={} expanded={} stack_slots={} register_slots={} binding_capacity={} binding_squares={} close_cells={} source_metered_work={} source_cfg_work={} plan_metered_work={} source_work_bytes={} numeric_cfg_bytes={} numeric_dominator_work={} internal_calls={} call_inputs={} result={result:?}",
            stats.instruction_squares,
            stats.expanded_instructions,
            stats.stack_slots,
            stats.register_slots,
            stats.binding_capacity,
            stats.binding_squares,
            stats.close_cells,
            stats.source_metered_work,
            stats.source_cfg_work,
            stats.plan_metered_work,
            stats.source_work_bytes,
            stats.numeric_cfg_bytes,
            stats.numeric_dominator_work,
            stats.internal_calls,
            stats.call_inputs,
        );
        eprintln!(
            "p15 db sizes instruction={} constant={} upvalue={} prototype={} binding={} close={} plan_call={} pc_map={} rvlu_pc={} source_prototype={} source_constant={} source_upvalue={} source_local={}",
            size_of::<BytecodeInstruction>(),
            size_of::<BytecodeConstant>(),
            size_of::<BytecodeUpvalue>(),
            size_of::<BytecodePrototype>(),
            size_of::<(BytecodeBindingId, Register)>(),
            size_of::<BytecodeClosePath>(),
            size_of::<OfficialPlanCall>(),
            size_of::<OfficialPcMap>(),
            size_of::<OfficialRvluPc>(),
            size_of::<super::super::official::OfficialPrototype>(),
            size_of::<super::super::official::OfficialConstant>(),
            size_of::<super::super::official::OfficialUpvalue>(),
            size_of::<super::super::official::OfficialLocal>(),
        );
        let prescan = bytes.len() * 2 + 1;
        assert!(result.subsequent_work + prescan as u64 <= 2 * 1024 * 1024 * 1024);
        assert!(result.temporary_bytes <= 256 * 1024 * 1024);
        assert!(result.retained_bytes <= 64 * 1024 * 1024);
        let mut decode_limits = limits;
        decode_limits.max_allocated_bytes = result.decoded_bytes;
        let decoded = decode_official_chunk(&bytes, LuaProfile::Lua55, &decode_limits).unwrap();
        let mut work = OfficialWorkBudget::new(result.subsequent_work);
        let translated = translate_official_chunk_with_work(&decoded, &verify, &mut work).unwrap();
        assert!(work.consumed() <= result.subsequent_work);
        assert!(
            verified_module_allocation_bytes(translated.verified()).unwrap()
                <= result.retained_bytes
        );
    }
}
