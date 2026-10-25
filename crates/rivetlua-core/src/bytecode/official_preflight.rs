//! 官方 chunk 的受限結構預掃描，供 P13 在 decode 前預扣工作與配置。

use rivetlua_alloc::{AllocationRecovery, GlobalAllocation, ReserveError, StateAllocator};

use core::mem::size_of;

use super::official::{OfficialChunkError, OfficialChunkErrorKind, OfficialChunkLimits, OfficialChunkRecoveryError};
use super::codec::Scratch;
use super::official_translation::OfficialPcMap;
use super::{
    BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeInstruction, BytecodePrototype,
    BytecodeVec,
    BytecodeUpvalue, InstructionOffset, LuaProfile, OfficialPlanCall, OfficialPlanFrameInput,
    OfficialPlanRootBinding, OfficialPlanUpvalueMap, OfficialRvluPc, Register, VerifyLimits,
};

const SIGNATURE: &[u8] = b"\x1bLua";
const DATA: &[u8] = b"\x19\x93\r\n\x1a\n";
const LUA54_INT_MAX: u32 = i32::MAX as u32 - 128;

/// 官方 chunk 游標擴充 frame backing 前的暫存額度預付入口。
#[doc(hidden)]
pub trait OfficialChunkCursorBudget: AllocationRecovery {
    fn claim_cursor_temporary(&mut self, additional: usize) -> Result<(), Self::Error>;
}

struct UnmeteredCursor<'a, R>(&'a mut R);

impl<R: AllocationRecovery> AllocationRecovery for UnmeteredCursor<'_, R> {
    type Error = R::Error;

    fn allocator(&self) -> StateAllocator { self.0.allocator() }

    fn recover_after_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        self.0.recover_after_refusal(before)
    }
}

impl<R: AllocationRecovery> OfficialChunkCursorBudget for UnmeteredCursor<'_, R> {
    fn claim_cursor_temporary(&mut self, _: usize) -> Result<(), Self::Error> { Ok(()) }
}

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
    need_end: Option<usize>,
}

struct ScanFrame {
    depth: usize,
    max_stack: u8,
    upvalue_count: usize,
    code_count: usize,
    remaining_children: usize,
}

impl<'a> Scan<'a> {
    fn read(&mut self, len: usize) -> Result<&'a [u8], OfficialChunkError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| overflow(self.offset))?;
        if end > self.limits.max_bytes {
            return Err(error(OfficialChunkErrorKind::LimitExceeded, 0, "chunk 長度超限"));
        }
        let Some(result) = self.input.get(self.offset..end) else {
            self.need_end = Some(end);
            return Err(error(OfficialChunkErrorKind::Truncated, self.offset, "官方 chunk 截斷"));
        };
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
        match self.probe_varint(self.offset) {
            Ok((value, end)) => {
                self.offset = end;
                Ok(value)
            }
            Err(Pause::NeedMore { minimum_total, error }) => {
                self.need_end = Some(minimum_total);
                Err(error)
            }
            Err(Pause::Failed(error)) => Err(error),
        }
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

    fn require_at(&self, at: usize, len: usize, detail: &'static str) -> Result<(), Pause> {
        let end = at.checked_add(len).ok_or_else(|| overflow(at))?;
        if end > self.limits.max_bytes {
            return Err(error(OfficialChunkErrorKind::LimitExceeded, 0, "chunk 長度超限").into());
        }
        if self.input.len() < end {
            return Err(Pause::NeedMore {
                minimum_total: end,
                error: error(OfficialChunkErrorKind::Truncated, at, detail),
            });
        }
        Ok(())
    }

    fn require_minimum(&self, count: usize, unit: usize) -> Result<(), Pause> {
        let bytes = count.checked_mul(unit).ok_or_else(|| overflow(self.offset))?;
        self.require_at(self.offset, bytes, "資料不足以容納宣稱項數")
    }

    fn probe_varint(&self, at: usize) -> Result<(u64, usize), Pause> {
        let mut result = 0_u64;
        for i in 0..10 {
            let pos = at.checked_add(i).ok_or_else(|| overflow(at))?;
            self.require_at(pos, 1, "官方 chunk 截斷")?;
            let byte = self.input[pos];
            let end = pos + 1;
            if result > u64::MAX >> 7 {
                return Err(overflow(end).into());
            }
            result = (result << 7) | u64::from(byte & 0x7f);
            let done = match self.profile {
                LuaProfile::Lua55 => byte & 0x80 == 0,
                LuaProfile::Lua54 => byte & 0x80 != 0,
            };
            if done {
                return Ok((result, end));
            }
        }
        Err(overflow(at + 10).into())
    }

    fn probe_int(&self, at: usize) -> Result<usize, Pause> {
        let (value, end) = self.probe_varint(at)?;
        let limit = match self.profile {
            LuaProfile::Lua55 => i32::MAX as u32,
            LuaProfile::Lua54 => LUA54_INT_MAX,
        };
        if u32::try_from(value).ok().is_none_or(|value| value > limit) {
            return Err(overflow(end).into());
        }
        Ok(end)
    }

    fn probe_string(&self, at: usize) -> Result<usize, Pause> {
        let (raw_size, after_size) = self.probe_varint(at)?;
        let size = usize::try_from(raw_size).map_err(|_| overflow(after_size))?;
        if self.profile == LuaProfile::Lua55 && size == 0 {
            return Ok(self.probe_varint(after_size)?.1);
        }
        if size == 0 {
            return Ok(after_size);
        }
        let len = size - 1;
        if len > self.limits.max_string_bytes {
            return Err(error(OfficialChunkErrorKind::LimitExceeded, after_size, "單一字串超限").into());
        }
        let payload = if self.profile == LuaProfile::Lua55 { size } else { len };
        self.require_at(after_size, payload, "資料不足以容納宣稱項數")?;
        Ok(after_size + payload)
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

    fn code(
        &mut self,
        code_count: usize,
        num_params: u8,
        max_stack: u8,
    ) -> Result<(), OfficialChunkError> {
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

        Ok(())
    }

    fn push_frame<R: OfficialChunkCursorBudget>(
        &self,
        stack: &mut BytecodeVec<ScanFrame>,
        frame: ScanFrame,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<(), OfficialChunkError> {
        if stack.len() == stack.capacity() {
            let additional = stack.capacity().max(1);
            let old_bytes = stack.capacity().saturating_mul(size_of::<ScanFrame>());
            let Some(target_bytes) = stack.capacity().checked_add(additional)
                .and_then(|capacity| capacity.checked_mul(size_of::<ScanFrame>())) else {
                return Err(error(OfficialChunkErrorKind::LimitExceeded, self.offset, "預掃 cursor 配置超限"));
            };
            if target_bytes > self.limits.max_allocated_bytes {
                return Err(error(OfficialChunkErrorKind::LimitExceeded, self.offset, "預掃 cursor 配置超限"));
            }
            if let Err(failure) = scratch.recovery().claim_cursor_temporary(target_bytes - old_bytes) {
                scratch.record_refusal(ReserveError::Recovery(failure));
                return Err(error(OfficialChunkErrorKind::AllocationFailed, self.offset, "預掃 cursor 額度不足"));
            }
            scratch.reserve_exact(stack, additional).map_err(|_| {
                error(OfficialChunkErrorKind::AllocationFailed, self.offset, "預掃 cursor 配置失敗")
            })?;
            let Some(actual_bytes) = stack.capacity().checked_mul(size_of::<ScanFrame>()) else {
                return Err(error(OfficialChunkErrorKind::LimitExceeded, self.offset, "預掃 cursor 實際容量超限"));
            };
            if actual_bytes > self.limits.max_allocated_bytes {
                return Err(error(OfficialChunkErrorKind::LimitExceeded, self.offset, "預掃 cursor 實際容量超限"));
            }
            if actual_bytes > target_bytes {
                if let Err(failure) = scratch.recovery().claim_cursor_temporary(actual_bytes - target_bytes) {
                    scratch.record_refusal(ReserveError::Recovery(failure));
                    return Err(error(OfficialChunkErrorKind::AllocationFailed, self.offset, "預掃 cursor 額度不足"));
                }
            }
        }
        stack.push(frame);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[doc(hidden)]
pub enum OfficialChunkProgress {
    NeedMore { minimum_total: usize },
    Complete { consumed: usize },
}

#[derive(Clone, Copy)]
enum Stage {
    Header,
    RootUpvalues,
    PrototypeStart,
    PrototypeSource,
    PrototypeHeader,
    CodeCount,
    Code,
    ConstantCount,
    Constants,
    UpvalueCount,
    Upvalues,
    ChildCount,
    ChildMinimum,
    Children,
    TailSource,
    DebugLineCount,
    DebugLines,
    DebugAbsCount,
    DebugAbs,
    DebugLocalCount,
    DebugLocals,
    DebugLocalStart,
    DebugLocalEnd,
    DebugNameCount,
    DebugNames,
    Done,
}

enum Pause {
    NeedMore { minimum_total: usize, error: OfficialChunkError },
    Failed(OfficialChunkError),
}

impl From<OfficialChunkError> for Pause {
    fn from(error: OfficialChunkError) -> Self {
        Self::Failed(error)
    }
}

/// 只保存位移與解析狀態；輸入資料始終由呼叫者持有。
#[doc(hidden)]
pub struct OfficialChunkCursor {
    profile: LuaProfile,
    limits: OfficialChunkLimits,
    verify: VerifyLimits,
    allocator: StateAllocator,
    offset: usize,
    stats: Stats,
    frames: BytecodeVec<ScanFrame>,
    stage: Stage,
    depth: usize,
    parent: Option<(u8, usize)>,
    line_defined: u32,
    last_line_defined: u32,
    num_params: u8,
    flags: u8,
    max_stack: u8,
    code_count: usize,
    upvalue_count: usize,
    remaining: usize,
    lines_start: usize,
    line_count: usize,
    local_start: u32,
    marker_count: usize,
    abs_count: usize,
    previous_pc: Option<i32>,
    root_upvalues: usize,
    need: Option<(usize, OfficialChunkError)>,
    complete: Option<usize>,
}

impl OfficialChunkCursor {
    pub fn new(
        profile: LuaProfile,
        limits: OfficialChunkLimits,
        verify: VerifyLimits,
        allocator: StateAllocator,
    ) -> Self {
        Self {
            profile,
            limits,
            verify,
            frames: BytecodeVec::new_in(allocator.clone()),
            allocator,
            offset: 0,
            stats: Stats::default(),
            stage: Stage::Header,
            depth: 0,
            parent: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            flags: 0,
            max_stack: 0,
            code_count: 0,
            upvalue_count: 0,
            remaining: 0,
            lines_start: 0,
            line_count: 0,
            local_start: 0,
            marker_count: 0,
            abs_count: 0,
            previous_pc: None,
            root_upvalues: 0,
            need: None,
            complete: None,
        }
    }

    pub fn temporary_allocation_bytes(&self) -> usize {
        self.frames.capacity() * size_of::<ScanFrame>()
    }

    /// 在輸入結束時回傳與整塊預掃相同的截斷位置及原因。
    pub fn eof_error(&self) -> OfficialChunkError {
        self.need.as_ref().map(|(_, error)| error.clone()).unwrap_or_else(|| {
            error(OfficialChunkErrorKind::Truncated, self.offset, "官方 chunk 截斷")
        })
    }

    pub fn advance<R: AllocationRecovery>(
        &mut self,
        prefix: &[u8],
        recovery: &mut R,
    ) -> Result<OfficialChunkProgress, OfficialChunkRecoveryError<R::Error>> {
        self.advance_budgeted(prefix, &mut UnmeteredCursor(recovery))
    }

    pub fn advance_budgeted<R: OfficialChunkCursorBudget>(
        &mut self,
        prefix: &[u8],
        recovery: &mut R,
    ) -> Result<OfficialChunkProgress, OfficialChunkRecoveryError<R::Error>> {
        if !self.allocator.same_binding(&recovery.allocator()) {
            return Err(OfficialChunkRecoveryError::Chunk(error(
                OfficialChunkErrorKind::InvalidFormat, self.offset, "預掃 cursor 配置器不符",
            )));
        }
        if let Some(consumed) = self.complete {
            return Ok(OfficialChunkProgress::Complete { consumed });
        }
        if prefix.len() < self.offset {
            return Err(OfficialChunkRecoveryError::Chunk(error(
                OfficialChunkErrorKind::Truncated, prefix.len(), "累積輸入短於預掃位移",
            )));
        }
        if let Some((minimum_total, _)) = self.need.as_ref() {
            if prefix.len() < *minimum_total {
                return Ok(OfficialChunkProgress::NeedMore { minimum_total: *minimum_total });
            }
        }
        let mut scratch = Scratch::new(recovery);
        let limits = self.limits;
        let verify = self.verify;
        let mut scan = Scan {
            input: prefix,
            offset: self.offset,
            profile: self.profile,
            limits: &limits,
            verify: &verify,
            stats: core::mem::take(&mut self.stats),
            need_end: None,
        };
        let result = self.advance_inner(&mut scan, &mut scratch);
        self.offset = scan.offset;
        self.stats = scan.stats;
        match result {
            Ok(consumed) => {
                self.complete = Some(consumed);
                self.need = None;
                Ok(OfficialChunkProgress::Complete { consumed })
            }
            Err(Pause::NeedMore { minimum_total, error }) => {
                self.need = Some((minimum_total, error));
                Ok(OfficialChunkProgress::NeedMore { minimum_total })
            }
            Err(Pause::Failed(error)) => Err(match scratch.take_refusal() {
                Some(refusal) => OfficialChunkRecoveryError::Reserve(refusal),
                None => OfficialChunkRecoveryError::Chunk(error),
            }),
        }
    }

    fn begin_prototype(&mut self, depth: usize, parent: Option<(u8, usize)>) {
        self.depth = depth;
        self.parent = parent;
        self.stage = Stage::PrototypeStart;
    }

    fn advance_inner<R: OfficialChunkCursorBudget>(
        &mut self,
        scan: &mut Scan<'_>,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<usize, Pause> {
        loop {
            match self.stage {
                Stage::Header => {
                    let mut header = Scan {
                        input: scan.input,
                        offset: 0,
                        profile: scan.profile,
                        limits: scan.limits,
                        verify: scan.verify,
                        stats: Stats::default(),
                        need_end: None,
                    };
                    match header.header() {
                        Ok(()) => {
                            scan.offset = header.offset;
                            self.stage = Stage::RootUpvalues;
                        }
                        Err(error) if error.kind == OfficialChunkErrorKind::Truncated => {
                            return Err(Pause::NeedMore {
                                minimum_total: header.need_end.expect("truncated read records length"),
                                error,
                            });
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Stage::RootUpvalues => {
                    scan.require_at(scan.offset, 1, "官方 chunk 截斷")?;
                    self.root_upvalues = scan.byte()? as usize;
                    self.begin_prototype(1, None);
                }
                Stage::PrototypeStart => {
                    if self.depth > scan.limits.max_depth {
                        return Err(error(OfficialChunkErrorKind::LimitExceeded, scan.offset, "prototype 深度超限").into());
                    }
                    scan.count(
                        |stats| &mut stats.prototypes, 1,
                        scan.limits.max_prototypes.min(scan.verify.max_prototypes),
                    )?;
                    self.stage = if scan.profile == LuaProfile::Lua54 {
                        Stage::PrototypeSource
                    } else {
                        Stage::PrototypeHeader
                    };
                }
                Stage::PrototypeSource => {
                    scan.probe_string(scan.offset)?;
                    scan.string()?;
                    self.stage = Stage::PrototypeHeader;
                }
                Stage::PrototypeHeader => {
                    let end = scan.probe_int(scan.offset)?;
                    let end = scan.probe_int(end)?;
                    for index in 0..3 {
                        scan.require_at(end + index, 1, "官方 chunk 截斷")?;
                    }
                    self.line_defined = scan.int()?;
                    self.last_line_defined = scan.int()?;
                    self.num_params = scan.byte()?;
                    self.flags = scan.byte()?;
                    self.max_stack = scan.byte()?;
                    if self.max_stack == 0
                        || self.num_params > self.max_stack
                        || (self.last_line_defined != 0 && self.line_defined > self.last_line_defined)
                        || match scan.profile {
                            LuaProfile::Lua55 => self.flags & !3 != 0,
                            LuaProfile::Lua54 => self.flags > 1,
                        }
                    {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "prototype signature 不符").into());
                    }
                    self.stage = Stage::CodeCount;
                }
                Stage::CodeCount => {
                    scan.probe_varint(scan.offset)?;
                    self.code_count = scan.int()? as usize;
                    scan.count(
                        |stats| &mut stats.instructions, self.code_count,
                        scan.limits.max_instructions.min(scan.verify.max_instructions),
                    )?;
                    self.stage = Stage::Code;
                }
                Stage::Code => {
                    if scan.profile == LuaProfile::Lua55 {
                        let pad = (4 - scan.offset % 4) % 4;
                        scan.require_at(scan.offset, pad, "官方 chunk 截斷")?;
                        scan.align4()?;
                    }
                    let bytes = self.code_count.checked_mul(4).ok_or_else(|| budget_overflow(scan.offset))?;
                    scan.require_at(scan.offset, bytes, "資料不足以容納宣稱項數")?;
                    scan.code(self.code_count, self.num_params, self.max_stack)?;
                    self.stage = Stage::ConstantCount;
                }
                Stage::ConstantCount => {
                    scan.probe_varint(scan.offset)?;
                    self.remaining = scan.int()? as usize;
                    scan.count(
                        |stats| &mut stats.constants, self.remaining,
                        scan.limits.max_constants.min(scan.verify.max_constants),
                    )?;
                    self.stage = Stage::Constants;
                }
                Stage::Constants => {
                    if self.remaining == 0 {
                        self.stage = Stage::UpvalueCount;
                        continue;
                    }
                    scan.require_minimum(self.remaining, 1)?;
                    let tag = scan.input[scan.offset];
                    match tag {
                        0 | 1 | 17 => {}
                        3 if scan.profile == LuaProfile::Lua55 => {
                            scan.probe_varint(scan.offset + 1)?;
                        }
                        3 | 19 => {
                            scan.require_at(scan.offset + 1, 8, "官方 chunk 截斷")?;
                        }
                        4 | 20 => {
                            scan.probe_string(scan.offset + 1)?;
                        }
                        _ => {
                            return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset + 1, "常數 tag 不符").into());
                        }
                    }
                    scan.byte()?;
                    match tag {
                        3 if scan.profile == LuaProfile::Lua55 => { scan.varint()?; }
                        3 | 19 => { scan.read(8)?; }
                        4 | 20 => {
                            if !scan.string()? {
                                return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "常數字串不可為 NULL").into());
                            }
                        }
                        _ => {}
                    }
                    self.remaining -= 1;
                }
                Stage::UpvalueCount => {
                    scan.probe_varint(scan.offset)?;
                    self.upvalue_count = scan.int()? as usize;
                    if self.upvalue_count > u8::MAX as usize
                        || self.upvalue_count > scan.verify.max_upvalues_per_prototype
                    {
                        return Err(error(OfficialChunkErrorKind::LimitExceeded, scan.offset, "upvalue 數超限").into());
                    }
                    scan.count(|stats| &mut stats.upvalues, self.upvalue_count, scan.limits.max_upvalues)?;
                    let translated = (self.upvalue_count as u128).checked_add(4).ok_or_else(|| budget_overflow(scan.offset))?;
                    add(&mut scan.stats.upvalue_squares,
                        translated.checked_mul(translated).ok_or_else(|| budget_overflow(scan.offset))?,
                        scan.offset)?;
                    self.remaining = self.upvalue_count;
                    self.stage = Stage::Upvalues;
                }
                Stage::Upvalues => {
                    if self.remaining == 0 {
                        self.stage = Stage::ChildCount;
                        continue;
                    }
                    scan.require_minimum(self.remaining, 3)?;
                    let in_stack = scan.byte()?;
                    let index = scan.byte()?;
                    let kind = scan.byte()?;
                    let max_kind = if scan.profile == LuaProfile::Lua55 { 3 } else { 2 };
                    let valid_parent = match (self.parent, in_stack) {
                        (Some((stack, _)), 1) => index < stack,
                        (Some((_, upvalues)), 0) => (index as usize) < upvalues,
                        (None, 0 | 1) => true,
                        _ => false,
                    };
                    if in_stack > 1 || kind > max_kind || !valid_parent {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "upvalue parent index 或 kind 不符").into());
                    }
                    self.remaining -= 1;
                }
                Stage::ChildCount => {
                    scan.probe_varint(scan.offset)?;
                    self.remaining = scan.int()? as usize;
                    if self.remaining as u128 > scan.limits.max_prototypes as u128 - scan.stats.prototypes {
                        return Err(error(OfficialChunkErrorKind::LimitExceeded, scan.offset, "子 prototype 數超限").into());
                    }
                    self.stage = Stage::ChildMinimum;
                }
                Stage::ChildMinimum => {
                    scan.require_minimum(self.remaining, 1)?;
                    let frame = ScanFrame {
                        depth: self.depth,
                        max_stack: self.max_stack,
                        upvalue_count: self.upvalue_count,
                        code_count: self.code_count,
                        remaining_children: self.remaining,
                    };
                    scan.push_frame(&mut self.frames, frame, scratch)?;
                    self.stage = Stage::Children;
                }
                Stage::Children => {
                    let frame = self.frames.last_mut().expect("prototype frame 已配置");
                    if frame.remaining_children == 0 {
                        self.stage = Stage::TailSource;
                        continue;
                    }
                    frame.remaining_children -= 1;
                    let depth = frame.depth.checked_add(1).ok_or_else(|| overflow(scan.offset))?;
                    let parent = Some((frame.max_stack, frame.upvalue_count));
                    self.begin_prototype(depth, parent);
                }
                Stage::TailSource => {
                    if scan.profile == LuaProfile::Lua55 {
                        scan.probe_string(scan.offset)?;
                        scan.string()?;
                    }
                    self.stage = Stage::DebugLineCount;
                }
                Stage::DebugLineCount => {
                    scan.probe_varint(scan.offset)?;
                    self.line_count = scan.int()? as usize;
                    let code_count = self.frames.last().expect("prototype frame 已配置").code_count;
                    if self.line_count != 0 && self.line_count != code_count {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "lineinfo 數與 code 不符").into());
                    }
                    scan.count(|stats| &mut stats.debug_entries, self.line_count, scan.limits.max_debug_entries)?;
                    self.stage = Stage::DebugLines;
                }
                Stage::DebugLines => {
                    scan.require_at(scan.offset, self.line_count, "資料不足以容納宣稱項數")?;
                    self.lines_start = scan.offset;
                    let lines = scan.read(self.line_count)?;
                    self.marker_count = lines.iter().filter(|line| **line == 0x80).count();
                    self.stage = Stage::DebugAbsCount;
                }
                Stage::DebugAbsCount => {
                    scan.probe_varint(scan.offset)?;
                    self.abs_count = scan.int()? as usize;
                    scan.count(|stats| &mut stats.debug_entries, self.abs_count, scan.limits.max_debug_entries)?;
                    self.remaining = self.abs_count;
                    self.previous_pc = None;
                    self.stage = Stage::DebugAbs;
                }
                Stage::DebugAbs => {
                    if self.remaining == 0 {
                        if self.marker_count != self.abs_count {
                            return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "絕對行號與 marker 不符").into());
                        }
                        self.stage = Stage::DebugLocalCount;
                        continue;
                    }
                    if scan.profile == LuaProfile::Lua55 {
                        let pad = (4 - scan.offset % 4) % 4;
                        scan.require_at(scan.offset, pad, "官方 chunk 截斷")?;
                        scan.align4()?;
                    }
                    scan.require_minimum(self.remaining, if scan.profile == LuaProfile::Lua55 { 8 } else { 2 })?;
                    if scan.profile == LuaProfile::Lua54 {
                        let end = scan.probe_int(scan.offset)?;
                        scan.probe_int(end)?;
                    }
                    let (pc, line) = match scan.profile {
                        LuaProfile::Lua55 => (scan.u32()? as i32, scan.u32()? as i32),
                        LuaProfile::Lua54 => (scan.int()? as i32, scan.int()? as i32),
                    };
                    let code_count = self.frames.last().expect("prototype frame 已配置").code_count;
                    if pc < 0
                        || pc as usize >= code_count
                        || line < 0
                        || self.previous_pc.is_some_and(|previous| pc <= previous)
                        || self.lines_start.checked_add(pc as usize)
                            .and_then(|index| scan.input.get(index)) != Some(&0x80)
                    {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "絕對行號 PC 或 line 不符").into());
                    }
                    self.previous_pc = Some(pc);
                    self.remaining -= 1;
                }
                Stage::DebugLocalCount => {
                    scan.probe_varint(scan.offset)?;
                    self.remaining = scan.int()? as usize;
                    scan.count(|stats| &mut stats.debug_entries, self.remaining, scan.limits.max_debug_entries)?;
                    self.stage = Stage::DebugLocals;
                }
                Stage::DebugLocals => {
                    if self.remaining == 0 {
                        self.stage = Stage::DebugNameCount;
                        continue;
                    }
                    scan.require_minimum(self.remaining, 3)?;
                    scan.probe_string(scan.offset)?;
                    scan.string()?;
                    self.stage = Stage::DebugLocalStart;
                }
                Stage::DebugLocalStart => {
                    scan.probe_int(scan.offset)?;
                    self.local_start = scan.int()?;
                    self.stage = Stage::DebugLocalEnd;
                }
                Stage::DebugLocalEnd => {
                    scan.probe_int(scan.offset)?;
                    let end = scan.int()?;
                    let code_count = self.frames.last().expect("prototype frame 已配置").code_count;
                    if self.local_start > end || end as usize > code_count {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "local PC 範圍不符").into());
                    }
                    self.remaining -= 1;
                    self.stage = Stage::DebugLocals;
                }
                Stage::DebugNameCount => {
                    scan.probe_varint(scan.offset)?;
                    self.remaining = scan.int()? as usize;
                    let upvalue_count = self.frames.last().expect("prototype frame 已配置").upvalue_count;
                    if self.remaining != 0 && self.remaining != upvalue_count {
                        return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "upvalue debug name 數不符").into());
                    }
                    scan.count(|stats| &mut stats.debug_entries, self.remaining, scan.limits.max_debug_entries)?;
                    self.stage = Stage::DebugNames;
                }
                Stage::DebugNames => {
                    if self.remaining == 0 {
                        self.stage = Stage::Done;
                        continue;
                    }
                    scan.require_minimum(self.remaining, 1)?;
                    scan.probe_string(scan.offset)?;
                    scan.string()?;
                    self.remaining -= 1;
                }
                Stage::Done => {
                    let done = self.frames.pop().expect("prototype frame 已配置");
                    if self.frames.is_empty() {
                        if done.upvalue_count != self.root_upvalues {
                            return Err(error(OfficialChunkErrorKind::InvalidFormat, scan.offset, "root upvalue 數不符").into());
                        }
                        return Ok(scan.offset);
                    }
                    self.stage = Stage::Children;
                }
            }
        }
    }

    fn preflight_stats(&self, input_len: usize) -> Result<OfficialChunkPreflight, OfficialChunkError> {
        let s = &self.stats;
        let offset = self.offset;
        let profile = self.profile;
        let limits = &self.limits;
        let p = s.prototypes;
        let i = s.instructions;
        let c = s.constants;
        let u = s.upvalues;
        let d = s.debug_entries;
        let strings = s.string_bytes;
        let saved_index = (if profile == LuaProfile::Lua55 {
            limits.max_strings.min(input_len / 2)
        } else {
            0
        } as u128)
            .checked_mul(size_of::<BytecodeVec<u8>>() as u128)
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
                mul(p, 2 * size_of::<super::official::DecodeFrame>() as u128, offset)?,
                mul(p, 2 * size_of::<super::ProtoId>() as u128, offset)?,
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
        // Reader 每個 prototype 的八個 retained Vec 與每個非 NULL 字串
        // 都建立 SharedBlock owner；預扣與 Reader 的 state 配置額度一致。
        let owners = sum(&[mul(p, 8, offset)?, s.strings, 2], offset)?;
        let owner_bytes = mul(
            owners,
            StateAllocator::shared_block_size::<BytecodeVec<u8>>() as u128,
            offset,
        )?;
        let decoded = sum(&[mul(decoded, 2, offset)?, 512, owner_bytes], offset)?;
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
                // 翻譯後的字串常數各自可能擁有獨立 SharedBlock。
                mul(
                    constants_upper,
                    StateAllocator::shared_block_size::<BytecodeVec<u8>>() as u128,
                    offset,
                )?,
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
                mul(p, 2 * size_of::<Option<super::ProtoId>>() as u128, offset)?,
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
                mul(p, 2 * size_of::<ScanFrame>() as u128, offset)?,
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
                // 最終模組量測的 owner 排序暫存，按最大常數數量預留。
                mul(
                    constants_upper,
                    2 * size_of::<(usize, usize)>() as u128,
                    offset,
                )?,
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
                mul(input_len as u128, 3, offset)?,
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
                sort_work(constants_upper, offset)?,
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

/// 呼叫者須先預扣至少 `2*input.len() + 1` 個工作單位。
pub fn preflight_official_chunk(
    input: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
    verify: &VerifyLimits,
) -> Result<OfficialChunkPreflight, OfficialChunkError> {
    let mut recovery = GlobalAllocation;
    preflight_official_chunk_with_recovery(input, profile, limits, verify, &mut recovery)
        .map_err(|failure| match failure {
            OfficialChunkRecoveryError::Chunk(error) => error,
            OfficialChunkRecoveryError::Reserve(ReserveError::Recovery(never)) => match never {},
            OfficialChunkRecoveryError::Reserve(_) => error(OfficialChunkErrorKind::AllocationFailed, 0, "預掃 cursor 配置失敗"),
        })
}

pub fn preflight_official_chunk_with_recovery<R: AllocationRecovery>(
    input: &[u8],
    profile: LuaProfile,
    limits: &OfficialChunkLimits,
    verify: &VerifyLimits,
    recovery: &mut R,
) -> Result<OfficialChunkPreflight, OfficialChunkRecoveryError<R::Error>> {
    if input.len() > limits.max_bytes {
        return Err(OfficialChunkRecoveryError::Chunk(error(
            OfficialChunkErrorKind::LimitExceeded, 0, "chunk 長度超限",
        )));
    }
    // 整塊輸入已先檢查長度；宣稱長度不足仍依舊回報截斷。
    let mut scan_limits = *limits;
    scan_limits.max_bytes = usize::MAX;
    let mut cursor = OfficialChunkCursor::new(profile, scan_limits, *verify, recovery.allocator());
    match cursor.advance(input, recovery)? {
        OfficialChunkProgress::Complete { .. } => cursor.preflight_stats(input.len())
            .map_err(OfficialChunkRecoveryError::Chunk),
        OfficialChunkProgress::NeedMore { .. } => {
            Err(OfficialChunkRecoveryError::Chunk(cursor.eof_error()))
        }
    }
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
