//! 官方 Lua 指令的驗證與 RVLU_V2 轉譯。

use core::mem::size_of;
use std::rc::Rc;
use std::sync::Arc;

use super::official::{
    OfficialChunk, OfficialChunkError, OfficialChunkErrorKind, OfficialChunkLimits,
    OfficialConstant, OfficialPrototype, clone_official_chunk_checked,
};
use super::official_artifact::OfficialArtifact;
pub use super::official_artifact::OfficialRvluPc;
use super::{
    BinaryOperation, BytecodeBindingId, BytecodeClosePath, BytecodeConstant, BytecodeError,
    BytecodeErrorCode, BytecodeExitKind, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, BytecodeUpvalue, BytecodeUpvalueSource, ConstId, EnvironmentSource, FrameLayout,
    Instruction, InstructionOffset, LuaProfile, OfficialPlanBuiltin, OfficialPlanCall,
    OfficialPlanCandidate, OfficialPlanFrameInput, OfficialPlanFrameInputSource,
    OfficialPlanRootBinding, OfficialPlanRootSource, OfficialPlanUpvalueMap, ProtoId,
    RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, UnaryOperation, UpvalueId, VerifiedModule,
    VerifyLimits, verify_module, verify_official_execution_plan,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialTranslationErrorKind {
    InvalidChunk,
    LimitExceeded,
    AllocationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialTranslationError {
    pub kind: OfficialTranslationErrorKind,
    pub prototype: ProtoId,
    pub pc: usize,
    pub detail: String,
}

impl std::fmt::Display for OfficialTranslationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "官方 prototype {} PC {}：{}",
            self.prototype.0, self.pc, self.detail
        )
    }
}

impl std::error::Error for OfficialTranslationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReserveFailure {
    Allocation,
    ExcessCapacity,
}

// P13 預掃描按各 Vec 的至多 2 倍 grow capacity 計費；配置後核對實際
// capacity，避免 allocator 超出已預付的 temporary/retained 上界。
pub(super) trait BoundedVecReserve {
    fn try_reserve_bounded_exact(&mut self, additional: usize) -> Result<(), ReserveFailure>;
    fn try_reserve_bounded(&mut self, additional: usize) -> Result<(), ReserveFailure>;
}

impl<T> BoundedVecReserve for Vec<T> {
    fn try_reserve_bounded_exact(&mut self, additional: usize) -> Result<(), ReserveFailure> {
        let requested = self
            .len()
            .checked_add(additional)
            .ok_or(ReserveFailure::ExcessCapacity)?;
        let allowed = requested
            .max(4)
            .checked_mul(2)
            .ok_or(ReserveFailure::ExcessCapacity)?;
        if self.capacity() >= requested {
            return Ok(());
        }
        Vec::try_reserve_exact(self, additional).map_err(|_| ReserveFailure::Allocation)?;
        if self.capacity() > allowed {
            return Err(ReserveFailure::ExcessCapacity);
        }
        Ok(())
    }

    fn try_reserve_bounded(&mut self, additional: usize) -> Result<(), ReserveFailure> {
        let requested = self
            .len()
            .checked_add(additional)
            .ok_or(ReserveFailure::ExcessCapacity)?;
        let allowed = requested
            .max(4)
            .checked_mul(2)
            .ok_or(ReserveFailure::ExcessCapacity)?;
        if self.capacity() >= requested {
            return Ok(());
        }
        Vec::try_reserve(self, additional).map_err(|_| ReserveFailure::Allocation)?;
        if self.capacity() > allowed {
            return Err(ReserveFailure::ExcessCapacity);
        }
        Ok(())
    }
}

/// 離線 P05 轉譯工作額度。各階段在掃描或配置前扣除保守上界。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OfficialWorkBudget {
    remaining: u64,
    consumed: u64,
    exhausted: bool,
}

impl OfficialWorkBudget {
    pub fn new(units: u64) -> Self {
        Self {
            remaining: units,
            consumed: 0,
            exhausted: false,
        }
    }

    pub fn for_limits(limits: &VerifyLimits) -> Result<Self, OfficialTranslationError> {
        let instructions = limits.max_instructions as u128;
        let prototypes = limits.max_prototypes as u128;
        let units = (limits.max_module_bytes as u128)
            .checked_add(limits.max_artifact_bytes as u128)
            .and_then(|bytes| bytes.checked_mul(16))
            .and_then(|value| {
                prototypes
                    .checked_mul(25)
                    .and_then(|protos| protos.checked_add(u128::from(limits.max_registers)))
                    .and_then(|per_instruction| per_instruction.checked_add(2048))
                    .and_then(|per_instruction| instructions.checked_mul(per_instruction))
                    .and_then(|extra| value.checked_add(extra))
            })
            .and_then(|value| {
                prototypes
                    .checked_mul(prototypes)
                    .and_then(|extra| value.checked_add(extra))
            })
            .and_then(|value| {
                (limits.max_constants as u128)
                    .checked_mul(16)
                    .and_then(|extra| value.checked_add(extra))
            })
            .and_then(|value| u64::try_from(value).ok())
            .ok_or_else(|| limited(ProtoId(0), 0, "P05 預設 work 額度溢位"))?;
        Ok(Self::new(units))
    }

    pub fn remaining(&self) -> u64 {
        self.remaining
    }

    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    pub fn exhausted(&self) -> bool {
        self.exhausted
    }

    /// 扣除官方轉譯／native debug 共用的離線工作額度。
    pub fn charge(
        &mut self,
        units: usize,
        prototype: ProtoId,
        pc: usize,
    ) -> Result<(), OfficialTranslationError> {
        let units = match u64::try_from(units) {
            Ok(units) => units,
            Err(_) => {
                self.exhausted = true;
                return Err(limited(prototype, pc, "P05 work 額度換算溢位"));
            }
        };
        if units > self.remaining {
            self.exhausted = true;
            return Err(limited(prototype, pc, "P05 work 額度耗盡"));
        }
        self.remaining -= units;
        self.consumed = self
            .consumed
            .checked_add(units)
            .ok_or_else(|| invalid(prototype, pc, "P05 work 記帳溢位"))?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialPcMap {
    prototype: ProtoId,
    official_to_rvlu: Vec<Option<InstructionOffset>>,
    rvlu_to_official: Vec<OfficialRvluPc>,
    lines: Vec<Option<u32>>,
}

impl OfficialPcMap {
    pub fn prototype(&self) -> ProtoId {
        self.prototype
    }
    pub fn official_to_rvlu(&self) -> &[Option<InstructionOffset>] {
        &self.official_to_rvlu
    }
    pub fn rvlu_to_official(&self) -> &[OfficialRvluPc] {
        &self.rvlu_to_official
    }
    pub fn line_at_official(&self, pc: u32) -> Option<u32> {
        self.lines.get(pc as usize).copied().flatten()
    }
    pub fn line_at_rvlu(&self, pc: InstructionOffset) -> Option<u32> {
        self.rvlu_to_official
            .get(pc.0 as usize)
            .and_then(|origin| origin.source_pc())
            .and_then(|source| self.line_at_official(source))
    }
    pub(crate) fn allocated_bytes(&self) -> Option<usize> {
        self.official_to_rvlu
            .capacity()
            .checked_mul(size_of::<Option<InstructionOffset>>())?
            .checked_add(
                self.rvlu_to_official
                    .capacity()
                    .checked_mul(size_of::<OfficialRvluPc>())?,
            )?
            .checked_add(
                self.lines
                    .capacity()
                    .checked_mul(size_of::<Option<u32>>())?,
            )
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialTranslation {
    verified: VerifiedModule,
    artifact: Arc<OfficialArtifact>,
    internal_calls: Vec<OfficialInternalCall>,
    frame_inputs: Vec<OfficialFrameInput>,
    upvalue_maps: Vec<OfficialUpvalueMap>,
    root_bindings: Vec<OfficialRootBinding>,
}

impl OfficialTranslation {
    pub fn verified(&self) -> &VerifiedModule {
        &self.verified
    }
    pub fn into_verified(self) -> VerifiedModule {
        self.verified
    }
    pub fn pc_mappings(&self) -> &[OfficialPcMap] {
        self.artifact.pc_mappings()
    }
    pub fn internal_calls(&self) -> &[OfficialInternalCall] {
        &self.internal_calls
    }
    pub fn frame_inputs(&self) -> &[OfficialFrameInput] {
        &self.frame_inputs
    }
    pub fn upvalue_maps(&self) -> &[OfficialUpvalueMap] {
        &self.upvalue_maps
    }
    pub fn root_bindings(&self) -> &[OfficialRootBinding] {
        &self.root_bindings
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialFrameInputSource {
    OriginalVarargs,
    GuestNamedVarargTable,
    ActiveVarargs,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialFrameInput {
    prototype: ProtoId,
    register: Register,
    source: OfficialFrameInputSource,
}

impl OfficialFrameInput {
    pub fn prototype(&self) -> ProtoId {
        self.prototype
    }
    pub fn register(&self) -> Register {
        self.register
    }
    pub fn source(&self) -> OfficialFrameInputSource {
        self.source
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum OfficialFixedBuiltin {
    RawListWrite,
    RawVarargGet,
    PackUnpack,
    GlobalNilCheck,
}

const BUILTIN_ORDER: [OfficialFixedBuiltin; 4] = [
    OfficialFixedBuiltin::RawListWrite,
    OfficialFixedBuiltin::RawVarargGet,
    OfficialFixedBuiltin::PackUnpack,
    OfficialFixedBuiltin::GlobalNilCheck,
];

fn builtin_bit(kind: OfficialFixedBuiltin) -> u8 {
    match kind {
        OfficialFixedBuiltin::RawListWrite => 1,
        OfficialFixedBuiltin::RawVarargGet => 2,
        OfficialFixedBuiltin::PackUnpack => 4,
        OfficialFixedBuiltin::GlobalNilCheck => 8,
    }
}

fn plan_builtin(kind: OfficialFixedBuiltin) -> OfficialPlanBuiltin {
    match kind {
        OfficialFixedBuiltin::RawListWrite => OfficialPlanBuiltin::RawListWrite,
        OfficialFixedBuiltin::RawVarargGet => OfficialPlanBuiltin::RawVarargGet,
        OfficialFixedBuiltin::PackUnpack => OfficialPlanBuiltin::PackUnpack,
        OfficialFixedBuiltin::GlobalNilCheck => OfficialPlanBuiltin::GlobalNilCheck,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialInternalCall {
    prototype: ProtoId,
    source_pc: usize,
    call_pc: InstructionOffset,
    function_register: Register,
    source_upvalue: UpvalueId,
    inputs: Vec<Register>,
    open_tail: Option<Register>,
    builtin: OfficialFixedBuiltin,
}

impl OfficialInternalCall {
    pub fn prototype(&self) -> ProtoId {
        self.prototype
    }
    pub fn source_pc(&self) -> usize {
        self.source_pc
    }
    pub fn call_pc(&self) -> InstructionOffset {
        self.call_pc
    }
    pub fn function_register(&self) -> Register {
        self.function_register
    }
    pub fn source_upvalue(&self) -> UpvalueId {
        self.source_upvalue
    }
    pub fn inputs(&self) -> &[Register] {
        &self.inputs
    }
    pub fn open_tail(&self) -> Option<Register> {
        self.open_tail
    }
    pub fn builtin(&self) -> OfficialFixedBuiltin {
        self.builtin
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialRootBindingSource {
    ExternalEnvironment,
    InitialNil,
    FixedBuiltin(OfficialFixedBuiltin),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialRootBinding {
    upvalue: UpvalueId,
    source: OfficialRootBindingSource,
}

impl OfficialRootBinding {
    pub fn upvalue(&self) -> UpvalueId {
        self.upvalue
    }
    pub fn source(&self) -> OfficialRootBindingSource {
        self.source
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OfficialUpvalueMap {
    prototype: ProtoId,
    guest_count: u16,
    hidden: Vec<(OfficialFixedBuiltin, UpvalueId)>,
}

impl OfficialUpvalueMap {
    pub fn prototype(&self) -> ProtoId {
        self.prototype
    }
    pub fn guest_count(&self) -> u16 {
        self.guest_count
    }
    pub fn hidden(&self) -> &[(OfficialFixedBuiltin, UpvalueId)] {
        &self.hidden
    }
}

fn invalid(id: ProtoId, pc: usize, detail: impl Into<String>) -> OfficialTranslationError {
    OfficialTranslationError {
        kind: OfficialTranslationErrorKind::InvalidChunk,
        prototype: id,
        pc,
        detail: detail.into(),
    }
}

fn limited(id: ProtoId, pc: usize, detail: impl Into<String>) -> OfficialTranslationError {
    OfficialTranslationError {
        kind: OfficialTranslationErrorKind::LimitExceeded,
        prototype: id,
        pc,
        detail: detail.into(),
    }
}

fn allocation_failed(
    id: ProtoId,
    pc: usize,
    detail: impl Into<String>,
) -> OfficialTranslationError {
    OfficialTranslationError {
        kind: OfficialTranslationErrorKind::AllocationFailed,
        prototype: id,
        pc,
        detail: detail.into(),
    }
}

fn reserve_failure(
    error: ReserveFailure,
    id: ProtoId,
    pc: usize,
    detail: &'static str,
) -> OfficialTranslationError {
    match error {
        ReserveFailure::Allocation => allocation_failed(id, pc, detail),
        ReserveFailure::ExcessCapacity => limited(id, pc, detail),
    }
}

fn from_bytecode_error(error: BytecodeError) -> OfficialTranslationError {
    match error.code {
        BytecodeErrorCode::Verify => invalid(ProtoId(0), 0, error.to_string()),
        BytecodeErrorCode::CompileLimit => limited(ProtoId(0), 0, error.to_string()),
        BytecodeErrorCode::AllocationFailed => allocation_failed(ProtoId(0), 0, error.to_string()),
    }
}

fn from_official_chunk_error(error: OfficialChunkError) -> OfficialTranslationError {
    match error.kind {
        OfficialChunkErrorKind::LimitExceeded | OfficialChunkErrorKind::WorkExhausted => {
            limited(ProtoId(0), 0, error.to_string())
        }
        OfficialChunkErrorKind::AllocationFailed => {
            allocation_failed(ProtoId(0), 0, error.to_string())
        }
        OfficialChunkErrorKind::InvalidFormat
        | OfficialChunkErrorKind::Truncated
        | OfficialChunkErrorKind::Overflow => invalid(ProtoId(0), 0, error.to_string()),
    }
}

fn charge_artifact_bytes(
    used: &mut usize,
    amount: usize,
    max: usize,
    id: ProtoId,
    pc: usize,
) -> Result<(), OfficialTranslationError> {
    *used = used
        .checked_add(amount)
        .ok_or_else(|| limited(id, pc, "官方 artifact 配置大小溢位"))?;
    if *used > max {
        return Err(limited(id, pc, "官方 artifact 超過 P05 bytes 限制"));
    }
    Ok(())
}

fn make_pc_map(
    entry: &PrototypeRef<'_>,
    validated: &ValidatedCode,
    mapping: Vec<Option<InstructionOffset>>,
    instructions: &[BytecodeInstruction],
    artifact_bytes: &mut usize,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<OfficialPcMap, OfficialTranslationError> {
    let id = entry.id;
    let source = entry.source;
    if mapping.len() != source.code.len() || validated.data.len() != source.code.len() {
        return Err(invalid(id, 0, "官方 PC map 長度不符"));
    }
    work.charge(
        mapping
            .len()
            .checked_mul(4)
            .and_then(|units| {
                instructions
                    .len()
                    .checked_mul(2)
                    .and_then(|extra| units.checked_add(extra))
            })
            .and_then(|units| units.checked_add(source.debug.line_info.len()))
            .ok_or_else(|| limited(id, 0, "PC/line map work 溢位"))?,
        id,
        0,
    )?;
    let mut previous = None;
    for (pc, target) in mapping.iter().enumerate() {
        let Some(target) = target else { continue };
        let target = target.0 as usize;
        if validated.data[pc]
            || target >= instructions.len()
            || previous.is_some_and(|old| target <= old)
        {
            return Err(invalid(id, pc, "官方 PC map 範圍或順序無效"));
        }
        previous = Some(target);
    }
    if previous.is_none() {
        return Err(invalid(id, 0, "官方 PC map 無執行入口"));
    }
    if mapping
        .iter()
        .enumerate()
        .any(|(pc, target)| target.is_none() != validated.data[pc])
    {
        return Err(invalid(id, 0, "官方資料 PC 映射無效"));
    }
    let reverse_bytes = instructions
        .len()
        .checked_mul(size_of::<OfficialRvluPc>())
        .ok_or_else(|| limited(id, 0, "反向 PC map bytes 溢位"))?;
    charge_artifact_bytes(
        artifact_bytes,
        reverse_bytes,
        limits.max_artifact_bytes,
        id,
        0,
    )?;
    let mut reverse = Vec::new();
    reverse
        .try_reserve_bounded_exact(instructions.len())
        .map_err(|error| reserve_failure(error, id, 0, "反向 PC map 配置失敗"))?;
    charge_artifact_bytes(
        artifact_bytes,
        (reverse.capacity() - instructions.len()) * size_of::<OfficialRvluPc>(),
        limits.max_artifact_bytes,
        id,
        0,
    )?;
    reverse.resize(instructions.len(), OfficialRvluPc::Prologue);
    let mut preceding = None;
    for (source_pc, target) in mapping.iter().enumerate() {
        let Some(target) = target else { continue };
        let start = target.0 as usize;
        if let Some((previous_pc, previous_start)) = preceding {
            fill_reverse_range(
                &mut reverse,
                instructions,
                previous_pc,
                previous_start,
                start,
                id,
            )?;
        }
        preceding = Some((source_pc, start));
    }
    if let Some((source_pc, start)) = preceding {
        fill_reverse_range(
            &mut reverse,
            instructions,
            source_pc,
            start,
            instructions.len(),
            id,
        )?;
    }
    let mut lines = Vec::new();
    if !source.debug.line_info.is_empty() {
        let line_bytes = source
            .code
            .len()
            .checked_mul(size_of::<Option<u32>>())
            .ok_or_else(|| limited(id, 0, "行號 map bytes 溢位"))?;
        charge_artifact_bytes(artifact_bytes, line_bytes, limits.max_artifact_bytes, id, 0)?;
        lines
            .try_reserve_bounded_exact(source.code.len())
            .map_err(|error| reserve_failure(error, id, 0, "行號 map 配置失敗"))?;
        charge_artifact_bytes(
            artifact_bytes,
            (lines.capacity() - source.code.len()) * size_of::<Option<u32>>(),
            limits.max_artifact_bytes,
            id,
            0,
        )?;
        let mut current = i64::from(source.line_defined);
        let mut abs_cursor = 0usize;
        for (pc, delta) in source.debug.line_info.iter().copied().enumerate() {
            current = if delta == -128 {
                let absolute = source
                    .debug
                    .abs_line_info
                    .get(abs_cursor)
                    .ok_or_else(|| invalid(id, pc, "行號 absolute marker 缺失"))?;
                if absolute.pc as usize != pc {
                    return Err(invalid(id, pc, "行號 absolute PC 不符"));
                }
                abs_cursor += 1;
                i64::from(absolute.line)
            } else {
                current
                    .checked_add(i64::from(delta))
                    .ok_or_else(|| invalid(id, pc, "行號溢位"))?
            };
            let line = u32::try_from(current).map_err(|_| invalid(id, pc, "行號為負或超過 u32"))?;
            lines.push(Some(line));
        }
        if abs_cursor != source.debug.abs_line_info.len() {
            return Err(invalid(id, 0, "行號 absolute 項未完全使用"));
        }
    }
    Ok(OfficialPcMap {
        prototype: id,
        official_to_rvlu: mapping,
        rvlu_to_official: reverse,
        lines,
    })
}

fn fill_reverse_range(
    reverse: &mut [OfficialRvluPc],
    instructions: &[BytecodeInstruction],
    source_pc: usize,
    start: usize,
    end: usize,
    id: ProtoId,
) -> Result<(), OfficialTranslationError> {
    let source_pc_u32 =
        u32::try_from(source_pc).map_err(|_| invalid(id, source_pc, "官方 PC 超過 u32"))?;
    for (offset, instruction) in instructions[start..end].iter().enumerate() {
        if instruction.span.start_byte != source_pc as u64 * 4
            || instruction.span.end_byte != (source_pc as u64 + 1) * 4
        {
            return Err(invalid(
                id,
                source_pc,
                "RVLU instruction 與來源 PC span 不符",
            ));
        }
        reverse[start + offset] = if offset == 0 {
            OfficialRvluPc::Anchor(source_pc_u32)
        } else {
            OfficialRvluPc::Expanded(source_pc_u32)
        };
    }
    Ok(())
}

fn hidden_upvalue(
    maps: &[OfficialUpvalueMap],
    id: ProtoId,
    pc: usize,
    builtin: OfficialFixedBuiltin,
) -> Result<UpvalueId, OfficialTranslationError> {
    maps[id.0 as usize]
        .hidden
        .iter()
        .find_map(|(kind, upvalue)| (*kind == builtin).then_some(*upvalue))
        .ok_or_else(|| invalid(id, pc, "固定內部 binding 缺失"))
}

#[derive(Clone, Copy)]
struct Decoded {
    opcode: u8,
    a: u16,
    b: u16,
    c: u16,
    k: bool,
    bx: u32,
    ax: u32,
    sbx: i32,
    sj: i32,
    sb: i16,
    sc: i16,
    vb: u16,
    vc: u16,
}

impl Decoded {
    fn new(word: u32) -> Self {
        Self {
            opcode: (word & 0x7f) as u8,
            a: ((word >> 7) & 0xff) as u16,
            b: ((word >> 16) & 0xff) as u16,
            c: ((word >> 24) & 0xff) as u16,
            k: ((word >> 15) & 1) != 0,
            bx: word >> 15,
            ax: word >> 7,
            sbx: (word >> 15) as i32 - 65_535,
            sj: (word >> 7) as i32 - 16_777_215,
            sb: ((word >> 16) & 0xff) as i16 - 127,
            sc: ((word >> 24) & 0xff) as i16 - 127,
            vb: ((word >> 16) & 0x3f) as u16,
            vc: ((word >> 22) & 0x3ff) as u16,
        }
    }
}

struct ValidatedCode {
    ops: Vec<Decoded>,
    data: Vec<bool>,
    edges: Vec<Vec<usize>>,
}

struct OpenListPlans {
    preparation_at: Vec<Option<usize>>,
    producer_at: Vec<Option<usize>>,
}

fn plan_open_lists(
    entry: &PrototypeRef<'_>,
    code: &ValidatedCode,
    profile: LuaProfile,
) -> Result<OpenListPlans, OfficialTranslationError> {
    let mut preparation_at = Vec::new();
    preparation_at
        .try_reserve_bounded_exact(code.ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "open list 索引配置失敗"))?;
    preparation_at.resize(code.ops.len(), None);
    let mut producer_at = Vec::new();
    producer_at
        .try_reserve_bounded_exact(code.ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "open producer 索引配置失敗"))?;
    producer_at.resize(code.ops.len(), None);
    let mut predecessors = Vec::new();
    predecessors
        .try_reserve_bounded_exact(code.ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "CFG predecessor 配置失敗"))?;
    predecessors.resize_with(code.ops.len(), Vec::new);
    for (pc, edges) in code.edges.iter().enumerate() {
        for &next in edges {
            predecessors[next].try_reserve_bounded(1).map_err(|error| {
                reserve_failure(error, entry.id, pc, "CFG predecessor 配置失敗")
            })?;
            predecessors[next].push(pc);
        }
    }
    for (sink, op) in code.ops.iter().enumerate() {
        if op.opcode != 78
            || (if profile == LuaProfile::Lua55 {
                op.vb
            } else {
                op.b
            }) != 0
        {
            continue;
        }
        let producer = sink
            .checked_sub(1)
            .ok_or_else(|| invalid(entry.id, sink, "開放 SETLIST 無 producer"))?;
        let mut first = producer;
        loop {
            let current = code.ops[first];
            if current.opcode == 80 && current.c == 0 {
                break;
            }
            if current.opcode != 68 || current.c != 0 {
                return Err(invalid(
                    entry.id,
                    first,
                    "開放 SETLIST producer 必須為 CALL/VARARG All",
                ));
            }
            if current.b != 0 {
                break;
            }
            first = first
                .checked_sub(1)
                .ok_or_else(|| invalid(entry.id, first, "動態 CALL 缺少 open producer"))?;
        }
        if code.ops[producer].a <= op.a {
            return Err(invalid(
                entry.id,
                sink,
                "開放 SETLIST producer base 不在 table 之後",
            ));
        }
        for middle in first + 1..=sink {
            if predecessors[middle].as_slice() != [middle - 1] {
                return Err(invalid(entry.id, middle, "開放列表中途有非線性 CFG 入口"));
            }
        }
        if preparation_at[first].replace(sink).is_some()
            || producer_at[sink].replace(producer).is_some()
        {
            return Err(invalid(entry.id, sink, "開放列表區段重疊"));
        }
    }
    Ok(OpenListPlans {
        preparation_at,
        producer_at,
    })
}

fn list_first_index(
    entry: &PrototypeRef<'_>,
    code: &ValidatedCode,
    pc: usize,
    profile: LuaProfile,
) -> Result<i64, OfficialTranslationError> {
    let op = code.ops[pc];
    let width = if profile == LuaProfile::Lua55 {
        1024_u64
    } else {
        256_u64
    };
    let lower = u64::from(if profile == LuaProfile::Lua55 {
        op.vc
    } else {
        op.c
    });
    let higher = if op.k {
        u64::from(code.ops[pc + 1].ax)
    } else {
        0
    };
    let first = higher
        .checked_mul(width)
        .and_then(|value| value.checked_add(lower))
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid(entry.id, pc, "SETLIST index 溢位"))?;
    i64::try_from(first).map_err(|_| invalid(entry.id, pc, "SETLIST index 超出 i64"))
}

fn check_reg(
    entry: &PrototypeRef<'_>,
    pc: usize,
    index: u16,
) -> Result<(), OfficialTranslationError> {
    if index >= u16::from(entry.source.max_stack_size) {
        return Err(invalid(entry.id, pc, "register index 超出官方 frame"));
    }
    Ok(())
}

fn check_range(
    entry: &PrototypeRef<'_>,
    pc: usize,
    start: u16,
    count: u16,
) -> Result<(), OfficialTranslationError> {
    if count == 0 {
        return Ok(());
    }
    let end = start
        .checked_add(count - 1)
        .ok_or_else(|| invalid(entry.id, pc, "register range 溢位"))?;
    check_reg(entry, pc, end)
}

fn check_const(
    entry: &PrototypeRef<'_>,
    pc: usize,
    index: u32,
) -> Result<(), OfficialTranslationError> {
    if index as usize >= entry.source.constants.len() {
        return Err(invalid(entry.id, pc, "constant index 無效"));
    }
    Ok(())
}

fn check_short_string(
    entry: &PrototypeRef<'_>,
    pc: usize,
    index: u32,
) -> Result<(), OfficialTranslationError> {
    check_const(entry, pc, index)?;
    if !matches!(
        entry.source.constants[index as usize],
        OfficialConstant::String { long: false, .. }
    ) {
        return Err(invalid(entry.id, pc, "field key 必須為短字串常數"));
    }
    Ok(())
}

fn check_number(
    entry: &PrototypeRef<'_>,
    pc: usize,
    index: u32,
    integer: bool,
) -> Result<(), OfficialTranslationError> {
    check_const(entry, pc, index)?;
    let valid = matches!(
        entry.source.constants[index as usize],
        OfficialConstant::Integer(_)
    ) || !integer
        && matches!(
            entry.source.constants[index as usize],
            OfficialConstant::Number(_)
        );
    if !valid {
        return Err(invalid(entry.id, pc, "算術常數型別無效"));
    }
    Ok(())
}

fn extra_opcode(profile: LuaProfile) -> u8 {
    match profile {
        LuaProfile::Lua54 => 82,
        LuaProfile::Lua55 => 84,
    }
}
fn varargprep_opcode(profile: LuaProfile) -> u8 {
    match profile {
        LuaProfile::Lua54 => 81,
        LuaProfile::Lua55 => 83,
    }
}
fn max_opcode(profile: LuaProfile) -> u8 {
    extra_opcode(profile) + 1
}

fn validate_arithmetic_pair(
    entry: &PrototypeRef<'_>,
    profile: LuaProfile,
    pc: usize,
    primary: Decoded,
    adjunct: Decoded,
) -> Result<(), OfficialTranslationError> {
    let shift_left_immediate = if profile == LuaProfile::Lua55 { 32 } else { 33 };
    let shift_right_immediate = if profile == LuaProfile::Lua55 { 33 } else { 32 };
    let event = match primary.opcode {
        21 if primary.sc < 0 && adjunct.c == 7 => 7,
        21 | 22 | 34 => 6,
        23 | 35 => 7,
        24 | 36 => 8,
        25 | 37 => 9,
        26 | 38 => 10,
        27 | 39 => 11,
        28 | 40 => 12,
        29 | 41 => 13,
        30 | 42 => 14,
        31 | 43 => 15,
        44 => 16,
        45 => 17,
        value if value == shift_left_immediate => 16,
        value if value == shift_right_immediate && primary.sc < 0 => 16,
        value if value == shift_right_immediate => 17,
        _ => return Err(invalid(entry.id, pc, "算術 opcode 無 adjunct 契約")),
    };
    let right_matches = if primary.opcode == 21 && adjunct.c == 7
        || primary.opcode == shift_right_immediate && primary.sc < 0
    {
        adjunct.sb == -primary.sc
    } else if matches!(primary.opcode, 21 | 32 | 33) {
        adjunct.sb == primary.sc
    } else {
        adjunct.b == primary.c
    };
    let flip_allowed = matches!(primary.opcode, 21 | 22 | 24 | 29..=31 | 34 | 36 | 41..=43)
        || primary.opcode == shift_left_immediate;
    let flip_required = primary.opcode == shift_left_immediate;
    if adjunct.a != primary.b
        || !right_matches
        || adjunct.c != event
        || adjunct.k && !flip_allowed
        || flip_required && !adjunct.k
        || primary.opcode == shift_right_immediate && adjunct.k
        || primary.opcode >= 34 && adjunct.k
    {
        return Err(invalid(
            entry.id,
            pc,
            "MMBIN operand/metamethod/flip 配對無效",
        ));
    }
    Ok(())
}

fn checked_target(
    entry: &PrototypeRef<'_>,
    pc: usize,
    target: i64,
    data: &[bool],
) -> Result<usize, OfficialTranslationError> {
    let target = usize::try_from(target).map_err(|_| invalid(entry.id, pc, "CFG target 為負"))?;
    if target >= data.len() || data[target] {
        return Err(invalid(entry.id, pc, "CFG target 超界或指向資料字"));
    }
    Ok(target)
}

fn validate_code(
    entry: &PrototypeRef<'_>,
    profile: LuaProfile,
    limits: &VerifyLimits,
) -> Result<ValidatedCode, OfficialTranslationError> {
    let source = entry.source;
    match profile {
        LuaProfile::Lua54 if source.flags & !1 != 0 => {
            return Err(invalid(entry.id, 0, "lua54 prototype flags 無效"));
        }
        LuaProfile::Lua55 if source.flags & !7 != 0 || source.flags & 3 == 3 => {
            return Err(invalid(entry.id, 0, "lua55 prototype flags 無效"));
        }
        LuaProfile::Lua55
            if source.flags & 2 != 0 && source.num_params >= source.max_stack_size =>
        {
            return Err(invalid(entry.id, 0, "named vararg table 無 register"));
        }
        _ => {}
    }
    if source.code.is_empty() {
        return Err(invalid(entry.id, 0, "官方 prototype 不可無指令"));
    }
    if source.code.len() > limits.max_instructions {
        return Err(limited(entry.id, 0, "官方指令數超過 P05 限制"));
    }
    let mut ops = Vec::new();
    ops.try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "opcode 配置失敗"))?;
    for &word in &source.code {
        ops.push(Decoded::new(word));
    }
    let mut data = Vec::new();
    data.try_reserve_bounded_exact(ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "opcode data mask 配置失敗"))?;
    data.resize(ops.len(), false);
    let mut edges = Vec::new();
    edges
        .try_reserve_bounded_exact(ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "CFG edge 索引配置失敗"))?;
    edges.resize_with(ops.len(), Vec::new);
    for (pc, op) in ops.iter().enumerate() {
        if data[pc] {
            continue;
        }
        if op.opcode >= max_opcode(profile) {
            return Err(invalid(entry.id, pc, "未知官方 opcode"));
        }
        let next = pc + 1;
        let expected_data = match op.opcode {
            4 => Some(extra_opcode(profile)),
            19 => Some(extra_opcode(profile)),
            78 if op.k => Some(extra_opcode(profile)),
            21 | 32 | 33 => Some(47),
            22..=31 => Some(48),
            34..=45 => Some(46),
            _ => None,
        };
        if let Some(expected) = expected_data {
            if next >= ops.len() || ops[next].opcode != expected || data[next] {
                return Err(invalid(entry.id, pc, "附加 opcode 或 EXTRAARG 配對無效"));
            }
            if (21..=45).contains(&op.opcode) {
                validate_arithmetic_pair(entry, profile, pc, *op, ops[next])?;
            }
            data[next] = true;
        }
        if (57..=67).contains(&op.opcode)
            && (next >= ops.len() || ops[next].opcode != 56 || data[next])
        {
            return Err(invalid(entry.id, pc, "條件 opcode 必須緊接 JMP"));
        }
        if op.opcode == 76 && (next >= ops.len() || ops[next].opcode != 77) {
            return Err(invalid(entry.id, pc, "TFORCALL 必須緊接 TFORLOOP"));
        }
    }
    for (pc, op) in ops.iter().enumerate() {
        if data[pc] {
            continue;
        }
        if op.opcode == extra_opcode(profile) || (46..=48).contains(&op.opcode) {
            return Err(invalid(entry.id, pc, "孤立 EXTRAARG/MMBIN"));
        }
        let r = |value| check_reg(entry, pc, value);
        let range = |start, count| check_range(entry, pc, start, count);
        let k = |index| check_const(entry, pc, index);
        match op.opcode {
            0 => {
                r(op.a)?;
                r(op.b)?;
            }
            1 | 2 | 5 | 6 | 7 => {
                r(op.a)?;
            }
            4 => {
                r(op.a)?;
                k(ops[pc + 1].ax)?;
            }
            3 => {
                r(op.a)?;
                k(op.bx)?;
            }
            8 => {
                range(op.a, op.b + 1)?;
            }
            9 => {
                r(op.a)?;
                if usize::from(op.b) >= source.upvalues.len() {
                    return Err(invalid(entry.id, pc, "upvalue index 無效"));
                }
            }
            10 => {
                r(op.a)?;
                if usize::from(op.b) >= source.upvalues.len() {
                    return Err(invalid(entry.id, pc, "upvalue index 無效"));
                }
            }
            11 => {
                r(op.a)?;
                if usize::from(op.b) >= source.upvalues.len() {
                    return Err(invalid(entry.id, pc, "upvalue index 無效"));
                }
                check_short_string(entry, pc, u32::from(op.c))?;
            }
            12 => {
                r(op.a)?;
                r(op.b)?;
                r(op.c)?;
            }
            13 => {
                r(op.a)?;
                r(op.b)?;
            }
            14 => {
                r(op.a)?;
                r(op.b)?;
                check_short_string(entry, pc, u32::from(op.c))?;
            }
            15 => {
                if usize::from(op.a) >= source.upvalues.len() {
                    return Err(invalid(entry.id, pc, "upvalue index 無效"));
                }
                check_short_string(entry, pc, u32::from(op.b))?;
                if op.k {
                    k(u32::from(op.c))?;
                } else {
                    r(op.c)?;
                }
            }
            16 => {
                r(op.a)?;
                r(op.b)?;
                if op.k {
                    k(u32::from(op.c))?;
                } else {
                    r(op.c)?;
                }
            }
            17 => {
                r(op.a)?;
                if op.k {
                    k(u32::from(op.c))?;
                } else {
                    r(op.c)?;
                }
            }
            18 => {
                r(op.a)?;
                check_short_string(entry, pc, u32::from(op.b))?;
                if op.k {
                    k(u32::from(op.c))?;
                } else {
                    r(op.c)?;
                }
            }
            19 => {
                r(op.a)?;
            }
            20 => {
                range(op.a, 2)?;
                r(op.b)?;
                if profile == LuaProfile::Lua55 || op.k {
                    check_short_string(entry, pc, u32::from(op.c))?;
                } else {
                    r(op.c)?;
                }
            }
            21 | 32 | 33 => {
                r(op.a)?;
                r(op.b)?;
            }
            22..=31 => {
                r(op.a)?;
                r(op.b)?;
                check_number(entry, pc, u32::from(op.c), (29..=31).contains(&op.opcode))?;
            }
            34..=45 => {
                r(op.a)?;
                r(op.b)?;
                r(op.c)?;
            }
            49..=52 => {
                r(op.a)?;
                r(op.b)?;
            }
            53 => {
                if op.b < 2 {
                    return Err(invalid(entry.id, pc, "CONCAT 長度小於二"));
                }
                range(op.a, op.b)?;
            }
            54 => {
                if op.a > u16::from(source.max_stack_size) {
                    return Err(invalid(entry.id, pc, "CLOSE base 超出 frame"));
                }
            }
            55 => {
                r(op.a)?;
            }
            56 => {
                checked_target(entry, pc, pc as i64 + 1 + i64::from(op.sj), &data)?;
            }
            57..=59 => {
                r(op.a)?;
                r(op.b)?;
            }
            60 => {
                r(op.a)?;
                k(u32::from(op.b))?;
            }
            61..=65 | 66 => {
                r(op.a)?;
            }
            67 => {
                r(op.a)?;
                r(op.b)?;
            }
            68 | 69 => {
                r(op.a)?;
                if op.b != 0 {
                    range(op.a, op.b)?;
                }
                if op.c != 0 {
                    range(op.a, op.c - 1)?;
                }
            }
            70 => {
                if op.b == 0 {
                    r(op.a)?;
                } else if op.b > 1 {
                    range(op.a, op.b - 1)?;
                }
            }
            71 => {}
            72 => {
                r(op.a)?;
            }
            73 | 74 => {
                range(op.a, if profile == LuaProfile::Lua54 { 4 } else { 3 })?;
            }
            75 => {
                range(op.a, 4)?;
            }
            76 => {
                range(op.a, if profile == LuaProfile::Lua54 { 7 } else { 6 })?;
                if op.c == 0 {
                    return Err(invalid(entry.id, pc, "TFORCALL result count 為零"));
                }
                range(
                    op.a + if profile == LuaProfile::Lua54 { 4 } else { 3 },
                    op.c,
                )?;
            }
            77 => {
                range(op.a, if profile == LuaProfile::Lua54 { 5 } else { 4 })?;
            }
            78 => {
                r(op.a)?;
                let count = if profile == LuaProfile::Lua54 {
                    op.b
                } else {
                    op.vb
                };
                if count != 0 {
                    range(op.a + 1, count)?;
                }
            }
            79 => {
                r(op.a)?;
                if op.bx as usize >= source.children.len() {
                    return Err(invalid(entry.id, pc, "child prototype index 無效"));
                }
            }
            80 => {
                r(op.a)?;
                if op.c > 1 {
                    range(op.a, op.c - 1)?;
                }
                if profile == LuaProfile::Lua55 && op.k != (source.flags & 2 != 0) {
                    return Err(invalid(entry.id, pc, "VARARG table flag 或 register 無效"));
                }
                if profile == LuaProfile::Lua55 && op.k {
                    r(op.b)?;
                }
            }
            81 if profile == LuaProfile::Lua55 => {
                if source.flags & 1 == 0 {
                    return Err(invalid(entry.id, pc, "GETVARG 需要 hidden vararg"));
                }
                r(op.a)?;
                r(op.b)?;
                r(op.c)?;
            }
            82 if profile == LuaProfile::Lua55 => {
                r(op.a)?;
                if op.bx != 0 {
                    check_short_string(entry, pc, op.bx - 1)?;
                }
            }
            opcode if opcode == varargprep_opcode(profile) => {
                let expected_a = if profile == LuaProfile::Lua54 {
                    u16::from(source.num_params)
                } else {
                    0
                };
                let vararg_mask = if profile == LuaProfile::Lua54 { 1 } else { 3 };
                if pc != 0 || op.a != expected_a || source.flags & vararg_mask == 0 {
                    return Err(invalid(
                        entry.id,
                        pc,
                        "VARARGPREP 位置、參數或 variadic flag 無效",
                    ));
                }
            }
            _ => return Err(invalid(entry.id, pc, "opcode 結構未定義")),
        }
        let mut successors = Vec::new();
        successors
            .try_reserve_bounded_exact(2)
            .map_err(|error| reserve_failure(error, entry.id, pc, "CFG successor 配置失敗"))?;
        match op.opcode {
            56 => successors.push(pc as i64 + 1 + i64::from(op.sj)),
            6 => successors.push(pc as i64 + 2),
            57..=67 => {
                successors.push(pc as i64 + 1);
                successors.push(pc as i64 + 2);
            }
            74 => {
                successors.push(pc as i64 + 1);
                successors.push(pc as i64 + 2 + i64::from(op.bx));
            }
            73 | 77 => {
                successors.push(pc as i64 + 1);
                successors.push(pc as i64 + 1 - i64::from(op.bx));
            }
            75 => successors.push(pc as i64 + 1 + i64::from(op.bx)),
            69..=72 => {}
            _ => successors.push(
                pc as i64
                    + 1
                    + i64::from(
                        op.opcode == 4
                            || op.opcode == 19
                            || op.opcode == 78 && op.k
                            || (21..=45).contains(&op.opcode),
                    ),
            ),
        }
        edges[pc]
            .try_reserve_bounded_exact(successors.len())
            .map_err(|error| reserve_failure(error, entry.id, pc, "CFG edge 配置失敗"))?;
        for target in successors {
            edges[pc].push(checked_target(entry, pc, target, &data)?);
        }
    }
    for (pc, op) in ops.iter().enumerate() {
        if op.opcode == 74 {
            let next = pc
                .checked_add(op.bx as usize + 1)
                .ok_or_else(|| invalid(entry.id, pc, "FORPREP 距離溢位"))?;
            if ops.get(next).is_none_or(|candidate| {
                candidate.opcode != 73 || candidate.a != op.a || candidate.bx != op.bx + 1
            }) {
                return Err(invalid(entry.id, pc, "FORPREP/FORLOOP 配對無效"));
            }
        }
        if op.opcode == 75 {
            let call = pc
                .checked_add(op.bx as usize + 1)
                .ok_or_else(|| invalid(entry.id, pc, "TFORPREP 距離溢位"))?;
            if ops
                .get(call)
                .is_none_or(|candidate| candidate.opcode != 76 || candidate.a != op.a)
            {
                return Err(invalid(entry.id, pc, "TFORPREP/TFORCALL 配對無效"));
            }
        }
    }
    Ok(ValidatedCode { ops, data, edges })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CloseDecl {
    pc: usize,
    register: Register,
    binding: BytecodeBindingId,
}

#[derive(Debug)]
struct CloseNode {
    decl: CloseDecl,
    previous: Option<Rc<CloseNode>>,
    depth: usize,
}

type CloseState = Option<Rc<CloseNode>>;

fn close_declaration(
    entry: &PrototypeRef<'_>,
    pc: usize,
    register: Register,
) -> Result<CloseDecl, OfficialTranslationError> {
    let ordinal = u32::from(entry.source.max_stack_size)
        .checked_add(1)
        .and_then(|base| base.checked_add(pc as u32))
        .ok_or_else(|| invalid(entry.id, pc, "close binding ID 溢位"))?;
    Ok(CloseDecl {
        pc,
        register,
        binding: BytecodeBindingId {
            function: entry.id.0,
            ordinal,
        },
    })
}

fn state_equal(mut left: CloseState, mut right: CloseState) -> bool {
    loop {
        match (left, right) {
            (None, None) => return true,
            (Some(a), Some(b)) => {
                if Rc::ptr_eq(&a, &b) {
                    return true;
                }
                if a.decl != b.decl {
                    return false;
                }
                left = a.previous.clone();
                right = b.previous.clone();
            }
            _ => return false,
        }
    }
}

fn analyze_close_flow(
    entry: &PrototypeRef<'_>,
    code: &ValidatedCode,
    profile: LuaProfile,
) -> Result<Vec<Option<CloseState>>, OfficialTranslationError> {
    let mut before: Vec<Option<CloseState>> = Vec::new();
    before
        .try_reserve_bounded_exact(code.ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "close CFG state 配置失敗"))?;
    before.resize(code.ops.len(), None);
    before[0] = Some(None);
    let mut worklist = Vec::new();
    worklist
        .try_reserve_bounded_exact(code.ops.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "close CFG worklist 配置失敗"))?;
    worklist.push(0usize);
    while let Some(pc) = worklist.pop() {
        let mut after = before[pc]
            .clone()
            .ok_or_else(|| invalid(entry.id, pc, "close CFG state 遺失"))?;
        let op = code.ops[pc];
        if op.opcode == 55 || op.opcode == 75 {
            let register = if op.opcode == 55 {
                Register(op.a)
            } else {
                Register(op.a + if profile == LuaProfile::Lua54 { 3 } else { 2 })
            };
            if after
                .as_ref()
                .is_some_and(|node| register.0 <= node.decl.register.0)
            {
                return Err(invalid(entry.id, pc, "TBC register 未依作用域遞增"));
            }
            let depth = after.as_ref().map_or(0, |node| node.depth) + 1;
            if depth > usize::from(entry.source.max_stack_size) {
                return Err(invalid(entry.id, pc, "TBC nesting 超出官方 frame"));
            }
            after = Some(Rc::new(CloseNode {
                decl: close_declaration(entry, pc, register)?,
                previous: after,
                depth,
            }));
        } else if op.opcode == 54 {
            while after
                .as_ref()
                .is_some_and(|node| node.decl.register.0 >= op.a)
            {
                after = after.and_then(|node| node.previous.clone());
            }
        }
        for &successor in &code.edges[pc] {
            match &before[successor] {
                None => {
                    before[successor] = Some(after.clone());
                    worklist.push(successor);
                }
                Some(existing) if state_equal(existing.clone(), after.clone()) => {}
                Some(_) => return Err(invalid(entry.id, successor, "CFG 匯合的 TBC 狀態不一致")),
            }
        }
    }
    Ok(before)
}

fn active_closes(
    mut state: CloseState,
    base: u16,
    id: ProtoId,
    pc: usize,
) -> Result<Vec<CloseDecl>, OfficialTranslationError> {
    let mut declarations = Vec::new();
    let depth = state.as_ref().map_or(0, |node| node.depth);
    declarations
        .try_reserve_bounded_exact(depth)
        .map_err(|error| reserve_failure(error, id, pc, "close state 配置失敗"))?;
    while let Some(node) = state {
        if node.decl.register.0 < base {
            break;
        }
        declarations.push(node.decl);
        state = node.previous.clone();
    }
    Ok(declarations)
}

fn charge_close_metadata(
    used: &mut usize,
    limits: &VerifyLimits,
    id: ProtoId,
    pc: usize,
    count: usize,
    copies: usize,
) -> Result<(), OfficialTranslationError> {
    let per_path = std::mem::size_of::<BytecodeClosePath>()
        .checked_add(
            count
                .checked_mul(
                    std::mem::size_of::<BytecodeBindingId>() + std::mem::size_of::<Register>(),
                )
                .ok_or_else(|| invalid(id, pc, "close metadata bytes 溢位"))?,
        )
        .ok_or_else(|| invalid(id, pc, "close metadata bytes 溢位"))?;
    *used = used
        .checked_add(
            per_path
                .checked_mul(copies)
                .ok_or_else(|| invalid(id, pc, "close metadata bytes 溢位"))?,
        )
        .ok_or_else(|| invalid(id, pc, "close metadata bytes 溢位"))?;
    if *used > limits.max_module_bytes {
        return Err(limited(id, pc, "close metadata 超過 P05 bytes 限制"));
    }
    Ok(())
}

fn clone_close_path(
    path: &BytecodeClosePath,
    id: ProtoId,
    pc: usize,
) -> Result<BytecodeClosePath, OfficialTranslationError> {
    let mut bindings = Vec::new();
    bindings
        .try_reserve_bounded_exact(path.bindings.len())
        .map_err(|error| reserve_failure(error, id, pc, "close binding 配置失敗"))?;
    bindings.extend_from_slice(&path.bindings);
    let mut registers = Vec::new();
    registers
        .try_reserve_bounded_exact(path.registers.len())
        .map_err(|error| reserve_failure(error, id, pc, "close register 配置失敗"))?;
    registers.extend_from_slice(&path.registers);
    Ok(BytecodeClosePath {
        kind: path.kind,
        span: path.span,
        from_scope: path.from_scope,
        target_scope: path.target_scope,
        bindings,
        registers,
    })
}

fn emit_close_sequence(
    entry: &PrototypeRef<'_>,
    pc: usize,
    base: u16,
    guest_base: u16,
    limits: &VerifyLimits,
    kind: BytecodeExitKind,
    state: CloseState,
    captured: &[Register],
    instructions: &mut Vec<BytecodeInstruction>,
    close_paths: &mut Vec<BytecodeClosePath>,
    metadata_bytes: &mut usize,
) -> Result<(), OfficialTranslationError> {
    let captured_count = captured
        .iter()
        .filter(|register| register.0 >= guest_base + base)
        .count();
    let active = active_closes(state, base, entry.id, pc)?;
    let required = captured_count
        .checked_add(active.len())
        .ok_or_else(|| invalid(entry.id, pc, "close 指令數溢位"))?;
    if instructions
        .len()
        .checked_add(required)
        .is_none_or(|count| count > limits.max_instructions)
    {
        return Err(limited(entry.id, pc, "轉譯指令超過 P05 限制"));
    }
    for &register in captured
        .iter()
        .rev()
        .filter(|register| register.0 >= guest_base + base)
    {
        push_instruction(
            instructions,
            limits,
            entry.id,
            pc,
            entry_at(
                pc,
                Instruction::Close {
                    base: register,
                    count: 0,
                },
            ),
        )?;
    }
    if active.is_empty() {
        return Ok(());
    }
    charge_close_metadata(
        metadata_bytes,
        limits,
        entry.id,
        pc,
        active.len(),
        active.len() + 1,
    )?;
    let scope = u32::try_from(pc + 1).map_err(|_| invalid(entry.id, pc, "close scope ID 溢位"))?;
    let mut bindings = Vec::new();
    bindings
        .try_reserve_bounded_exact(active.len())
        .map_err(|error| reserve_failure(error, entry.id, pc, "close binding 配置失敗"))?;
    let mut registers = Vec::new();
    registers
        .try_reserve_bounded_exact(active.len())
        .map_err(|error| reserve_failure(error, entry.id, pc, "close register 配置失敗"))?;
    for declaration in &active {
        bindings.push(declaration.binding);
        registers.push(Register(guest_base + declaration.register.0));
    }
    let path = BytecodeClosePath {
        kind,
        span: BytecodeSpan {
            start_byte: pc as u64 * 4,
            end_byte: (pc as u64 + 1) * 4,
        },
        from_scope: scope,
        target_scope: if kind == BytecodeExitKind::Return {
            None
        } else {
            Some(0)
        },
        bindings,
        registers,
    };
    close_paths
        .try_reserve_bounded(1)
        .map_err(|error| reserve_failure(error, entry.id, pc, "close path 配置失敗"))?;
    close_paths.push(clone_close_path(&path, entry.id, pc)?);
    for register in &path.registers {
        push_instruction(
            instructions,
            limits,
            entry.id,
            pc,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: *register,
                    count: 1,
                },
                span: path.span,
                close_path: Some(clone_close_path(&path, entry.id, pc)?),
            },
        )?;
    }
    Ok(())
}

fn emit_close_marker(
    entry: &PrototypeRef<'_>,
    pc: usize,
    register: Register,
    limits: &VerifyLimits,
    binding_registers: &mut Vec<(BytecodeBindingId, Register)>,
    instructions: &mut Vec<BytecodeInstruction>,
    metadata_bytes: &mut usize,
) -> Result<(), OfficialTranslationError> {
    let declaration = close_declaration(entry, pc, register)?;
    let scope = u32::try_from(pc + 1).map_err(|_| invalid(entry.id, pc, "close scope ID 溢位"))?;
    let span = BytecodeSpan {
        start_byte: pc as u64 * 4,
        end_byte: (pc as u64 + 1) * 4,
    };
    charge_close_metadata(metadata_bytes, limits, entry.id, pc, 1, 1)?;
    binding_registers
        .try_reserve_bounded(1)
        .map_err(|error| reserve_failure(error, entry.id, pc, "close binding register 配置失敗"))?;
    binding_registers.push((declaration.binding, register));
    let mut bindings = Vec::new();
    bindings
        .try_reserve_bounded_exact(1)
        .map_err(|error| reserve_failure(error, entry.id, pc, "close marker binding 配置失敗"))?;
    bindings.push(declaration.binding);
    let mut registers = Vec::new();
    registers
        .try_reserve_bounded_exact(1)
        .map_err(|error| reserve_failure(error, entry.id, pc, "close marker register 配置失敗"))?;
    registers.push(register);
    push_instruction(
        instructions,
        limits,
        entry.id,
        pc,
        BytecodeInstruction {
            instruction: Instruction::Move {
                dest: register,
                src: register,
            },
            span,
            close_path: Some(BytecodeClosePath {
                kind: BytecodeExitKind::Normal,
                span,
                from_scope: scope,
                target_scope: Some(scope),
                bindings,
                registers,
            }),
        },
    )?;
    Ok(())
}

fn arithmetic_operation(opcode: u8) -> Option<BinaryOperation> {
    Some(match opcode {
        21 | 22 | 34 => BinaryOperation::Add,
        23 | 35 => BinaryOperation::Subtract,
        24 | 36 => BinaryOperation::Multiply,
        25 | 37 => BinaryOperation::Modulo,
        26 | 38 => BinaryOperation::Power,
        27 | 39 => BinaryOperation::Divide,
        28 | 40 => BinaryOperation::FloorDivide,
        29 | 41 => BinaryOperation::Ampersand,
        30 | 42 => BinaryOperation::Pipe,
        31 | 43 => BinaryOperation::BitXor,
        44 => BinaryOperation::ShiftLeft,
        45 => BinaryOperation::ShiftRight,
        _ => return None,
    })
}

fn entry_at(pc: usize, instruction: Instruction) -> BytecodeInstruction {
    BytecodeInstruction {
        instruction,
        span: BytecodeSpan {
            start_byte: pc as u64 * 4,
            end_byte: (pc as u64 + 1) * 4,
        },
        close_path: None,
    }
}

fn push_instruction(
    instructions: &mut Vec<BytecodeInstruction>,
    limits: &VerifyLimits,
    id: ProtoId,
    pc: usize,
    instruction: BytecodeInstruction,
) -> Result<(), OfficialTranslationError> {
    if instructions.len() >= limits.max_instructions {
        return Err(limited(id, pc, "轉譯指令超過 P05 限制"));
    }
    instructions
        .try_reserve_bounded(1)
        .map_err(|error| reserve_failure(error, id, pc, "轉譯指令配置失敗"))?;
    instructions.push(instruction);
    Ok(())
}

fn append_constant(
    constants: &mut Vec<BytecodeConstant>,
    limits: &VerifyLimits,
    prototype: ProtoId,
    pc: usize,
    value: BytecodeConstant,
) -> Result<ConstId, OfficialTranslationError> {
    if constants.len() >= limits.max_constants {
        return Err(limited(prototype, pc, "轉譯常數超過 P05 限制"));
    }
    let id = ConstId(
        u32::try_from(constants.len()).map_err(|_| invalid(prototype, pc, "轉譯常數 ID 溢位"))?,
    );
    constants
        .try_reserve_bounded(1)
        .map_err(|error| reserve_failure(error, prototype, pc, "轉譯常數配置失敗"))?;
    constants.push(value);
    Ok(id)
}

fn original_constant_load(source: &OfficialPrototype, dest: Register, index: u32) -> Instruction {
    if matches!(source.constants[index as usize], OfficialConstant::Nil) {
        Instruction::LoadNil {
            start: dest,
            count: 1,
        }
    } else {
        Instruction::LoadConst {
            dest,
            constant: ConstId(index),
        }
    }
}

struct PrototypeRef<'a> {
    id: ProtoId,
    parent: Option<ProtoId>,
    source: &'a OfficialPrototype,
    children: Vec<ProtoId>,
}

struct Preflight {
    prototypes: usize,
    source_instructions: usize,
    constants: usize,
    source_bytes: usize,
    debug_bytes: usize,
}

fn preflight(
    prototype: &OfficialPrototype,
    profile: LuaProfile,
    depth: usize,
    state: &mut Preflight,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<(), OfficialTranslationError> {
    let fail = |detail| invalid(ProtoId(0), 0, detail);
    let limit_fail = |detail| limited(ProtoId(0), 0, detail);
    if depth > 64 {
        return Err(limit_fail("官方 prototype 遞迴超過安全深度"));
    }
    let scan_units = prototype
        .code
        .len()
        .checked_add(prototype.constants.len())
        .and_then(|units| units.checked_add(prototype.upvalues.len()))
        .and_then(|units| units.checked_add(prototype.children.len()))
        .and_then(|units| units.checked_add(prototype.debug.line_info.len()))
        .and_then(|units| units.checked_add(prototype.debug.abs_line_info.len()))
        .and_then(|units| units.checked_add(prototype.debug.locals.len()))
        .and_then(|units| units.checked_add(prototype.debug.upvalue_names.len()))
        .and_then(|units| units.checked_add(1))
        .ok_or_else(|| fail("官方 source scan work 溢位"))?;
    work.charge(scan_units, ProtoId(0), 0)?;
    state.prototypes = state
        .prototypes
        .checked_add(1)
        .ok_or_else(|| fail("prototype 數溢位"))?;
    if state.prototypes > limits.max_prototypes {
        return Err(limit_fail("prototype 數超過 P05 限制"));
    }
    state.source_instructions = state
        .source_instructions
        .checked_add(prototype.code.len())
        .ok_or_else(|| fail("指令總數溢位"))?;
    if state.source_instructions > limits.max_instructions {
        return Err(limit_fail("官方指令總數超過 P05 限制"));
    }
    if prototype.max_stack_size == 0 {
        return Err(fail("官方 frame size 為零"));
    }
    let mut maximum_list = 3usize;
    let mut numeric_loops = 0usize;
    for &word in &prototype.code {
        let op = Decoded::new(word);
        if op.opcode == 78 {
            maximum_list = maximum_list.max(usize::from(if profile == LuaProfile::Lua55 {
                op.vb
            } else {
                op.b
            }));
        }
        if op.opcode == 74 {
            numeric_loops = numeric_loops
                .checked_add(1)
                .ok_or_else(|| fail("numeric loop 數溢位"))?;
        }
    }
    let register_need = usize::from(prototype.num_params)
        .checked_add(5)
        .and_then(|count| count.checked_add(maximum_list.max(3)))
        .and_then(|count| count.checked_add(4))
        .and_then(|count| count.checked_add(numeric_loops.checked_mul(3)?))
        .and_then(|count| count.checked_add(6))
        .and_then(|count| count.checked_add(usize::from(prototype.max_stack_size)))
        .ok_or_else(|| fail("轉譯 register 額度溢位"))?;
    if register_need > usize::from(limits.max_registers) || register_need > usize::from(u16::MAX) {
        return Err(limit_fail("必要轉譯暫存器超過 P05 限制"));
    }
    state.constants = state
        .constants
        .checked_add(prototype.constants.len())
        .ok_or_else(|| fail("常數總數溢位"))?;
    if state.constants > limits.max_constants {
        return Err(limit_fail("官方常數總數超過 P05 限制"));
    }
    let constant_bytes = prototype
        .constants
        .iter()
        .try_fold(0usize, |sum, constant| {
            let bytes = match constant {
                OfficialConstant::String { bytes, .. } => bytes.len(),
                _ => 8,
            };
            sum.checked_add(bytes)
        })
        .ok_or_else(|| fail("常數 bytes 溢位"))?;
    let debug_string_bytes = prototype
        .source
        .as_ref()
        .map_or(0, Vec::len)
        .checked_add(
            prototype
                .debug
                .locals
                .iter()
                .filter_map(|entry| entry.name.as_ref())
                .try_fold(0usize, |total, name| total.checked_add(name.len()))
                .ok_or_else(|| fail("local name bytes 溢位"))?,
        )
        .and_then(|total| {
            prototype
                .debug
                .upvalue_names
                .iter()
                .filter_map(Option::as_ref)
                .try_fold(total, |sum, name| sum.checked_add(name.len()))
        })
        .ok_or_else(|| fail("debug string bytes 溢位"))?;
    work.charge(
        prototype
            .code
            .len()
            .checked_mul(4)
            .and_then(|units| units.checked_add(constant_bytes))
            .and_then(|units| units.checked_add(debug_string_bytes))
            .ok_or_else(|| fail("官方 source bytes work 溢位"))?,
        ProtoId(0),
        0,
    )?;
    state.debug_bytes = state
        .debug_bytes
        .checked_add(debug_string_bytes)
        .ok_or_else(|| fail("官方 debug bytes 溢位"))?;
    if state.debug_bytes > limits.max_artifact_bytes {
        return Err(limit_fail("官方 debug bytes 超過 artifact 限制"));
    }
    state.source_bytes = state
        .source_bytes
        .checked_add(
            prototype
                .code
                .len()
                .checked_mul(4)
                .ok_or_else(|| fail("指令 bytes 溢位"))?,
        )
        .and_then(|size| size.checked_add(constant_bytes))
        .ok_or_else(|| fail("官方轉譯來源 bytes 溢位"))?;
    if state.source_bytes > limits.max_module_bytes {
        return Err(limit_fail("官方轉譯來源 bytes 超過 P05 限制"));
    }
    if prototype.upvalues.len() > limits.max_upvalues_per_prototype {
        return Err(limit_fail("官方 upvalue 超過 P05 限制"));
    }
    for child in &prototype.children {
        preflight(child, profile, depth + 1, state, limits, work)?;
    }
    Ok(())
}

fn collect<'a>(
    source: &'a OfficialPrototype,
    parent: Option<ProtoId>,
    depth: usize,
    refs: &mut Vec<PrototypeRef<'a>>,
    limits: &VerifyLimits,
) -> Result<ProtoId, OfficialTranslationError> {
    if depth > 64 || refs.len() >= limits.max_prototypes {
        return Err(limited(
            parent.unwrap_or(ProtoId(0)),
            0,
            "prototype 數超過 P05 限制",
        ));
    }
    let id = ProtoId(
        u32::try_from(refs.len()).map_err(|_| invalid(ProtoId(0), 0, "prototype ID 溢位"))?,
    );
    let mut children = Vec::new();
    children
        .try_reserve_bounded_exact(source.children.len())
        .map_err(|error| reserve_failure(error, id, 0, "child 索引配置失敗"))?;
    refs.push(PrototypeRef {
        id,
        parent,
        source,
        children,
    });
    for child in &source.children {
        let child_id = collect(child, Some(id), depth + 1, refs, limits)?;
        refs[id.0 as usize].children.push(child_id);
    }
    Ok(id)
}

pub fn translate_official_chunk(
    chunk: &OfficialChunk,
    limits: &VerifyLimits,
) -> Result<OfficialTranslation, OfficialTranslationError> {
    let mut work = OfficialWorkBudget::for_limits(limits)?;
    translate_official_chunk_with_work(chunk, limits, &mut work)
}

pub fn translate_official_chunk_with_work(
    chunk: &OfficialChunk,
    limits: &VerifyLimits,
    work: &mut OfficialWorkBudget,
) -> Result<OfficialTranslation, OfficialTranslationError> {
    if usize::from(chunk.root_upvalues) != chunk.main.upvalues.len() {
        return Err(invalid(ProtoId(0), 0, "root upvalue 數不符"));
    }
    let mut preflight_state = Preflight {
        prototypes: 0,
        source_instructions: 0,
        constants: 0,
        source_bytes: 0,
        debug_bytes: 0,
    };
    preflight(
        &chunk.main,
        chunk.profile,
        1,
        &mut preflight_state,
        limits,
        work,
    )?;
    work.charge(
        preflight_state
            .source_bytes
            .checked_add(preflight_state.debug_bytes)
            .and_then(|units| units.checked_add(preflight_state.source_instructions))
            .and_then(|units| units.checked_add(preflight_state.prototypes))
            .ok_or_else(|| invalid(ProtoId(0), 0, "官方 clone work 溢位"))?,
        ProtoId(0),
        0,
    )?;
    let official_limits = OfficialChunkLimits {
        max_bytes: limits.max_artifact_bytes,
        max_prototypes: limits.max_prototypes,
        max_instructions: limits.max_instructions,
        max_constants: limits.max_constants,
        max_total_string_bytes: limits.max_artifact_bytes,
        max_allocated_bytes: limits.max_artifact_bytes,
        ..OfficialChunkLimits::default()
    };
    let (owned_chunk, chunk_bytes) =
        clone_official_chunk_checked(chunk, &official_limits).map_err(from_official_chunk_error)?;
    let mut artifact_bytes = chunk_bytes;
    charge_artifact_bytes(
        &mut artifact_bytes,
        size_of::<OfficialArtifact>() + 2 * size_of::<usize>(),
        limits.max_artifact_bytes,
        ProtoId(0),
        0,
    )?;
    let mut refs = Vec::new();
    refs.try_reserve_bounded_exact(preflight_state.prototypes)
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "prototype 索引配置失敗"))?;
    collect(&chunk.main, None, 1, &mut refs, limits)?;
    let mut validated_codes = Vec::new();
    validated_codes
        .try_reserve_bounded_exact(refs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "opcode 索引配置失敗"))?;
    for entry in &refs {
        work.charge(
            entry
                .source
                .code
                .len()
                .checked_mul(8)
                .and_then(|units| units.checked_add(entry.source.upvalues.len()))
                .ok_or_else(|| invalid(entry.id, 0, "官方 CFG 驗證 work 溢位"))?,
            entry.id,
            0,
        )?;
        validated_codes.push(validate_code(entry, chunk.profile, limits)?);
    }
    let mut hidden = Vec::new();
    hidden
        .try_reserve_bounded_exact(refs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "hidden binding 索引配置失敗"))?;
    hidden.resize(refs.len(), 0_u8);
    for index in (0..refs.len()).rev() {
        for (pc, op) in validated_codes[index].ops.iter().enumerate() {
            if validated_codes[index].data[pc] {
                continue;
            }
            match op.opcode {
                78 => {
                    hidden[index] |= builtin_bit(OfficialFixedBuiltin::RawListWrite);
                }
                81 if chunk.profile == LuaProfile::Lua55 => {
                    hidden[index] |= builtin_bit(OfficialFixedBuiltin::RawVarargGet);
                }
                80 if chunk.profile == LuaProfile::Lua55 && op.k => {
                    hidden[index] |= builtin_bit(OfficialFixedBuiltin::PackUnpack);
                }
                82 if chunk.profile == LuaProfile::Lua55 => {
                    hidden[index] |= builtin_bit(OfficialFixedBuiltin::GlobalNilCheck);
                }
                _ => {}
            }
        }
        for &child in &refs[index].children {
            hidden[index] |= hidden[child.0 as usize];
        }
    }
    let mut upvalue_maps = Vec::new();
    upvalue_maps
        .try_reserve_bounded_exact(refs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "upvalue mapping 配置失敗"))?;
    for (index, entry) in refs.iter().enumerate() {
        let source_work = entry
            .source
            .code
            .len()
            .checked_mul(
                usize::from(entry.source.max_stack_size)
                    .checked_add(512)
                    .ok_or_else(|| invalid(entry.id, 0, "轉譯 work 溢位"))?,
            )
            .and_then(|units| {
                entry
                    .source
                    .constants
                    .len()
                    .checked_mul(4)
                    .and_then(|extra| units.checked_add(extra))
            })
            .and_then(|units| {
                entry
                    .source
                    .upvalues
                    .len()
                    .checked_mul(4)
                    .and_then(|extra| units.checked_add(extra))
            })
            .ok_or_else(|| invalid(entry.id, 0, "轉譯 work 溢位"))?;
        work.charge(source_work, entry.id, 0)?;
        let guest_count = u16::try_from(entry.source.upvalues.len())
            .map_err(|_| invalid(entry.id, 0, "guest upvalue 數超出 u16"))?;
        let total = entry
            .source
            .upvalues
            .len()
            .checked_add(hidden[index].count_ones() as usize)
            .ok_or_else(|| invalid(entry.id, 0, "hidden upvalue 數溢位"))?;
        if total > limits.max_upvalues_per_prototype || total > usize::from(u16::MAX) {
            return Err(limited(entry.id, 0, "guest + hidden upvalue 超過 P05 限制"));
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_bounded_exact(hidden[index].count_ones() as usize)
            .map_err(|error| reserve_failure(error, entry.id, 0, "hidden upvalue 配置失敗"))?;
        for kind in BUILTIN_ORDER {
            if hidden[index] & builtin_bit(kind) != 0 {
                slots.push((kind, UpvalueId(guest_count + slots.len() as u16)));
            }
        }
        upvalue_maps.push(OfficialUpvalueMap {
            prototype: entry.id,
            guest_count,
            hidden: slots,
        });
    }
    let mut root_bindings = Vec::new();
    root_bindings
        .try_reserve_bounded_exact(
            upvalue_maps[0].guest_count as usize + upvalue_maps[0].hidden.len(),
        )
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "root binding 配置失敗"))?;
    for index in 0..usize::from(upvalue_maps[0].guest_count) {
        root_bindings.push(OfficialRootBinding {
            upvalue: UpvalueId(index as u16),
            source: if index == 0 {
                OfficialRootBindingSource::ExternalEnvironment
            } else {
                OfficialRootBindingSource::InitialNil
            },
        });
    }
    for &(kind, upvalue) in &upvalue_maps[0].hidden {
        root_bindings.push(OfficialRootBinding {
            upvalue,
            source: OfficialRootBindingSource::FixedBuiltin(kind),
        });
    }
    let mut prototypes = Vec::new();
    prototypes
        .try_reserve_bounded_exact(refs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "轉譯 prototype 配置失敗"))?;
    let mut pc_mappings = Vec::new();
    charge_artifact_bytes(
        &mut artifact_bytes,
        refs.len()
            .checked_mul(size_of::<OfficialPcMap>())
            .ok_or_else(|| invalid(ProtoId(0), 0, "PC mapping bytes 溢位"))?,
        limits.max_artifact_bytes,
        ProtoId(0),
        0,
    )?;
    pc_mappings
        .try_reserve_bounded_exact(refs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "PC mapping 配置失敗"))?;
    charge_artifact_bytes(
        &mut artifact_bytes,
        (pc_mappings.capacity() - refs.len()) * size_of::<OfficialPcMap>(),
        limits.max_artifact_bytes,
        ProtoId(0),
        0,
    )?;
    let mut internal_calls = Vec::new();
    let mut frame_inputs = Vec::new();
    frame_inputs
        .try_reserve_bounded_exact(
            refs.len()
                .checked_mul(3)
                .ok_or_else(|| invalid(ProtoId(0), 0, "frame input 數溢位"))?,
        )
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "frame input 索引配置失敗"))?;
    let mut translated_instructions = 0usize;
    let mut translated_constants = 0usize;
    let mut close_metadata_bytes = 0usize;
    for (index, entry) in refs.iter().enumerate() {
        // 每個 prototype 都只能使用 module 尚未消耗的額度；展開期間即須拒絕超限配置。
        let mut remaining = *limits;
        remaining.max_instructions = limits
            .max_instructions
            .checked_sub(translated_instructions)
            .ok_or_else(|| limited(entry.id, 0, "轉譯指令總數超過 P05 限制"))?;
        remaining.max_constants = limits
            .max_constants
            .checked_sub(translated_constants)
            .ok_or_else(|| limited(entry.id, 0, "轉譯常數總數超過 P05 限制"))?;
        let (prototype, mapping, calls, inputs) = translate_prototype(
            entry,
            &refs,
            &validated_codes[index],
            &upvalue_maps,
            chunk.profile,
            &remaining,
            &mut close_metadata_bytes,
            &mut artifact_bytes,
            work,
        )?;
        translated_instructions = translated_instructions
            .checked_add(prototype.instructions.len())
            .ok_or_else(|| invalid(entry.id, 0, "轉譯指令總數溢位"))?;
        translated_constants = translated_constants
            .checked_add(prototype.constants.len())
            .ok_or_else(|| invalid(entry.id, 0, "轉譯常數總數溢位"))?;
        if translated_instructions > limits.max_instructions
            || translated_constants > limits.max_constants
        {
            return Err(limited(entry.id, 0, "轉譯結果超過 P05 module 額度"));
        }
        prototypes.push(prototype);
        pc_mappings.push(mapping);
        frame_inputs.extend(inputs);
        internal_calls
            .try_reserve_bounded(calls.len())
            .map_err(|error| reserve_failure(error, entry.id, 0, "內部 Call 總索引配置失敗"))?;
        internal_calls.extend(calls);
    }
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: refs
            .iter()
            .map(|entry| entry.source.code.len() as u64 * 4)
            .max()
            .unwrap_or(0),
    };
    let mut function_prototypes = Vec::new();
    function_prototypes
        .try_reserve_bounded_exact(prototypes.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "function 索引配置失敗"))?;
    for prototype in &prototypes {
        function_prototypes.push((prototype.function, prototype.id));
    }
    let module = BytecodeModule {
        format_version: RVLU_V2,
        profile: chunk.profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        span,
        function_prototypes,
        prototypes,
    };
    work.charge(
        translated_instructions
            .checked_mul(8)
            .and_then(|units| {
                translated_constants
                    .checked_mul(4)
                    .and_then(|extra| units.checked_add(extra))
            })
            .and_then(|units| {
                refs.len()
                    .checked_mul(refs.len())
                    .and_then(|extra| units.checked_add(extra))
            })
            .ok_or_else(|| invalid(ProtoId(0), 0, "P05 module 驗證 work 溢位"))?,
        ProtoId(0),
        0,
    )?;
    let verified = verify_module(module, chunk.profile, limits).map_err(from_bytecode_error)?;
    work.charge(refs.len(), ProtoId(0), 0)?;
    let actual_register_work = verified
        .module()
        .prototypes
        .iter()
        .try_fold(0usize, |total, prototype| {
            prototype
                .instructions
                .len()
                .checked_mul(usize::from(prototype.register_count))
                .and_then(|units| total.checked_add(units))
        })
        .ok_or_else(|| invalid(ProtoId(0), 0, "P05 plan register work 溢位"))?;
    work.charge(
        actual_register_work
            .checked_add(
                translated_instructions
                    .checked_mul(refs.len())
                    .ok_or_else(|| invalid(ProtoId(0), 0, "P05 plan 驗證 work 溢位"))?,
            )
            .and_then(|units| {
                frame_inputs
                    .len()
                    .checked_mul(8)
                    .and_then(|per_call| per_call.checked_add(16))
                    .and_then(|per_call| internal_calls.len().checked_mul(per_call))
                    .and_then(|extra| units.checked_add(extra))
            })
            .ok_or_else(|| invalid(ProtoId(0), 0, "P05 plan 驗證 work 溢位"))?,
        ProtoId(0),
        0,
    )?;
    let mut input_cursor = 0usize;
    for (index, entry) in refs.iter().enumerate() {
        let start = input_cursor;
        while frame_inputs
            .get(input_cursor)
            .is_some_and(|input| input.prototype == entry.id)
        {
            input_cursor += 1;
        }
        let inputs = &frame_inputs[start..input_cursor];
        let prototype = &verified.module().prototypes[index];
        let guest_start = prototype
            .binding_registers
            .iter()
            .find_map(|(binding, register)| {
                (binding.function == entry.id.0 && binding.ordinal == 1).then_some(register.0)
            })
            .ok_or_else(|| invalid(entry.id, 0, "guest R0 binding 缺失"))?;
        let raw_register = guest_start
            .checked_sub(6)
            .ok_or_else(|| invalid(entry.id, 0, "raw vararg prefix 無效"))?;
        let active_register = guest_start
            .checked_sub(5)
            .ok_or_else(|| invalid(entry.id, 0, "active vararg prefix 無效"))?;
        let raw_needed = chunk.profile == LuaProfile::Lua55
            && validated_codes[index]
                .ops
                .iter()
                .any(|op| op.opcode == 81 || op.opcode == 80 && !op.k);
        let table_needed = chunk.profile == LuaProfile::Lua55 && entry.source.flags & 2 != 0;
        let active_needed = chunk.profile == LuaProfile::Lua55
            && validated_codes[index].ops.iter().any(|op| op.opcode == 80);
        let expected = [
            (
                OfficialFrameInputSource::OriginalVarargs,
                raw_needed,
                Some(raw_register),
            ),
            (
                OfficialFrameInputSource::GuestNamedVarargTable,
                table_needed,
                guest_start.checked_add(u16::from(entry.source.num_params)),
            ),
            (
                OfficialFrameInputSource::ActiveVarargs,
                active_needed,
                Some(active_register),
            ),
        ];
        for (kind, needed, register) in expected {
            let mut matching = inputs.iter().filter(|input| input.source == kind);
            let first = matching.next();
            if first.is_some() != needed
                || matching.next().is_some()
                || first.is_some_and(|input| Some(input.register.0) != register)
            {
                return Err(invalid(entry.id, 0, "frame input 來源或 register 無效"));
            }
        }
        let active_binding = BytecodeBindingId {
            function: entry.id.0,
            ordinal: u32::from(entry.source.max_stack_size)
                .checked_add(
                    u32::try_from(entry.source.code.len())
                        .map_err(|_| invalid(entry.id, 0, "active binding ID 溢位"))?,
                )
                .and_then(|ordinal| ordinal.checked_add(1))
                .ok_or_else(|| invalid(entry.id, 0, "active binding ID 溢位"))?,
        };
        if prototype.named_vararg
            != active_needed.then_some((active_binding, Register(active_register)))
            || inputs.iter().any(|input| {
                input.source == OfficialFrameInputSource::OriginalVarargs
                    && prototype
                        .binding_registers
                        .iter()
                        .any(|(_, register)| *register == input.register)
            })
        {
            return Err(invalid(
                entry.id,
                0,
                "active vararg 或 raw prefix binding 無效",
            ));
        }
    }
    if input_cursor != frame_inputs.len() {
        return Err(invalid(ProtoId(0), 0, "frame input prototype 排序無效"));
    }
    for call in &internal_calls {
        let Some(prototype) = verified.module().prototypes.get(call.prototype.0 as usize) else {
            return Err(invalid(
                call.prototype,
                call.source_pc,
                "內部 binding prototype 無效",
            ));
        };
        let expected_count = if call.open_tail.is_some() {
            u16::MAX
        } else {
            u16::try_from(call.inputs.len())
                .map_err(|_| invalid(call.prototype, call.source_pc, "固定 builtin 引數數量溢位"))?
        };
        if prototype
            .binding_registers
            .iter()
            .skip(1)
            .any(|(_, register)| *register == call.function_register)
            || !upvalue_maps[call.prototype.0 as usize]
                .hidden
                .contains(&(call.builtin, call.source_upvalue))
            || !matches!(prototype.instructions.get(call.call_pc.0 as usize).map(|entry| &entry.instruction), Some(Instruction::Call { base, arg_count, .. }) if *base == call.function_register && *arg_count == expected_count)
            || call.inputs.iter().enumerate().any(|(offset, register)| {
                register.0 != call.function_register.0 + offset as u16 + 1
            })
            || call.open_tail.is_some_and(|tail| {
                call.function_register.0 + call.inputs.len() as u16 + 1 != tail.0
            })
            || (call.builtin == OfficialFixedBuiltin::RawVarargGet
                && {
                    let input = frame_inputs.iter().find(|input| {
                        input.prototype == call.prototype
                            && input.source == OfficialFrameInputSource::OriginalVarargs
                    });
                    let source_op = validated_codes[call.prototype.0 as usize]
                        .ops
                        .get(call.source_pc);
                    input.is_none_or(|input| source_op.is_none_or(|op| {
                        let call_pc = call.call_pc.0 as usize;
                        if op.opcode != 81 || call.inputs.len() != 2 || call_pc < 2 {
                            return true;
                        }
                        let key = prototype.binding_registers.iter().find_map(|(binding, register)|
                            (binding.function == call.prototype.0
                                && binding.ordinal == u32::from(op.c) + 1).then_some(*register));
                        !matches!(prototype.instructions.get(call_pc - 2).map(|entry| &entry.instruction),
                            Some(Instruction::Move { dest, src })
                                if *dest == call.inputs[0] && *src == input.register)
                            || !matches!(prototype.instructions.get(call_pc - 1).map(|entry| &entry.instruction),
                                Some(Instruction::Move { dest, src })
                                    if *dest == call.inputs[1] && Some(*src) == key)
                            || !matches!(prototype.instructions.get(call_pc).map(|entry| &entry.instruction),
                                Some(Instruction::Call { result_mode: ResultMode::Fixed(1), .. }))
                    }))
                })
            || (call.builtin == OfficialFixedBuiltin::PackUnpack
                && {
                    let input = frame_inputs.iter().find(|input| {
                        input.prototype == call.prototype
                            && input.source == OfficialFrameInputSource::ActiveVarargs
                    });
                    let source_op = validated_codes[call.prototype.0 as usize]
                        .ops
                        .get(call.source_pc);
                    input.is_none_or(|input| source_op.is_none_or(|op| {
                    let call_pc = call.call_pc.0 as usize;
                    if op.opcode != 80 || !op.k || call.inputs.len() != 2 || call_pc < 2 {
                        return true;
                    }
                    let table = prototype.binding_registers.iter().find_map(|(binding, register)|
                        (binding.function == call.prototype.0 && binding.ordinal == u32::from(op.b) + 1)
                            .then_some(*register));
                    let wanted = if op.c == 0 { -1 } else { i64::from(op.c - 1) };
                    let count_matches = matches!(prototype.instructions.get(call_pc.saturating_sub(1))
                        .map(|entry| &entry.instruction), Some(Instruction::LoadConst { dest, constant })
                            if *dest == call.inputs[1]
                                && prototype.constants.get(constant.0 as usize) == Some(&BytecodeConstant::Integer(wanted)));
                    !matches!(prototype.instructions.get(call_pc - 2).map(|entry| &entry.instruction),
                            Some(Instruction::Move { dest, src })
                                if *dest == call.inputs[0] && Some(*src) == table)
                        || !count_matches
                        || !matches!(prototype.instructions.get(call_pc).map(|entry| &entry.instruction),
                            Some(Instruction::Call { result_mode: ResultMode::Fixed(1), .. }))
                        || !matches!(prototype.instructions.get(call_pc + 1).map(|entry| &entry.instruction),
                            Some(Instruction::Move { dest, src })
                                if *dest == input.register && *src == call.function_register)
                        || !matches!(prototype.instructions.get(call_pc + 2).map(|entry| &entry.instruction),
                            Some(Instruction::Vararg { .. }))
                }))
                })
        {
            return Err(invalid(
                call.prototype,
                call.source_pc,
                "內部 binding 來源、Call 或輸入映射無效",
            ));
        }
    }
    let mut verified = attach_official_plan(
        verified,
        &root_bindings,
        &upvalue_maps,
        &frame_inputs,
        &internal_calls,
        &refs,
        limits,
    )?;
    let artifact = OfficialArtifact::new(
        owned_chunk,
        chunk_bytes,
        pc_mappings,
        limits.max_artifact_bytes,
    )
    .ok_or_else(|| limited(ProtoId(0), 0, "官方 artifact 總配置超過 P05 限制"))?;
    let artifact = Arc::new(artifact);
    verified.set_official_artifact(Arc::clone(&artifact));
    Ok(OfficialTranslation {
        verified,
        artifact,
        internal_calls,
        frame_inputs,
        upvalue_maps,
        root_bindings,
    })
}

fn attach_official_plan(
    verified: VerifiedModule,
    roots: &[OfficialRootBinding],
    maps: &[OfficialUpvalueMap],
    inputs: &[OfficialFrameInput],
    calls: &[OfficialInternalCall],
    refs: &[PrototypeRef<'_>],
    limits: &VerifyLimits,
) -> Result<VerifiedModule, OfficialTranslationError> {
    let fail = |detail| invalid(ProtoId(0), 0, detail);
    let mut root_bindings = Vec::new();
    root_bindings
        .try_reserve_bounded_exact(roots.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "P05 root 描述配置失敗"))?;
    for root in roots {
        let source = match root.source {
            OfficialRootBindingSource::ExternalEnvironment => {
                OfficialPlanRootSource::ExternalEnvironment
            }
            OfficialRootBindingSource::InitialNil => OfficialPlanRootSource::InitialNil,
            OfficialRootBindingSource::FixedBuiltin(kind) => {
                OfficialPlanRootSource::FixedBuiltin(plan_builtin(kind))
            }
        };
        root_bindings.push(OfficialPlanRootBinding {
            upvalue: root.upvalue,
            source,
        });
    }
    let mut upvalue_maps = Vec::new();
    upvalue_maps
        .try_reserve_bounded_exact(maps.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "P05 upvalue 描述配置失敗"))?;
    for (index, map) in maps.iter().enumerate() {
        let guest_start = verified.module().prototypes[index]
            .binding_registers
            .iter()
            .find_map(|(binding, register)| {
                (binding.function == map.prototype.0 && binding.ordinal == 1).then_some(*register)
            })
            .ok_or_else(|| fail("P05 guest R0 binding 缺失"))?;
        let mut hidden = Vec::new();
        hidden
            .try_reserve_bounded_exact(map.hidden.len())
            .map_err(|error| {
                reserve_failure(error, ProtoId(0), 0, "P05 hidden upvalue 描述配置失敗")
            })?;
        for &(kind, upvalue) in &map.hidden {
            hidden.push((plan_builtin(kind), upvalue));
        }
        upvalue_maps.push(OfficialPlanUpvalueMap {
            prototype: map.prototype,
            guest_count: map.guest_count,
            guest_start,
            guest_register_count: u16::from(refs[index].source.max_stack_size),
            hidden,
        });
    }
    let mut frame_inputs = Vec::new();
    frame_inputs
        .try_reserve_bounded_exact(inputs.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "P05 frame input 描述配置失敗"))?;
    for input in inputs {
        let source = match input.source {
            OfficialFrameInputSource::OriginalVarargs => {
                OfficialPlanFrameInputSource::OriginalVarargs
            }
            OfficialFrameInputSource::GuestNamedVarargTable => {
                OfficialPlanFrameInputSource::GuestNamedVarargTable
            }
            OfficialFrameInputSource::ActiveVarargs => OfficialPlanFrameInputSource::ActiveVarargs,
        };
        frame_inputs.push(OfficialPlanFrameInput {
            prototype: input.prototype,
            register: input.register,
            source,
        });
    }
    let mut plan_calls = Vec::new();
    plan_calls
        .try_reserve_bounded_exact(calls.len())
        .map_err(|error| reserve_failure(error, ProtoId(0), 0, "P05 Call 描述配置失敗"))?;
    for call in calls {
        let mut inputs = Vec::new();
        inputs
            .try_reserve_bounded_exact(call.inputs.len())
            .map_err(|error| reserve_failure(error, ProtoId(0), 0, "P05 Call 輸入描述配置失敗"))?;
        inputs.extend_from_slice(&call.inputs);
        plan_calls.push(OfficialPlanCall {
            prototype: call.prototype,
            call_pc: call.call_pc,
            function_register: call.function_register,
            source_upvalue: call.source_upvalue,
            inputs,
            open_tail: call.open_tail,
            builtin: plan_builtin(call.builtin),
        });
    }
    verify_official_execution_plan(
        verified,
        OfficialPlanCandidate {
            root_bindings,
            upvalue_maps,
            frame_inputs,
            calls: plan_calls,
        },
        limits,
    )
    .map_err(from_bytecode_error)
}

fn translate_prototype(
    entry: &PrototypeRef<'_>,
    refs: &[PrototypeRef<'_>],
    validated: &ValidatedCode,
    upvalue_maps: &[OfficialUpvalueMap],
    profile: LuaProfile,
    limits: &VerifyLimits,
    metadata_bytes: &mut usize,
    artifact_bytes: &mut usize,
    work: &mut OfficialWorkBudget,
) -> Result<
    (
        BytecodePrototype,
        OfficialPcMap,
        Vec<OfficialInternalCall>,
        Vec<OfficialFrameInput>,
    ),
    OfficialTranslationError,
> {
    let source = entry.source;
    let close_states = analyze_close_flow(entry, &validated, profile)?;
    let open_plans = plan_open_lists(entry, validated, profile)?;
    if source.code.is_empty() {
        return Err(invalid(entry.id, 0, "官方 prototype 不可無指令"));
    }
    if source.max_stack_size == 0 || source.num_params > source.max_stack_size {
        return Err(invalid(entry.id, 0, "官方 frame size 或參數無效"));
    }
    // P05 的 R0 保留給呼叫入口，參數從 R1 起；環境置於參數後方。
    let environment = Register(u16::from(source.num_params) + 1);
    let scratch = Register(environment.0 + 1);
    let scratch1 = Register(environment.0 + 2);
    let scratch2 = Register(environment.0 + 3);
    let builtin_base = Register(environment.0 + 4);
    let maximum_list = validated
        .ops
        .iter()
        .filter(|op| op.opcode == 78)
        .map(|op| {
            if profile == LuaProfile::Lua55 {
                op.vb
            } else {
                op.b
            }
        })
        .max()
        .unwrap_or(0);
    let tuple_start = builtin_base
        .0
        .checked_add(maximum_list.max(3) + 4)
        .ok_or_else(|| invalid(entry.id, 0, "frame register 溢位"))?;
    let mut next_tuple = tuple_start;
    let mut numeric_tuples = Vec::new();
    numeric_tuples
        .try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "numeric tuple 配置失敗"))?;
    numeric_tuples.resize(source.code.len(), None);
    for (pc, op) in validated.ops.iter().enumerate() {
        if op.opcode != 74 {
            continue;
        }
        let loop_pc = pc + op.bx as usize + 1;
        let visible = Register(op.a + if profile == LuaProfile::Lua54 { 3 } else { 2 });
        let tuple = (
            Register(next_tuple),
            Register(next_tuple + 1),
            Register(next_tuple + 2),
            visible,
        );
        next_tuple = next_tuple
            .checked_add(3)
            .ok_or_else(|| invalid(entry.id, pc, "numeric tuple register 溢位"))?;
        numeric_tuples[pc] = Some(tuple);
        numeric_tuples[loop_pc] = Some(tuple);
    }
    let backup_base = next_tuple;
    let raw_varargs = Register(backup_base);
    let active_varargs = Register(
        backup_base
            .checked_add(1)
            .ok_or_else(|| invalid(entry.id, 0, "active vararg register 溢位"))?,
    );
    let guest_base = backup_base
        .checked_add(6)
        .ok_or_else(|| invalid(entry.id, 0, "guest register 偏移溢位"))?;
    let open_base = Register(guest_base - 4);
    let register_count = guest_base
        .checked_add(u16::from(source.max_stack_size))
        .ok_or_else(|| invalid(entry.id, 0, "frame register 溢位"))?;
    if register_count > limits.max_registers {
        return Err(limited(entry.id, 0, "frame register 超過 P05 限制"));
    }
    let guest = |register: u16| Register(guest_base + register);
    for tuple in numeric_tuples.iter_mut().flatten() {
        tuple.3 = guest(tuple.3.0);
    }
    let global_environment_binding = BytecodeBindingId {
        function: entry.id.0,
        ordinal: 0,
    };
    let mut binding_registers = Vec::new();
    binding_registers
        .try_reserve_bounded_exact(2 + usize::from(source.max_stack_size) + source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "binding register 配置失敗"))?;
    binding_registers.push((global_environment_binding, environment));
    for register in 0..u16::from(source.max_stack_size) {
        binding_registers.push((
            BytecodeBindingId {
                function: entry.id.0,
                ordinal: u32::from(register) + 1,
            },
            guest(register),
        ));
    }
    let uses_active_varargs =
        profile == LuaProfile::Lua55 && validated.ops.iter().any(|op| op.opcode == 80);
    let active_vararg_binding = BytecodeBindingId {
        function: entry.id.0,
        ordinal: u32::from(source.max_stack_size)
            .checked_add(
                u32::try_from(source.code.len())
                    .map_err(|_| invalid(entry.id, 0, "active vararg binding ID 溢位"))?,
            )
            .and_then(|ordinal| ordinal.checked_add(1))
            .ok_or_else(|| invalid(entry.id, 0, "active vararg binding ID 溢位"))?,
    };
    if uses_active_varargs {
        binding_registers.push((active_vararg_binding, active_varargs));
    }
    let mut upvalues = Vec::new();
    upvalues
        .try_reserve_bounded_exact(
            upvalue_maps[entry.id.0 as usize].guest_count as usize
                + upvalue_maps[entry.id.0 as usize].hidden.len(),
        )
        .map_err(|error| reserve_failure(error, entry.id, 0, "upvalue 配置失敗"))?;
    for (index, upvalue) in source.upvalues.iter().enumerate() {
        let origin = if let Some(parent) = entry.parent {
            let parent_source = refs[parent.0 as usize].source;
            if upvalue.in_stack {
                if upvalue.index >= parent_source.max_stack_size {
                    return Err(invalid(entry.id, 0, "upvalue parent register 無效"));
                }
                BytecodeUpvalueSource::ParentLocal(BytecodeBindingId {
                    function: parent.0,
                    ordinal: u32::from(upvalue.index) + 1,
                })
            } else {
                if usize::from(upvalue.index) >= parent_source.upvalues.len() {
                    return Err(invalid(entry.id, 0, "upvalue parent index 無效"));
                }
                BytecodeUpvalueSource::ParentUpvalue(UpvalueId(u16::from(upvalue.index)))
            }
        } else {
            BytecodeUpvalueSource::ParentLocal(global_environment_binding)
        };
        upvalues.push(BytecodeUpvalue {
            id: UpvalueId(index as u16),
            source: origin,
        });
    }
    for &(kind, hidden_id) in &upvalue_maps[entry.id.0 as usize].hidden {
        let origin = if let Some(parent) = entry.parent {
            let parent_id = upvalue_maps[parent.0 as usize]
                .hidden
                .iter()
                .find_map(|(candidate, id)| (*candidate == kind).then_some(*id))
                .ok_or_else(|| invalid(entry.id, 0, "parent hidden binding 缺失"))?;
            BytecodeUpvalueSource::ParentUpvalue(parent_id)
        } else {
            BytecodeUpvalueSource::ParentLocal(global_environment_binding)
        };
        upvalues.push(BytecodeUpvalue {
            id: hidden_id,
            source: origin,
        });
    }
    let mut constants = Vec::new();
    for constant in &source.constants {
        let copied = match constant {
            OfficialConstant::Nil => BytecodeConstant::Boolean(false),
            OfficialConstant::Boolean(value) => BytecodeConstant::Boolean(*value),
            OfficialConstant::Integer(value) => BytecodeConstant::Integer(*value),
            OfficialConstant::Number(value) => BytecodeConstant::FloatBits(value.to_bits()),
            OfficialConstant::String { bytes, .. } => {
                let mut copy = Vec::new();
                copy.try_reserve_bounded_exact(bytes.len())
                    .map_err(|error| reserve_failure(error, entry.id, 0, "字串常數配置失敗"))?;
                copy.extend_from_slice(bytes);
                BytecodeConstant::String(copy)
            }
        };
        append_constant(&mut constants, limits, entry.id, 0, copied)?;
    }
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: source.code.len() as u64 * 4,
    };
    let mut instructions = Vec::new();
    let mut mapping = Vec::new();
    charge_artifact_bytes(
        artifact_bytes,
        source
            .code
            .len()
            .checked_mul(size_of::<Option<InstructionOffset>>())
            .ok_or_else(|| invalid(entry.id, 0, "正向 PC map bytes 溢位"))?,
        limits.max_artifact_bytes,
        entry.id,
        0,
    )?;
    mapping
        .try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "PC mapping 配置失敗"))?;
    charge_artifact_bytes(
        artifact_bytes,
        (mapping.capacity() - source.code.len()) * size_of::<Option<InstructionOffset>>(),
        limits.max_artifact_bytes,
        entry.id,
        0,
    )?;
    let mut patches = Vec::<(usize, usize)>::new();
    patches
        .try_reserve_bounded_exact(
            source
                .code
                .len()
                .checked_mul(2)
                .ok_or_else(|| invalid(entry.id, 0, "CFG patch 數溢位"))?,
        )
        .map_err(|error| reserve_failure(error, entry.id, 0, "CFG patch 配置失敗"))?;
    let mut numeric_exit_patches = Vec::<(usize, usize)>::new();
    numeric_exit_patches
        .try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "numeric exit 配置失敗"))?;
    let mut internal_calls = Vec::new();
    internal_calls
        .try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "內部 Call mapping 配置失敗"))?;
    let mut close_paths = Vec::new();
    close_paths
        .try_reserve_bounded_exact(source.code.len())
        .map_err(|error| reserve_failure(error, entry.id, 0, "close path 配置失敗"))?;
    let mut captured_flags = [false; 256];
    for child in refs.iter().filter(|child| child.parent == Some(entry.id)) {
        for upvalue in &child.source.upvalues {
            if upvalue.in_stack {
                if upvalue.index >= source.max_stack_size {
                    return Err(invalid(child.id, 0, "upvalue parent register 無效"));
                }
                captured_flags[upvalue.index as usize] = true;
            }
        }
    }
    let mut captured = Vec::new();
    captured
        .try_reserve_bounded_exact(usize::from(source.max_stack_size))
        .map_err(|error| reserve_failure(error, entry.id, 0, "captured register 配置失敗"))?;
    for (register, needed) in captured_flags.into_iter().enumerate() {
        if needed {
            captured.push(guest(register as u16));
        }
    }
    let pc = 0usize;
    for register in (0..u16::from(source.num_params)).rev() {
        push_instruction(
            &mut instructions,
            limits,
            entry.id,
            pc,
            entry_at(
                0,
                Instruction::Move {
                    dest: guest(register),
                    src: Register(register + 1),
                },
            ),
        )?;
    }
    for pc in 0..source.code.len() {
        if validated.data[pc] {
            mapping.push(None);
            continue;
        }
        mapping.push(Some(InstructionOffset(instructions.len() as u32)));
        let decoded = validated.ops[pc];
        if let Some(sink) = open_plans.preparation_at[pc] {
            let builtin = OfficialFixedBuiltin::RawListWrite;
            let source_upvalue = hidden_upvalue(upvalue_maps, entry.id, sink, builtin)?;
            let first = list_first_index(entry, validated, sink, profile)?;
            let table = guest(validated.ops[sink].a);
            let first_id = append_constant(
                &mut constants,
                limits,
                entry.id,
                pc,
                BytecodeConstant::Integer(first),
            )?;
            let skip_id = append_constant(
                &mut constants,
                limits,
                entry.id,
                pc,
                BytecodeConstant::Integer(i64::from(validated.ops[sink].a) + 1),
            )?;
            push_instruction(
                &mut instructions,
                limits,
                entry.id,
                pc,
                entry_at(
                    pc,
                    Instruction::GetUpvalue {
                        dest: open_base,
                        upvalue: source_upvalue,
                    },
                ),
            )?;
            push_instruction(
                &mut instructions,
                limits,
                entry.id,
                pc,
                entry_at(
                    pc,
                    Instruction::Move {
                        dest: Register(open_base.0 + 1),
                        src: table,
                    },
                ),
            )?;
            push_instruction(
                &mut instructions,
                limits,
                entry.id,
                pc,
                entry_at(
                    pc,
                    Instruction::LoadConst {
                        dest: Register(open_base.0 + 2),
                        constant: first_id,
                    },
                ),
            )?;
            push_instruction(
                &mut instructions,
                limits,
                entry.id,
                pc,
                entry_at(
                    pc,
                    Instruction::LoadConst {
                        dest: Register(open_base.0 + 3),
                        constant: skip_id,
                    },
                ),
            )?;
        }
        if usize::from(decoded.opcode)
            >= match profile {
                LuaProfile::Lua54 => 83,
                LuaProfile::Lua55 => 85,
            }
        {
            return Err(invalid(entry.id, pc, "未知官方 opcode"));
        }
        if decoded.opcode == 55 {
            if close_states[pc].is_some() {
                emit_close_marker(
                    entry,
                    pc,
                    guest(decoded.a),
                    limits,
                    &mut binding_registers,
                    &mut instructions,
                    metadata_bytes,
                )?;
            } else {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: scratch,
                            src: scratch,
                        },
                    ),
                )?;
            }
            continue;
        }
        if decoded.opcode == 54 {
            let start = instructions.len();
            emit_close_sequence(
                entry,
                pc,
                decoded.a,
                guest_base,
                limits,
                BytecodeExitKind::Normal,
                close_states[pc].clone().flatten(),
                &captured,
                &mut instructions,
                &mut close_paths,
                metadata_bytes,
            )?;
            if instructions.len() == start {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: scratch,
                            src: scratch,
                        },
                    ),
                )?;
            }
            continue;
        }
        if decoded.opcode == 69 {
            let active = active_closes(close_states[pc].clone().flatten(), 0, entry.id, pc)?;
            if !active.is_empty() || !captured.is_empty() {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Call {
                            base: guest(decoded.a),
                            arg_count: if decoded.b == 0 {
                                u16::MAX
                            } else {
                                decoded.b - 1
                            },
                            result_mode: ResultMode::All,
                        },
                    ),
                )?;
                emit_close_sequence(
                    entry,
                    pc,
                    0,
                    guest_base,
                    limits,
                    BytecodeExitKind::Return,
                    close_states[pc].clone().flatten(),
                    &captured,
                    &mut instructions,
                    &mut close_paths,
                    metadata_bytes,
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Return {
                            base: guest(decoded.a),
                            result_mode: ResultMode::All,
                        },
                    ),
                )?;
                continue;
            }
        }
        if (70..=72).contains(&decoded.opcode) {
            emit_close_sequence(
                entry,
                pc,
                0,
                guest_base,
                limits,
                BytecodeExitKind::Return,
                close_states[pc].clone().flatten(),
                &captured,
                &mut instructions,
                &mut close_paths,
                metadata_bytes,
            )?;
        }
        let instruction = match decoded.opcode {
            0 => Instruction::Move {
                dest: guest(decoded.a),
                src: guest(decoded.b),
            },
            1 | 2 => {
                let constant = if decoded.opcode == 1 {
                    append_constant(
                        &mut constants,
                        limits,
                        entry.id,
                        pc,
                        BytecodeConstant::Integer(i64::from(decoded.sbx)),
                    )?
                } else {
                    append_constant(
                        &mut constants,
                        limits,
                        entry.id,
                        pc,
                        BytecodeConstant::FloatBits(f64::from(decoded.sbx).to_bits()),
                    )?
                };
                Instruction::LoadConst {
                    dest: guest(decoded.a),
                    constant,
                }
            }
            3 => original_constant_load(source, guest(decoded.a), decoded.bx),
            4 => original_constant_load(source, guest(decoded.a), validated.ops[pc + 1].ax),
            5 | 7 => {
                let constant = append_constant(
                    &mut constants,
                    limits,
                    entry.id,
                    pc,
                    BytecodeConstant::Boolean(decoded.opcode == 7),
                )?;
                Instruction::LoadConst {
                    dest: guest(decoded.a),
                    constant,
                }
            }
            8 => Instruction::LoadNil {
                start: guest(decoded.a),
                count: decoded.b + 1,
            },
            9 => Instruction::GetUpvalue {
                dest: guest(decoded.a),
                upvalue: UpvalueId(decoded.b),
            },
            10 => Instruction::SetUpvalue {
                upvalue: UpvalueId(decoded.b),
                src: guest(decoded.a),
            },
            11 => {
                let get = Instruction::GetUpvalue {
                    dest: scratch,
                    upvalue: UpvalueId(decoded.b),
                };
                push_instruction(&mut instructions, limits, entry.id, pc, entry_at(pc, get))?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        original_constant_load(source, scratch1, u32::from(decoded.c)),
                    ),
                )?;
                Instruction::GetTable {
                    dest: guest(decoded.a),
                    table: scratch,
                    key: scratch1,
                }
            }
            12 => Instruction::GetTable {
                dest: guest(decoded.a),
                table: guest(decoded.b),
                key: guest(decoded.c),
            },
            13 => {
                let key = append_constant(
                    &mut constants,
                    limits,
                    entry.id,
                    pc,
                    BytecodeConstant::Integer(i64::from(decoded.c)),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::LoadConst {
                            dest: scratch,
                            constant: key,
                        },
                    ),
                )?;
                Instruction::GetTable {
                    dest: guest(decoded.a),
                    table: guest(decoded.b),
                    key: scratch,
                }
            }
            14 => {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        original_constant_load(source, scratch, u32::from(decoded.c)),
                    ),
                )?;
                Instruction::GetTable {
                    dest: guest(decoded.a),
                    table: guest(decoded.b),
                    key: scratch,
                }
            }
            15 => {
                let get = Instruction::GetUpvalue {
                    dest: scratch,
                    upvalue: UpvalueId(decoded.a),
                };
                push_instruction(&mut instructions, limits, entry.id, pc, entry_at(pc, get))?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        original_constant_load(source, scratch1, u32::from(decoded.b)),
                    ),
                )?;
                let value = if decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch2, u32::from(decoded.c)),
                        ),
                    )?;
                    scratch2
                } else {
                    guest(decoded.c)
                };
                Instruction::SetTable {
                    table: scratch,
                    key: scratch1,
                    value,
                }
            }
            16 => {
                let value = if decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch, u32::from(decoded.c)),
                        ),
                    )?;
                    scratch
                } else {
                    guest(decoded.c)
                };
                Instruction::SetTable {
                    table: guest(decoded.a),
                    key: guest(decoded.b),
                    value,
                }
            }
            17 => {
                let key = append_constant(
                    &mut constants,
                    limits,
                    entry.id,
                    pc,
                    BytecodeConstant::Integer(i64::from(decoded.b)),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::LoadConst {
                            dest: scratch,
                            constant: key,
                        },
                    ),
                )?;
                let value = if decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch1, u32::from(decoded.c)),
                        ),
                    )?;
                    scratch1
                } else {
                    guest(decoded.c)
                };
                Instruction::SetTable {
                    table: guest(decoded.a),
                    key: scratch,
                    value,
                }
            }
            18 => {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        original_constant_load(source, scratch, u32::from(decoded.b)),
                    ),
                )?;
                let value = if decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch1, u32::from(decoded.c)),
                        ),
                    )?;
                    scratch1
                } else {
                    guest(decoded.c)
                };
                Instruction::SetTable {
                    table: guest(decoded.a),
                    key: scratch,
                    value,
                }
            }
            19 => Instruction::NewTable {
                dest: guest(decoded.a),
            },
            20 => {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: scratch,
                            src: guest(decoded.b),
                        },
                    ),
                )?;
                let key = if profile == LuaProfile::Lua55 || decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch1, u32::from(decoded.c)),
                        ),
                    )?;
                    scratch1
                } else {
                    guest(decoded.c)
                };
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: guest(decoded.a + 1),
                            src: scratch,
                        },
                    ),
                )?;
                Instruction::GetTable {
                    dest: guest(decoded.a),
                    table: scratch,
                    key,
                }
            }
            21..=45 => {
                let shift_left_immediate = if profile == LuaProfile::Lua55 { 32 } else { 33 };
                let shift_right_immediate = if profile == LuaProfile::Lua55 { 33 } else { 32 };
                let mut op = arithmetic_operation(decoded.opcode).unwrap_or(
                    if decoded.opcode == shift_right_immediate {
                        BinaryOperation::ShiftRight
                    } else {
                        BinaryOperation::ShiftLeft
                    },
                );
                let mut left = guest(decoded.b);
                let mut right = guest(decoded.c);
                if decoded.opcode < 34 {
                    let adjacent = validated.ops[pc + 1];
                    let value = if decoded.opcode == 21 && adjacent.c == 7 {
                        op = BinaryOperation::Subtract;
                        i64::from(-decoded.sc)
                    } else if decoded.opcode == shift_right_immediate && decoded.sc < 0 {
                        op = BinaryOperation::ShiftLeft;
                        i64::from(-decoded.sc)
                    } else if decoded.opcode == shift_left_immediate {
                        op = BinaryOperation::ShiftLeft;
                        i64::from(decoded.sc)
                    } else {
                        i64::from(decoded.sc)
                    };
                    let constant = if (22..=31).contains(&decoded.opcode) {
                        ConstId(u32::from(decoded.c))
                    } else {
                        append_constant(
                            &mut constants,
                            limits,
                            entry.id,
                            pc,
                            BytecodeConstant::Integer(value),
                        )?
                    };
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::LoadConst {
                                dest: scratch,
                                constant,
                            },
                        ),
                    )?;
                    right = scratch;
                    if adjacent.k {
                        std::mem::swap(&mut left, &mut right);
                    }
                }
                Instruction::BinaryOp {
                    dest: guest(decoded.a),
                    op,
                    left,
                    right,
                }
            }
            49..=52 => Instruction::UnaryOp {
                dest: guest(decoded.a),
                op: match decoded.opcode {
                    49 => UnaryOperation::Negate,
                    50 => UnaryOperation::BitNot,
                    51 => UnaryOperation::Not,
                    _ => UnaryOperation::Length,
                },
                src: guest(decoded.b),
            },
            53 => {
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: scratch,
                            src: guest(decoded.a + decoded.b - 1),
                        },
                    ),
                )?;
                for register in (decoded.a..decoded.a + decoded.b - 1).rev() {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::BinaryOp {
                                dest: scratch,
                                op: BinaryOperation::Concat,
                                left: guest(register),
                                right: scratch,
                            },
                        ),
                    )?;
                }
                Instruction::Move {
                    dest: guest(decoded.a),
                    src: scratch,
                }
            }
            6 => {
                let constant = append_constant(
                    &mut constants,
                    limits,
                    entry.id,
                    pc,
                    BytecodeConstant::Boolean(false),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::LoadConst {
                            dest: guest(decoded.a),
                            constant,
                        },
                    ),
                )?;
                patches.push((instructions.len(), pc + 2));
                Instruction::Jump {
                    target: InstructionOffset(0),
                }
            }
            56 => {
                let target = checked_target(
                    entry,
                    pc,
                    pc as i64 + 1 + i64::from(decoded.sj),
                    &validated.data,
                )?;
                if target == pc {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: scratch2,
                                src: scratch2,
                            },
                        ),
                    )?;
                }
                patches.push((instructions.len(), target));
                Instruction::Jump {
                    target: InstructionOffset(0),
                }
            }
            57..=65 => {
                let operation = match decoded.opcode {
                    57 | 60 | 61 => BinaryOperation::Equal,
                    58 | 62 => BinaryOperation::Less,
                    59 | 63 => BinaryOperation::LessEqual,
                    64 => BinaryOperation::Greater,
                    65 => BinaryOperation::GreaterEqual,
                    _ => return Err(invalid(entry.id, pc, "比較 opcode 對應缺失")),
                };
                let right = if decoded.opcode == 60 {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            original_constant_load(source, scratch1, u32::from(decoded.b)),
                        ),
                    )?;
                    scratch1
                } else if decoded.opcode >= 61 {
                    let constant = append_constant(
                        &mut constants,
                        limits,
                        entry.id,
                        pc,
                        BytecodeConstant::Integer(i64::from(decoded.sb)),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::LoadConst {
                                dest: scratch1,
                                constant,
                            },
                        ),
                    )?;
                    scratch1
                } else {
                    guest(decoded.b)
                };
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::BinaryOp {
                            dest: scratch,
                            op: operation,
                            left: guest(decoded.a),
                            right,
                        },
                    ),
                )?;
                if !decoded.k {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::UnaryOp {
                                dest: scratch,
                                op: UnaryOperation::Not,
                                src: scratch,
                            },
                        ),
                    )?;
                }
                patches.push((instructions.len(), pc + 2));
                Instruction::JumpIfFalse {
                    condition: scratch,
                    target: InstructionOffset(0),
                }
            }
            66 => {
                let condition = if decoded.k {
                    Instruction::Move {
                        dest: scratch,
                        src: guest(decoded.a),
                    }
                } else {
                    Instruction::UnaryOp {
                        dest: scratch,
                        op: UnaryOperation::Not,
                        src: guest(decoded.a),
                    }
                };
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    BytecodeInstruction {
                        instruction: condition,
                        span: BytecodeSpan {
                            start_byte: pc as u64 * 4,
                            end_byte: (pc as u64 + 1) * 4,
                        },
                        close_path: None,
                    },
                )?;
                patches.push((instructions.len(), pc + 2));
                Instruction::JumpIfFalse {
                    condition: scratch,
                    target: InstructionOffset(0),
                }
            }
            67 => {
                let condition = if decoded.k {
                    Instruction::Move {
                        dest: scratch,
                        src: guest(decoded.b),
                    }
                } else {
                    Instruction::UnaryOp {
                        dest: scratch,
                        op: UnaryOperation::Not,
                        src: guest(decoded.b),
                    }
                };
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(pc, condition),
                )?;
                patches.push((instructions.len(), pc + 2));
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::JumpIfFalse {
                            condition: scratch,
                            target: InstructionOffset(0),
                        },
                    ),
                )?;
                Instruction::Move {
                    dest: guest(decoded.a),
                    src: guest(decoded.b),
                }
            }
            68 => Instruction::Call {
                base: guest(decoded.a),
                arg_count: if decoded.b == 0 {
                    u16::MAX
                } else {
                    decoded.b - 1
                },
                result_mode: if decoded.c == 0 {
                    ResultMode::All
                } else {
                    ResultMode::Fixed(decoded.c - 1)
                },
            },
            69 => Instruction::TailCall {
                base: guest(decoded.a),
                arg_count: if decoded.b == 0 {
                    u16::MAX
                } else {
                    decoded.b - 1
                },
                result_mode: ResultMode::All,
            },
            70 => Instruction::Return {
                base: if decoded.b == 1 {
                    guest(0)
                } else {
                    guest(decoded.a)
                },
                result_mode: if decoded.b == 0 {
                    ResultMode::All
                } else {
                    ResultMode::Fixed(decoded.b - 1)
                },
            },
            71 => Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            },
            72 => Instruction::Return {
                base: guest(decoded.a),
                result_mode: ResultMode::Fixed(1),
            },
            73 => {
                let (control, limit, step, visible) = numeric_tuples[pc]
                    .ok_or_else(|| invalid(entry.id, pc, "FORLOOP 缺配對 tuple"))?;
                let target = (pc + 1)
                    .checked_sub(decoded.bx as usize)
                    .ok_or_else(|| invalid(entry.id, pc, "FORLOOP 回邊欠位"))?;
                let exit = pc + 1;
                patches.push((instructions.len(), target));
                numeric_exit_patches.push((instructions.len(), exit));
                Instruction::NumericForNext {
                    control,
                    limit,
                    step,
                    visible,
                    target: InstructionOffset(0),
                    exit: InstructionOffset(0),
                }
            }
            74 => {
                let (control, limit, step, visible) = numeric_tuples[pc]
                    .ok_or_else(|| invalid(entry.id, pc, "FORPREP 缺配對 tuple"))?;
                for (dest, src) in [
                    (control, decoded.a),
                    (limit, decoded.a + 1),
                    (step, decoded.a + 2),
                ] {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest,
                                src: guest(src),
                            },
                        ),
                    )?;
                }
                patches.push((instructions.len(), pc + decoded.bx as usize + 2));
                Instruction::NumericForPrepare {
                    control,
                    limit,
                    step,
                    visible,
                    exit: InstructionOffset(0),
                }
            }
            75 => {
                if profile == LuaProfile::Lua55 {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: scratch,
                                src: guest(decoded.a + 2),
                            },
                        ),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: guest(decoded.a + 2),
                                src: guest(decoded.a + 3),
                            },
                        ),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: guest(decoded.a + 3),
                                src: scratch,
                            },
                        ),
                    )?;
                }
                if close_states[pc].is_some() {
                    let closing =
                        guest(decoded.a + if profile == LuaProfile::Lua54 { 3 } else { 2 });
                    emit_close_marker(
                        entry,
                        pc,
                        closing,
                        limits,
                        &mut binding_registers,
                        &mut instructions,
                        metadata_bytes,
                    )?;
                }
                patches.push((instructions.len(), pc + decoded.bx as usize + 1));
                Instruction::Jump {
                    target: InstructionOffset(0),
                }
            }
            76 => {
                let call_base = guest(decoded.a + if profile == LuaProfile::Lua54 { 4 } else { 3 });
                let control = guest(decoded.a + if profile == LuaProfile::Lua54 { 2 } else { 3 });
                for (dest, src) in [
                    (scratch, guest(decoded.a)),
                    (scratch1, guest(decoded.a + 1)),
                    (scratch2, control),
                ] {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(pc, Instruction::Move { dest, src }),
                    )?;
                }
                for (dest, src) in [
                    (call_base, scratch),
                    (Register(call_base.0 + 1), scratch1),
                    (Register(call_base.0 + 2), scratch2),
                ] {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(pc, Instruction::Move { dest, src }),
                    )?;
                }
                Instruction::Call {
                    base: call_base,
                    arg_count: 2,
                    result_mode: ResultMode::Fixed(decoded.c),
                }
            }
            77 => {
                let result = guest(decoded.a + if profile == LuaProfile::Lua54 { 4 } else { 3 });
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::LoadNil {
                            start: scratch,
                            count: 1,
                        },
                    ),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::BinaryOp {
                            dest: scratch1,
                            op: BinaryOperation::Equal,
                            left: result,
                            right: scratch,
                        },
                    ),
                )?;
                let target = (pc + 1)
                    .checked_sub(decoded.bx as usize)
                    .ok_or_else(|| invalid(entry.id, pc, "TFORLOOP 回邊欠位"))?;
                if profile == LuaProfile::Lua55 {
                    patches.push((instructions.len(), target));
                    Instruction::JumpIfFalse {
                        condition: scratch1,
                        target: InstructionOffset(0),
                    }
                } else {
                    let move_index = instructions.len() + 2;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::JumpIfFalse {
                                condition: scratch1,
                                target: InstructionOffset(move_index as u32),
                            },
                        ),
                    )?;
                    patches.push((instructions.len(), pc + 1));
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Jump {
                                target: InstructionOffset(0),
                            },
                        ),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: guest(decoded.a + 2),
                                src: result,
                            },
                        ),
                    )?;
                    patches.push((instructions.len(), target));
                    Instruction::Jump {
                        target: InstructionOffset(0),
                    }
                }
            }
            78 => {
                let count = if profile == LuaProfile::Lua55 {
                    decoded.vb
                } else {
                    decoded.b
                };
                let builtin = OfficialFixedBuiltin::RawListWrite;
                let source_upvalue = hidden_upvalue(upvalue_maps, entry.id, pc, builtin)?;
                if count == 0 {
                    let producer_pc = open_plans.producer_at[pc]
                        .ok_or_else(|| invalid(entry.id, pc, "開放 SETLIST producer 映射缺失"))?;
                    let producer = guest(validated.ops[producer_pc].a);
                    let call_pc = InstructionOffset(instructions.len() as u32);
                    let mut inputs = Vec::new();
                    inputs
                        .try_reserve_bounded_exact(usize::from(producer.0 - open_base.0 - 1))
                        .map_err(|error| {
                            reserve_failure(error, entry.id, pc, "開放 SETLIST 引數索引配置失敗")
                        })?;
                    for register in open_base.0 + 1..producer.0 {
                        inputs.push(Register(register));
                    }
                    internal_calls.push(OfficialInternalCall {
                        prototype: entry.id,
                        source_pc: pc,
                        call_pc,
                        function_register: open_base,
                        source_upvalue,
                        inputs,
                        open_tail: Some(producer),
                        builtin,
                    });
                    Instruction::Call {
                        base: open_base,
                        arg_count: u16::MAX,
                        result_mode: ResultMode::Fixed(0),
                    }
                } else {
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::GetUpvalue {
                                dest: builtin_base,
                                upvalue: source_upvalue,
                            },
                        ),
                    )?;
                    let first = list_first_index(entry, validated, pc, profile)?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::Move {
                                dest: Register(builtin_base.0 + 1),
                                src: guest(decoded.a),
                            },
                        ),
                    )?;
                    let index = append_constant(
                        &mut constants,
                        limits,
                        entry.id,
                        pc,
                        BytecodeConstant::Integer(first),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::LoadConst {
                                dest: Register(builtin_base.0 + 2),
                                constant: index,
                            },
                        ),
                    )?;
                    let skip = append_constant(
                        &mut constants,
                        limits,
                        entry.id,
                        pc,
                        BytecodeConstant::Integer(0),
                    )?;
                    push_instruction(
                        &mut instructions,
                        limits,
                        entry.id,
                        pc,
                        entry_at(
                            pc,
                            Instruction::LoadConst {
                                dest: Register(builtin_base.0 + 3),
                                constant: skip,
                            },
                        ),
                    )?;
                    for offset in 0..count {
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::Move {
                                    dest: Register(builtin_base.0 + 4 + offset),
                                    src: guest(decoded.a + 1 + offset),
                                },
                            ),
                        )?;
                    }
                    let call_pc = InstructionOffset(instructions.len() as u32);
                    let mut inputs = Vec::new();
                    inputs
                        .try_reserve_bounded_exact(usize::from(count + 3))
                        .map_err(|error| {
                            reserve_failure(error, entry.id, pc, "SETLIST 引數索引配置失敗")
                        })?;
                    for offset in 1..=count + 3 {
                        inputs.push(Register(builtin_base.0 + offset));
                    }
                    internal_calls.push(OfficialInternalCall {
                        prototype: entry.id,
                        source_pc: pc,
                        call_pc,
                        function_register: builtin_base,
                        source_upvalue,
                        inputs,
                        open_tail: None,
                        builtin,
                    });
                    Instruction::Call {
                        base: builtin_base,
                        arg_count: count + 3,
                        result_mode: ResultMode::Fixed(0),
                    }
                }
            }
            79 => Instruction::Closure {
                dest: guest(decoded.a),
                proto: entry.children[decoded.bx as usize],
            },
            80 => {
                if profile == LuaProfile::Lua55 {
                    if decoded.k {
                        let builtin = OfficialFixedBuiltin::PackUnpack;
                        let source_upvalue = hidden_upvalue(upvalue_maps, entry.id, pc, builtin)?;
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::GetUpvalue {
                                    dest: builtin_base,
                                    upvalue: source_upvalue,
                                },
                            ),
                        )?;
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::Move {
                                    dest: Register(builtin_base.0 + 1),
                                    src: guest(decoded.b),
                                },
                            ),
                        )?;
                        let wanted = if decoded.c == 0 {
                            -1
                        } else {
                            i64::from(decoded.c - 1)
                        };
                        let count = append_constant(
                            &mut constants,
                            limits,
                            entry.id,
                            pc,
                            BytecodeConstant::Integer(wanted),
                        )?;
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::LoadConst {
                                    dest: Register(builtin_base.0 + 2),
                                    constant: count,
                                },
                            ),
                        )?;
                        let call_pc = InstructionOffset(instructions.len() as u32);
                        let mut inputs = Vec::new();
                        inputs.try_reserve_bounded_exact(2).map_err(|error| {
                            reserve_failure(error, entry.id, pc, "PackUnpack 引數索引配置失敗")
                        })?;
                        inputs.extend([Register(builtin_base.0 + 1), Register(builtin_base.0 + 2)]);
                        internal_calls.push(OfficialInternalCall {
                            prototype: entry.id,
                            source_pc: pc,
                            call_pc,
                            function_register: builtin_base,
                            source_upvalue,
                            inputs,
                            open_tail: None,
                            builtin,
                        });
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::Call {
                                    base: builtin_base,
                                    arg_count: 2,
                                    result_mode: ResultMode::Fixed(1),
                                },
                            ),
                        )?;
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::Move {
                                    dest: active_varargs,
                                    src: builtin_base,
                                },
                            ),
                        )?;
                    } else {
                        push_instruction(
                            &mut instructions,
                            limits,
                            entry.id,
                            pc,
                            entry_at(
                                pc,
                                Instruction::Move {
                                    dest: active_varargs,
                                    src: raw_varargs,
                                },
                            ),
                        )?;
                    }
                }
                Instruction::Vararg {
                    base: guest(decoded.a),
                    result_mode: if decoded.c == 0 {
                        ResultMode::All
                    } else {
                        ResultMode::Fixed(decoded.c - 1)
                    },
                }
            }
            81 if profile == LuaProfile::Lua55 => {
                let builtin = OfficialFixedBuiltin::RawVarargGet;
                let source_upvalue = hidden_upvalue(upvalue_maps, entry.id, pc, builtin)?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::GetUpvalue {
                            dest: builtin_base,
                            upvalue: source_upvalue,
                        },
                    ),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: Register(builtin_base.0 + 1),
                            src: raw_varargs,
                        },
                    ),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: Register(builtin_base.0 + 2),
                            src: guest(decoded.c),
                        },
                    ),
                )?;
                let call_pc = InstructionOffset(instructions.len() as u32);
                let mut inputs = Vec::new();
                inputs.try_reserve_bounded_exact(2).map_err(|error| {
                    reserve_failure(error, entry.id, pc, "VarargGet 引數索引配置失敗")
                })?;
                inputs.extend([Register(builtin_base.0 + 1), Register(builtin_base.0 + 2)]);
                internal_calls.push(OfficialInternalCall {
                    prototype: entry.id,
                    source_pc: pc,
                    call_pc,
                    function_register: builtin_base,
                    source_upvalue,
                    inputs,
                    open_tail: None,
                    builtin,
                });
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Call {
                            base: builtin_base,
                            arg_count: 2,
                            result_mode: ResultMode::Fixed(1),
                        },
                    ),
                )?;
                Instruction::Move {
                    dest: guest(decoded.a),
                    src: builtin_base,
                }
            }
            82 if profile == LuaProfile::Lua55 => {
                let builtin = OfficialFixedBuiltin::GlobalNilCheck;
                let source_upvalue = hidden_upvalue(upvalue_maps, entry.id, pc, builtin)?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::GetUpvalue {
                            dest: builtin_base,
                            upvalue: source_upvalue,
                        },
                    ),
                )?;
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(
                        pc,
                        Instruction::Move {
                            dest: Register(builtin_base.0 + 1),
                            src: guest(decoded.a),
                        },
                    ),
                )?;
                let name = Register(builtin_base.0 + 2);
                let load_name = if decoded.bx == 0 {
                    Instruction::LoadNil {
                        start: name,
                        count: 1,
                    }
                } else {
                    original_constant_load(source, name, decoded.bx - 1)
                };
                push_instruction(
                    &mut instructions,
                    limits,
                    entry.id,
                    pc,
                    entry_at(pc, load_name),
                )?;
                let call_pc = InstructionOffset(instructions.len() as u32);
                let mut inputs = Vec::new();
                inputs.try_reserve_bounded_exact(2).map_err(|error| {
                    reserve_failure(error, entry.id, pc, "GlobalNilCheck 引數索引配置失敗")
                })?;
                inputs.extend([Register(builtin_base.0 + 1), name]);
                internal_calls.push(OfficialInternalCall {
                    prototype: entry.id,
                    source_pc: pc,
                    call_pc,
                    function_register: builtin_base,
                    source_upvalue,
                    inputs,
                    open_tail: None,
                    builtin,
                });
                Instruction::Call {
                    base: builtin_base,
                    arg_count: 2,
                    result_mode: ResultMode::Fixed(0),
                }
            }
            opcode if opcode == varargprep_opcode(profile) => Instruction::Move {
                dest: scratch,
                src: scratch,
            },
            _ => {
                return Err(invalid(
                    entry.id,
                    pc,
                    format!("opcode {} 尚未完成轉譯", decoded.opcode),
                ));
            }
        };
        push_instruction(
            &mut instructions,
            limits,
            entry.id,
            pc,
            BytecodeInstruction {
                instruction,
                span: BytecodeSpan {
                    start_byte: pc as u64 * 4,
                    end_byte: (pc as u64 + 1) * 4,
                },
                close_path: None,
            },
        )?;
        if decoded.opcode == 78 || decoded.opcode == 82 && profile == LuaProfile::Lua55 {
            let register = if decoded.opcode == 78
                && (if profile == LuaProfile::Lua55 {
                    decoded.vb
                } else {
                    decoded.b
                }) == 0
            {
                open_base
            } else {
                builtin_base
            };
            push_instruction(
                &mut instructions,
                limits,
                entry.id,
                pc,
                entry_at(
                    pc,
                    Instruction::LoadNil {
                        start: register,
                        count: 1,
                    },
                ),
            )?;
        }
    }
    for (index, target) in patches {
        let Some(Some(target)) = mapping.get(target) else {
            return Err(invalid(entry.id, target, "轉譯 CFG target 缺失"));
        };
        match &mut instructions[index].instruction {
            Instruction::Jump { target: slot } | Instruction::JumpIfFalse { target: slot, .. } => {
                *slot = *target
            }
            Instruction::NumericForPrepare { exit, .. } => *exit = *target,
            Instruction::NumericForNext { target: slot, .. } => *slot = *target,
            _ => {
                return Err(invalid(
                    entry.id,
                    target.0 as usize,
                    "轉譯 patch 指令型別無效",
                ));
            }
        }
    }
    for (index, target) in numeric_exit_patches {
        let Some(Some(target)) = mapping.get(target) else {
            return Err(invalid(entry.id, target, "轉譯 numeric exit 缺失"));
        };
        match &mut instructions[index].instruction {
            Instruction::NumericForNext { exit, .. } => *exit = *target,
            _ => {
                return Err(invalid(
                    entry.id,
                    target.0 as usize,
                    "轉譯 numeric exit 型別無效",
                ));
            }
        }
    }
    let environment_source = match entry.parent {
        Some(parent) => EnvironmentSource::ParentFrame {
            parent,
            register: Register(u16::from(refs[parent.0 as usize].source.num_params) + 1),
        },
        None => EnvironmentSource::RootExternal,
    };
    let prototype = BytecodePrototype {
        id: entry.id,
        function: entry.id.0,
        parent: entry.parent,
        span,
        register_count,
        parameter_count: u16::from(source.num_params),
        is_variadic: match profile {
            LuaProfile::Lua54 => source.flags & 1 != 0,
            LuaProfile::Lua55 => source.flags & 3 != 0,
        },
        named_vararg: if uses_active_varargs {
            Some((active_vararg_binding, active_varargs))
        } else {
            None
        },
        frame: FrameLayout {
            register_limit: limits.max_registers,
            initial_top: Register(u16::from(source.num_params) + 1),
            dynamic_top: Register(register_count),
            return_base: Register(0),
            environment,
            environment_source,
            registers_start_as_nil: true,
        },
        global_environment: environment,
        global_environment_binding,
        binding_registers,
        constants,
        upvalues,
        instructions,
        close_paths,
    };
    let mut frame_inputs = Vec::new();
    if profile == LuaProfile::Lua55 {
        frame_inputs
            .try_reserve_bounded_exact(3)
            .map_err(|error| reserve_failure(error, entry.id, 0, "frame input 配置失敗"))?;
        if validated
            .ops
            .iter()
            .any(|op| op.opcode == 81 || op.opcode == 80 && !op.k)
        {
            frame_inputs.push(OfficialFrameInput {
                prototype: entry.id,
                register: raw_varargs,
                source: OfficialFrameInputSource::OriginalVarargs,
            });
        }
        if source.flags & 2 != 0 {
            frame_inputs.push(OfficialFrameInput {
                prototype: entry.id,
                register: guest(u16::from(source.num_params)),
                source: OfficialFrameInputSource::GuestNamedVarargTable,
            });
        }
        if uses_active_varargs {
            frame_inputs.push(OfficialFrameInput {
                prototype: entry.id,
                register: active_varargs,
                source: OfficialFrameInputSource::ActiveVarargs,
            });
        }
    }
    let pc_map = make_pc_map(
        entry,
        validated,
        mapping,
        &prototype.instructions,
        artifact_bytes,
        limits,
        work,
    )?;
    Ok((prototype, pc_map, internal_calls, frame_inputs))
}

#[cfg(test)]
mod error_kind_tests {
    use super::*;

    #[test]
    fn official_translation_preserves_failure_kinds() {
        let id = ProtoId(0);
        let mut work = OfficialWorkBudget::new(1);
        assert_eq!(
            work.charge(2, id, 0).unwrap_err().kind,
            OfficialTranslationErrorKind::LimitExceeded
        );
        assert!(work.exhausted());

        for (code, expected) in [
            (
                BytecodeErrorCode::Verify,
                OfficialTranslationErrorKind::InvalidChunk,
            ),
            (
                BytecodeErrorCode::CompileLimit,
                OfficialTranslationErrorKind::LimitExceeded,
            ),
            (
                BytecodeErrorCode::AllocationFailed,
                OfficialTranslationErrorKind::AllocationFailed,
            ),
        ] {
            assert_eq!(
                from_bytecode_error(BytecodeError {
                    code,
                    offset: 0,
                    message: String::new()
                })
                .kind,
                expected,
            );
        }

        for (kind, expected) in [
            (
                OfficialChunkErrorKind::Truncated,
                OfficialTranslationErrorKind::InvalidChunk,
            ),
            (
                OfficialChunkErrorKind::Overflow,
                OfficialTranslationErrorKind::InvalidChunk,
            ),
            (
                OfficialChunkErrorKind::LimitExceeded,
                OfficialTranslationErrorKind::LimitExceeded,
            ),
            (
                OfficialChunkErrorKind::WorkExhausted,
                OfficialTranslationErrorKind::LimitExceeded,
            ),
            (
                OfficialChunkErrorKind::AllocationFailed,
                OfficialTranslationErrorKind::AllocationFailed,
            ),
        ] {
            assert_eq!(
                from_official_chunk_error(OfficialChunkError {
                    kind,
                    offset: 0,
                    detail: "test"
                })
                .kind,
                expected,
            );
        }

        assert_eq!(
            reserve_failure(ReserveFailure::ExcessCapacity, id, 0, "test").kind,
            OfficialTranslationErrorKind::LimitExceeded,
        );
        assert_eq!(
            reserve_failure(ReserveFailure::Allocation, id, 0, "test").kind,
            OfficialTranslationErrorKind::AllocationFailed,
        );
    }
}
