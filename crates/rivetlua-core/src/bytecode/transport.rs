//! P05 所有的 RVLU 外掛來源資料傳輸。Sidecar 不屬於 RVLU_V2 wire。

use core::mem::size_of;
use std::sync::Arc;

use super::codec::{
    BytecodeClosePath, BytecodeConstant, BytecodeError, BytecodeErrorCode, BytecodeModule,
    VerifiedModule, VerifyLimits, decode_module, encode_verified_module_bytes_bounded,
};
use super::native_debug::{
    NativeDebugCandidate, NativeLocal, NativePrototypeDebug, verify_native_debug,
};
use super::official::{
    OfficialChunkError, OfficialChunkErrorKind, OfficialChunkLimits, decode_official_chunk,
    encode_official_chunk_metered,
};
use super::official_execution::{
    OfficialExecutionPlan, OfficialPlanBuiltin, OfficialPlanCall,
    native_builtin_candidate_from_calls_metered, native_reserve_exact,
    verify_native_builtin_plan_metered,
};
use super::official_preflight::preflight_official_chunk;
use super::official_translation::{
    OfficialTranslationError, OfficialTranslationErrorKind, OfficialWorkBudget, ReserveFailure,
    translate_official_chunk_with_work,
};
use super::{BytecodeBindingId, InstructionOffset, LuaProfile, ProtoId, Register, UpvalueId};

const MAGIC: &[u8; 4] = b"RVAS";
const HEADER_LEN: usize = 16;
const VERSION: u16 = 1;

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_block(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut words = [0u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        words[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for index in 16..64 {
        let left = words[index - 15].rotate_right(7)
            ^ words[index - 15].rotate_right(18)
            ^ (words[index - 15] >> 3);
        let right = words[index - 2].rotate_right(17)
            ^ words[index - 2].rotate_right(19)
            ^ (words[index - 2] >> 10);
        words[index] = words[index - 16]
            .wrapping_add(left)
            .wrapping_add(words[index - 7])
            .wrapping_add(right);
    }
    let mut work = *state;
    for index in 0..64 {
        let choose = (work[4] & work[5]) ^ (!work[4] & work[6]);
        let majority = (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
        let first = work[7]
            .wrapping_add(
                work[4].rotate_right(6) ^ work[4].rotate_right(11) ^ work[4].rotate_right(25),
            )
            .wrapping_add(choose)
            .wrapping_add(SHA256_K[index])
            .wrapping_add(words[index]);
        let second =
            (work[0].rotate_right(2) ^ work[0].rotate_right(13) ^ work[0].rotate_right(22))
                .wrapping_add(majority);
        work = [
            first.wrapping_add(second),
            work[0],
            work[1],
            work[2],
            work[3].wrapping_add(first),
            work[4],
            work[5],
            work[6],
        ];
    }
    for (slot, value) in state.iter_mut().zip(work) {
        *slot = slot.wrapping_add(value);
    }
}

fn sha256(bytes: &[u8]) -> Result<[u8; 32], TransportError> {
    let bit_length = u64::try_from(bytes.len())
        .ok()
        .and_then(|length| length.checked_mul(8))
        .ok_or_else(|| limit("RVLU signature 長度溢位"))?;
    let mut state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut chunks = bytes.chunks_exact(64);
    for chunk in &mut chunks {
        let block: &[u8; 64] = chunk
            .try_into()
            .map_err(|_| invalid(0, "SHA-256 block 無效"))?;
        sha256_block(&mut state, block);
    }
    let rest = chunks.remainder();
    let mut final_blocks = [0u8; 128];
    final_blocks[..rest.len()].copy_from_slice(rest);
    final_blocks[rest.len()] = 0x80;
    let used = if rest.len() < 56 { 64 } else { 128 };
    final_blocks[used - 8..used].copy_from_slice(&bit_length.to_be_bytes());
    for block in final_blocks[..used].chunks_exact(64) {
        let block: &[u8; 64] = block
            .try_into()
            .map_err(|_| invalid(0, "SHA-256 final block 無效"))?;
        sha256_block(&mut state, block);
    }
    let mut output = [0u8; 32];
    for (index, word) in state.into_iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(output)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportLimits {
    pub verify: VerifyLimits,
    pub official: OfficialChunkLimits,
    pub max_sidecar_bytes: usize,
    pub max_temporary_bytes: usize,
    pub max_retained_bytes: usize,
    pub max_work: u64,
}

impl Default for TransportLimits {
    fn default() -> Self {
        Self {
            verify: VerifyLimits::default(),
            official: OfficialChunkLimits::default(),
            max_sidecar_bytes: 32 * 1024 * 1024 + HEADER_LEN,
            max_temporary_bytes: 512 * 1024 * 1024,
            max_retained_bytes: 256 * 1024 * 1024,
            max_work: u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportScanAdmission {
    /// 無配置 preflight 掃描前必須預付的工作量。
    pub work: u64,
    /// 掃描診斷使用固定靜態錯誤，不持有輸入資料。
    pub temporary_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportAdmission {
    /// 不含前置掃描；實際操作前預付。
    pub subsequent_work: u64,
    pub temporary_bytes: usize,
    pub retained_bytes: usize,
    pub rvlu_bytes_upper: usize,
    pub sidecar_bytes_upper: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    InvalidFormat,
    LimitExceeded,
    AllocationFailed,
    Bytecode,
    OfficialChunk,
    OfficialTranslation,
}

#[derive(Debug)]
pub struct TransportError {
    pub kind: TransportErrorKind,
    pub offset: usize,
    pub detail: &'static str,
}

impl core::fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "傳輸資料位移 {}：{}", self.offset, self.detail)
    }
}

impl std::error::Error for TransportError {}

fn invalid(offset: usize, detail: &'static str) -> TransportError {
    TransportError {
        kind: TransportErrorKind::InvalidFormat,
        offset,
        detail,
    }
}
fn limit(detail: &'static str) -> TransportError {
    TransportError {
        kind: TransportErrorKind::LimitExceeded,
        offset: 0,
        detail,
    }
}
fn allocated(detail: &'static str) -> TransportError {
    TransportError {
        kind: TransportErrorKind::AllocationFailed,
        offset: 0,
        detail,
    }
}
impl From<BytecodeError> for TransportError {
    fn from(error: BytecodeError) -> Self {
        let kind = match error.code {
            BytecodeErrorCode::CompileLimit => TransportErrorKind::LimitExceeded,
            BytecodeErrorCode::AllocationFailed => TransportErrorKind::AllocationFailed,
            BytecodeErrorCode::Verify => TransportErrorKind::Bytecode,
        };
        Self {
            kind,
            offset: error.offset,
            detail: "RVLU 驗證或編碼失敗",
        }
    }
}
impl From<OfficialChunkError> for TransportError {
    fn from(error: OfficialChunkError) -> Self {
        let kind = match error.kind {
            OfficialChunkErrorKind::LimitExceeded
            | OfficialChunkErrorKind::Overflow
            | OfficialChunkErrorKind::WorkExhausted => TransportErrorKind::LimitExceeded,
            OfficialChunkErrorKind::AllocationFailed => TransportErrorKind::AllocationFailed,
            OfficialChunkErrorKind::Truncated | OfficialChunkErrorKind::InvalidFormat => {
                TransportErrorKind::OfficialChunk
            }
        };
        Self {
            kind,
            offset: error.offset,
            detail: "官方 chunk 無效",
        }
    }
}
impl From<OfficialTranslationError> for TransportError {
    fn from(error: OfficialTranslationError) -> Self {
        let kind = match error.kind {
            OfficialTranslationErrorKind::LimitExceeded => TransportErrorKind::LimitExceeded,
            OfficialTranslationErrorKind::AllocationFailed => TransportErrorKind::AllocationFailed,
            OfficialTranslationErrorKind::InvalidChunk => TransportErrorKind::OfficialTranslation,
        };
        Self {
            kind,
            offset: error.pc,
            detail: "官方 chunk 轉譯失敗",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncodedTransportModule {
    rvlu: Vec<u8>,
    sidecar: Vec<u8>,
}
impl EncodedTransportModule {
    pub fn rvlu(&self) -> &[u8] {
        &self.rvlu
    }
    pub fn sidecar(&self) -> &[u8] {
        &self.sidecar
    }
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.rvlu, self.sidecar)
    }
}

fn checked_add(left: usize, right: usize) -> Result<usize, TransportError> {
    left.checked_add(right).ok_or_else(|| limit("傳輸長度溢位"))
}
fn checked_mul(left: usize, right: usize) -> Result<usize, TransportError> {
    left.checked_mul(right).ok_or_else(|| limit("傳輸容量溢位"))
}
fn checked_u32(value: usize) -> Result<u32, TransportError> {
    u32::try_from(value).map_err(|_| limit("傳輸 count/length 超過 u32"))
}
fn checked_u64(value: usize) -> Result<u64, TransportError> {
    u64::try_from(value).map_err(|_| limit("傳輸 length 超過 u64"))
}

/// 呼叫者可僅由輸入長度，在觸碰內容及任何 heap 配置前取得第一段預扣量。
pub fn transport_scan_admission(
    rvlu_len: usize,
    sidecar_len: usize,
) -> Result<TransportScanAdmission, TransportError> {
    let total = checked_add(rvlu_len, sidecar_len)?;
    let work = checked_add(checked_mul(total, 2)?, 1)?;
    Ok(TransportScanAdmission {
        work: checked_u64(work)?,
        temporary_bytes: 0,
    })
}

/// 編碼掃描額度由 VerifiedModule 在 P05 驗證時快取，取值不走訪 IR。
pub fn transport_encode_scan_admission(
    verified: &VerifiedModule,
    limits: &TransportLimits,
) -> Result<TransportScanAdmission, TransportError> {
    let mut work = checked_mul(verified.transport_scan_units(), 4)?;
    if let Some(artifact) = verified.official_artifact() {
        work = checked_add(work, checked_mul(artifact.allocated_bytes(), 4)?)?;
    }
    if let Some(debug) = verified.native_debug() {
        work = checked_add(work, checked_mul(debug.allocated_bytes(), 4)?)?;
    }
    if let Some(plan) = verified.official_execution() {
        work = checked_add(
            work,
            checked_mul(
                plan.allocated_bytes()
                    .ok_or_else(|| limit("private plan 容量溢位"))?,
                4,
            )?,
        )?;
    }
    let work = checked_u64(work)?;
    if work > limits.max_work {
        return Err(limit("transport 編碼掃描 work 超限"));
    }
    Ok(TransportScanAdmission {
        work,
        temporary_bytes: 0,
    })
}

fn charge_work(work: &mut OfficialWorkBudget, units: u64) -> Result<(), TransportError> {
    let count = usize::try_from(units).map_err(|_| limit("transport work 超過平台 usize"))?;
    work.charge(count, ProtoId(0), 0)?;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, size: usize) -> Result<&'a [u8], TransportError> {
        let end = self
            .at
            .checked_add(size)
            .ok_or_else(|| invalid(self.at, "長度溢位"))?;
        let bytes = self
            .bytes
            .get(self.at..end)
            .ok_or_else(|| invalid(self.at, "資料截斷"))?;
        self.at = end;
        Ok(bytes)
    }
    fn u8(&mut self) -> Result<u8, TransportError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, TransportError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| invalid(self.at, "u16 截斷"))?,
        ))
    }
    fn u32(&mut self) -> Result<u32, TransportError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| invalid(self.at, "u32 截斷"))?,
        ))
    }
    fn u64(&mut self) -> Result<u64, TransportError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| invalid(self.at, "u64 截斷"))?,
        ))
    }
    fn section(&mut self) -> Result<&'a [u8], TransportError> {
        let size =
            usize::try_from(self.u32()?).map_err(|_| invalid(self.at, "section 長度溢位"))?;
        self.take(size)
    }
    fn blob(&mut self) -> Result<&'a [u8], TransportError> {
        self.section()
    }
    fn end(&self) -> Result<(), TransportError> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid(self.at, "多餘尾端資料"))
        }
    }
}

fn sidecar_body<'a>(
    sidecar: &'a [u8],
    limits: &TransportLimits,
) -> Result<(u8, &'a [u8]), TransportError> {
    if sidecar.len() > limits.max_sidecar_bytes {
        return Err(limit("sidecar bytes 超限"));
    }
    let mut reader = Cursor::new(sidecar);
    if reader.take(4)? != MAGIC {
        return Err(invalid(0, "sidecar magic 不符"));
    }
    if reader.u16()? != VERSION {
        return Err(invalid(4, "sidecar version 不支援"));
    }
    let kind = reader.u8()?;
    if kind > 3 {
        return Err(invalid(6, "sidecar kind 無效"));
    }
    if reader.u8()? != 0 {
        return Err(invalid(7, "sidecar reserved 必須為零"));
    }
    if reader.u64()? != checked_u64(sidecar.len())? {
        return Err(invalid(8, "sidecar length 不符"));
    }
    let body = reader.take(sidecar.len() - HEADER_LEN)?;
    if kind == 0 && !body.is_empty() {
        return Err(invalid(HEADER_LEN, "None sidecar 不得有 body"));
    }
    Ok((kind, body))
}

fn allocate_bytes(size: usize, maximum: usize) -> Result<Vec<u8>, TransportError> {
    if size > maximum {
        return Err(limit("傳輸配置上限"));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| allocated("傳輸輸出配置失敗"))?;
    if bytes.capacity() > maximum {
        return Err(limit("傳輸實際容量超限"));
    }
    Ok(bytes)
}

fn write_header(bytes: &mut Vec<u8>, kind: u8, len: usize) -> Result<(), TransportError> {
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.push(kind);
    bytes.push(0);
    bytes.extend_from_slice(&checked_u64(len)?.to_le_bytes());
    Ok(())
}

fn native_body_size(
    source: &[u8],
    prototypes: &[NativePrototypeDebug],
) -> Result<usize, TransportError> {
    checked_u32(source.len())?;
    checked_u32(prototypes.len())?;
    let mut size = checked_add(checked_add(4, source.len())?, 4)?;
    for proto in prototypes {
        checked_u32(proto.lines.len())?;
        checked_u32(proto.locals.len())?;
        checked_u32(proto.upvalue_names.len())?;
        size = checked_add(size, 25)?; // id、兩個 line range、max active、三個 count
        size = checked_add(size, checked_mul(proto.lines.len(), 4)?)?;
        for local in &proto.locals {
            checked_u32(local.name.len())?;
            size = checked_add(size, checked_add(27, local.name.len())?)?;
        }
        for name in &proto.upvalue_names {
            size = checked_add(size, 1)?;
            if let Some(name) = name {
                checked_u32(name.len())?;
                size = checked_add(size, checked_add(4, name.len())?)?;
            }
        }
    }
    Ok(size)
}

const NATIVE_DECLARATION_RECORD_BYTES: usize = 24;

fn native_declarations_size(
    plan: &OfficialExecutionPlan,
    debug: Option<&super::native_debug::NativeDebug>,
) -> Result<usize, TransportError> {
    if !plan.is_native_builtin() {
        return Err(invalid(0, "native helper plan kind 無效"));
    }
    checked_u32(plan.calls().len())?;
    let mut size = checked_add(
        37,
        checked_mul(plan.calls().len(), NATIVE_DECLARATION_RECORD_BYTES)?,
    )?;
    if let Some(debug) = debug {
        size = checked_add(
            size,
            checked_add(
                4,
                native_body_size(debug.source_name(), debug.prototypes())?,
            )?,
        )?;
    }
    Ok(size)
}

fn write_native_declarations(
    bytes: &mut Vec<u8>,
    rvlu: &[u8],
    plan: &OfficialExecutionPlan,
    debug: Option<&super::native_debug::NativeDebug>,
) -> Result<(), TransportError> {
    bytes.extend_from_slice(&sha256(rvlu)?);
    bytes.extend_from_slice(&checked_u32(plan.calls().len())?.to_le_bytes());
    for call in plan.calls() {
        let Some(tail) = call.open_tail else {
            return Err(invalid(0, "native helper open tail 缺失"));
        };
        if call.builtin != OfficialPlanBuiltin::RawListWrite || call.inputs.len() != 3 {
            return Err(invalid(0, "native helper 宣告不符合 RawListWrite ABI"));
        }
        bytes.extend_from_slice(&call.prototype.0.to_le_bytes());
        bytes.extend_from_slice(&call.call_pc.0.to_le_bytes());
        bytes.extend_from_slice(&call.function_register.0.to_le_bytes());
        bytes.extend_from_slice(&call.source_upvalue.0.to_le_bytes());
        bytes.extend_from_slice(&3u16.to_le_bytes());
        for input in &call.inputs {
            bytes.extend_from_slice(&input.0.to_le_bytes());
        }
        bytes.push(1);
        bytes.extend_from_slice(&tail.0.to_le_bytes());
        bytes.push(0);
    }
    match debug {
        Some(debug) => {
            bytes.push(1);
            bytes.extend_from_slice(
                &checked_u32(native_body_size(debug.source_name(), debug.prototypes())?)?
                    .to_le_bytes(),
            );
            write_native_body(bytes, debug.source_name(), debug.prototypes())?;
        }
        None => bytes.push(0),
    }
    Ok(())
}

struct NativeDeclarationCounts {
    calls: usize,
    debug: Option<NativeCounts>,
}

fn scan_native_declarations(
    body: &[u8],
    limits: &TransportLimits,
) -> Result<NativeDeclarationCounts, TransportError> {
    let mut reader = Cursor::new(body);
    reader.take(32)?;
    let calls = reader.u32()? as usize;
    if calls == 0
        || calls > limits.verify.max_instructions
        || calls > body.len() / NATIVE_DECLARATION_RECORD_BYTES
    {
        return Err(limit("native helper call count 超限"));
    }
    let mut previous = None;
    for _ in 0..calls {
        let prototype = reader.u32()?;
        let pc = reader.u32()?;
        let base = reader.u16()?;
        let _upvalue = reader.u16()?;
        if reader.u16()? != 3 {
            return Err(invalid(reader.at, "native helper input count 無效"));
        }
        for offset in 1..=3 {
            if reader.u16()?
                != base
                    .checked_add(offset)
                    .ok_or_else(|| invalid(reader.at, "native helper register 溢位"))?
            {
                return Err(invalid(reader.at, "native helper inputs 不連續"));
            }
        }
        if reader.u8()? != 1
            || reader.u16()?
                != base
                    .checked_add(4)
                    .ok_or_else(|| invalid(reader.at, "native helper tail register 溢位"))?
            || reader.u8()? != 0
        {
            return Err(invalid(reader.at, "native helper tail/builtin 無效"));
        }
        if previous.is_some_and(|last| last >= (prototype, pc)) {
            return Err(invalid(reader.at, "native helper call 重複或順序無效"));
        }
        previous = Some((prototype, pc));
    }
    let debug = match reader.u8()? {
        0 => None,
        1 => Some(scan_native(reader.section()?, limits)?),
        _ => return Err(invalid(reader.at - 1, "native helper debug tag 無效")),
    };
    reader.end()?;
    Ok(NativeDeclarationCounts { calls, debug })
}

fn read_native_declarations(
    body: &[u8],
    limits: &TransportLimits,
    meter: &mut AllocationMeter,
) -> Result<(Vec<OfficialPlanCall>, Option<NativeDebugCandidate>), TransportError> {
    let mut reader = Cursor::new(body);
    reader.take(32)?;
    let count = reader.u32()? as usize;
    if count == 0
        || count > limits.verify.max_instructions
        || count > body.len() / NATIVE_DECLARATION_RECORD_BYTES
    {
        return Err(limit("native helper call count 超限"));
    }
    let mut calls = Vec::new();
    meter.reserve(&mut calls, count)?;
    for _ in 0..count {
        let prototype = ProtoId(reader.u32()?);
        let call_pc = InstructionOffset(reader.u32()?);
        let function_register = Register(reader.u16()?);
        let source_upvalue = UpvalueId(reader.u16()?);
        if reader.u16()? != 3 {
            return Err(invalid(reader.at, "native helper input count 無效"));
        }
        let mut inputs = Vec::new();
        meter.reserve(&mut inputs, 3)?;
        for _ in 0..3 {
            inputs.push(Register(reader.u16()?));
        }
        if reader.u8()? != 1 {
            return Err(invalid(reader.at, "native helper open tail 缺失"));
        }
        let open_tail = Some(Register(reader.u16()?));
        if reader.u8()? != 0 {
            return Err(invalid(reader.at, "native helper builtin 未知"));
        }
        calls.push(OfficialPlanCall {
            prototype,
            call_pc,
            function_register,
            source_upvalue,
            inputs,
            open_tail,
            builtin: OfficialPlanBuiltin::RawListWrite,
        });
    }
    let debug = match reader.u8()? {
        0 => None,
        1 => Some(read_native_body(reader.section()?, limits, meter)?),
        _ => return Err(invalid(reader.at - 1, "native helper debug tag 無效")),
    };
    reader.end()?;
    Ok((calls, debug))
}

fn write_native_body(
    bytes: &mut Vec<u8>,
    source: &[u8],
    prototypes: &[NativePrototypeDebug],
) -> Result<(), TransportError> {
    bytes.extend_from_slice(&checked_u32(source.len())?.to_le_bytes());
    bytes.extend_from_slice(source);
    bytes.extend_from_slice(&checked_u32(prototypes.len())?.to_le_bytes());
    for proto in prototypes {
        bytes.extend_from_slice(&proto.prototype.0.to_le_bytes());
        bytes.extend_from_slice(&proto.line_defined.to_le_bytes());
        bytes.extend_from_slice(&proto.last_line_defined.to_le_bytes());
        bytes.push(proto.max_active_locals);
        bytes.extend_from_slice(&checked_u32(proto.lines.len())?.to_le_bytes());
        for line in &proto.lines {
            bytes.extend_from_slice(&line.to_le_bytes());
        }
        bytes.extend_from_slice(&checked_u32(proto.locals.len())?.to_le_bytes());
        for local in &proto.locals {
            bytes.extend_from_slice(&local.binding.function.to_le_bytes());
            bytes.extend_from_slice(&local.binding.ordinal.to_le_bytes());
            bytes.extend_from_slice(&local.register.0.to_le_bytes());
            bytes.push(local.slot);
            bytes.extend_from_slice(&local.initialized_pc.to_le_bytes());
            bytes.extend_from_slice(&local.start_pc.to_le_bytes());
            bytes.extend_from_slice(&local.end_pc.to_le_bytes());
            bytes.extend_from_slice(&checked_u32(local.name.len())?.to_le_bytes());
            bytes.extend_from_slice(&local.name);
        }
        bytes.extend_from_slice(&checked_u32(proto.upvalue_names.len())?.to_le_bytes());
        for name in &proto.upvalue_names {
            match name {
                Some(name) => {
                    bytes.push(1);
                    bytes.extend_from_slice(&checked_u32(name.len())?.to_le_bytes());
                    bytes.extend_from_slice(name);
                }
                None => bytes.push(0),
            }
        }
    }
    Ok(())
}

struct AllocationMeter {
    used: usize,
    limit: usize,
}
impl AllocationMeter {
    fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }
    fn reserve<T>(&mut self, vec: &mut Vec<T>, count: usize) -> Result<(), TransportError> {
        let requested = checked_mul(count, size_of::<T>())?;
        if checked_add(self.used, requested)? > self.limit {
            return Err(limit("native candidate 配置超出 aggregate 預准入"));
        }
        native_reserve_exact(vec, count).map_err(|error| match error {
            ReserveFailure::Allocation => allocated("native candidate 配置失敗"),
            ReserveFailure::ExcessCapacity => limit("native candidate 容量超限"),
        })?;
        self.used = checked_add(self.used, checked_mul(vec.capacity(), size_of::<T>())?)?;
        if self.used > self.limit {
            return Err(limit("native candidate 實際容量超出 aggregate 預准入"));
        }
        Ok(())
    }
}

fn read_copy(
    reader: &mut Cursor<'_>,
    meter: &mut AllocationMeter,
) -> Result<Vec<u8>, TransportError> {
    let original = reader.blob()?;
    let mut bytes = Vec::new();
    meter.reserve(&mut bytes, original.len())?;
    bytes.extend_from_slice(original);
    Ok(bytes)
}

fn read_native_body(
    body: &[u8],
    limits: &TransportLimits,
    meter: &mut AllocationMeter,
) -> Result<NativeDebugCandidate, TransportError> {
    let mut reader = Cursor::new(body);
    let source_name = read_copy(&mut reader, meter)?;
    let count = reader.u32()? as usize;
    if count > limits.verify.max_prototypes || count > body.len() / 25 {
        return Err(limit("native prototype count 超限"));
    }
    let mut prototypes = Vec::new();
    meter.reserve(&mut prototypes, count)?;
    for _ in 0..count {
        let prototype = ProtoId(reader.u32()?);
        let line_defined = reader.u32()?;
        let last_line_defined = reader.u32()?;
        let max_active_locals = reader.u8()?;
        let line_count = reader.u32()? as usize;
        if line_count > limits.verify.max_instructions || line_count > body.len() / 4 {
            return Err(limit("native line count 超限"));
        }
        let mut lines = Vec::new();
        meter.reserve(&mut lines, line_count)?;
        for _ in 0..line_count {
            lines.push(reader.u32()?);
        }
        let local_count = reader.u32()? as usize;
        if local_count > limits.verify.max_constants || local_count > body.len() / 27 {
            return Err(limit("native local count 超限"));
        }
        let mut locals = Vec::new();
        meter.reserve(&mut locals, local_count)?;
        for _ in 0..local_count {
            locals.push(NativeLocal {
                binding: BytecodeBindingId {
                    function: reader.u32()?,
                    ordinal: reader.u32()?,
                },
                register: Register(reader.u16()?),
                slot: reader.u8()?,
                initialized_pc: reader.u32()?,
                start_pc: reader.u32()?,
                end_pc: reader.u32()?,
                name: read_copy(&mut reader, meter)?,
            });
        }
        let name_count = reader.u32()? as usize;
        if name_count > limits.verify.max_upvalues_per_prototype || name_count > body.len() {
            return Err(limit("native upvalue-name count 超限"));
        }
        let mut upvalue_names = Vec::new();
        meter.reserve(&mut upvalue_names, name_count)?;
        for _ in 0..name_count {
            upvalue_names.push(match reader.u8()? {
                0 => None,
                1 => Some(read_copy(&mut reader, meter)?),
                _ => return Err(invalid(reader.at - 1, "native upvalue-name tag 無效")),
            });
        }
        prototypes.push(NativePrototypeDebug {
            prototype,
            line_defined,
            last_line_defined,
            lines,
            locals,
            upvalue_names,
            max_active_locals,
        });
    }
    reader.end()?;
    Ok(NativeDebugCandidate {
        source_name,
        prototypes,
    })
}

#[derive(Default)]
struct RvluCounts {
    prototypes: usize,
    instructions: usize,
    constants: usize,
    metadata_quadratic: usize,
}

fn scan_close_path(
    reader: &mut Cursor<'_>,
    limits: &VerifyLimits,
) -> Result<usize, TransportError> {
    reader.take(1 + 16 + 4)?;
    match reader.u8()? {
        0 => {}
        1 => {
            reader.take(4)?;
        }
        _ => return Err(invalid(reader.at - 1, "RVLU close target tag 無效")),
    }
    let bindings = reader.u32()? as usize;
    if bindings > limits.max_constants {
        return Err(limit("RVLU close binding count 超限"));
    }
    reader.take(checked_mul(bindings, 8)?)?;
    let registers = reader.u32()? as usize;
    if registers > limits.max_registers as usize || registers != bindings {
        return Err(limit("RVLU close register count 無效"));
    }
    reader.take(checked_mul(registers, 2)?)?;
    Ok(bindings)
}

fn scan_constants(section: &[u8], limits: &VerifyLimits) -> Result<usize, TransportError> {
    let mut reader = Cursor::new(section);
    let count = reader.u32()? as usize;
    if count > limits.max_constants {
        return Err(limit("RVLU constant count 超限"));
    }
    for _ in 0..count {
        match reader.u8()? {
            0 | 1 => {
                reader.take(8)?;
            }
            2 | 3 => {
                reader.blob()?;
            }
            4 => {
                reader.take(1)?;
            }
            _ => return Err(invalid(reader.at - 1, "RVLU constant tag 無效")),
        }
    }
    reader.end()?;
    Ok(count)
}

fn scan_result_mode(reader: &mut Cursor<'_>) -> Result<(), TransportError> {
    match reader.u8()? {
        0 => {
            reader.take(2)?;
        }
        1 => {}
        _ => return Err(invalid(reader.at - 1, "RVLU result mode 無效")),
    }
    Ok(())
}

fn scan_instructions(
    section: &[u8],
    limits: &VerifyLimits,
) -> Result<(usize, usize), TransportError> {
    let mut reader = Cursor::new(section);
    let count = reader.u32()? as usize;
    let mut close_bindings = 0usize;
    if count > limits.max_instructions {
        return Err(limit("RVLU instruction count 超限"));
    }
    for _ in 0..count {
        match reader.u8()? {
            0 | 11 | 12 => {
                reader.take(6)?;
            }
            1 | 2 | 3 | 4 | 17 => {
                reader.take(4)?;
            }
            5 => {
                reader.take(2)?;
            }
            6 | 7 => {
                reader.take(6)?;
            }
            8 => {
                reader.take(5)?;
            }
            9 => {
                reader.take(7)?;
            }
            10 => {
                reader.take(4)?;
            }
            13 | 14 => {
                reader.take(4)?;
                scan_result_mode(&mut reader)?;
            }
            15 | 16 => {
                reader.take(2)?;
                scan_result_mode(&mut reader)?;
            }
            18 => {
                reader.take(12)?;
            }
            19 => {
                reader.take(16)?;
            }
            _ => return Err(invalid(reader.at - 1, "RVLU opcode 無效")),
        }
        reader.take(1 + 16)?;
        match reader.u8()? {
            0 => {}
            1 => {
                close_bindings =
                    checked_add(close_bindings, scan_close_path(&mut reader, limits)?)?;
            }
            _ => return Err(invalid(reader.at - 1, "RVLU instruction close tag 無效")),
        }
    }
    reader.end()?;
    Ok((count, close_bindings))
}

fn scan_metadata(
    section: &[u8],
    limits: &VerifyLimits,
) -> Result<(usize, usize, usize), TransportError> {
    let mut reader = Cursor::new(section);
    let bindings = reader.u32()? as usize;
    if bindings > limits.max_constants {
        return Err(limit("RVLU metadata binding count 超限"));
    }
    reader.take(checked_mul(bindings, 10)?)?;
    let upvalues = reader.u32()? as usize;
    if upvalues > limits.max_upvalues_per_prototype {
        return Err(limit("RVLU metadata upvalue count 超限"));
    }
    for _ in 0..upvalues {
        reader.take(2)?;
        match reader.u8()? {
            0 => {
                reader.take(8)?;
            }
            1 => {
                reader.take(2)?;
            }
            _ => return Err(invalid(reader.at - 1, "RVLU upvalue source tag 無效")),
        }
    }
    let close = reader.u32()? as usize;
    if close > limits.max_constants {
        return Err(limit("RVLU metadata close count 超限"));
    }
    let mut close_bindings = 0usize;
    for _ in 0..close {
        close_bindings = checked_add(close_bindings, scan_close_path(&mut reader, limits)?)?;
    }
    reader.end()?;
    Ok((bindings, upvalues, close_bindings))
}

fn scan_rvlu(
    rvlu: &[u8],
    profile: LuaProfile,
    limits: &VerifyLimits,
) -> Result<RvluCounts, TransportError> {
    if rvlu.len() > limits.max_module_bytes {
        return Err(limit("RVLU bytes 超限"));
    }
    let mut reader = Cursor::new(rvlu);
    if reader.take(4)? != b"RVLU" {
        return Err(invalid(0, "RVLU magic 不符"));
    }
    if reader.u16()? != 2 {
        return Err(invalid(4, "RVLU format version 不支援"));
    }
    if reader.u8()? != if profile == LuaProfile::Lua55 { 0 } else { 1 } {
        return Err(invalid(6, "RVLU profile 不符"));
    }
    if reader.u8()? != 1 {
        return Err(invalid(7, "RVLU numeric config 不符"));
    }
    reader.take(16)?;
    let section = reader.section()?;
    reader.end()?;
    let mut prototypes = Cursor::new(section);
    let count = prototypes.u32()? as usize;
    if count > limits.max_prototypes {
        return Err(limit("RVLU prototype count 超限"));
    }
    let mut stats = RvluCounts {
        prototypes: count,
        ..RvluCounts::default()
    };
    for _ in 0..count {
        let record = prototypes.section()?;
        let mut proto = Cursor::new(record);
        proto.take(8)?;
        match proto.u8()? {
            0 => {}
            1 => {
                proto.take(4)?;
            }
            _ => return Err(invalid(proto.at - 1, "RVLU parent tag 無效")),
        }
        proto.take(16 + 2 + 2 + 1)?;
        match proto.u8()? {
            0 => {}
            1 => {
                proto.take(10)?;
            }
            _ => return Err(invalid(proto.at - 1, "RVLU vararg tag 無效")),
        }
        proto.take(10)?;
        match proto.u8()? {
            0 => {}
            1 => {
                proto.take(6)?;
            }
            2 | 3 => {
                proto.take(2)?;
            }
            _ => return Err(invalid(proto.at - 1, "RVLU env tag 無效")),
        }
        proto.take(1 + 2 + 8)?;
        let constants = proto.section()?;
        let instructions = proto.section()?;
        let metadata = proto.section()?;
        proto.end()?;
        stats.constants = checked_add(stats.constants, scan_constants(constants, limits)?)?;
        let (instruction_count, inline_close) = scan_instructions(instructions, limits)?;
        stats.instructions = checked_add(stats.instructions, instruction_count)?;
        let (bindings, upvalues, metadata_close) = scan_metadata(metadata, limits)?;
        let close = checked_add(inline_close, metadata_close)?;
        let b_plus_close = checked_add(bindings, close)?;
        let i_plus_close = checked_add(instruction_count, close)?;
        let metadata_work = checked_add(
            checked_add(
                checked_mul(b_plus_close, b_plus_close)?,
                checked_mul(upvalues, upvalues)?,
            )?,
            checked_mul(i_plus_close, i_plus_close)?,
        )?;
        stats.metadata_quadratic = checked_add(stats.metadata_quadratic, metadata_work)?;
        if stats.constants > limits.max_constants || stats.instructions > limits.max_instructions {
            return Err(limit("RVLU instruction/constant count 超限"));
        }
    }
    prototypes.end()?;
    Ok(stats)
}

#[derive(Default)]
struct NativeCounts {
    lines: usize,
    locals: usize,
    names: usize,
}

fn scan_native(body: &[u8], limits: &TransportLimits) -> Result<NativeCounts, TransportError> {
    let mut reader = Cursor::new(body);
    reader.blob()?;
    let count = reader.u32()? as usize;
    if count > limits.verify.max_prototypes || count > body.len() / 25 {
        return Err(limit("native prototype count 超限"));
    }
    let mut stats = NativeCounts::default();
    for _ in 0..count {
        reader.take(13)?;
        let line_count = reader.u32()? as usize;
        stats.lines = checked_add(stats.lines, line_count)?;
        if stats.lines > limits.verify.max_instructions {
            return Err(limit("native line count 超限"));
        }
        reader.take(checked_mul(line_count, 4)?)?;
        let local_count = reader.u32()? as usize;
        stats.locals = checked_add(stats.locals, local_count)?;
        if stats.locals > limits.verify.max_constants {
            return Err(limit("native local count 超限"));
        }
        for _ in 0..local_count {
            reader.take(23)?;
            reader.blob()?;
        }
        let name_count = reader.u32()? as usize;
        stats.names = checked_add(stats.names, name_count)?;
        if name_count > limits.verify.max_upvalues_per_prototype {
            return Err(limit("native name count 超限"));
        }
        for _ in 0..name_count {
            match reader.u8()? {
                0 => {}
                1 => {
                    reader.blob()?;
                }
                _ => return Err(invalid(reader.at - 1, "native name tag 無效")),
            }
        }
    }
    reader.end()?;
    Ok(stats)
}

fn bound_admission(
    admission: TransportAdmission,
    limits: &TransportLimits,
) -> Result<TransportAdmission, TransportError> {
    if admission.rvlu_bytes_upper > limits.verify.max_module_bytes
        || admission.sidecar_bytes_upper > limits.max_sidecar_bytes
        || admission.temporary_bytes > limits.max_temporary_bytes
        || admission.retained_bytes > limits.max_retained_bytes
        || admission.subsequent_work > limits.max_work
    {
        return Err(limit("transport 預准入上限"));
    }
    Ok(admission)
}

pub fn preflight_transport_decode(
    rvlu: &[u8],
    sidecar: &[u8],
    profile: LuaProfile,
    limits: &TransportLimits,
) -> Result<TransportAdmission, TransportError> {
    let scan = transport_scan_admission(rvlu.len(), sidecar.len())?;
    if scan.work > limits.max_work {
        return Err(limit("transport 掃描 work 超限"));
    }
    let (kind, body) = sidecar_body(sidecar, limits)?;
    let rvlu_stats = scan_rvlu(rvlu, profile, &limits.verify)?;
    let base_work = checked_add(
        checked_add(
            checked_mul(rvlu.len(), 64)?,
            checked_mul(rvlu_stats.prototypes, rvlu_stats.prototypes)?,
        )?,
        checked_mul(rvlu_stats.metadata_quadratic, 256)?,
    )?;
    let mut temporary = checked_mul(rvlu.len(), 256)?;
    let mut retained = checked_mul(rvlu.len(), 128)?;
    let mut subsequent_work = base_work;
    match kind {
        0 => {}
        1 => {
            let official =
                preflight_official_chunk(body, profile, &limits.official, &limits.verify)?;
            temporary = checked_add(temporary, official.temporary_bytes)?;
            retained = checked_add(retained, official.retained_bytes)?;
            subsequent_work = checked_add(
                subsequent_work,
                usize::try_from(official.subsequent_work)
                    .map_err(|_| limit("official work 溢位"))?,
            )?;
        }
        2 => {
            let native = scan_native(body, limits)?;
            temporary = checked_add(temporary, checked_mul(body.len(), 64)?)?;
            temporary = checked_add(
                temporary,
                checked_mul(checked_mul(native.locals, rvlu_stats.instructions)?, 64)?,
            )?;
            retained = checked_add(retained, checked_mul(body.len(), 32)?)?;
            subsequent_work = checked_add(subsequent_work, checked_mul(body.len(), 64)?)?;
            subsequent_work = checked_add(
                subsequent_work,
                checked_mul(checked_mul(native.locals, rvlu_stats.instructions)?, 256)?,
            )?;
        }
        3 => {
            let native = scan_native_declarations(body, limits)?;
            let calls = native.calls;
            let instructions = rvlu_stats.instructions;
            let prototypes = rvlu_stats.prototypes;
            let candidate_bytes = checked_add(
                checked_mul(
                    calls,
                    size_of::<OfficialPlanCall>() + 3 * size_of::<Register>(),
                )?,
                checked_add(
                    checked_mul(
                        prototypes,
                        size_of::<super::official_execution::OfficialPlanUpvalueMap>()
                            + size_of::<bool>()
                            + size_of::<(OfficialPlanBuiltin, UpvalueId)>(),
                    )?,
                    checked_mul(calls, size_of::<(ProtoId, usize)>())?,
                )?,
            )?;
            temporary = checked_add(temporary, checked_mul(body.len(), 64)?)?;
            temporary = checked_add(temporary, checked_mul(candidate_bytes, 8)?)?;
            retained = checked_add(retained, checked_mul(body.len(), 32)?)?;
            retained = checked_add(retained, checked_mul(candidate_bytes, 4)?)?;
            subsequent_work = checked_add(subsequent_work, checked_mul(rvlu.len(), 64)?)?;
            subsequent_work = checked_add(subsequent_work, checked_mul(body.len(), 64)?)?;
            subsequent_work = checked_add(
                subsequent_work,
                checked_mul(
                    checked_add(
                        checked_mul(calls, checked_add(instructions, prototypes)?)?,
                        checked_add(
                            checked_mul(calls, calls)?,
                            checked_mul(prototypes, prototypes)?,
                        )?,
                    )?,
                    512,
                )?,
            )?;
            if let Some(debug) = native.debug {
                temporary = checked_add(
                    temporary,
                    checked_mul(checked_mul(debug.locals, instructions)?, 64)?,
                )?;
                subsequent_work = checked_add(
                    subsequent_work,
                    checked_mul(checked_mul(debug.locals, instructions)?, 256)?,
                )?;
            }
        }
        _ => return Err(invalid(6, "sidecar kind 無效")),
    }
    // canonical RVLU 身分核對仍需一次短暫的 borrowed 輸出及巢狀 section。
    temporary = checked_add(temporary, checked_mul(rvlu.len(), 16)?)?;
    let result = bound_admission(
        TransportAdmission {
            subsequent_work: checked_u64(subsequent_work)?,
            temporary_bytes: temporary,
            retained_bytes: retained,
            rvlu_bytes_upper: rvlu.len(),
            sidecar_bytes_upper: sidecar.len(),
        },
        limits,
    )?;
    if scan
        .work
        .checked_add(result.subsequent_work)
        .is_none_or(|total| total > limits.max_work)
    {
        return Err(limit("transport scan+operation work 超限"));
    }
    Ok(result)
}

fn close_wire_upper(close: &BytecodeClosePath) -> Result<usize, TransportError> {
    checked_add(
        checked_add(40, checked_mul(close.bindings.len(), 8)?)?,
        checked_mul(close.registers.len(), 2)?,
    )
}

fn vector_bytes<T>(values: &Vec<T>) -> Result<usize, TransportError> {
    checked_mul(values.capacity(), size_of::<T>())
}

fn close_retained(close: &BytecodeClosePath) -> Result<usize, TransportError> {
    checked_add(
        vector_bytes(&close.bindings)?,
        vector_bytes(&close.registers)?,
    )
}

/// 計入已驗證模組及其私有 plan/debug 的實際巢狀 Vec 容量。
pub fn verified_module_allocation_bytes(
    verified: &VerifiedModule,
) -> Result<usize, TransportError> {
    let mut bytes = bytecode_module_allocation_bytes(verified.module())?;
    bytes = checked_add(
        bytes,
        size_of::<VerifiedModule>()
            .checked_sub(size_of::<BytecodeModule>())
            .ok_or_else(|| limit("verified module 佈局大小無效"))?,
    )?;
    if let Some(plan) = verified.official_execution() {
        bytes = checked_add(
            bytes,
            plan.allocated_bytes()
                .ok_or_else(|| limit("official plan 容量溢位"))?,
        )?;
    }
    if let Some(artifact) = verified.official_artifact() {
        bytes = checked_add(bytes, artifact.allocated_bytes())?;
    }
    if let Some(debug) = verified.native_debug() {
        bytes = checked_add(bytes, debug.allocated_bytes())?;
    }
    Ok(bytes)
}

/// 已驗證模組的容量量測上界；只讀取驗證時快取的計數，不走訪模組。
pub fn verified_module_measurement_work(
    verified: &VerifiedModule,
) -> Result<usize, TransportError> {
    let plan_items = verified
        .official_execution()
        .map(|plan| {
            plan.allocation_measurement_items()
                .ok_or_else(|| limit("private plan 量測工作溢位"))
        })
        .transpose()?
        .unwrap_or(0);
    checked_add(
        checked_mul(checked_add(verified.transport_scan_units(), plan_items)?, 4)?,
        8,
    )
}

/// 編碼前的 owned candidate 實際巢狀 Vec 容量；不視其為已驗證模組。
pub fn bytecode_module_allocation_bytes(module: &BytecodeModule) -> Result<usize, TransportError> {
    let mut bytes = checked_add(
        size_of::<BytecodeModule>(),
        vector_bytes(&module.prototypes)?,
    )?;
    bytes = checked_add(bytes, vector_bytes(&module.function_prototypes)?)?;
    for proto in &module.prototypes {
        bytes = checked_add(bytes, vector_bytes(&proto.binding_registers)?)?;
        bytes = checked_add(bytes, vector_bytes(&proto.constants)?)?;
        bytes = checked_add(bytes, vector_bytes(&proto.upvalues)?)?;
        bytes = checked_add(bytes, vector_bytes(&proto.instructions)?)?;
        bytes = checked_add(bytes, vector_bytes(&proto.close_paths)?)?;
        for constant in &proto.constants {
            if let BytecodeConstant::Name(value) | BytecodeConstant::String(value) = constant {
                bytes = checked_add(bytes, value.capacity())?;
            }
        }
        for path in &proto.close_paths {
            bytes = checked_add(bytes, close_retained(path)?)?;
        }
        for instruction in &proto.instructions {
            if let Some(path) = &instruction.close_path {
                bytes = checked_add(bytes, close_retained(path)?)?;
            }
        }
    }
    Ok(bytes)
}

fn verified_retained_bytes(verified: &VerifiedModule) -> Result<usize, TransportError> {
    verified_module_allocation_bytes(verified)
}

/// 已組成的 RVLU candidate 之編碼位元組上界；不驗證 candidate。
pub fn bytecode_wire_upper_bytes(module: &BytecodeModule) -> Result<usize, TransportError> {
    let mut size = 32usize;
    for proto in &module.prototypes {
        size = checked_add(size, 4 + 128)?;
        for constant in &proto.constants {
            size = checked_add(
                size,
                match constant {
                    BytecodeConstant::Integer(_) | BytecodeConstant::FloatBits(_) => 9,
                    BytecodeConstant::Boolean(_) => 2,
                    BytecodeConstant::Name(bytes) | BytecodeConstant::String(bytes) => {
                        checked_add(5, bytes.len())?
                    }
                },
            )?;
        }
        size = checked_add(size, checked_mul(proto.instructions.len(), 40)?)?;
        for instruction in &proto.instructions {
            if let Some(close) = &instruction.close_path {
                size = checked_add(size, close_wire_upper(close)?)?;
            }
        }
        size = checked_add(size, checked_mul(proto.binding_registers.len(), 10)?)?;
        size = checked_add(size, checked_mul(proto.upvalues.len(), 11)?)?;
        for close in &proto.close_paths {
            size = checked_add(size, close_wire_upper(close)?)?;
        }
    }
    Ok(size)
}

fn transport_kind(verified: &VerifiedModule) -> Result<u8, TransportError> {
    match (
        verified.official_execution(),
        verified.official_artifact(),
        verified.native_debug(),
    ) {
        (None, None, None) => Ok(0),
        (Some(plan), Some(_), None) if !plan.is_native_builtin() => Ok(1),
        (None, None, Some(_)) => Ok(2),
        (Some(plan), None, _) if plan.is_native_builtin() => Ok(3),
        _ => Err(invalid(0, "私有 plan/artifact/native debug 狀態不一致")),
    }
}

pub fn preflight_transport_encode(
    verified: &VerifiedModule,
    limits: &TransportLimits,
) -> Result<TransportAdmission, TransportError> {
    let scan = transport_encode_scan_admission(verified, limits)?;
    let kind = transport_kind(verified)?;
    if verified.module().prototypes.len() > limits.verify.max_prototypes {
        return Err(limit("RVLU prototype count 超限"));
    }
    let rvlu_upper = bytecode_wire_upper_bytes(verified.module())?;
    let sidecar_upper = match kind {
        0 => HEADER_LEN,
        1 => {
            let allocated = verified
                .official_artifact()
                .ok_or_else(|| invalid(0, "官方 artifact 缺失"))?
                .allocated_bytes();
            checked_add(HEADER_LEN, checked_add(checked_mul(allocated, 4)?, 1024)?)?
        }
        2 => {
            let debug = verified
                .native_debug()
                .ok_or_else(|| invalid(0, "native debug 缺失"))?;
            checked_add(
                HEADER_LEN,
                native_body_size(debug.source_name(), debug.prototypes())?,
            )?
        }
        3 => checked_add(
            HEADER_LEN,
            native_declarations_size(
                verified
                    .official_execution()
                    .ok_or_else(|| invalid(0, "native helper plan 缺失"))?,
                verified.native_debug(),
            )?,
        )?,
        _ => return Err(invalid(0, "module sidecar kind 無效")),
    };
    let source = verified.module();
    let instructions = source.prototypes.iter().try_fold(0usize, |total, proto| {
        checked_add(total, proto.instructions.len())
    })?;
    let mut work = checked_add(
        checked_add(
            checked_mul(rvlu_upper, 64)?,
            checked_mul(verified.transport_scan_units(), 64)?,
        )?,
        checked_mul(checked_mul(instructions, instructions)?, 256)?,
    )?;
    if kind == 1 {
        let artifact = verified
            .official_artifact()
            .ok_or_else(|| invalid(0, "官方 artifact 缺失"))?;
        work = checked_add(
            work,
            checked_mul(
                checked_mul(artifact.allocated_bytes(), artifact.allocated_bytes())?,
                4,
            )?,
        )?;
    } else if kind == 2 {
        work = checked_add(work, checked_mul(sidecar_upper, 64)?)?;
    } else if kind == 3 {
        let plan = verified
            .official_execution()
            .ok_or_else(|| invalid(0, "native helper plan 缺失"))?;
        let calls = plan.calls().len();
        work = checked_add(work, checked_mul(sidecar_upper, 64)?)?;
        work = checked_add(work, checked_mul(rvlu_upper, 64)?)?;
        work = checked_add(work, checked_mul(checked_mul(calls, instructions)?, 512)?)?;
    }
    let temporary = checked_add(checked_mul(rvlu_upper, 16)?, checked_mul(sidecar_upper, 4)?)?;
    let retained = checked_add(rvlu_upper, sidecar_upper)?;
    let result = bound_admission(
        TransportAdmission {
            subsequent_work: checked_u64(work)?,
            temporary_bytes: temporary,
            retained_bytes: retained,
            rvlu_bytes_upper: rvlu_upper,
            sidecar_bytes_upper: sidecar_upper,
        },
        limits,
    )?;
    if scan
        .work
        .checked_add(result.subsequent_work)
        .is_none_or(|total| total > limits.max_work)
    {
        return Err(limit("transport encode scan+operation work 超限"));
    }
    Ok(result)
}

pub fn encode_transport_module(
    verified: &VerifiedModule,
    limits: &TransportLimits,
    work: &mut OfficialWorkBudget,
) -> Result<EncodedTransportModule, TransportError> {
    let scan = transport_encode_scan_admission(verified, limits)?;
    charge_work(work, scan.work)?;
    let admission = preflight_transport_encode(verified, limits)?;
    let kind = transport_kind(verified)?;
    charge_work(work, admission.subsequent_work)?;
    let mut child_work = OfficialWorkBudget::new(admission.subsequent_work);
    let rvlu = encode_verified_module_bytes_bounded(
        verified,
        &limits.verify,
        checked_mul(admission.rvlu_bytes_upper, 2)?,
    )?;
    if rvlu.len() > admission.rvlu_bytes_upper || rvlu.capacity() > admission.temporary_bytes {
        return Err(limit("RVLU 輸出超出預准入"));
    }
    let body = if kind == 1 {
        let artifact = verified
            .official_artifact()
            .ok_or_else(|| invalid(0, "官方 artifact 缺失"))?;
        if artifact.profile() != verified.profile() {
            return Err(invalid(0, "官方來源 profile 不符"));
        }
        encode_official_chunk_metered(artifact.chunk(), false, &limits.official, &mut child_work)?
    } else {
        Vec::new()
    };
    let sidecar_len = if kind == 1 {
        checked_add(HEADER_LEN, body.len())?
    } else if kind == 2 {
        let debug = verified
            .native_debug()
            .ok_or_else(|| invalid(0, "native debug 缺失"))?;
        checked_add(
            HEADER_LEN,
            native_body_size(debug.source_name(), debug.prototypes())?,
        )?
    } else if kind == 3 {
        let plan = verified
            .official_execution()
            .ok_or_else(|| invalid(0, "native helper plan 缺失"))?;
        checked_add(
            HEADER_LEN,
            native_declarations_size(plan, verified.native_debug())?,
        )?
    } else {
        HEADER_LEN
    };
    if sidecar_len > admission.sidecar_bytes_upper {
        return Err(limit("sidecar 輸出超出預准入"));
    }
    let mut sidecar = allocate_bytes(sidecar_len, limits.max_sidecar_bytes)?;
    write_header(&mut sidecar, kind, sidecar_len)?;
    match kind {
        0 => {}
        1 => sidecar.extend_from_slice(&body),
        2 => {
            let debug = verified
                .native_debug()
                .ok_or_else(|| invalid(0, "native debug 缺失"))?;
            write_native_body(&mut sidecar, debug.source_name(), debug.prototypes())?;
        }
        3 => {
            let plan = verified
                .official_execution()
                .ok_or_else(|| invalid(0, "native helper plan 缺失"))?;
            write_native_declarations(&mut sidecar, &rvlu, plan, verified.native_debug())?;
        }
        _ => return Err(invalid(0, "module sidecar kind 無效")),
    }
    if sidecar.len() != sidecar_len
        || checked_add(rvlu.capacity(), sidecar.capacity())? > admission.retained_bytes
    {
        return Err(limit("transport 輸出實際容量超限"));
    }
    Ok(EncodedTransportModule { rvlu, sidecar })
}

pub fn decode_transport_module(
    rvlu: &[u8],
    sidecar: &[u8],
    profile: LuaProfile,
    limits: &TransportLimits,
    work: &mut OfficialWorkBudget,
) -> Result<VerifiedModule, TransportError> {
    let scan = transport_scan_admission(rvlu.len(), sidecar.len())?;
    charge_work(work, scan.work)?;
    let admission = preflight_transport_decode(rvlu, sidecar, profile, limits)?;
    charge_work(work, admission.subsequent_work)?;
    let mut child_work = OfficialWorkBudget::new(admission.subsequent_work);
    let (kind, body) = sidecar_body(sidecar, limits)?;
    if kind == 3 && body.get(..32) != Some(sha256(rvlu)?.as_slice()) {
        return Err(invalid(HEADER_LEN, "native helper RVLU signature 不符"));
    }
    let mut module = decode_module(rvlu, profile, &limits.verify)?;
    match kind {
        0 => {
            if verified_retained_bytes(&module)? > admission.retained_bytes {
                return Err(limit("RVLU 實際保留容量超出預准入"));
            }
            Ok(module)
        }
        1 => {
            let source = decode_official_chunk(body, profile, &limits.official)?;
            let translated =
                translate_official_chunk_with_work(&source, &limits.verify, &mut child_work)?;
            let rebuilt = translated.into_verified();
            let canonical = encode_verified_module_bytes_bounded(
                &rebuilt,
                &limits.verify,
                checked_mul(rvlu.len(), 2)?,
            )?;
            if canonical != rvlu {
                return Err(invalid(0, "官方來源與完整 RVLU 身分不符"));
            }
            if canonical.capacity() > admission.temporary_bytes {
                return Err(limit("canonical RVLU 實際容量超限"));
            }
            if verified_retained_bytes(&rebuilt)? > admission.retained_bytes {
                return Err(limit("官方模組實際保留容量超出預准入"));
            }
            Ok(rebuilt)
        }
        2 => {
            let mut meter = AllocationMeter::new(admission.temporary_bytes);
            let candidate = read_native_body(body, limits, &mut meter)?;
            let debug = verify_native_debug(&module, candidate, &limits.verify, &mut child_work)?;
            if checked_add(meter.used, debug.allocated_bytes())? > admission.temporary_bytes {
                return Err(limit(
                    "native candidate+derived debug 超出 aggregate 預准入",
                ));
            }
            if checked_add(debug.allocated_bytes(), checked_mul(rvlu.len(), 128)?)?
                > admission.retained_bytes
            {
                return Err(limit("native debug 實際保留容量超限"));
            }
            module.set_native_debug(Arc::new(debug));
            if verified_retained_bytes(&module)? > admission.retained_bytes {
                return Err(limit("native module 實際保留容量超出預准入"));
            }
            Ok(module)
        }
        3 => {
            let mut meter = AllocationMeter::new(admission.temporary_bytes);
            let (calls, native_debug) = read_native_declarations(body, limits, &mut meter)?;
            let remaining = admission
                .temporary_bytes
                .checked_sub(meter.used)
                .ok_or_else(|| limit("native helper candidate 預准入不足"))?;
            let (candidate, peak_extra, resident_extra) =
                native_builtin_candidate_from_calls_metered(&module, calls, remaining)?;
            if peak_extra > remaining {
                return Err(limit("native helper candidate 實際容量超出預准入"));
            }
            let verify_remaining = remaining
                .checked_sub(resident_extra)
                .ok_or_else(|| limit("native helper verifier 預准入不足"))?;
            module = verify_native_builtin_plan_metered(
                module,
                candidate,
                &limits.verify,
                verify_remaining,
            )?;
            if let Some(candidate) = native_debug {
                let debug =
                    verify_native_debug(&module, candidate, &limits.verify, &mut child_work)?;
                if checked_add(
                    checked_add(meter.used, resident_extra)?,
                    debug.allocated_bytes(),
                )? > admission.temporary_bytes
                {
                    return Err(limit("native helper+debug 實際暫存容量超出預准入"));
                }
                module.set_native_debug(Arc::new(debug));
            }
            if verified_retained_bytes(&module)? > admission.retained_bytes {
                return Err(limit("native helper 模組實際保留容量超出預准入"));
            }
            Ok(module)
        }
        _ => Err(invalid(6, "sidecar kind 無效")),
    }
}

#[cfg(test)]
mod sha256_tests {
    use super::sha256;

    #[test]
    fn kind3_signature_matches_sha256_known_vectors() {
        assert_eq!(
            sha256(b"").unwrap(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b"abc").unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }
}

#[cfg(test)]
mod native_failure_tests {
    use super::super::codec::{
        BytecodeInstruction, BytecodePrototype, BytecodeSpan, BytecodeUpvalue,
        RVLU_NUMERIC_I64_F64, verify_module,
    };
    use super::super::official_execution::{
        native_builtin_candidate_from_calls, native_reserve_attempts, native_reserve_fail_at,
        verify_native_builtin_plan,
    };
    use super::super::{
        BytecodeUpvalueSource, ConstId, EnvironmentSource, FrameLayout, Instruction, RVLU_V2,
        ResultMode,
    };
    use super::*;

    fn native_fixture(profile: LuaProfile) -> VerifiedModule {
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 1,
        };
        let binding = BytecodeBindingId {
            function: 0,
            ordinal: 0,
        };
        let instructions = [
            Instruction::NewTable { dest: Register(1) },
            Instruction::GetUpvalue {
                dest: Register(2),
                upvalue: UpvalueId(0),
            },
            Instruction::Move {
                dest: Register(3),
                src: Register(1),
            },
            Instruction::LoadConst {
                dest: Register(4),
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: Register(5),
                constant: ConstId(1),
            },
            Instruction::Vararg {
                base: Register(6),
                result_mode: ResultMode::All,
            },
            Instruction::Call {
                base: Register(2),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(0),
            },
            Instruction::LoadNil {
                start: Register(2),
                count: 1,
            },
            Instruction::Return {
                base: Register(1),
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
            profile,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 7,
                parameter_count: 0,
                is_variadic: true,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 7,
                    initial_top: Register(1),
                    dynamic_top: Register(6),
                    return_base: Register(1),
                    environment: Register(0),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(0),
                global_environment_binding: binding,
                binding_registers: vec![(binding, Register(0))],
                constants: vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
                upvalues: vec![BytecodeUpvalue {
                    id: UpvalueId(0),
                    source: BytecodeUpvalueSource::ParentLocal(binding),
                }],
                instructions,
                close_paths: Vec::new(),
            }],
        };
        let plain = verify_module(module, profile, &VerifyLimits::default()).unwrap();
        let calls = vec![OfficialPlanCall {
            prototype: ProtoId(0),
            call_pc: InstructionOffset(6),
            function_register: Register(2),
            source_upvalue: UpvalueId(0),
            inputs: vec![Register(3), Register(4), Register(5)],
            open_tail: Some(Register(6)),
            builtin: OfficialPlanBuiltin::RawListWrite,
        }];
        let candidate = native_builtin_candidate_from_calls(&plain, calls).unwrap();
        verify_native_builtin_plan(plain, candidate, &VerifyLimits::default()).unwrap()
    }

    #[test]
    fn kind3_reader_mapping_verifier_each_bounded_reserve_fails_then_retries() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            native_reserve_fail_at(None);
            let module = native_fixture(profile);
            let limits = TransportLimits::default();
            let encoded = encode_transport_module(
                &module,
                &limits,
                &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
            )
            .unwrap();
            native_reserve_fail_at(None);
            let baseline = decode_transport_module(
                encoded.rvlu(),
                encoded.sidecar(),
                profile,
                &limits,
                &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
            )
            .unwrap();
            assert!(
                baseline
                    .official_execution()
                    .is_some_and(|plan| plan.is_native_builtin())
            );
            let sites = native_reserve_attempts();
            assert_eq!(sites, 8, "reader 2、mapping 4、verifier 2");
            for at in 0..sites {
                native_reserve_fail_at(Some(at));
                let error = decode_transport_module(
                    encoded.rvlu(),
                    encoded.sidecar(),
                    profile,
                    &limits,
                    &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
                )
                .unwrap_err();
                assert_eq!(
                    error.kind,
                    TransportErrorKind::AllocationFailed,
                    "{profile:?} site {at}"
                );
                assert_eq!(native_reserve_attempts(), at + 1);
                native_reserve_fail_at(None);
                let retry = decode_transport_module(
                    encoded.rvlu(),
                    encoded.sidecar(),
                    profile,
                    &limits,
                    &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
                )
                .unwrap();
                assert!(
                    retry
                        .official_execution()
                        .is_some_and(|plan| plan.is_native_builtin())
                );
                assert_eq!(native_reserve_attempts(), sites);
            }
            native_reserve_fail_at(None);
        }
    }
}
