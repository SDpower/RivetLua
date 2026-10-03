//! P05 的語言輸入分類與無 sidecar 載入准入。

use super::LuaProfile;
use super::codec::{BytecodeError, BytecodeErrorCode, VerifiedModule, decode_module};
use super::official::{OfficialChunkError, OfficialChunkErrorKind, decode_official_chunk};
use super::official_preflight::{OfficialChunkPreflight, preflight_official_chunk};
use super::official_translation::{
    OfficialTranslationError, OfficialTranslationErrorKind, OfficialWorkBudget,
    translate_official_chunk_with_work,
};
use super::transport::{
    TransportError, TransportErrorKind, TransportLimits, TransportScanAdmission,
    preflight_transport_decode, transport_scan_admission, verified_module_allocation_bytes,
};

// kind 0 的固定 RVAS header 僅在 Core 內供 raw RVLU 預掃描使用；沒有可還原的 sidecar。
const RAW_NONE_SIDECAR: [u8; 16] = [b'R', b'V', b'A', b'S', 1, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputFormat {
    Source,
    RawRvlu,
    Official,
    UnsupportedBinary,
}

/// 只查看固定前綴；`RVLU` 後的 binary version bytes 才視為 RVLU wire。
pub fn classify_input(bytes: &[u8]) -> InputFormat {
    if bytes.first() == Some(&0x1b) {
        return if bytes.starts_with(b"\x1bLua") {
            InputFormat::Official
        } else {
            InputFormat::UnsupportedBinary
        };
    }
    if bytes.starts_with(b"RVLU")
        && bytes.get(4..).is_some_and(|version| {
            version
                .iter()
                .take(2)
                .any(|byte| !byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
        })
    {
        InputFormat::RawRvlu
    } else {
        InputFormat::Source
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputErrorKind {
    InvalidFormat,
    LimitExceeded,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputError {
    pub kind: InputErrorKind,
    pub offset: usize,
    pub detail: &'static str,
}

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "輸入位移 {}：{}", self.offset, self.detail)
    }
}

impl std::error::Error for InputError {}

fn invalid(detail: &'static str) -> InputError {
    InputError {
        kind: InputErrorKind::InvalidFormat,
        offset: 0,
        detail,
    }
}

fn limit(detail: &'static str) -> InputError {
    InputError {
        kind: InputErrorKind::LimitExceeded,
        offset: 0,
        detail,
    }
}

impl From<TransportError> for InputError {
    fn from(error: TransportError) -> Self {
        let kind = match error.kind {
            TransportErrorKind::LimitExceeded => InputErrorKind::LimitExceeded,
            TransportErrorKind::AllocationFailed => InputErrorKind::AllocationFailed,
            TransportErrorKind::InvalidFormat
            | TransportErrorKind::Bytecode
            | TransportErrorKind::OfficialChunk
            | TransportErrorKind::OfficialTranslation => InputErrorKind::InvalidFormat,
        };
        Self {
            kind,
            offset: error.offset,
            detail: error.detail,
        }
    }
}

impl From<BytecodeError> for InputError {
    fn from(error: BytecodeError) -> Self {
        Self {
            kind: match error.code {
                BytecodeErrorCode::CompileLimit => InputErrorKind::LimitExceeded,
                BytecodeErrorCode::AllocationFailed => InputErrorKind::AllocationFailed,
                BytecodeErrorCode::Verify => InputErrorKind::InvalidFormat,
            },
            offset: error.offset,
            detail: "RVLU 解碼或驗證失敗",
        }
    }
}

impl From<OfficialChunkError> for InputError {
    fn from(error: OfficialChunkError) -> Self {
        Self {
            kind: match error.kind {
                OfficialChunkErrorKind::LimitExceeded | OfficialChunkErrorKind::WorkExhausted => {
                    InputErrorKind::LimitExceeded
                }
                OfficialChunkErrorKind::AllocationFailed => InputErrorKind::AllocationFailed,
                OfficialChunkErrorKind::InvalidFormat
                | OfficialChunkErrorKind::Truncated
                | OfficialChunkErrorKind::Overflow => InputErrorKind::InvalidFormat,
            },
            offset: 0,
            detail: "官方 Lua chunk 無效或超限",
        }
    }
}

impl From<OfficialTranslationError> for InputError {
    fn from(error: OfficialTranslationError) -> Self {
        Self {
            kind: match error.kind {
                OfficialTranslationErrorKind::InvalidChunk => InputErrorKind::InvalidFormat,
                OfficialTranslationErrorKind::LimitExceeded => InputErrorKind::LimitExceeded,
                OfficialTranslationErrorKind::AllocationFailed => InputErrorKind::AllocationFailed,
            },
            offset: 0,
            detail: "官方 Lua chunk 翻譯失敗",
        }
    }
}

pub fn input_scan_admission(
    byte_len: usize,
    format: InputFormat,
) -> Result<TransportScanAdmission, InputError> {
    match format {
        InputFormat::RawRvlu => Ok(transport_scan_admission(byte_len, RAW_NONE_SIDECAR.len())?),
        InputFormat::Official => {
            let len = u64::try_from(byte_len).map_err(|_| limit("輸入長度超限"))?;
            let work = len
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(|| limit("輸入掃描工作量溢位"))?;
            Ok(TransportScanAdmission {
                work,
                temporary_bytes: 0,
            })
        }
        InputFormat::Source | InputFormat::UnsupportedBinary => {
            Err(invalid("輸入格式沒有 bytecode scanner"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputAdmission {
    pub scan_work: u64,
    pub subsequent_work: u64,
    pub temporary_bytes: usize,
    pub retained_bytes: usize,
}

#[derive(Debug)]
pub struct InputPreflight<'a> {
    bytes: &'a [u8],
    profile: LuaProfile,
    format: InputFormat,
    limits: TransportLimits,
    official: Option<OfficialChunkPreflight>,
    admission: InputAdmission,
}

impl InputPreflight<'_> {
    pub fn format(&self) -> InputFormat {
        self.format
    }

    pub fn admission(&self) -> InputAdmission {
        self.admission
    }
}

/// 呼叫者須先支付 `input_scan_admission`；此函式只借用原輸入，decode 不可偷換 bytes。
pub fn preflight_input_module<'a>(
    bytes: &'a [u8],
    profile: LuaProfile,
    limits: &TransportLimits,
) -> Result<InputPreflight<'a>, InputError> {
    let format = classify_input(bytes);
    let scan = input_scan_admission(bytes.len(), format)?;
    if scan.work > limits.max_work {
        return Err(limit("輸入掃描工作量超限"));
    }
    let (subsequent_work, temporary_bytes, retained_bytes, official) = match format {
        InputFormat::RawRvlu => {
            let admission = preflight_transport_decode(bytes, &RAW_NONE_SIDECAR, profile, limits)?;
            (
                admission.subsequent_work,
                admission.temporary_bytes,
                admission.retained_bytes,
                None,
            )
        }
        InputFormat::Official => {
            let mut official_limits = limits.official;
            official_limits.max_allocated_bytes = official_limits
                .max_allocated_bytes
                .min(limits.max_temporary_bytes);
            let stats = preflight_official_chunk(bytes, profile, &official_limits, &limits.verify)?;
            (
                stats.subsequent_work,
                stats.temporary_bytes,
                stats.retained_bytes,
                Some(stats),
            )
        }
        InputFormat::Source | InputFormat::UnsupportedBinary => {
            return Err(invalid("無法解碼為 bytecode"));
        }
    };
    if scan
        .work
        .checked_add(subsequent_work)
        .is_none_or(|total| total > limits.max_work)
        || temporary_bytes > limits.max_temporary_bytes
        || retained_bytes > limits.max_retained_bytes
    {
        return Err(limit("輸入資源准入超限"));
    }
    Ok(InputPreflight {
        bytes,
        profile,
        format,
        limits: *limits,
        official,
        admission: InputAdmission {
            scan_work: scan.work,
            subsequent_work,
            temporary_bytes,
            retained_bytes,
        },
    })
}

/// 在 subsequent work、temporary 與 retained 由呼叫者預付後執行。
pub fn decode_input_module(preflight: InputPreflight<'_>) -> Result<VerifiedModule, InputError> {
    let admission = preflight.admission;
    let module = match preflight.format {
        InputFormat::RawRvlu => {
            // raw RVLU 不帶 RVAS：只驗證 wire，不重建私有 plan/debug/artifact。
            decode_module(preflight.bytes, preflight.profile, &preflight.limits.verify)?
        }
        InputFormat::Official => {
            let stats = preflight
                .official
                .ok_or_else(|| invalid("官方預掃描缺失"))?;
            let mut official_limits = preflight.limits.official;
            official_limits.max_allocated_bytes = official_limits
                .max_allocated_bytes
                .min(stats.decoded_bytes)
                .min(admission.temporary_bytes);
            let decoded =
                decode_official_chunk(preflight.bytes, preflight.profile, &official_limits)?;
            let mut work = OfficialWorkBudget::new(admission.subsequent_work);
            let translated =
                translate_official_chunk_with_work(&decoded, &preflight.limits.verify, &mut work)
                    .map_err(|error| {
                    if work.exhausted() {
                        limit("官方翻譯工作量超限")
                    } else {
                        InputError::from(error)
                    }
                })?;
            translated.into_verified()
        }
        InputFormat::Source | InputFormat::UnsupportedBinary => {
            return Err(invalid("無法解碼為 bytecode"));
        }
    };
    if verified_module_allocation_bytes(&module)? > admission.retained_bytes {
        return Err(limit("模組實際保留容量超出預准入"));
    }
    Ok(module)
}
