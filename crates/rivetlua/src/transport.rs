//! 公開 SDK 的 RVCT 傳輸容器；payload 一律交由 P05 驗證。

use rivetlua_core::{
    InputError, InputErrorKind, InputFormat, OfficialWorkBudget, TransportError,
    TransportErrorKind, TransportLimits, classify_input, decode_input_module,
    decode_transport_module, encode_transport_module, input_scan_admission, preflight_input_module,
    preflight_transport_decode, preflight_transport_encode, transport_encode_scan_admission,
    transport_scan_admission,
};
use rivetlua_runtime::{AllocationLedger, AllocationTrace, LedgerSnapshot, VmError};
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use crate::{Engine, Module};

const MAGIC: &[u8; 4] = b"RVCT";
const HEADER_LEN: usize = 40;
const VERSION: u16 = 1;
const CRC_OFFSET: usize = 32;
const CRC_LEN: usize = 4;
const ARC_CONTROL_OVERHEAD: usize = 128;

/// SDK 容器的長度、work、配置及 P05 verifier policy。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerLimits {
    /// 輸入或輸出 RVCT 的總長上限，包含 40-byte header。
    pub max_container_bytes: usize,
    /// 單次 save/load 可預付的保守 peak 配置上限。
    pub max_allocation_bytes: usize,
    /// 單次 save/load 的總 work 上限，包含外層 checksum/copy 與 P05。
    pub max_work: u64,
    /// 交由 P05 使用的格式、profile、sidecar、retained 與 work 限額。
    pub transport: TransportLimits,
}

impl Default for ContainerLimits {
    fn default() -> Self {
        Self {
            max_container_bytes: 64 * 1024 * 1024,
            max_allocation_bytes: 768 * 1024 * 1024,
            max_work: u64::MAX,
            transport: TransportLimits::default(),
        }
    }
}

/// 可重用的容器處理額度。帳本在此 context 建立，不在解析輸入時建立。
#[derive(Clone)]
pub struct TransportBudget {
    limits: ContainerLimits,
    ledger: AllocationLedger,
}

impl TransportBudget {
    /// 建立可重用的 P06 host allocation ledger 與容器 policy。
    pub fn new(limits: ContainerLimits) -> Self {
        Self {
            ledger: AllocationLedger::new(limits.max_allocation_bytes),
            limits,
        }
    }

    pub const fn limits(&self) -> &ContainerLimits {
        &self.limits
    }

    /// 讀取單次操作完成後的帳本；SDK 對輸出採逐操作 peak 額度，不累積 host resident bytes。
    pub fn allocation_snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    /// 讀取單次操作的公開配置嘗試序號，供呼叫端與測試觀察。
    pub fn allocation_trace(&self) -> AllocationTrace {
        self.ledger.trace()
    }

    /// 在指定帳本序號注入一次配置失敗；通常傳入 `allocation_trace().next_ordinal`。
    pub fn fail_once_at_ordinal(&self, ordinal: u64) {
        self.ledger.fail_once_at_ordinal(ordinal);
    }

    /// 更新後續操作的總配置上限。
    pub fn set_allocation_limit(&self, limit: usize) {
        self.ledger.set_limit(limit);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContainerErrorKind {
    InvalidFormat,
    UnsupportedVersion,
    IntegrityMismatch,
    LimitExceeded,
    AllocationFailed,
    Payload,
}

/// RVCT 外層或其 P05 payload 驗證錯誤；訊息使用靜態文字，不保留輸入資料。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContainerError {
    pub kind: ContainerErrorKind,
    pub offset: usize,
    pub detail: &'static str,
    pub payload_kind: Option<TransportErrorKind>,
    pub input_kind: Option<InputErrorKind>,
}

impl fmt::Display for ContainerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RVCT 位移 {}：{}", self.offset, self.detail)
    }
}

impl Error for ContainerError {}

fn error(kind: ContainerErrorKind, offset: usize, detail: &'static str) -> ContainerError {
    ContainerError {
        kind,
        offset,
        detail,
        payload_kind: None,
        input_kind: None,
    }
}

impl From<TransportError> for ContainerError {
    fn from(source: TransportError) -> Self {
        let kind = match source.kind {
            TransportErrorKind::LimitExceeded => ContainerErrorKind::LimitExceeded,
            TransportErrorKind::AllocationFailed => ContainerErrorKind::AllocationFailed,
            TransportErrorKind::InvalidFormat
            | TransportErrorKind::Bytecode
            | TransportErrorKind::OfficialChunk
            | TransportErrorKind::OfficialTranslation => ContainerErrorKind::Payload,
        };
        Self {
            kind,
            offset: source.offset,
            detail: "P05 transport verifier 拒絕 payload",
            payload_kind: Some(source.kind),
            input_kind: None,
        }
    }
}

impl From<InputError> for ContainerError {
    fn from(source: InputError) -> Self {
        let kind = match source.kind {
            InputErrorKind::InvalidFormat => ContainerErrorKind::InvalidFormat,
            InputErrorKind::LimitExceeded => ContainerErrorKind::LimitExceeded,
            InputErrorKind::AllocationFailed => ContainerErrorKind::AllocationFailed,
        };
        Self {
            kind,
            offset: source.offset,
            detail: source.detail,
            payload_kind: None,
            input_kind: Some(source.kind),
        }
    }
}

fn allocation_error(source: VmError) -> ContainerError {
    let kind = match source {
        VmError::ArithmeticOverflow => ContainerErrorKind::LimitExceeded,
        _ => ContainerErrorKind::AllocationFailed,
    };
    error(kind, 0, "單次容器配置 escrow 失敗")
}

fn add(left: usize, right: usize) -> Result<usize, ContainerError> {
    left.checked_add(right)
        .ok_or_else(|| error(ContainerErrorKind::LimitExceeded, 0, "容器長度加法溢位"))
}

fn mul(left: usize, right: usize) -> Result<usize, ContainerError> {
    left.checked_mul(right).ok_or_else(|| {
        error(
            ContainerErrorKind::LimitExceeded,
            0,
            "容器配置或工作量乘法溢位",
        )
    })
}

fn to_u64(value: usize) -> Result<u64, ContainerError> {
    u64::try_from(value)
        .map_err(|_| error(ContainerErrorKind::LimitExceeded, 0, "容器長度超出 u64"))
}

fn crc32_parts(parts: &[&[u8]]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for part in parts {
        for &byte in *part {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
            }
        }
    }
    !crc
}

#[derive(Debug)]
struct Envelope<'a> {
    rvlu: &'a [u8],
    sidecar: &'a [u8],
}

/// 只讀 RVCT 自身欄位；不解析 RVLU 或 RVAS，也不配置記憶體。
fn read_envelope_fields<'a>(
    bytes: &'a [u8],
    limits: &ContainerLimits,
) -> Result<Envelope<'a>, ContainerError> {
    if bytes.len() < HEADER_LEN {
        return Err(error(
            ContainerErrorKind::InvalidFormat,
            bytes.len(),
            "RVCT header 截斷",
        ));
    }
    if &bytes[0..4] != MAGIC {
        return Err(error(
            ContainerErrorKind::InvalidFormat,
            0,
            "RVCT magic 無效",
        ));
    }
    let version = u16::from_le_bytes([bytes[4], bytes[5]]);
    if version != VERSION {
        return Err(error(
            ContainerErrorKind::UnsupportedVersion,
            4,
            "不支援的 RVCT version",
        ));
    }
    if u16::from_le_bytes([bytes[6], bytes[7]]) != 0 {
        return Err(error(
            ContainerErrorKind::InvalidFormat,
            6,
            "RVCT flags 必須為零",
        ));
    }
    if bytes[36..40] != [0; 4] {
        return Err(error(
            ContainerErrorKind::InvalidFormat,
            36,
            "RVCT reserved 必須為零",
        ));
    }

    let declared_total = u64::from_le_bytes(bytes[8..16].try_into().expect("fixed header"));
    let rvlu_u64 = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed header"));
    let sidecar_u64 = u64::from_le_bytes(bytes[24..32].try_into().expect("fixed header"));
    let total = usize::try_from(declared_total).map_err(|_| {
        error(
            ContainerErrorKind::LimitExceeded,
            8,
            "RVCT total length 超出平台 usize",
        )
    })?;
    let rvlu_len = usize::try_from(rvlu_u64).map_err(|_| {
        error(
            ContainerErrorKind::LimitExceeded,
            16,
            "RVCT RVLU length 超出平台 usize",
        )
    })?;
    let sidecar_len = usize::try_from(sidecar_u64).map_err(|_| {
        error(
            ContainerErrorKind::LimitExceeded,
            24,
            "RVCT sidecar length 超出平台 usize",
        )
    })?;
    let payload_len = add(rvlu_len, sidecar_len)?;
    let calculated_total = add(HEADER_LEN, payload_len)?;
    if total != bytes.len() || calculated_total != total {
        return Err(error(
            ContainerErrorKind::InvalidFormat,
            8,
            "RVCT declared length 與輸入長度不一致",
        ));
    }
    if total > limits.max_container_bytes {
        return Err(error(
            ContainerErrorKind::LimitExceeded,
            8,
            "RVCT container 長度超限",
        ));
    }
    if rvlu_len > limits.transport.verify.max_module_bytes {
        return Err(error(
            ContainerErrorKind::LimitExceeded,
            16,
            "RVLU payload 長度超限",
        ));
    }
    if sidecar_len > limits.transport.max_sidecar_bytes {
        return Err(error(
            ContainerErrorKind::LimitExceeded,
            24,
            "sidecar payload 長度超限",
        ));
    }

    let rvlu_end = add(HEADER_LEN, rvlu_len)?;
    Ok(Envelope {
        rvlu: &bytes[HEADER_LEN..rvlu_end],
        sidecar: &bytes[rvlu_end..total],
    })
}

fn verify_integrity(bytes: &[u8]) -> Result<(), ContainerError> {
    let expected_crc = u32::from_le_bytes(
        bytes[CRC_OFFSET..CRC_OFFSET + CRC_LEN]
            .try_into()
            .expect("fixed header"),
    );
    let actual_crc = crc32_parts(&[&bytes[..CRC_OFFSET], &bytes[CRC_OFFSET + CRC_LEN..]]);
    if actual_crc != expected_crc {
        return Err(error(
            ContainerErrorKind::IntegrityMismatch,
            CRC_OFFSET,
            "RVCT CRC32 不符",
        ));
    }

    Ok(())
}

#[cfg(test)]
fn read_envelope<'a>(
    bytes: &'a [u8],
    limits: &ContainerLimits,
) -> Result<Envelope<'a>, ContainerError> {
    let envelope = read_envelope_fields(bytes, limits)?;
    verify_integrity(bytes)?;
    Ok(envelope)
}

fn checksum_prepaid_work(bytes_len: usize) -> Result<u128, ContainerError> {
    // 每個輸入 byte 的 CRC 最多 8 次 bitwise polynomial 更新；header 欄位驗證固定計 40。
    let byte_count = u128::try_from(bytes_len).map_err(|_| {
        error(
            ContainerErrorKind::LimitExceeded,
            0,
            "容器 work 長度超出 u128",
        )
    })?;
    byte_count
        .checked_mul(8)
        .and_then(|work| work.checked_add(HEADER_LEN as u128))
        .ok_or_else(|| {
            error(
                ContainerErrorKind::LimitExceeded,
                0,
                "容器 checksum work 溢位",
            )
        })
}

fn add_work(left: u128, right: u128) -> Result<u128, ContainerError> {
    left.checked_add(right)
        .ok_or_else(|| error(ContainerErrorKind::LimitExceeded, 0, "容器 work 加法溢位"))
}

fn ensure_work(total: u128, limit: u64) -> Result<u64, ContainerError> {
    let total = u64::try_from(total)
        .map_err(|_| error(ContainerErrorKind::LimitExceeded, 0, "容器 work 超出 u64"))?;
    if total > limit {
        return Err(error(
            ContainerErrorKind::LimitExceeded,
            0,
            "容器 work 超限",
        ));
    }
    Ok(total)
}

fn escrow_peak(
    limits: &ContainerLimits,
    transport_temporary: usize,
    transport_retained: usize,
    outer_capacity_upper: usize,
    arc_control: usize,
) -> Result<usize, ContainerError> {
    let total = transport_temporary
        .checked_add(transport_retained)
        .and_then(|value| value.checked_add(outer_capacity_upper))
        .and_then(|value| value.checked_add(arc_control))
        .ok_or_else(|| error(ContainerErrorKind::LimitExceeded, 0, "容器 peak 配置量溢位"))?;
    if total > limits.max_allocation_bytes {
        return Err(error(
            ContainerErrorKind::LimitExceeded,
            0,
            "容器 peak 配置量超限",
        ));
    }
    Ok(total)
}

impl Engine {
    /// 只透過 P05 將已驗證 module 編成 RVLU／sidecar，再包入 RVCT v1。
    pub fn save_module(
        &self,
        module: &Module,
        budget: &TransportBudget,
    ) -> Result<Vec<u8>, ContainerError> {
        let limits = &budget.limits;
        let transport_scan = transport_encode_scan_admission(&module.verified, &limits.transport)?;
        // 第一次 P05 掃描是 caller 在呼叫無配置 preflight 前必須支付的部分。
        let preflight_work = u128::from(transport_scan.work);
        ensure_work(preflight_work, limits.max_work)?;
        let admission = preflight_transport_encode(&module.verified, &limits.transport)?;
        let p05_actual_work = transport_scan
            .work
            .checked_add(admission.subsequent_work)
            .ok_or_else(|| {
                error(
                    ContainerErrorKind::LimitExceeded,
                    0,
                    "P05 scan 與 operation work 溢位",
                )
            })?;
        let outer_len_upper = add(
            HEADER_LEN,
            add(admission.rvlu_bytes_upper, admission.sidecar_bytes_upper)?,
        )?;
        if outer_len_upper > limits.max_container_bytes {
            return Err(error(
                ContainerErrorKind::LimitExceeded,
                8,
                "RVCT 預准入長度超過 container 上限",
            ));
        }
        let outer_capacity_upper = mul(outer_len_upper, 2)?;
        let outer_copy_work = u128::from(to_u64(outer_len_upper)?);
        // Save 也預付與 load 相同的每位元組 CRC 上界，再加上最壞輸出複製量。
        let outer_work = add_work(checksum_prepaid_work(outer_len_upper)?, outer_copy_work)?;
        let total_work = add_work(
            add_work(preflight_work, u128::from(p05_actual_work))?,
            outer_work,
        )?;
        ensure_work(total_work, limits.max_work)?;

        let escrow = escrow_peak(
            limits,
            admission.temporary_bytes,
            admission.retained_bytes,
            outer_capacity_upper,
            0,
        )?;
        let _reservation = budget.ledger.reserve(escrow).map_err(allocation_error)?;

        let mut p05_work = OfficialWorkBudget::new(p05_actual_work);
        let encoded = encode_transport_module(&module.verified, &limits.transport, &mut p05_work)?;
        let (rvlu, sidecar) = encoded.into_parts();
        let total = add(HEADER_LEN, add(rvlu.len(), sidecar.len())?)?;
        if total > limits.max_container_bytes {
            return Err(error(
                ContainerErrorKind::LimitExceeded,
                8,
                "RVCT 輸出長度超限",
            ));
        }
        if total > outer_len_upper {
            return Err(error(
                ContainerErrorKind::LimitExceeded,
                8,
                "P05 實際輸出超出預准入長度",
            ));
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(total).map_err(|_| {
            error(
                ContainerErrorKind::AllocationFailed,
                0,
                "RVCT 輸出緩衝配置失敗",
            )
        })?;
        if bytes.capacity() > outer_capacity_upper {
            return Err(error(
                ContainerErrorKind::LimitExceeded,
                0,
                "RVCT 實際輸出容量超出 escrow",
            ));
        }
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&to_u64(total)?.to_le_bytes());
        bytes.extend_from_slice(&to_u64(rvlu.len())?.to_le_bytes());
        bytes.extend_from_slice(&to_u64(sidecar.len())?.to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(&rvlu);
        bytes.extend_from_slice(&sidecar);
        debug_assert_eq!(bytes.len(), total);
        let checksum = crc32_parts(&[&bytes[..CRC_OFFSET], &bytes[CRC_OFFSET + CRC_LEN..]]);
        bytes[CRC_OFFSET..CRC_OFFSET + CRC_LEN].copy_from_slice(&checksum.to_le_bytes());
        Ok(bytes)
    }

    /// 驗 RVCT 外層後，將兩段 opaque payload 交給 P05 重建新的已驗證 Module。
    pub fn load_module(
        &self,
        bytes: &[u8],
        budget: &TransportBudget,
    ) -> Result<Module, ContainerError> {
        let limits = &budget.limits;
        let envelope = read_envelope_fields(bytes, limits)?;

        // CRC 會逐 bitwise 掃描輸入；先預付其上界，拒絕不足額度時不讀 payload。
        let outer_prepaid = checksum_prepaid_work(bytes.len())?;
        ensure_work(outer_prepaid, limits.max_work)?;
        verify_integrity(bytes)?;

        let scan = transport_scan_admission(envelope.rvlu.len(), envelope.sidecar.len())?;
        let preflight_paid = add_work(outer_prepaid, u128::from(scan.work))?;
        ensure_work(preflight_paid, limits.max_work)?;
        let admission = preflight_transport_decode(
            envelope.rvlu,
            envelope.sidecar,
            self.profile,
            &limits.transport,
        )?;
        let p05_work = scan
            .work
            .checked_add(admission.subsequent_work)
            .ok_or_else(|| {
                error(
                    ContainerErrorKind::LimitExceeded,
                    0,
                    "P05 scan 與 operation work 溢位",
                )
            })?;
        // producer 還會自行重做 scan+operation；Arc 建立另計固定一個 SDK work unit。
        let total_work = add_work(add_work(preflight_paid, u128::from(p05_work))?, 1)?;
        ensure_work(total_work, limits.max_work)?;

        let escrow = escrow_peak(
            limits,
            admission.temporary_bytes,
            admission.retained_bytes,
            0,
            ARC_CONTROL_OVERHEAD,
        )?;
        let _reservation = budget.ledger.reserve(escrow).map_err(allocation_error)?;

        let mut p05_budget = OfficialWorkBudget::new(p05_work);
        let verified = decode_transport_module(
            envelope.rvlu,
            envelope.sidecar,
            self.profile,
            &limits.transport,
            &mut p05_budget,
        )?;
        Ok(Module {
            verified: Arc::new(verified),
        })
    }

    /// 依 Core classifier 載入 raw RVLU 或官方 chunk；RVCT 前綴沿用既有容器驗證。
    pub fn load_binary_module(
        &self,
        bytes: &[u8],
        budget: &TransportBudget,
    ) -> Result<Module, ContainerError> {
        if bytes.starts_with(MAGIC) {
            return self.load_module(bytes, budget);
        }

        let format = classify_input(bytes);
        if !matches!(format, InputFormat::RawRvlu | InputFormat::Official) {
            return Err(ContainerError {
                kind: ContainerErrorKind::InvalidFormat,
                offset: 0,
                detail: match format {
                    InputFormat::Source => "load_binary_module 不接受 Lua source",
                    InputFormat::UnsupportedBinary => "不支援的 binary input",
                    InputFormat::RawRvlu | InputFormat::Official => unreachable!(),
                },
                payload_kind: None,
                input_kind: Some(InputErrorKind::InvalidFormat),
            });
        }

        let limits = &budget.limits;
        let scan = input_scan_admission(bytes.len(), format)?;
        ensure_work(u128::from(scan.work), limits.max_work)?;
        let preflight = preflight_input_module(bytes, self.profile, &limits.transport)?;
        let admission = preflight.admission();
        let total_work = add_work(
            add_work(u128::from(scan.work), u128::from(admission.subsequent_work))?,
            1,
        )?;
        ensure_work(total_work, limits.max_work)?;
        let escrow = escrow_peak(
            limits,
            admission.temporary_bytes,
            admission.retained_bytes,
            0,
            ARC_CONTROL_OVERHEAD,
        )?;
        let _reservation = budget.ledger.reserve(escrow).map_err(allocation_error)?;
        let verified = decode_input_module(preflight)?;
        Ok(Module {
            verified: Arc::new(verified),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CRC_OFFSET, ContainerErrorKind, ContainerLimits, HEADER_LEN, MAGIC, VERSION, add_work,
        checksum_prepaid_work, crc32_parts, ensure_work, preflight_transport_encode, read_envelope,
        transport_encode_scan_admission,
    };
    use crate::{Engine, LuaProfile, TransportBudget};

    fn empty_container() -> Vec<u8> {
        let mut bytes = vec![0; HEADER_LEN];
        bytes[0..4].copy_from_slice(MAGIC);
        bytes[4..6].copy_from_slice(&VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&(HEADER_LEN as u64).to_le_bytes());
        let crc = crc32_parts(&[&bytes[..CRC_OFFSET], &bytes[CRC_OFFSET + 4..]]);
        bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
        bytes
    }

    fn refresh_crc(bytes: &mut [u8]) {
        let crc = crc32_parts(&[&bytes[..CRC_OFFSET], &bytes[CRC_OFFSET + 4..]]);
        bytes[CRC_OFFSET..CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    }

    #[test]
    fn wrapper_reader_checks_outer_header_and_integrity_without_payload_knowledge() {
        let bytes = empty_container();
        let envelope = read_envelope(&bytes, &ContainerLimits::default()).unwrap();
        assert!(envelope.rvlu.is_empty());
        assert!(envelope.sidecar.is_empty());

        let mut bad_crc = bytes.clone();
        bad_crc[39] ^= 1;
        assert_eq!(
            read_envelope(&bad_crc, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::InvalidFormat
        );

        let mut bad_payload_crc = bytes;
        bad_payload_crc[32] ^= 1;
        assert_eq!(
            read_envelope(&bad_payload_crc, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::IntegrityMismatch
        );
    }

    #[test]
    fn wrapper_reader_rejects_invalid_outer_fields_lengths_overflow_and_limits() {
        let valid = empty_container();

        let mut bad_magic = valid.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            read_envelope(&bad_magic, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::InvalidFormat
        );

        let mut bad_version = valid.clone();
        bad_version[4] = 2;
        assert_eq!(
            read_envelope(&bad_version, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::UnsupportedVersion
        );

        let mut bad_flags = valid.clone();
        bad_flags[6] = 1;
        assert_eq!(
            read_envelope(&bad_flags, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::InvalidFormat
        );

        let mut bad_total = valid.clone();
        bad_total[8] = (HEADER_LEN as u64 + 1).to_le_bytes()[0];
        refresh_crc(&mut bad_total);
        assert_eq!(
            read_envelope(&bad_total, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::InvalidFormat
        );

        let mut overflowing = valid.clone();
        overflowing[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        overflowing[24..32].copy_from_slice(&1u64.to_le_bytes());
        refresh_crc(&mut overflowing);
        assert_eq!(
            read_envelope(&overflowing, &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::LimitExceeded
        );

        assert_eq!(
            read_envelope(&valid[..HEADER_LEN - 1], &ContainerLimits::default())
                .unwrap_err()
                .kind,
            ContainerErrorKind::InvalidFormat
        );

        let too_small = ContainerLimits {
            max_container_bytes: HEADER_LEN - 1,
            ..ContainerLimits::default()
        };
        assert_eq!(
            read_envelope(&valid, &too_small).unwrap_err().kind,
            ContainerErrorKind::LimitExceeded
        );
    }

    #[test]
    fn wrapper_writer_checks_exact_container_allocation_and_crc_work_escrow() {
        let engine = Engine::new(LuaProfile::Lua55);
        let module = engine.compile(b"return 44").unwrap();
        let defaults = ContainerLimits::default();
        let scan = transport_encode_scan_admission(&module.verified, &defaults.transport).unwrap();
        let admission = preflight_transport_encode(&module.verified, &defaults.transport).unwrap();
        let p05_operation_work = scan.work.checked_add(admission.subsequent_work).unwrap();
        let container_upper = HEADER_LEN
            .checked_add(admission.rvlu_bytes_upper)
            .and_then(|value| value.checked_add(admission.sidecar_bytes_upper))
            .unwrap();
        let outer_copy_work = u128::try_from(container_upper).unwrap();
        let outer_work = add_work(
            checksum_prepaid_work(container_upper).unwrap(),
            outer_copy_work,
        )
        .unwrap();
        let expected_work = u128::from(scan.work)
            .checked_add(u128::from(p05_operation_work))
            .and_then(|value| value.checked_add(outer_work))
            .unwrap();
        let exact_work = u64::try_from(expected_work).unwrap();
        assert_eq!(ensure_work(expected_work, exact_work).unwrap(), exact_work);
        assert!(ensure_work(expected_work, exact_work - 1).is_err());

        let output_capacity_upper = container_upper.checked_mul(2).unwrap();
        let exact_allocation = admission
            .temporary_bytes
            .checked_add(admission.retained_bytes)
            .and_then(|value| value.checked_add(output_capacity_upper))
            .unwrap();
        let exact_limits = ContainerLimits {
            max_container_bytes: container_upper,
            max_allocation_bytes: exact_allocation,
            max_work: exact_work,
            ..defaults
        };
        let exact_budget = TransportBudget::new(exact_limits);
        let bytes = engine.save_module(&module, &exact_budget).unwrap();
        assert!(bytes.len() <= container_upper);
        assert_eq!(
            exact_budget.allocation_trace().last_attempt.unwrap().bytes,
            exact_allocation
        );
        assert_eq!(exact_budget.allocation_snapshot().reserved, 0);

        for limits in [
            ContainerLimits {
                max_container_bytes: container_upper - 1,
                ..exact_limits
            },
            ContainerLimits {
                max_allocation_bytes: exact_allocation - 1,
                ..exact_limits
            },
            ContainerLimits {
                max_work: exact_work - 1,
                ..exact_limits
            },
        ] {
            let denied_budget = TransportBudget::new(limits);
            assert!(engine.save_module(&module, &denied_budget).is_err());
            assert_eq!(denied_budget.allocation_trace().next_ordinal, 1);
            assert_eq!(denied_budget.allocation_snapshot().reserved, 0);
        }
    }
}
