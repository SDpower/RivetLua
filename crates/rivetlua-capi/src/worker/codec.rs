use std::path::PathBuf;

use crate::abi::{self, AbiIdentity};
use crate::native::{NativeArtifact, NativePolicy, SymbolVisibility, UnwindAttestation};

pub const MAGIC: &[u8; 4] = b"RVWK";
pub const VERSION: u16 = 1;
pub const HARD_FRAME_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_FRAME_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_STATUS_BYTES: usize = 4096;
const ABI_BYTES: usize = 246;
pub const HEADER_BYTES: usize = 24 + ABI_BYTES;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub frame_bytes: usize,
    pub max_values: usize,
    pub max_native: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            frame_bytes: DEFAULT_FRAME_BYTES,
            max_values: 128,
            max_native: 16,
        }
    }
}

impl Limits {
    fn valid(self) -> Result<Self, WireError> {
        if self.frame_bytes < HEADER_BYTES
            || self.frame_bytes > HARD_FRAME_BYTES
            || self.max_values == 0
            || self.max_values > 128
            || self.max_native > 16
        {
            return Err(WireError::Limit);
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum CopyValue {
    Nil,
    Boolean(bool),
    Integer(i64),
    NumberBits(u64),
    Bytes(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct NativeSpec {
    pub artifact: NativeArtifact,
    pub policy: NativePolicy,
    pub visibility: SymbolVisibility,
    pub module_name: String,
    pub opener_symbol: String,
    pub global_result: bool,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub rvlu: Vec<u8>,
    pub sidecar: Vec<u8>,
    pub native: Vec<NativeSpec>,
    pub args: Vec<CopyValue>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    Complete(Vec<CopyValue>),
    RuntimeError(Vec<u8>),
    Rejected(Vec<u8>),
    NonCopyable { index: u16, lua_type: u8 },
}

#[derive(Clone, Debug)]
pub enum FrameKind {
    Hello { pid: u32 },
    Request(Request),
    Response(Response),
}

#[derive(Clone, Debug)]
pub struct Frame {
    pub request_id: u64,
    pub identity: AbiIdentity,
    pub kind: FrameKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Invalid,
    Limit,
    Abi,
    Allocation,
}

struct Writer {
    bytes: Vec<u8>,
    cap: usize,
}

impl Writer {
    fn new(cap: usize) -> Self {
        Self {
            bytes: Vec::new(),
            cap,
        }
    }
    fn append(&mut self, data: &[u8]) -> Result<(), WireError> {
        if self
            .bytes
            .len()
            .checked_add(data.len())
            .ok_or(WireError::Limit)?
            > self.cap
        {
            return Err(WireError::Limit);
        }
        self.bytes
            .try_reserve(data.len())
            .map_err(|_| WireError::Allocation)?;
        self.bytes.extend_from_slice(data);
        Ok(())
    }
    fn u8(&mut self, n: u8) -> Result<(), WireError> {
        self.append(&[n])
    }
    fn u16(&mut self, n: u16) -> Result<(), WireError> {
        self.append(&n.to_le_bytes())
    }
    fn u32(&mut self, n: u32) -> Result<(), WireError> {
        self.append(&n.to_le_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<(), WireError> {
        self.append(&n.to_le_bytes())
    }
    fn sized(&mut self, data: &[u8], max: usize) -> Result<(), WireError> {
        if data.len() > max {
            return Err(WireError::Limit);
        }
        self.u32(u32::try_from(data.len()).map_err(|_| WireError::Limit)?)?;
        self.append(data)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.cursor.checked_add(n).ok_or(WireError::Limit)?;
        let part = self.bytes.get(self.cursor..end).ok_or(WireError::Invalid)?;
        self.cursor = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn sized(&mut self, max: usize) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32()?).map_err(|_| WireError::Limit)?;
        if len > max {
            return Err(WireError::Limit);
        }
        self.take(len)
    }
    fn string(&mut self, max: usize) -> Result<String, WireError> {
        let data = self.sized(max)?;
        std::str::from_utf8(data)
            .map(str::to_owned)
            .map_err(|_| WireError::Invalid)
    }
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        let data = self.sized(max)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(data.len())
            .map_err(|_| WireError::Allocation)?;
        bytes.extend_from_slice(data);
        Ok(bytes)
    }
    fn finished(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

fn write_identity(w: &mut Writer, id: &AbiIdentity) -> Result<(), WireError> {
    w.u32(id.revision)?;
    w.u16(id.profile)?;
    w.u16(id.numeric_config)?;
    w.u8(id.pointer_width_bits)?;
    w.u8(id.endianness)?;
    w.u16(id.reserved_zero)?;
    w.append(&id.target)?;
    w.append(&id.header_set_sha256)?;
    w.append(&id.lua_h_sha256)?;
    w.append(&id.lauxlib_h_sha256)?;
    w.append(&id.luaconf_h_sha256)?;
    for field in id.layout {
        w.u16(field)?;
    }
    Ok(())
}

fn read_identity(r: &mut Reader<'_>) -> Result<AbiIdentity, WireError> {
    let revision = r.u32()?;
    let profile = r.u16()?;
    let numeric_config = r.u16()?;
    let pointer_width_bits = r.u8()?;
    let endianness = r.u8()?;
    let reserved_zero = r.u16()?;
    let mut id = abi::current_identity();
    id.revision = revision;
    id.profile = profile;
    id.numeric_config = numeric_config;
    id.pointer_width_bits = pointer_width_bits;
    id.endianness = endianness;
    id.reserved_zero = reserved_zero;
    id.target.copy_from_slice(r.take(32)?);
    id.header_set_sha256.copy_from_slice(r.take(32)?);
    id.lua_h_sha256.copy_from_slice(r.take(32)?);
    id.lauxlib_h_sha256.copy_from_slice(r.take(32)?);
    id.luaconf_h_sha256.copy_from_slice(r.take(32)?);
    for field in &mut id.layout {
        *field = r.u16()?;
    }
    Ok(id)
}

fn write_value(w: &mut Writer, value: &CopyValue) -> Result<(), WireError> {
    match value {
        CopyValue::Nil => w.u8(0),
        CopyValue::Boolean(false) => w.u8(1),
        CopyValue::Boolean(true) => w.u8(2),
        CopyValue::Integer(n) => {
            w.u8(3)?;
            w.u64(*n as u64)
        }
        CopyValue::NumberBits(n) => {
            w.u8(4)?;
            w.u64(*n)
        }
        CopyValue::Bytes(data) => {
            w.u8(5)?;
            w.sized(data, DEFAULT_FRAME_BYTES)
        }
    }
}

fn read_value(r: &mut Reader<'_>) -> Result<CopyValue, WireError> {
    Ok(match r.u8()? {
        0 => CopyValue::Nil,
        1 => CopyValue::Boolean(false),
        2 => CopyValue::Boolean(true),
        3 => CopyValue::Integer(r.u64()? as i64),
        4 => CopyValue::NumberBits(r.u64()?),
        5 => CopyValue::Bytes(r.bytes(DEFAULT_FRAME_BYTES)?),
        _ => return Err(WireError::Invalid),
    })
}

fn write_native(w: &mut Writer, native: &NativeSpec) -> Result<(), WireError> {
    let path = native.artifact.path.to_str().ok_or(WireError::Invalid)?;
    w.sized(path.as_bytes(), 4096)?;
    abi::compare_identity(&abi::current_identity(), Some(&native.artifact.identity))
        .map_err(|_| WireError::Abi)?;
    write_identity(w, &native.artifact.identity)?;
    w.append(&native.artifact.sha256)?;
    w.u8(match native.artifact.unwind {
        UnwindAttestation::CNoUnwind => 1,
        _ => return Err(WireError::Invalid),
    })?;
    w.sized(native.policy.id.as_bytes(), 1024)?;
    w.u8(native.policy.authorized as u8)?;
    w.u8(native.policy.accepts_process_permissions as u8)?;
    w.u8(native.policy.allow_global_symbols as u8)?;
    w.u8(matches!(native.visibility, SymbolVisibility::Global) as u8)?;
    w.sized(native.module_name.as_bytes(), 1024)?;
    w.sized(native.opener_symbol.as_bytes(), 1024)?;
    w.u8(native.global_result as u8)
}

fn read_bool(r: &mut Reader<'_>) -> Result<bool, WireError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::Invalid),
    }
}

fn read_native(r: &mut Reader<'_>) -> Result<NativeSpec, WireError> {
    let path = r.string(4096)?;
    if path.is_empty() || !PathBuf::from(&path).is_absolute() {
        return Err(WireError::Invalid);
    }
    let identity = read_identity(r)?;
    abi::compare_identity(&abi::current_identity(), Some(&identity)).map_err(|_| WireError::Abi)?;
    let mut sha256 = [0_u8; 32];
    sha256.copy_from_slice(r.take(32)?);
    if r.u8()? != 1 {
        return Err(WireError::Invalid);
    }
    let id = r.string(1024)?;
    let authorized = read_bool(r)?;
    let accepts_process_permissions = read_bool(r)?;
    let allow_global_symbols = read_bool(r)?;
    let visibility = if read_bool(r)? {
        SymbolVisibility::Global
    } else {
        SymbolVisibility::Local
    };
    let module_name = r.string(1024)?;
    let opener_symbol = r.string(1024)?;
    let global_result = read_bool(r)?;
    if id.is_empty()
        || module_name.is_empty()
        || opener_symbol.is_empty()
        || module_name.contains('\0')
        || opener_symbol.contains('\0')
    {
        return Err(WireError::Invalid);
    }
    Ok(NativeSpec {
        artifact: NativeArtifact {
            path: PathBuf::from(path),
            identity,
            sha256,
            unwind: UnwindAttestation::CNoUnwind,
        },
        policy: NativePolicy {
            id,
            authorized,
            accepts_process_permissions,
            allow_global_symbols,
        },
        visibility,
        module_name,
        opener_symbol,
        global_result,
    })
}

impl Frame {
    pub fn encode(&self, limits: Limits) -> Result<Vec<u8>, WireError> {
        let limits = limits.valid()?;
        abi::compare_identity(&abi::current_identity(), Some(&self.identity))
            .map_err(|_| WireError::Abi)?;
        let mut w = Writer::new(limits.frame_bytes);
        w.append(MAGIC)?;
        w.u16(VERSION)?;
        let kind = match &self.kind {
            FrameKind::Hello { .. } => 1,
            FrameKind::Request(_) => 2,
            FrameKind::Response(_) => 3,
        };
        w.u16(kind)?;
        w.u32(0)?;
        w.u64(self.request_id)?;
        w.u16(self.identity.profile)?;
        w.u16(0)?;
        write_identity(&mut w, &self.identity)?;
        match &self.kind {
            FrameKind::Hello { pid } => w.u32(*pid)?,
            FrameKind::Request(request) => {
                if request.native.len() > limits.max_native
                    || request.args.len() > limits.max_values
                {
                    return Err(WireError::Limit);
                }
                w.sized(&request.rvlu, limits.frame_bytes)?;
                w.sized(&request.sidecar, limits.frame_bytes)?;
                w.u16(request.native.len() as u16)?;
                for item in &request.native {
                    write_native(&mut w, item)?;
                }
                w.u16(request.args.len() as u16)?;
                for item in &request.args {
                    write_value(&mut w, item)?;
                }
            }
            FrameKind::Response(response) => match response {
                Response::Complete(values) => {
                    if values.len() > limits.max_values {
                        return Err(WireError::Limit);
                    }
                    w.u8(0)?;
                    w.u16(values.len() as u16)?;
                    for item in values {
                        write_value(&mut w, item)?;
                    }
                }
                Response::RuntimeError(bytes) => {
                    w.u8(1)?;
                    w.sized(bytes, MAX_STATUS_BYTES)?;
                }
                Response::Rejected(bytes) => {
                    w.u8(2)?;
                    w.sized(bytes, MAX_STATUS_BYTES)?;
                }
                Response::NonCopyable { index, lua_type } => {
                    w.u8(3)?;
                    w.u16(*index)?;
                    w.u8(*lua_type)?;
                }
            },
        }
        let len = u32::try_from(w.bytes.len()).map_err(|_| WireError::Limit)?;
        w.bytes[8..12].copy_from_slice(&len.to_le_bytes());
        Ok(w.bytes)
    }

    pub fn decode(bytes: &[u8], limits: Limits) -> Result<Self, WireError> {
        let limits = limits.valid()?;
        if bytes.len() > limits.frame_bytes || bytes.len() < HEADER_BYTES {
            return Err(WireError::Limit);
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != MAGIC || r.u16()? != VERSION {
            return Err(WireError::Invalid);
        }
        let kind = r.u16()?;
        if r.u32()? as usize != bytes.len() {
            return Err(WireError::Invalid);
        }
        let request_id = r.u64()?;
        let profile = r.u16()?;
        if r.u16()? != 0 {
            return Err(WireError::Invalid);
        }
        let identity = read_identity(&mut r)?;
        if profile != identity.profile
            || abi::compare_identity(&abi::current_identity(), Some(&identity)).is_err()
        {
            return Err(WireError::Abi);
        }
        let kind = match kind {
            1 => FrameKind::Hello { pid: r.u32()? },
            2 => {
                let rvlu = r.bytes(limits.frame_bytes)?;
                let sidecar = r.bytes(limits.frame_bytes)?;
                let count = r.u16()? as usize;
                if count > limits.max_native {
                    return Err(WireError::Limit);
                }
                let mut native = Vec::new();
                native
                    .try_reserve_exact(count)
                    .map_err(|_| WireError::Allocation)?;
                for _ in 0..count {
                    native.push(read_native(&mut r)?);
                }
                let count = r.u16()? as usize;
                if count > limits.max_values {
                    return Err(WireError::Limit);
                }
                let mut args = Vec::new();
                args.try_reserve_exact(count)
                    .map_err(|_| WireError::Allocation)?;
                for _ in 0..count {
                    args.push(read_value(&mut r)?);
                }
                FrameKind::Request(Request {
                    rvlu,
                    sidecar,
                    native,
                    args,
                })
            }
            3 => {
                let response = match r.u8()? {
                    0 => {
                        let count = r.u16()? as usize;
                        if count > limits.max_values {
                            return Err(WireError::Limit);
                        }
                        let mut values = Vec::new();
                        values
                            .try_reserve_exact(count)
                            .map_err(|_| WireError::Allocation)?;
                        for _ in 0..count {
                            values.push(read_value(&mut r)?);
                        }
                        Response::Complete(values)
                    }
                    1 => Response::RuntimeError(r.bytes(MAX_STATUS_BYTES)?),
                    2 => Response::Rejected(r.bytes(MAX_STATUS_BYTES)?),
                    3 => Response::NonCopyable {
                        index: r.u16()?,
                        lua_type: r.u8()?,
                    },
                    _ => return Err(WireError::Invalid),
                };
                FrameKind::Response(response)
            }
            _ => return Err(WireError::Invalid),
        };
        if !r.finished() {
            return Err(WireError::Invalid);
        }
        Ok(Self {
            request_id,
            identity,
            kind,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_invalid_frame() {
        let source = Frame {
            request_id: 44,
            identity: abi::current_identity(),
            kind: FrameKind::Response(Response::Complete(vec![
                CopyValue::Nil,
                CopyValue::Boolean(false),
                CopyValue::Integer(-5),
                CopyValue::NumberBits(f64::NAN.to_bits()),
                CopyValue::Bytes(vec![0, 0xff]),
            ])),
        };
        let data = source.encode(Limits::default()).unwrap();
        let decoded = Frame::decode(&data, Limits::default()).unwrap();
        assert_eq!(decoded.request_id, 44);
        match decoded.kind {
            FrameKind::Response(Response::Complete(values)) => assert_eq!(
                values,
                vec![
                    CopyValue::Nil,
                    CopyValue::Boolean(false),
                    CopyValue::Integer(-5),
                    CopyValue::NumberBits(f64::NAN.to_bits()),
                    CopyValue::Bytes(vec![0, 0xff]),
                ]
            ),
            _ => panic!("回應類型"),
        }
        let mut bad = data.clone();
        bad.push(0);
        assert_eq!(
            Frame::decode(&bad, Limits::default()).unwrap_err(),
            WireError::Invalid
        );
        let mut bad = data.clone();
        bad[22] = 1;
        assert_eq!(
            Frame::decode(&bad, Limits::default()).unwrap_err(),
            WireError::Invalid
        );
        let mut bad = data;
        bad[HEADER_BYTES + 1] = 255;
        assert_eq!(
            Frame::decode(&bad, Limits::default()).unwrap_err(),
            WireError::Limit
        );
    }
}
