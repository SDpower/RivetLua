//! P21 平台與 board 的版本化外層身分；不改動 RVLU 語言模組格式。

use alloc::string::String;
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::borrow::ToOwned;

use alloc::collections::BTreeSet;

use crate::{LuaProfile, RVLU_NUMERIC_I64_F64};

const WIRE_VERSION: u16 = 1;
const TARGET_MAGIC: &[u8; 4] = b"RTGT";
const BOARD_MAGIC: &[u8; 4] = b"RBRD";
const MAX_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 255;
const MAX_FEATURES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetError {
    InvalidField(&'static str),
    Mismatch(&'static str),
    Malformed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endian { Little, Big }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecMemoryPolicy { Forbidden, WriteThenExecute, MapJit }

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeploymentStatus {
    Supported { evidence_id: String },
    BuildOnly,
    Experimental { limits: String },
    Unsupported { reason: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDescriptor {
    pub target_triple: String,
    pub isa: String,
    pub cpu_features: BTreeSet<String>,
    pub os: String,
    pub abi: String,
    pub endian: Endian,
    pub lua_profile: LuaProfile,
    pub numeric_config: u8,
    pub flash_cap: Option<u64>,
    pub ram_cap: u64,
    pub code_cap: u64,
    pub exec_memory_policy: ExecMemoryPolicy,
    pub runtime_version: String,
    pub compiler_version: String,
    pub build_provenance: String,
}

impl TargetDescriptor {
    pub fn validate(&self) -> Result<(), TargetError> {
        for (name, value) in [
            ("target_triple", &self.target_triple), ("isa", &self.isa),
            ("os", &self.os), ("abi", &self.abi),
            ("runtime_version", &self.runtime_version),
            ("compiler_version", &self.compiler_version),
            ("build_provenance", &self.build_provenance),
        ] {
            valid_text(value).then_some(()).ok_or(TargetError::InvalidField(name))?;
        }
        if self.cpu_features.len() > MAX_FEATURES
            || self.cpu_features.iter().any(|value| !valid_text(value))
        {
            return Err(TargetError::InvalidField("cpu_features"));
        }
        if self.numeric_config != RVLU_NUMERIC_I64_F64 {
            return Err(TargetError::InvalidField("numeric_config"));
        }
        if self.flash_cap == Some(0) || self.ram_cap == 0 || self.code_cap == 0 {
            return Err(TargetError::InvalidField("capacity"));
        }
        let triple_arm64 = self.target_triple.starts_with("aarch64-")
            || self.target_triple.starts_with("arm64-");
        let triple_thumb = self.target_triple.starts_with("thumb");
        let isa_arm64 = self.isa.eq_ignore_ascii_case("aarch64")
            || self.isa.eq_ignore_ascii_case("arm64");
        let isa_thumb = self.isa.to_ascii_lowercase().starts_with("thumb")
            || self.isa.to_ascii_lowercase().starts_with("cortex-m");
        if (triple_arm64 && isa_thumb) || (triple_thumb && isa_arm64) {
            return Err(TargetError::InvalidField("isa"));
        }
        Ok(())
    }

    pub fn ensure_matches(&self, other: &Self) -> Result<(), TargetError> {
        self.validate()?;
        other.validate()?;
        if self == other { Ok(()) } else { Err(TargetError::Mismatch("target descriptor")) }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TargetError> {
        self.validate()?;
        let mut body = Vec::new();
        put_text(&mut body, &self.target_triple);
        put_text(&mut body, &self.isa);
        put_u16(&mut body, self.cpu_features.len() as u16);
        for feature in &self.cpu_features { put_text(&mut body, feature); }
        put_text(&mut body, &self.os);
        put_text(&mut body, &self.abi);
        body.push(match self.endian { Endian::Little => 0, Endian::Big => 1 });
        body.push(match self.lua_profile { LuaProfile::Lua54 => 54, LuaProfile::Lua55 => 55 });
        body.push(self.numeric_config);
        match self.flash_cap {
            Some(cap) => { body.push(1); put_u64(&mut body, cap); }
            None => body.push(0),
        }
        put_u64(&mut body, self.ram_cap);
        put_u64(&mut body, self.code_cap);
        body.push(match self.exec_memory_policy {
            ExecMemoryPolicy::Forbidden => 0,
            ExecMemoryPolicy::WriteThenExecute => 1,
            ExecMemoryPolicy::MapJit => 2,
        });
        put_text(&mut body, &self.runtime_version);
        put_text(&mut body, &self.compiler_version);
        put_text(&mut body, &self.build_provenance);
        wrap(TARGET_MAGIC, body)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TargetError> {
        let mut reader = unwrap(TARGET_MAGIC, bytes)?;
        let target_triple = reader.text()?;
        let isa = reader.text()?;
        let count = reader.u16()? as usize;
        if count > MAX_FEATURES { return Err(TargetError::Malformed); }
        let mut cpu_features = BTreeSet::new();
        for _ in 0..count {
            if !cpu_features.insert(reader.text()?) { return Err(TargetError::Malformed); }
        }
        let os = reader.text()?;
        let abi = reader.text()?;
        let endian = match reader.u8()? {
            0 => Endian::Little, 1 => Endian::Big, _ => return Err(TargetError::Malformed),
        };
        let lua_profile = match reader.u8()? {
            54 => LuaProfile::Lua54, 55 => LuaProfile::Lua55, _ => return Err(TargetError::Malformed),
        };
        let numeric_config = reader.u8()?;
        let flash_cap = match reader.u8()? {
            0 => None, 1 => Some(reader.u64()?), _ => return Err(TargetError::Malformed),
        };
        let ram_cap = reader.u64()?;
        let code_cap = reader.u64()?;
        let exec_memory_policy = match reader.u8()? {
            0 => ExecMemoryPolicy::Forbidden,
            1 => ExecMemoryPolicy::WriteThenExecute,
            2 => ExecMemoryPolicy::MapJit,
            _ => return Err(TargetError::Malformed),
        };
        let runtime_version = reader.text()?;
        let compiler_version = reader.text()?;
        let build_provenance = reader.text()?;
        reader.finish()?;
        let result = Self { target_triple, isa, cpu_features, os, abi, endian,
            lua_profile, numeric_config, flash_cap, ram_cap, code_cap, exec_memory_policy,
            runtime_version, compiler_version, build_provenance };
        result.validate()?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoardConfig {
    pub schema_version: u32,
    pub board_id: String,
    pub cpu: String,
    pub thumb: bool,
    pub fpu: Option<String>,
    pub float_abi: String,
    pub linker_map_digest: [u8; 32],
    pub allocator: String,
    pub panic_strategy: String,
    pub entry: String,
    pub clock: String,
    pub timer: String,
}

impl BoardConfig {
    pub fn validate(&self) -> Result<(), TargetError> {
        if self.schema_version != 1 { return Err(TargetError::InvalidField("schema_version")); }
        for (name, value) in [
            ("board_id", &self.board_id), ("cpu", &self.cpu),
            ("float_abi", &self.float_abi), ("allocator", &self.allocator),
            ("panic_strategy", &self.panic_strategy), ("entry", &self.entry),
            ("clock", &self.clock), ("timer", &self.timer),
        ] {
            valid_text(value).then_some(()).ok_or(TargetError::InvalidField(name))?;
        }
        if self.fpu.as_ref().is_some_and(|value| !valid_text(value)) {
            return Err(TargetError::InvalidField("fpu"));
        }
        let cpu = self.cpu.to_ascii_lowercase();
        if (cpu.starts_with("cortex-m") && !self.thumb)
            || ((cpu.starts_with("aarch64") || cpu.starts_with("arm64")) && self.thumb)
        {
            return Err(TargetError::InvalidField("thumb"));
        }
        if self.float_abi == "hard" && self.fpu.is_none() {
            return Err(TargetError::InvalidField("fpu"));
        }
        Ok(())
    }

    pub fn ensure_matches(&self, other: &Self) -> Result<(), TargetError> {
        self.validate()?;
        other.validate()?;
        if self == other { Ok(()) } else { Err(TargetError::Mismatch("board config")) }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, TargetError> {
        self.validate()?;
        let mut body = Vec::new();
        put_u32(&mut body, self.schema_version);
        put_text(&mut body, &self.board_id);
        put_text(&mut body, &self.cpu);
        body.push(u8::from(self.thumb));
        match &self.fpu {
            Some(fpu) => { body.push(1); put_text(&mut body, fpu); }
            None => body.push(0),
        }
        put_text(&mut body, &self.float_abi);
        body.extend_from_slice(&self.linker_map_digest);
        put_text(&mut body, &self.allocator);
        put_text(&mut body, &self.panic_strategy);
        put_text(&mut body, &self.entry);
        put_text(&mut body, &self.clock);
        put_text(&mut body, &self.timer);
        wrap(BOARD_MAGIC, body)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TargetError> {
        let mut reader = unwrap(BOARD_MAGIC, bytes)?;
        let schema_version = reader.u32()?;
        let board_id = reader.text()?;
        let cpu = reader.text()?;
        let thumb = match reader.u8()? { 0 => false, 1 => true, _ => return Err(TargetError::Malformed) };
        let fpu = match reader.u8()? { 0 => None, 1 => Some(reader.text()?), _ => return Err(TargetError::Malformed) };
        let float_abi = reader.text()?;
        let mut linker_map_digest = [0; 32];
        linker_map_digest.copy_from_slice(reader.take(32)?);
        let allocator = reader.text()?;
        let panic_strategy = reader.text()?;
        let entry = reader.text()?;
        let clock = reader.text()?;
        let timer = reader.text()?;
        reader.finish()?;
        let result = Self { schema_version, board_id, cpu, thumb, fpu, float_abi,
            linker_map_digest, allocator, panic_strategy, entry, clock, timer };
        result.validate()?;
        Ok(result)
    }
}

fn valid_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_TEXT_BYTES && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn put_u16(bytes: &mut Vec<u8>, value: u16) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn put_u32(bytes: &mut Vec<u8>, value: u32) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn put_u64(bytes: &mut Vec<u8>, value: u64) { bytes.extend_from_slice(&value.to_le_bytes()); }
fn put_text(bytes: &mut Vec<u8>, value: &str) {
    put_u16(bytes, value.len() as u16);
    bytes.extend_from_slice(value.as_bytes());
}

fn wrap(magic: &[u8; 4], body: Vec<u8>) -> Result<Vec<u8>, TargetError> {
    if body.len().checked_add(10).is_none_or(|length| length > MAX_BYTES) {
        return Err(TargetError::InvalidField("metadata length"));
    }
    let mut bytes = Vec::with_capacity(10 + body.len());
    bytes.extend_from_slice(magic);
    put_u16(&mut bytes, WIRE_VERSION);
    put_u32(&mut bytes, body.len() as u32);
    bytes.extend_from_slice(&body);
    Ok(bytes)
}

fn unwrap<'a>(magic: &[u8; 4], bytes: &'a [u8]) -> Result<Reader<'a>, TargetError> {
    if bytes.len() < 10 || bytes.len() > MAX_BYTES || &bytes[..4] != magic
        || u16::from_le_bytes([bytes[4], bytes[5]]) != WIRE_VERSION
        || u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize != bytes.len() - 10
    {
        return Err(TargetError::Malformed);
    }
    Ok(Reader { bytes: &bytes[10..], cursor: 0 })
}

struct Reader<'a> { bytes: &'a [u8], cursor: usize }

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], TargetError> {
        let end = self.cursor.checked_add(length).ok_or(TargetError::Malformed)?;
        let value = self.bytes.get(self.cursor..end).ok_or(TargetError::Malformed)?;
        self.cursor = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, TargetError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, TargetError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, TargetError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| TargetError::Malformed)?))
    }
    fn u64(&mut self) -> Result<u64, TargetError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| TargetError::Malformed)?))
    }
    fn text(&mut self) -> Result<String, TargetError> {
        let length = self.u16()? as usize;
        if length > MAX_TEXT_BYTES { return Err(TargetError::Malformed); }
        let text = core::str::from_utf8(self.take(length)?).map_err(|_| TargetError::Malformed)?;
        Ok(text.to_owned())
    }
    fn finish(self) -> Result<(), TargetError> {
        if self.cursor == self.bytes.len() { Ok(()) } else { Err(TargetError::Malformed) }
    }
}
