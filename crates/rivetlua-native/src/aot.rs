//! P21 AOT 外層產物；語言模組仍只使用 P05 RVLU_V2。

use rivetlua_core::{
    BytecodeVersion, LuaProfile, OfficialWorkBudget, RVLU_V2, TargetDescriptor, TransportLimits,
    VerifiedModule, VmId, encode_transport_module, sha256_bytes,
};

use crate::abi::NativeError;
#[cfg(feature = "compiler")]
use crate::artifact::NativeCompileError;
use crate::artifact::{
    BACKEND_VERSION, CODE_VERSION, NativeArtifact, ValidatedCode, check_prototype,
};
use crate::execmem::{self, ExecutableCode};

const MAGIC: &[u8; 4] = b"RAOT";
const SCHEMA_VERSION: u16 = 1;
const HEADER_LEN: usize = 14;
const DIGEST_LEN: usize = 32;
const MAX_METADATA: usize = 64 * 1024;
const MAX_CODE: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum AotError {
    Malformed,
    Unsupported(&'static str),
    Mismatch(&'static str),
    Untrusted,
    Producer(String),
    Native(NativeError),
}

pub struct AotBuildInput<'a> {
    pub module: &'a VerifiedModule,
    pub prototype_index: usize,
    pub entry_pc: usize,
    pub target: &'a TargetDescriptor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AotManifest {
    pub schema_version: u16,
    pub format_version: BytecodeVersion,
    pub profile: LuaProfile,
    pub numeric_config: u8,
    pub module_digest: [u8; 32],
    pub target: TargetDescriptor,
    pub prototype_index: usize,
    pub entry_pc: usize,
    pub code_len: usize,
    pub metadata_len: usize,
    pub backend_version: String,
    pub code_version: u32,
    pub runtime_version: String,
    pub compiler_version: String,
    pub build_provenance: String,
}

pub struct AotArtifact {
    bytes: Vec<u8>,
    manifest: AotManifest,
    trust: TrustedAotBuild,
}

impl AotArtifact {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn manifest(&self) -> &AotManifest {
        &self.manifest
    }
    pub fn trusted_build(&self) -> TrustedAotBuild {
        self.trust.clone()
    }
}

#[derive(Clone)]
pub struct TrustedAotBuild {
    artifact_digest: [u8; 32],
    build_identity: String,
}

impl TrustedAotBuild {
    /// # Safety
    /// 呼叫端必須在可信建置鏈中獨立確認此精確 artifact digest 由本版本 builder 產生，
    /// 並確認機器碼 ABI、白名單、relocation、安全性與 build identity；檔案自身 digest 不構成信任。
    pub unsafe fn attest_external(artifact_digest: [u8; 32], build_identity: String) -> Self {
        Self {
            artifact_digest,
            build_identity,
        }
    }
}

#[cfg(feature = "compiler")]
pub fn build_aot(input: AotBuildInput<'_>) -> Result<AotArtifact, AotError> {
    validate_target(input.target, input.module)?;
    let (code, mask) = crate::codegen::lower_aot(
        input.module,
        input.prototype_index,
        input.entry_pc,
        input.target.target_triple.clone(),
    )
    .map_err(|error| match error {
        NativeCompileError::Unsupported(reason) => AotError::Unsupported(reason),
        NativeCompileError::Rejected(reason) => AotError::Mismatch(reason),
        NativeCompileError::Native(error) => AotError::Native(error),
        NativeCompileError::Backend(error) => AotError::Producer(error),
    })?;
    if code.bytes().len() > MAX_CODE || code.bytes().len() as u64 > input.target.code_cap {
        return Err(AotError::Unsupported("AOT code cap"));
    }
    let mut manifest = AotManifest {
        schema_version: SCHEMA_VERSION,
        format_version: input.module.format_version(),
        profile: input.module.profile(),
        numeric_config: input.module.module().numeric_config,
        module_digest: canonical_digest(input.module)?,
        target: input.target.clone(),
        prototype_index: input.prototype_index,
        entry_pc: input.entry_pc,
        code_len: code.bytes().len(),
        metadata_len: 0,
        backend_version: BACKEND_VERSION.into(),
        code_version: CODE_VERSION,
        runtime_version: input.target.runtime_version.clone(),
        compiler_version: input.target.compiler_version.clone(),
        build_provenance: input.target.build_provenance.clone(),
    };
    let metadata = encode_metadata(&manifest, &code, &mask)?;
    manifest.metadata_len = metadata.len();
    let mut bytes =
        Vec::with_capacity(HEADER_LEN + metadata.len() + code.bytes().len() + DIGEST_LEN);
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(code.bytes().len() as u32).to_le_bytes());
    bytes.extend_from_slice(&metadata);
    bytes.extend_from_slice(code.bytes());
    let integrity = digest(&bytes)?;
    bytes.extend_from_slice(&integrity);
    if let Some(flash) = input.target.flash_cap {
        if bytes.len() as u64 > flash {
            return Err(AotError::Unsupported("AOT flash cap"));
        }
    }
    let trust = TrustedAotBuild {
        artifact_digest: digest(&bytes)?,
        build_identity: build_identity(&manifest),
    };
    Ok(AotArtifact {
        bytes,
        manifest,
        trust,
    })
}

pub fn inspect_aot(bytes: &[u8]) -> Result<AotManifest, AotError> {
    Ok(parse(bytes)?.manifest)
}

pub fn load_aot(
    bytes: &[u8],
    module: &VerifiedModule,
    expected_target: &TargetDescriptor,
    trust: &TrustedAotBuild,
    vm_id: VmId,
) -> Result<NativeArtifact, AotError> {
    let parsed = parse(bytes)?;
    let manifest = &parsed.manifest;
    if digest(bytes)? != trust.artifact_digest || trust.build_identity != build_identity(manifest) {
        return Err(AotError::Untrusted);
    }
    if manifest.module_digest != canonical_digest(module)?
        || manifest.format_version != module.format_version()
        || manifest.profile != module.profile()
        || manifest.numeric_config != module.module().numeric_config
        || manifest.format_version != RVLU_V2
    {
        return Err(AotError::Mismatch("module identity"));
    }
    if manifest.backend_version != BACKEND_VERSION
        || manifest.code_version != CODE_VERSION
        || manifest.runtime_version != env!("CARGO_PKG_VERSION")
        || manifest.compiler_version != env!("CARGO_PKG_VERSION")
        || manifest.build_provenance != manifest.target.build_provenance
    {
        return Err(AotError::Mismatch("builder version or provenance"));
    }
    expected_target
        .ensure_matches(&manifest.target)
        .map_err(|_| AotError::Mismatch("target descriptor"))?;
    validate_target(expected_target, module)?;
    if expected_target.target_triple != execmem::host_target() {
        return Err(AotError::Unsupported("AOT target differs from host"));
    }
    let prototype = module
        .module()
        .prototypes
        .get(manifest.prototype_index)
        .ok_or(AotError::Mismatch("prototype index"))?;
    if prototype.register_count == 0
        || prototype.register_count > 4096
        || prototype.instructions.is_empty()
        || prototype.instructions.len() > 100_000
        || manifest.entry_pc >= prototype.instructions.len()
        || !prototype.close_paths.is_empty()
    {
        return Err(AotError::Mismatch("prototype limits"));
    }
    let mask =
        check_prototype(prototype).map_err(|_| AotError::Mismatch("instruction whitelist"))?;
    if parsed.mask != mask
        || parsed.register_count != usize::from(prototype.register_count)
        || parsed.max_pc != prototype.instructions.len() - 1
        || parsed.entry_offset != 0
    {
        return Err(AotError::Mismatch("AOT derived metadata"));
    }
    let code_limit = usize::try_from(expected_target.code_cap)
        .map_err(|_| AotError::Unsupported("code cap overflow"))?;
    if parsed.code.len() > code_limit || parsed.code.len() > MAX_CODE {
        return Err(AotError::Unsupported("AOT code cap"));
    }
    if let Some(flash) = expected_target.flash_cap {
        if bytes.len() as u64 > flash {
            return Err(AotError::Unsupported("AOT flash cap"));
        }
    }
    // trust 與 module／target／白名單均已確認後，才可密封 raw code 供 execmem 使用。
    let code = ValidatedCode {
        bytes: parsed.code.to_vec(),
        entry_offset: parsed.entry_offset,
        entry_pc: manifest.entry_pc as u64,
        max_pc: parsed.max_pc as u64,
        register_count: parsed.register_count,
        target: manifest.target.target_triple.clone(),
        required_cpu_features: Vec::new(),
    };
    let planned = execmem::planned_usage(&code, code_limit).map_err(AotError::Native)?;
    // 包含可執行映射、arena/free list、artifact 及載入時的 code/metadata 暫存。
    let metadata_charge = manifest
        .metadata_len
        .checked_add(mask.len())
        .and_then(|n| n.checked_add(parsed.mask.len()))
        .and_then(|n| n.checked_add(core::mem::size_of::<NativeArtifact>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<AotManifest>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<Parsed<'static>>()))
        .and_then(|n| n.checked_add(core::mem::size_of::<ValidatedCode>()))
        .and_then(|n| n.checked_add(code.bytes().len()))
        .and_then(|n| n.checked_add(manifest.target.target_triple.len()))
        .ok_or(AotError::Unsupported("AOT metadata cap overflow"))?;
    let ram_needed = planned
        .code_bytes
        .checked_add(planned.metadata_bytes)
        .and_then(|n| n.checked_add(metadata_charge))
        .ok_or(AotError::Unsupported("AOT RAM cap overflow"))?;
    if ram_needed as u64 > expected_target.ram_cap {
        return Err(AotError::Unsupported("AOT RAM cap"));
    }
    execmem::preflight(&code, code_limit).map_err(AotError::Native)?;
    let executable = ExecutableCode::publish(&code, code_limit).map_err(AotError::Native)?;
    Ok(NativeArtifact {
        code: executable,
        module_digest: manifest.module_digest,
        vm_id,
        function_id: prototype.id,
        function: prototype.function,
        format_version: manifest.format_version,
        code_version: CODE_VERSION,
        profile: manifest.profile,
        numeric_config: manifest.numeric_config,
        entry_pc: manifest.entry_pc,
        register_mask: mask,
        code_bytes: manifest.code_len,
        compile_ns: 0,
        target: manifest.target.target_triple.clone(),
        cpu_features: &[],
    })
}

fn validate_target(target: &TargetDescriptor, module: &VerifiedModule) -> Result<(), AotError> {
    target
        .validate()
        .map_err(|_| AotError::Mismatch("target descriptor fields"))?;
    let platform = crate::targets::platform_target(&target.target_triple)
        .ok_or(AotError::Unsupported("AOT target ISA/backend"))?;
    if !platform.aot_codegen {
        return Err(AotError::Unsupported("AOT target ISA/backend"));
    }
    if target.isa != platform.isa
        || target.os != platform.os
        || target.abi != platform.abi
        || target.exec_memory_policy != platform.exec_memory_policy
        || target.endian != rivetlua_core::Endian::Little
        || !target.cpu_features.is_empty()
        || target.runtime_version != env!("CARGO_PKG_VERSION")
        || target.compiler_version != env!("CARGO_PKG_VERSION")
    {
        return Err(AotError::Unsupported("AOT target identity/capability"));
    }
    if target.lua_profile != module.profile()
        || target.numeric_config != module.module().numeric_config
        || module.format_version() != RVLU_V2
    {
        return Err(AotError::Mismatch("AOT profile/numeric/format"));
    }
    Ok(())
}

fn canonical_digest(module: &VerifiedModule) -> Result<[u8; 32], AotError> {
    let mut work = OfficialWorkBudget::new(u64::MAX);
    let encoded = encode_transport_module(module, &TransportLimits::default(), &mut work)
        .map_err(|error| AotError::Producer(format!("{error:?}")))?;
    digest(encoded.rvlu())
}

fn build_identity(manifest: &AotManifest) -> String {
    format!(
        "{}:{}:{}:{}",
        manifest.backend_version,
        manifest.code_version,
        manifest.compiler_version,
        manifest.build_provenance
    )
}

fn digest(bytes: &[u8]) -> Result<[u8; 32], AotError> {
    sha256_bytes(bytes).ok_or(AotError::Unsupported("SHA-256 input length"))
}

struct Parsed<'a> {
    manifest: AotManifest,
    code: &'a [u8],
    entry_offset: usize,
    max_pc: usize,
    register_count: usize,
    mask: Vec<bool>,
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>, AotError> {
    if bytes.len() < HEADER_LEN + DIGEST_LEN
        || bytes.len() > HEADER_LEN + MAX_METADATA + MAX_CODE + DIGEST_LEN
        || bytes.get(..4) != Some(MAGIC.as_slice())
    {
        return Err(AotError::Malformed);
    }
    let mut header = Reader::new(bytes);
    header.take(4)?;
    if header.u16()? != SCHEMA_VERSION {
        return Err(AotError::Malformed);
    }
    let metadata_len = header.u32()? as usize;
    let code_len = header.u32()? as usize;
    let body_len = metadata_len
        .checked_add(code_len)
        .and_then(|n| n.checked_add(HEADER_LEN + DIGEST_LEN))
        .ok_or(AotError::Malformed)?;
    if metadata_len == 0
        || metadata_len > MAX_METADATA
        || code_len == 0
        || code_len > MAX_CODE
        || body_len != bytes.len()
    {
        return Err(AotError::Malformed);
    }
    let metadata = header.take(metadata_len)?;
    let code = header.take(code_len)?;
    let integrity = header.take(DIGEST_LEN)?;
    header.finish()?;
    if digest(&bytes[..bytes.len() - DIGEST_LEN])?.as_slice() != integrity {
        return Err(AotError::Malformed);
    }
    let mut reader = Reader::new(metadata);
    let target_len = reader.u32()? as usize;
    if target_len == 0 || target_len > 16 * 1024 {
        return Err(AotError::Malformed);
    }
    let target =
        TargetDescriptor::from_bytes(reader.take(target_len)?).map_err(|_| AotError::Malformed)?;
    let mut module_digest = [0; 32];
    module_digest.copy_from_slice(reader.take(32)?);
    let format_version = BytecodeVersion(reader.u16()?);
    let profile = match reader.u8()? {
        54 => LuaProfile::Lua54,
        55 => LuaProfile::Lua55,
        _ => return Err(AotError::Malformed),
    };
    let numeric_config = reader.u8()?;
    let prototype_index = reader.u32()? as usize;
    let entry_pc = reader.u32()? as usize;
    let backend_version = reader.text()?;
    let code_version = reader.u32()?;
    let runtime_version = reader.text()?;
    let compiler_version = reader.text()?;
    let build_provenance = reader.text()?;
    let entry_offset = reader.u32()? as usize;
    let max_pc = reader.u32()? as usize;
    let register_count = reader.u16()? as usize;
    let mask_len = reader.u16()? as usize;
    if register_count == 0
        || register_count > 4096
        || mask_len != register_count
        || entry_offset >= code_len
        || entry_pc > max_pc
    {
        return Err(AotError::Malformed);
    }
    let mask = reader
        .take(mask_len)?
        .iter()
        .map(|&byte| match byte {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AotError::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    reader.finish()?;
    if format_version != RVLU_V2
        || numeric_config != rivetlua_core::RVLU_NUMERIC_I64_F64
        || runtime_version != target.runtime_version
        || compiler_version != target.compiler_version
        || build_provenance != target.build_provenance
    {
        return Err(AotError::Malformed);
    }
    let manifest = AotManifest {
        schema_version: SCHEMA_VERSION,
        format_version,
        profile,
        numeric_config,
        module_digest,
        target,
        prototype_index,
        entry_pc,
        code_len,
        metadata_len,
        backend_version,
        code_version,
        runtime_version,
        compiler_version,
        build_provenance,
    };
    Ok(Parsed {
        manifest,
        code,
        entry_offset,
        max_pc,
        register_count,
        mask,
    })
}

#[cfg(feature = "compiler")]
fn encode_metadata(
    manifest: &AotManifest,
    code: &ValidatedCode,
    mask: &[bool],
) -> Result<Vec<u8>, AotError> {
    let target = manifest
        .target
        .to_bytes()
        .map_err(|_| AotError::Malformed)?;
    let mut bytes = Vec::new();
    put_u32(&mut bytes, target.len())?;
    bytes.extend_from_slice(&target);
    bytes.extend_from_slice(&manifest.module_digest);
    bytes.extend_from_slice(&manifest.format_version.0.to_le_bytes());
    bytes.push(match manifest.profile {
        LuaProfile::Lua54 => 54,
        LuaProfile::Lua55 => 55,
    });
    bytes.push(manifest.numeric_config);
    put_u32(&mut bytes, manifest.prototype_index)?;
    put_u32(&mut bytes, manifest.entry_pc)?;
    put_text(&mut bytes, &manifest.backend_version)?;
    bytes.extend_from_slice(&manifest.code_version.to_le_bytes());
    put_text(&mut bytes, &manifest.runtime_version)?;
    put_text(&mut bytes, &manifest.compiler_version)?;
    put_text(&mut bytes, &manifest.build_provenance)?;
    put_u32(&mut bytes, code.entry_offset())?;
    put_u32(&mut bytes, code.max_pc() as usize)?;
    put_u16(&mut bytes, code.register_count())?;
    put_u16(&mut bytes, mask.len())?;
    bytes.extend(mask.iter().map(|value| u8::from(*value)));
    if bytes.len() > MAX_METADATA {
        return Err(AotError::Unsupported("AOT metadata cap"));
    }
    Ok(bytes)
}

#[cfg(feature = "compiler")]
fn put_u16(bytes: &mut Vec<u8>, value: usize) -> Result<(), AotError> {
    bytes.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| AotError::Unsupported("AOT u16 length"))?
            .to_le_bytes(),
    );
    Ok(())
}
#[cfg(feature = "compiler")]
fn put_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), AotError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| AotError::Unsupported("AOT u32 length"))?
            .to_le_bytes(),
    );
    Ok(())
}
#[cfg(feature = "compiler")]
fn put_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), AotError> {
    if value.is_empty() || value.len() > 255 {
        return Err(AotError::Malformed);
    }
    put_u16(bytes, value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], AotError> {
        let end = self.cursor.checked_add(length).ok_or(AotError::Malformed)?;
        let result = self
            .bytes
            .get(self.cursor..end)
            .ok_or(AotError::Malformed)?;
        self.cursor = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, AotError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, AotError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
    fn u32(&mut self) -> Result<u32, AotError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    fn text(&mut self) -> Result<String, AotError> {
        let length = self.u16()? as usize;
        if length == 0 || length > 255 {
            return Err(AotError::Malformed);
        }
        let text = std::str::from_utf8(self.take(length)?).map_err(|_| AotError::Malformed)?;
        Ok(text.to_owned())
    }
    fn finish(self) -> Result<(), AotError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(AotError::Malformed)
        }
    }
}
