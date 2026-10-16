//! 宿主明示的 P17 原生授權。此層只解析、核對與預檢，不呼叫原生程式碼。

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use rivetlua::LuaProfile;
use rivetlua_capi::abi::{self, AbiIdentity};
use rivetlua_capi::native::{
    self, NativeArtifact, NativePolicy, SymbolVisibility, UnwindAttestation,
};

const MAX_GRANT_BYTES: usize = 1024 * 1024;
const MAX_MODULES: usize = 64;
const MAX_CPATH: usize = 32;
const MAX_EXPORTS: usize = 64;
const MAX_DEPENDENCIES: usize = 16;
const MAX_PATH_BYTES: usize = native::MAX_PATH_BYTES;
const MAX_SYMBOL_BYTES: usize = native::MAX_NAME_BYTES;
const ABI_MANIFEST: &[u8] = include_bytes!("../../../tests/p16/abi-manifest.toml");

#[derive(Debug)]
pub(super) struct NativeGrant {
    pub(super) profile: LuaProfile,
    pub(super) cpath: Vec<String>,
    pub(super) modules: Vec<GrantedModule>,
}

#[derive(Debug)]
pub(super) struct GrantedModule {
    pub(super) path: PathBuf,
    pub(super) sha256: [u8; 32],
    pub(super) source_sha256: [u8; 32],
    pub(super) identity: AbiIdentity,
    pub(super) exports: Vec<String>,
    pub(super) visibility: SymbolVisibility,
    pub(super) dependencies: Vec<PathBuf>,
}

impl NativeGrant {
    pub(super) fn cpath_bytes(&self) -> Vec<u8> {
        self.cpath.join(";").into_bytes()
    }

    pub(super) fn from_env(profile: LuaProfile) -> Result<Option<Self>, String> {
        let Some(path) = std::env::var_os("RIVETLUA_NATIVE_MANIFEST") else {
            return Ok(None);
        };
        if path.is_empty() {
            return Err("RIVETLUA_NATIVE_MANIFEST 不可為空".into());
        }
        Self::read(Path::new(&path), profile)
            .map(Some)
            .map_err(|error| {
                if error.starts_with("native-grant: ") {
                    error
                } else {
                    format!("native-grant: format {error}")
                }
            })
    }

    fn read(path: &Path, profile: LuaProfile) -> Result<Self, String> {
        let path = canonical_file_path(path, MAX_PATH_BYTES, "native grant")?;
        let file = File::open(&path).map_err(|error| format!("native grant 開啟失敗：{error}"))?;
        if file.metadata().map_err(|error| error.to_string())?.len() > MAX_GRANT_BYTES as u64 {
            return Err("native grant 超過 1 MiB".into());
        }
        let mut bytes = Vec::new();
        file.take((MAX_GRANT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("native grant 讀取失敗：{error}"))?;
        if bytes.len() > MAX_GRANT_BYTES {
            return Err("native grant 超過 1 MiB".into());
        }
        let input = std::str::from_utf8(&bytes)
            .map_err(|_| "native grant 必須是 UTF-8 JSON".to_string())?;
        Self::parse(input, profile)
    }

    fn parse(input: &str, profile: LuaProfile) -> Result<Self, String> {
        if input.len() > MAX_GRANT_BYTES {
            return Err("native grant 超過 1 MiB".into());
        }
        let value = JsonParser::parse(input)?;
        let fields = exact_fields(
            &value,
            &[
                "schema",
                "profile",
                "target",
                "abi_manifest_sha256",
                "capability",
                "cpath",
                "modules",
            ],
            "native grant",
        )?;
        if string_field(fields, "schema")? != "rivetlua-native-grant-v1" {
            return Err("native grant schema 不符".into());
        }
        let declared_profile = match string_field(fields, "profile")? {
            "lua55-i64f64" => LuaProfile::Lua55,
            "lua54-i64f64" => LuaProfile::Lua54,
            _ => return Err("native-grant: profile 不受支援".into()),
        };
        if declared_profile != profile
            || declared_profile
                != if cfg!(feature = "native-lua55") {
                    LuaProfile::Lua55
                } else {
                    LuaProfile::Lua54
                }
        {
            return Err("native-grant: profile 與 VM/C API artifact 不符".into());
        }
        if string_field(fields, "target")? != abi::TARGET_TRIPLE {
            return Err("native-grant: target 不符".into());
        }
        let declared_abi = hex32(string_field(fields, "abi_manifest_sha256")?, "ABI manifest")
            .map_err(|error| format!("native-grant: abi {error}"))?;
        let actual_abi = native::binary_sha256(ABI_MANIFEST)
            .ok_or_else(|| "ABI manifest hash 計算失敗".to_string())?;
        if declared_abi != actual_abi {
            return Err("native-grant: abi manifest SHA-256 不符".into());
        }
        if string_field(fields, "capability")? != "trusted-host-process-permissions-v1" {
            return Err("native-grant: grant 未授予 process permissions".into());
        }

        let paths = array_field(fields, "cpath")?;
        if paths.is_empty() || paths.len() > MAX_CPATH {
            return Err("native grant cpath 數量超限或為空".into());
        }
        let mut cpath = Vec::with_capacity(paths.len());
        for value in paths {
            let template = as_string(value, "cpath 模板")?;
            if template.as_bytes().len() > MAX_PATH_BYTES
                || template.bytes().filter(|byte| *byte == b'?').count() != 1
                || template.as_bytes().contains(&0)
                || !Path::new(template).is_absolute()
            {
                return Err("native grant cpath 模板必須是含唯一 ? 的絕對路徑".into());
            }
            if cpath.iter().any(|old| old == template) {
                return Err("native grant cpath 模板重複".into());
            }
            cpath.push(template.to_owned());
        }

        let entries = array_field(fields, "modules")?;
        if entries.is_empty() || entries.len() > MAX_MODULES {
            return Err("native grant modules 數量超限或為空".into());
        }
        let mut modules = Vec::with_capacity(entries.len());
        for entry in entries {
            modules.push(parse_module(entry, &modules)?);
        }
        Ok(Self {
            profile,
            cpath,
            modules,
        })
    }

    /// 每個 artifact 都先過 P16 safe preflight；只有之後的受控 driver 才可載入。
    pub(super) fn preflight_all(&self) -> Result<(), String> {
        for module in &self.modules {
            self.preflight_module(module)?;
        }
        Ok(())
    }

    pub(super) fn preflight_module(
        &self,
        module: &GrantedModule,
    ) -> Result<native::VerifiedNative, String> {
        let artifact = NativeArtifact {
            path: module.path.clone(),
            identity: module.identity,
            sha256: module.sha256,
            unwind: UnwindAttestation::CNoUnwind,
        };
        let policy = NativePolicy {
            id: "rivetlua-native-grant-v1".into(),
            authorized: true,
            accepts_process_permissions: true,
            allow_global_symbols: module.visibility == SymbolVisibility::Global,
        };
        native::preflight(artifact, &policy, module.visibility).map_err(|error| {
            let category = match error {
                native::NativeError::Digest => "digest",
                native::NativeError::Abi(_) => "abi",
                native::NativeError::Denied | native::NativeError::Unwind => "grant",
                _ => "preflight",
            };
            format!(
                "native-grant: {category} module {} 預檢失敗：{error:?}",
                module.path.display()
            )
        })
    }

    /// 授權只比對候選 canonical path；呼叫者須另保留原始 filename 傳給 Lua。
    pub(super) fn match_candidate(&self, candidate: &Path) -> Result<&GrantedModule, String> {
        let canonical = fs::canonicalize(candidate)
            .map_err(|error| format!("native 候選路徑無法解析：{error}"))?;
        self.modules
            .iter()
            .find(|module| module.path == canonical)
            .ok_or_else(|| "native 候選路徑不在 grant 白名單".into())
    }
}

fn parse_module(value: &Json, preceding: &[GrantedModule]) -> Result<GrantedModule, String> {
    let fields = exact_fields(
        value,
        &[
            "canonical_path",
            "sha256",
            "source_sha256",
            "header_binding",
            "abi_identity",
            "unwind",
            "exports",
            "visibility",
            "dependencies",
        ],
        "native module",
    )?;
    let path = canonical_file_path(
        Path::new(string_field(fields, "canonical_path")?),
        MAX_PATH_BYTES,
        "native module",
    )?;
    if preceding.iter().any(|module| module.path == path) {
        return Err("native grant module canonical_path 重複".into());
    }
    let sha256 = hex32(string_field(fields, "sha256")?, "module SHA-256")?;
    let source_sha256 = hex32(string_field(fields, "source_sha256")?, "source SHA-256")?;
    let header_binding = hex32(string_field(fields, "header_binding")?, "header binding")?;
    let identity = parse_identity(field(fields, "abi_identity")?)?;
    if header_binding != identity.header_set_sha256 {
        return Err("native-grant: abi header binding 與 identity 不符".into());
    }
    abi::compare_identity(&abi::current_identity(), Some(&identity))
        .map_err(|error| format!("native-grant: abi identity 不符：{error:?}"))?;
    if string_field(fields, "unwind")? != "CNoUnwind" {
        return Err("native grant 必須明示 CNoUnwind".into());
    }
    let visibility = match string_field(fields, "visibility")? {
        "global" => SymbolVisibility::Global,
        "local" => SymbolVisibility::Local,
        _ => return Err("native grant visibility 無效".into()),
    };
    let export_values = array_field(fields, "exports")?;
    if export_values.is_empty() || export_values.len() > MAX_EXPORTS {
        return Err("native grant exports 數量超限或為空".into());
    }
    let mut exports = Vec::with_capacity(export_values.len());
    for value in export_values {
        let symbol = as_string(value, "export symbol")?;
        if !valid_symbol(symbol) || exports.iter().any(|old| old == symbol) {
            return Err("native grant export symbol 無效或重複".into());
        }
        exports.push(symbol.to_owned());
    }
    let dependency_values = array_field(fields, "dependencies")?;
    if dependency_values.len() > MAX_DEPENDENCIES {
        return Err("native grant dependencies 超過 16 筆".into());
    }
    let mut dependencies = Vec::with_capacity(dependency_values.len());
    for value in dependency_values {
        let dependency = Path::new(as_string(value, "dependency path")?);
        let Some(existing) = preceding.iter().find(|module| module.path == dependency) else {
            return Err("native grant dependency 必須引用較早的 canonical module".into());
        };
        if dependencies.contains(&existing.path) {
            return Err("native grant dependency 重複".into());
        }
        dependencies.push(existing.path.clone());
    }
    Ok(GrantedModule {
        path,
        sha256,
        source_sha256,
        identity,
        exports,
        visibility,
        dependencies,
    })
}

fn parse_identity(value: &Json) -> Result<AbiIdentity, String> {
    let fields = exact_fields(
        value,
        &[
            "revision",
            "profile_id",
            "numeric_config",
            "pointer_width_bits",
            "endianness",
            "reserved_zero",
            "target",
            "header_set_sha256",
            "lua_h_sha256",
            "lauxlib_h_sha256",
            "luaconf_h_sha256",
            "layout",
        ],
        "ABI identity",
    )?;
    let target = string_field(fields, "target")?;
    if !target.is_ascii() || target.as_bytes().len() >= 32 || target.as_bytes().contains(&0) {
        return Err("ABI target 字串無效".into());
    }
    let mut target_bytes = [0_u8; 32];
    target_bytes[..target.len()].copy_from_slice(target.as_bytes());
    let layout_values = array_field(fields, "layout")?;
    if layout_values.len() != abi::LAYOUT_COUNT {
        return Err("ABI layout 必須恰有 37 個 u16".into());
    }
    let mut layout = [0_u16; abi::LAYOUT_COUNT];
    for (slot, value) in layout.iter_mut().zip(layout_values) {
        *slot = u16::try_from(as_number(value, "ABI layout")?)
            .map_err(|_| "ABI layout 數值超出 u16".to_string())?;
    }
    Ok(AbiIdentity {
        revision: u32_field(fields, "revision")?,
        profile: u16_field(fields, "profile_id")?,
        numeric_config: u16_field(fields, "numeric_config")?,
        pointer_width_bits: u8_field(fields, "pointer_width_bits")?,
        endianness: u8_field(fields, "endianness")?,
        reserved_zero: u16_field(fields, "reserved_zero")?,
        target: target_bytes,
        header_set_sha256: hex32(string_field(fields, "header_set_sha256")?, "header SHA-256")?,
        lua_h_sha256: hex32(string_field(fields, "lua_h_sha256")?, "lua.h SHA-256")?,
        lauxlib_h_sha256: hex32(
            string_field(fields, "lauxlib_h_sha256")?,
            "lauxlib.h SHA-256",
        )?,
        luaconf_h_sha256: hex32(
            string_field(fields, "luaconf_h_sha256")?,
            "luaconf.h SHA-256",
        )?,
        layout,
    })
}

fn canonical_file_path(path: &Path, limit: usize, what: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > limit {
        return Err(format!("{what} 路徑必須是上限內的絕對路徑"));
    }
    let canonical =
        fs::canonicalize(path).map_err(|error| format!("{what} 路徑無法 canonicalize：{error}"))?;
    if canonical != path || !path.is_file() {
        return Err(format!("{what} 路徑必須是 canonical 一般檔案"));
    }
    Ok(canonical)
}

fn valid_symbol(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= MAX_SYMBOL_BYTES
        && matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn hex32(value: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = value.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("{what} 必須是 64 位小寫十六進位"));
    }
    let mut digest = [0; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        let hi = lower_hex(pair[0]).ok_or_else(|| format!("{what} 不是小寫十六進位"))?;
        let lo = lower_hex(pair[1]).ok_or_else(|| format!("{what} 不是小寫十六進位"))?;
        digest[index] = hi * 16 + lo;
    }
    Ok(digest)
}

fn lower_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn exact_fields<'a>(
    value: &'a Json,
    expected: &[&str],
    what: &str,
) -> Result<&'a [(String, Json)], String> {
    let Json::Object(fields) = value else {
        return Err(format!("{what} 必須是 JSON object"));
    };
    if fields.len() != expected.len()
        || fields
            .iter()
            .any(|(name, _)| !expected.contains(&name.as_str()))
    {
        return Err(format!("{what} 欄位缺失或有未授權欄位"));
    }
    Ok(fields)
}

fn field<'a>(fields: &'a [(String, Json)], name: &str) -> Result<&'a Json, String> {
    fields
        .iter()
        .find_map(|(key, value)| (key == name).then_some(value))
        .ok_or_else(|| format!("JSON 缺少 {name}"))
}

fn as_string<'a>(value: &'a Json, what: &str) -> Result<&'a str, String> {
    match value {
        Json::String(value) => Ok(value),
        _ => Err(format!("{what} 必須是字串")),
    }
}

fn string_field<'a>(fields: &'a [(String, Json)], name: &str) -> Result<&'a str, String> {
    as_string(field(fields, name)?, name)
}

fn as_number(value: &Json, what: &str) -> Result<u64, String> {
    match value {
        Json::Number(value) => Ok(*value),
        _ => Err(format!("{what} 必須是非負整數")),
    }
}

fn number_field(fields: &[(String, Json)], name: &str) -> Result<u64, String> {
    as_number(field(fields, name)?, name)
}

fn u8_field(fields: &[(String, Json)], name: &str) -> Result<u8, String> {
    u8::try_from(number_field(fields, name)?).map_err(|_| format!("{name} 超出 u8"))
}

fn u16_field(fields: &[(String, Json)], name: &str) -> Result<u16, String> {
    u16::try_from(number_field(fields, name)?).map_err(|_| format!("{name} 超出 u16"))
}

fn u32_field(fields: &[(String, Json)], name: &str) -> Result<u32, String> {
    u32::try_from(number_field(fields, name)?).map_err(|_| format!("{name} 超出 u32"))
}

fn array_field<'a>(fields: &'a [(String, Json)], name: &str) -> Result<&'a [Json], String> {
    match field(fields, name)? {
        Json::Array(values) => Ok(values),
        _ => Err(format!("{name} 必須是陣列")),
    }
}

#[derive(Debug)]
enum Json {
    Object(Vec<(String, Self)>),
    Array(Vec<Self>),
    String(String),
    Number(u64),
}

struct JsonParser<'a> {
    input: &'a str,
    cursor: usize,
}

impl<'a> JsonParser<'a> {
    fn parse(input: &'a str) -> Result<Json, String> {
        let mut parser = Self { input, cursor: 0 };
        let result = parser.value(0)?;
        parser.space();
        if parser.cursor != input.len() {
            return Err(parser.error("JSON 根值後有多餘資料"));
        }
        Ok(result)
    }

    fn bytes(&self) -> &'a [u8] {
        self.input.as_bytes()
    }

    fn error(&self, message: &str) -> String {
        format!("{message}（byte {}）", self.cursor)
    }

    fn space(&mut self) {
        while matches!(
            self.bytes().get(self.cursor),
            Some(b' ' | b'\t' | b'\r' | b'\n')
        ) {
            self.cursor += 1;
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > 16 {
            return Err(self.error("JSON 巢狀超過 16 層"));
        }
        self.space();
        match self.bytes().get(self.cursor).copied() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Json::String),
            Some(b'0'..=b'9') => self.number(),
            _ => Err(self.error("JSON 值格式錯誤或不屬於 grant schema")),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.cursor += 1;
        self.space();
        let mut fields: Vec<(String, Json)> = Vec::new();
        if self.bytes().get(self.cursor) == Some(&b'}') {
            self.cursor += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            if fields.len() >= 32 {
                return Err(self.error("JSON object 欄位超過 32"));
            }
            if self.bytes().get(self.cursor) != Some(&b'"') {
                return Err(self.error("JSON 欄位名稱必須是字串"));
            }
            let key = self.string()?;
            if fields.iter().any(|(old, _)| old == &key) {
                return Err(self.error("JSON 重複欄位"));
            }
            self.space();
            if self.bytes().get(self.cursor) != Some(&b':') {
                return Err(self.error("JSON 缺少冒號"));
            }
            self.cursor += 1;
            let value = self.value(depth)?;
            fields.push((key, value));
            self.space();
            match self.bytes().get(self.cursor) {
                Some(b',') => {
                    self.cursor += 1;
                    self.space();
                }
                Some(b'}') => {
                    self.cursor += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(self.error("JSON object 缺少逗號或結尾")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.cursor += 1;
        self.space();
        let mut values = Vec::new();
        if self.bytes().get(self.cursor) == Some(&b']') {
            self.cursor += 1;
            return Ok(Json::Array(values));
        }
        loop {
            if values.len() >= 1024 {
                return Err(self.error("JSON array 超過 1024 項"));
            }
            values.push(self.value(depth)?);
            self.space();
            match self.bytes().get(self.cursor) {
                Some(b',') => {
                    self.cursor += 1;
                    self.space();
                }
                Some(b']') => {
                    self.cursor += 1;
                    return Ok(Json::Array(values));
                }
                _ => return Err(self.error("JSON array 缺少逗號或結尾")),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.cursor += 1;
        let mut output = String::new();
        let mut start = self.cursor;
        loop {
            match self.bytes().get(self.cursor).copied() {
                Some(b'"') => {
                    self.push_chunk(&mut output, start)?;
                    self.cursor += 1;
                    return Ok(output);
                }
                Some(b'\\') => {
                    self.push_chunk(&mut output, start)?;
                    self.cursor += 1;
                    let escape = self
                        .bytes()
                        .get(self.cursor)
                        .copied()
                        .ok_or_else(|| self.error("JSON 跳脫未完成"))?;
                    self.cursor += 1;
                    match escape {
                        b'"' => output.push('"'),
                        b'\\' => output.push('\\'),
                        b'/' => output.push('/'),
                        b'b' => output.push('\u{0008}'),
                        b'f' => output.push('\u{000c}'),
                        b'n' => output.push('\n'),
                        b'r' => output.push('\r'),
                        b't' => output.push('\t'),
                        b'u' => {
                            let first = self.quad()?;
                            let scalar = if (0xd800..=0xdbff).contains(&first) {
                                if self.bytes().get(self.cursor..self.cursor + 2) != Some(b"\\u") {
                                    return Err(self.error("JSON Unicode 高代理缺少低代理"));
                                }
                                self.cursor += 2;
                                let second = self.quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(self.error("JSON Unicode 低代理無效"));
                                }
                                0x10000
                                    + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
                            } else if (0xdc00..=0xdfff).contains(&first) {
                                return Err(self.error("JSON Unicode 孤立低代理"));
                            } else {
                                first as u32
                            };
                            output.push(
                                char::from_u32(scalar)
                                    .ok_or_else(|| self.error("JSON Unicode 純量無效"))?,
                            );
                        }
                        _ => return Err(self.error("JSON 跳脫無效")),
                    }
                    start = self.cursor;
                }
                Some(byte) if byte < 0x20 => return Err(self.error("JSON 未跳脫控制字元")),
                Some(_) => self.cursor += 1,
                None => return Err(self.error("JSON 字串未結束")),
            }
        }
    }

    fn push_chunk(&self, output: &mut String, start: usize) -> Result<(), String> {
        output.push_str(
            std::str::from_utf8(&self.bytes()[start..self.cursor])
                .map_err(|_| self.error("JSON 字串含無效 UTF-8"))?,
        );
        Ok(())
    }

    fn quad(&mut self) -> Result<u16, String> {
        let digits = self
            .bytes()
            .get(self.cursor..self.cursor + 4)
            .ok_or_else(|| self.error("JSON Unicode 少於四碼"))?;
        let mut value = 0_u16;
        for digit in digits {
            let next = (*digit as char)
                .to_digit(16)
                .ok_or_else(|| self.error("JSON Unicode 非十六進位"))?;
            value = (value << 4) | next as u16;
        }
        self.cursor += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.cursor;
        if self.bytes().get(self.cursor) == Some(&b'0') {
            self.cursor += 1;
            if self
                .bytes()
                .get(self.cursor)
                .is_some_and(u8::is_ascii_digit)
            {
                return Err(self.error("JSON 數值不可有前導零"));
            }
        } else {
            while self
                .bytes()
                .get(self.cursor)
                .is_some_and(u8::is_ascii_digit)
            {
                self.cursor += 1;
            }
        }
        let value = self.input[start..self.cursor]
            .parse::<u64>()
            .map_err(|_| self.error("JSON 整數超限"))?;
        Ok(Json::Number(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_CASE: AtomicU64 = AtomicU64::new(1);

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn grant_json(path: &Path, digest: [u8; 32]) -> String {
        let id = abi::current_identity();
        let profile = if cfg!(feature = "native-lua55") {
            "lua55-i64f64"
        } else {
            "lua54-i64f64"
        };
        let target = abi::TARGET_TRIPLE;
        let identity_target = std::str::from_utf8(
            &id.target[..id.target.iter().position(|byte| *byte == 0).unwrap_or(32)],
        )
        .expect("固定 ASCII target");
        let layout = id
            .layout
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"schema\":\"rivetlua-native-grant-v1\",\"profile\":\"{profile}\",\"target\":\"{target}\",\"abi_manifest_sha256\":\"{}\",\"capability\":\"trusted-host-process-permissions-v1\",\"cpath\":[\"{}/?.so\"],\"modules\":[{{\"canonical_path\":\"{}\",\"sha256\":\"{}\",\"source_sha256\":\"{}\",\"header_binding\":\"{}\",\"abi_identity\":{{\"revision\":{},\"profile_id\":{},\"numeric_config\":{},\"pointer_width_bits\":{},\"endianness\":{},\"reserved_zero\":{},\"target\":\"{identity_target}\",\"header_set_sha256\":\"{}\",\"lua_h_sha256\":\"{}\",\"lauxlib_h_sha256\":\"{}\",\"luaconf_h_sha256\":\"{}\",\"layout\":[{layout}]}},\"unwind\":\"CNoUnwind\",\"exports\":[\"luaopen_lib1_sub\",\"onefunction\",\"anotherfunc\"],\"visibility\":\"global\",\"dependencies\":[]}}]}}",
            hex(&native::binary_sha256(ABI_MANIFEST).expect("固定 manifest 可計算")),
            path.parent().expect("測試檔有父目錄").display(),
            path.display(),
            hex(&digest),
            "00".repeat(32),
            hex(&id.header_set_sha256),
            id.revision,
            id.profile,
            id.numeric_config,
            id.pointer_width_bits,
            id.endianness,
            id.reserved_zero,
            hex(&id.header_set_sha256),
            hex(&id.lua_h_sha256),
            hex(&id.lauxlib_h_sha256),
            hex(&id.luaconf_h_sha256),
        )
    }

    fn fixture() -> (PathBuf, PathBuf, String) {
        let directory = std::env::temp_dir().join(format!(
            "rivetlua-p17-grant-{}-{}",
            std::process::id(),
            NEXT_CASE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).expect("建立外接測試目錄");
        let binary = directory.join("lib1.so");
        fs::write(&binary, b"preflight-only-bytes").expect("寫入預檢測試位元組");
        let digest = native::binary_sha256(b"preflight-only-bytes").expect("計算測試 SHA");
        let json = grant_json(&binary, digest);
        (directory, binary, json)
    }

    #[test]
    fn p17_grant_rejects_duplicate_and_unknown_json_fields() {
        assert!(JsonParser::parse(r#"{"schema":"a","schema":"b"}"#).is_err());
        assert!(NativeGrant::parse(r#"{"unexpected":1}"#, LuaProfile::Lua55).is_err());
    }

    #[test]
    fn p17_grant_rejects_malformed_unicode_and_noninteger_identity() {
        assert!(JsonParser::parse(r#"{"x":"\ud800"}"#).is_err());
        assert!(JsonParser::parse(r#"{"x":1.5}"#).is_err());
    }

    #[test]
    fn p17_grant_symbol_and_digest_contract() {
        assert!(valid_symbol("onefunction"));
        assert!(valid_symbol("luaopen_lib1_sub"));
        assert!(!valid_symbol("lib2-v2"));
        assert!(hex32(&"ab".repeat(32), "test").is_ok());
        assert!(hex32(&"AB".repeat(32), "test").is_err());
    }

    #[test]
    fn p17_grant_typed_identity_preflight_and_candidate_whitelist() {
        let (directory, binary, json) = fixture();
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let grant = NativeGrant::parse(&json, profile).expect("完整 typed grant 可解析");
        assert_eq!(grant.modules.len(), 1);
        assert_eq!(grant.modules[0].exports.len(), 3);
        grant.preflight_all().expect("P16 預檢正確 bytes");
        let candidate = directory.join(".").join("lib1.so");
        assert_eq!(grant.match_candidate(&candidate).unwrap().path, binary);

        fs::write(&binary, b"changed-after-grant").expect("修改測試位元組");
        assert!(
            grant
                .preflight_all()
                .unwrap_err()
                .starts_with("native-grant: digest")
        );
        fs::remove_dir_all(directory).expect("清理外接測試目錄");
    }

    #[test]
    fn p17_grant_profile_target_and_abi_categories_are_distinct() {
        let (directory, _binary, json) = fixture();
        let profile = if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let other_profile = if profile == LuaProfile::Lua55 {
            "lua54-i64f64"
        } else {
            "lua55-i64f64"
        };
        let current_profile = if profile == LuaProfile::Lua55 {
            "lua55-i64f64"
        } else {
            "lua54-i64f64"
        };
        let wrong_profile = json.replacen(current_profile, other_profile, 1);
        assert!(
            NativeGrant::parse(&wrong_profile, profile)
                .unwrap_err()
                .starts_with("native-grant: profile")
        );
        let wrong_target = json.replacen(abi::TARGET_TRIPLE, "wrong-target", 1);
        assert!(
            NativeGrant::parse(&wrong_target, profile)
                .unwrap_err()
                .starts_with("native-grant: target")
        );
        let abi_hash = hex(&native::binary_sha256(ABI_MANIFEST).unwrap());
        let wrong_abi = json.replacen(&abi_hash, &"00".repeat(32), 1);
        assert!(
            NativeGrant::parse(&wrong_abi, profile)
                .unwrap_err()
                .starts_with("native-grant: abi")
        );
        fs::remove_dir_all(directory).expect("清理外接測試目錄");
    }
}
