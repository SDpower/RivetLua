use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use rivetlua::{
    CompileBudget, CompileBudgetLimits, Engine, LuaProfile, Root, RunOutcome, Value, Vm,
};

use super::{PackageIdentity, Profile, segment};
use crate::json_escape;

const MAX_SOURCE: usize = 256 * 1024;
const MAX_MANIFEST_SOURCE: usize = 1024 * 1024;
const MAX_OUTPUT: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 65_536;

pub(super) struct Parsed {
    pub identity: PackageIdentity,
    pub dependencies: [Vec<String>; 3],
    pub sha256: String,
    pub json: String,
}

#[derive(Clone)]
enum Data {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Self>),
    Object(BTreeMap<String, Self>),
}

impl Data {
    fn object(&self, label: &str) -> Result<&BTreeMap<String, Self>, String> {
        if let Self::Object(value) = self {
            Ok(value)
        } else {
            Err(format!("{label} 必須是 table"))
        }
    }
    fn text(&self, label: &str) -> Result<&str, String> {
        if let Self::Text(value) = self {
            Ok(value)
        } else {
            Err(format!("{label} 必須是字串"))
        }
    }
    fn json(&self, out: &mut String) {
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Number(value) => out.push_str(value),
            Self::Text(value) => {
                out.push('"');
                out.push_str(&json_escape(value));
                out.push('"');
            }
            Self::Array(values) => {
                out.push('[');
                for (i, value) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    value.json(out);
                }
                out.push(']');
            }
            Self::Object(values) => {
                out.push('{');
                for (i, (key, value)) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(&json_escape(key));
                    out.push_str("\":");
                    value.json(out);
                }
                out.push('}');
            }
        }
    }
}

struct Reader<'a> {
    vm: &'a mut Vm,
    next: Root,
    ty: Root,
    nodes: usize,
    bytes: usize,
    ancestors: Vec<Value>,
}

fn invoke(vm: &mut Vm, function: &Root, args: &[Value]) -> Result<Vec<Value>, String> {
    let mut execution = vm
        .call(function, args)
        .map_err(|_| "rockspec VM 呼叫失敗")?;
    execution
        .set_fuel(1_000_000)
        .map_err(|_| "rockspec VM 額度設定失敗")?;
    match execution.run().map_err(|_| "rockspec VM 執行失敗")? {
        RunOutcome::Returned(values) => Ok(values),
        _ => Err("rockspec 執行未正常返回".into()),
    }
}

impl Reader<'_> {
    fn charge(&mut self, size: usize) -> Result<(), String> {
        self.bytes = self.bytes.checked_add(size).ok_or("rockspec 資料量溢位")?;
        if self.bytes > MAX_OUTPUT {
            return Err("rockspec 資料量超過限制".into());
        }
        Ok(())
    }

    fn global(&mut self, name: &[u8]) -> Result<Data, String> {
        let value = self
            .vm
            .get_global(name)
            .map_err(|_| "rockspec 欄位讀取失敗")?;
        self.value(value, 0)
    }

    fn value(&mut self, value: Value, depth: usize) -> Result<Data, String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES || depth > 32 {
            return Err("rockspec 巢狀資料超過限制".into());
        }
        self.charge(32)?;
        match value {
            Value::Nil => Ok(Data::Null),
            Value::Boolean(value) => Ok(Data::Bool(value)),
            Value::Integer(value) => Ok(Data::Number(value.to_string())),
            Value::Float(value) if value.is_finite() => Ok(Data::Number(value.to_string())),
            Value::Float(_) => Err("rockspec 不接受非有限數值".into()),
            Value::Object(_) => {
                let rooted = self.vm.root(value).map_err(|_| "rockspec root 建立失敗")?;
                let kind = invoke(self.vm, &self.ty, &[value])?;
                let kind_root = self
                    .vm
                    .root(*kind.first().ok_or("rockspec type 無回傳")?)
                    .map_err(|_| "rockspec type 回傳無效")?;
                let kind = self
                    .vm
                    .read_byte_string(&kind_root)
                    .map_err(|_| "rockspec type 讀取失敗")?;
                match kind.as_slice() {
                    b"string" => {
                        let bytes = self
                            .vm
                            .read_byte_string(&rooted)
                            .map_err(|_| "rockspec 字串讀取失敗")?;
                        if bytes.len() > MAX_OUTPUT {
                            return Err("rockspec 字串超過限制".into());
                        }
                        self.charge(bytes.len().checked_mul(6).ok_or("rockspec 字串長度溢位")?)?;
                        String::from_utf8(bytes)
                            .map(Data::Text)
                            .map_err(|_| "rockspec 字串不是 UTF-8".into())
                    }
                    b"table" => self.table(value, &rooted, depth),
                    _ => Err("rockspec 欄位含不支援的 Lua 值".into()),
                }
            }
            _ => Err("rockspec 欄位含不支援的 Lua 值".into()),
        }
    }

    fn table(&mut self, value: Value, table: &Root, depth: usize) -> Result<Data, String> {
        if self.ancestors.contains(&value) {
            return Err("rockspec table 含循環".into());
        }
        self.ancestors.push(value);
        let converted = (|| {
            let mut strings = BTreeMap::new();
            let mut numbers = BTreeMap::new();
            let mut previous = Value::Nil;
            let mut previous_root: Option<Root> = None;
            loop {
                let table_value = table
                    .value(self.vm)
                    .map_err(|_| "rockspec table root 無效")?;
                let pair = invoke(self.vm, &self.next, &[table_value, previous])?;
                let Some(&key) = pair.first() else {
                    return Err("rockspec next 無回傳".into());
                };
                if key == Value::Nil {
                    break;
                }
                let item = *pair.get(1).ok_or("rockspec next 缺少 value")?;
                let key_root = if matches!(key, Value::Object(_)) {
                    Some(
                        self.vm
                            .root(key)
                            .map_err(|_| "rockspec key root 建立失敗")?,
                    )
                } else {
                    None
                };
                let item_root = if matches!(item, Value::Object(_)) {
                    Some(
                        self.vm
                            .root(item)
                            .map_err(|_| "rockspec value root 建立失敗")?,
                    )
                } else {
                    None
                };
                let data = self.value(item, depth + 1)?;
                match key {
                    Value::Integer(index) if index > 0 => {
                        numbers.insert(index, data);
                    }
                    Value::Object(_) => {
                        let bytes = self
                            .vm
                            .read_byte_string(key_root.as_ref().ok_or("rockspec key root 缺失")?)
                            .map_err(|_| "rockspec key 必須是字串")?;
                        self.charge(bytes.len().checked_mul(6).ok_or("rockspec key 長度溢位")?)?;
                        let key =
                            String::from_utf8(bytes).map_err(|_| "rockspec key 不是 UTF-8")?;
                        if strings.insert(key, data).is_some() {
                            return Err("rockspec key 重複".into());
                        }
                    }
                    _ => return Err("rockspec table key 只接受字串或正整數".into()),
                }
                drop(item_root);
                previous = key;
                drop(previous_root.take());
                previous_root = key_root;
            }
            if strings.is_empty() && !numbers.is_empty() {
                let len = numbers.len();
                if numbers
                    .keys()
                    .copied()
                    .eq(1..=i64::try_from(len).map_err(|_| "rockspec array 過大")?)
                {
                    return Ok(Data::Array(numbers.into_values().collect()));
                }
            }
            for (index, data) in numbers {
                if strings.insert(index.to_string(), data).is_some() {
                    return Err("rockspec key 重複".into());
                }
            }
            Ok(Data::Object(strings))
        })();
        self.ancestors.pop();
        converted
    }
}

fn dependency(value: Data, label: &str) -> Result<Data, String> {
    match value {
        Data::Null => Ok(Data::Array(Vec::new())),
        Data::Array(values) if values.iter().all(|item| matches!(item, Data::Text(_))) => {
            Ok(Data::Array(values))
        }
        Data::Object(values) if values.is_empty() => Ok(Data::Array(Vec::new())),
        Data::Object(values) => Ok(Data::Object(values)),
        _ => Err(format!("{label} 必須是相依清單或含 platform 覆寫的 table")),
    }
}

fn check_system_lua(value: &Data) -> Result<(), String> {
    match value {
        Data::Object(map) => {
            for (key, item) in map {
                if matches!(
                    key.to_ascii_lowercase().as_str(),
                    "lua" | "luajit" | "lua_incdir" | "lua_libdir" | "lua_bindir"
                ) {
                    return Err("rockspec 要求系統 Lua linkage".into());
                }
                if key == "libraries" && library_is_system_lua(item) {
                    return Err("rockspec 要求系統 Lua linkage".into());
                }
                check_system_lua(item)?;
            }
        }
        Data::Array(values) => {
            for item in values {
                check_system_lua(item)?;
            }
        }
        Data::Text(text) => {
            if system_lua_flag(text) {
                return Err("rockspec 要求系統 Lua linkage".into());
            }
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn system_lua_flag(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    let words = lower.split_whitespace().collect::<Vec<_>>();
    words.iter().any(|word| {
        let word = word.trim_matches(|ch: char| matches!(ch, '\'' | '"' | ',' | ';'));
        word == "-llua"
            || word.starts_with("-llua5")
            || word == "-lluajit"
            || word.starts_with("-lluajit-")
            || word.contains("/liblua.")
            || word.contains("/liblua5")
            || word.contains("/libluajit")
            || word.starts_with("liblua.")
            || word.starts_with("liblua5")
            || word.starts_with("libluajit")
    }) || words.windows(2).any(|pair| {
        (pair[0] == "-l" || pair[0] == "pkg-config")
            && (pair[1] == "lua" || pair[1] == "luajit" || pair[1].starts_with("lua5."))
    })
}

fn library_is_system_lua(value: &Data) -> bool {
    match value {
        Data::Text(name) => {
            let name = name.to_ascii_lowercase();
            let name = name.trim_start_matches("-l");
            name == "lua"
                || name == "luajit"
                || name.starts_with("lua5.")
                || name.starts_with("lua-")
                || name.starts_with("luajit-")
                || name.starts_with("liblua.")
                || name.starts_with("liblua5")
                || name.starts_with("libluajit")
        }
        Data::Array(values) => values.iter().any(library_is_system_lua),
        Data::Object(values) => values.iter().any(|(name, item)| {
            library_is_system_lua(&Data::Text(name.clone())) || library_is_system_lua(item)
        }),
        _ => false,
    }
}

fn source_policy(source: &Data) -> Result<(), String> {
    let map = source.object("source")?;
    let url = map
        .get("url")
        .ok_or("source 缺少 url")?
        .text("source.url")?;
    let authority = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("git+https://"))
        .ok_or("source.url 必須使用 HTTPS")?
        .split('/')
        .next()
        .unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || url.contains('?')
        || url.chars().any(char::is_control)
    {
        return Err("source.url 不合法或包含登入資訊".into());
    }
    for field in ["tag", "branch"] {
        if let Some(value) = map.get(field) {
            if value.text(field)?.is_empty() {
                return Err(format!("source.{field} 不可為空"));
            }
        }
    }
    Ok(())
}

fn requested_identity(
    reader: &mut Reader<'_>,
    profile: Profile,
    target: &str,
    abi: &str,
) -> Result<(), String> {
    for (field, expected) in [
        (b"lua_profile".as_slice(), profile.name()),
        (b"target".as_slice(), target),
        (b"abi".as_slice(), abi),
    ] {
        match reader.global(field)? {
            Data::Null => {}
            Data::Text(value) if value == expected => {}
            _ => return Err("rockspec 的 profile／target／ABI 與要求不符".into()),
        }
    }
    Ok(())
}

fn supported_target(value: &Data, target: &str) -> Result<(), String> {
    let Data::Array(platforms) = value else {
        return Ok(());
    };
    let family = if target.contains("apple-darwin") {
        "macosx"
    } else if target.contains("linux") {
        "linux"
    } else if target.contains("windows") {
        "windows"
    } else {
        target
    };
    let mut positive = false;
    let mut matched = false;
    for platform in platforms {
        let name = platform.text("supported_platforms 項目")?;
        let excluded = name.starts_with('!');
        let name = name.strip_prefix('!').unwrap_or(name);
        let applies = name == family
            || name == target
            || (name == "unix" && matches!(family, "linux" | "macosx"));
        if excluded && applies {
            return Err("rockspec 不支援指定 target".into());
        }
        if !excluded {
            positive = true;
            matched |= applies;
        }
    }
    if positive && !matched {
        return Err("rockspec 不支援指定 target".into());
    }
    Ok(())
}

pub(super) fn platform_keys(target: &str) -> Vec<&str> {
    let family = if target == "macosx" || target.contains("apple-darwin") {
        "macosx"
    } else if target == "linux" || target.split('-').any(|part| part == "linux") {
        "linux"
    } else if target == "windows" || target.split('-').any(|part| part == "windows") {
        "windows"
    } else {
        target
    };
    let mut keys = Vec::with_capacity(3);
    if family == "macosx" || family == "linux" {
        keys.push("unix");
    }
    if family != target {
        keys.push(family);
    }
    keys.push(target);
    keys
}

fn selected_dependency<'a>(value: &'a Data, target: &str) -> Result<&'a Data, String> {
    let mut selected = value;
    if let Data::Object(map) = value {
        if let Some(Data::Object(platforms)) = map.get("platforms") {
            for key in platform_keys(target) {
                if let Some(override_value) = platforms.get(key) {
                    selected = override_value;
                }
            }
        }
    }
    Ok(selected)
}

fn dependency_strings(value: &Data, target: &str) -> Result<Vec<String>, String> {
    let value = selected_dependency(value, target)?;
    match value {
        Data::Null => Ok(Vec::new()),
        Data::Array(values) => values
            .iter()
            .map(|value| value.text("dependency").map(str::to_owned))
            .collect(),
        Data::Object(values) => {
            let mut numbered = Vec::new();
            for (key, value) in values {
                if key == "platforms" {
                    continue;
                }
                let index: usize = key.parse().map_err(|_| "dependency table 欄位無效")?;
                if index == 0 || index > MAX_NODES {
                    return Err("dependency index 無效".into());
                }
                numbered.push((index, value.text("dependency")?.to_owned()));
            }
            numbered.sort_by_key(|(index, _)| *index);
            if numbered
                .iter()
                .enumerate()
                .any(|(offset, (index, _))| *index != offset + 1)
            {
                return Err("dependency 清單索引不連續".into());
            }
            Ok(numbered.into_iter().map(|(_, value)| value).collect())
        }
        _ => Err("dependency 格式無效".into()),
    }
}

fn effective_dependencies<'a>(
    runtime: &'a Data,
    build: &'a Data,
    test: &'a Data,
    platforms: &'a Data,
    target: &str,
) -> Result<[Vec<String>; 3], String> {
    let mut selected = [runtime, build, test];
    if let Data::Object(all) = platforms {
        for key in platform_keys(target) {
            if let Some(Data::Object(override_fields)) = all.get(key) {
                for (index, field) in ["dependencies", "build_dependencies", "test_dependencies"]
                    .iter()
                    .enumerate()
                {
                    if let Some(value) = override_fields.get(*field) {
                        selected[index] = value;
                    }
                }
            }
        }
    }
    Ok([
        dependency_strings(selected[0], target)?,
        dependency_strings(selected[1], target)?,
        dependency_strings(selected[2], target)?,
    ])
}

pub(super) fn read(args: &[String]) -> Result<(), String> {
    let [file, profile, target, abi] = args else {
        return Err("用法：package rockspec <file> <profile> <target> <abi>".into());
    };
    let profile = Profile::parse(profile)?;
    segment(target, "target")?;
    if abi.len() != 64 || !abi.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("ABI 必須是 64 位十六進位字串".into());
    }
    let parsed = evaluate(Path::new(file), profile, target, abi)?;
    println!("{}", parsed.json);
    Ok(())
}

fn sandbox<T>(
    source: &[u8],
    profile: Profile,
    name: &[u8],
    extract: impl FnOnce(&mut Reader<'_>) -> Result<T, String>,
) -> Result<T, String> {
    let engine = Engine::new(match profile {
        Profile::Lua54 => LuaProfile::Lua54,
        Profile::Lua55 => LuaProfile::Lua55,
    });
    let budget = CompileBudget::new(CompileBudgetLimits {
        max_work: 1_000_000,
        max_allocation_bytes: 16 * 1024 * 1024,
    });
    let module = engine
        .compile_named_with_budget(source, name, &budget)
        .map_err(|_| "rockspec 編譯失敗或超過額度")?;
    let mut vm = engine.new_vm().map_err(|_| "rockspec VM 建立失敗")?;
    vm.set_allocation_limit(16 * 1024 * 1024);
    let next = vm
        .get_global(b"next")
        .map_err(|_| "rockspec next 無法讀取")?;
    let next = vm.root(next).map_err(|_| "rockspec next 無法保根")?;
    let ty = vm
        .get_global(b"type")
        .map_err(|_| "rockspec type 無法讀取")?;
    let ty = vm.root(ty).map_err(|_| "rockspec type 無法保根")?;
    for name in [
        b"io".as_slice(),
        b"os",
        b"package",
        b"debug",
        b"require",
        b"dofile",
        b"loadfile",
        b"load",
        b"loadstring",
    ] {
        vm.set_global(name, Value::Nil)
            .map_err(|_| "rockspec VM 隔離失敗")?;
    }
    let mut execution = vm.load_module(&module).map_err(|_| "rockspec 載入失敗")?;
    execution
        .set_fuel(1_000_000)
        .map_err(|_| "rockspec 執行額度設定失敗")?;
    if !matches!(
        execution.run().map_err(|_| "rockspec 執行失敗")?,
        RunOutcome::Returned(_)
    ) {
        return Err("rockspec 未正常返回".into());
    }
    drop(execution);
    let mut reader = Reader {
        vm: &mut vm,
        next,
        ty,
        nodes: 0,
        bytes: 0,
        ancestors: Vec::new(),
    };
    extract(&mut reader)
}

pub(super) fn manifest_versions(
    source: &[u8],
    profile: Profile,
) -> Result<BTreeMap<String, Vec<String>>, String> {
    if source.len() > MAX_MANIFEST_SOURCE {
        return Err("manifest 來源超過限制".into());
    }
    sandbox(source, profile, b"=manifest", |reader| {
        let repository = reader.global(b"repository")?;
        let packages = repository.object("manifest.repository")?;
        let mut versions = BTreeMap::new();
        for (name, entries) in packages {
            segment(name, "manifest package")?;
            if name != &name.to_ascii_lowercase() {
                return Err("manifest package 名稱必須小寫".into());
            }
            let entries = entries.object("manifest package versions")?;
            let mut releases = Vec::new();
            for version in entries.keys() {
                segment(version, "manifest version")?;
                releases.push(version.clone());
            }
            versions.insert(name.clone(), releases);
        }
        Ok(versions)
    })
}

pub(super) fn evaluate(
    file: &Path,
    profile: Profile,
    target: &str,
    abi: &str,
) -> Result<Parsed, String> {
    let meta = fs::symlink_metadata(file).map_err(|_| "rockspec 檔案不可讀")?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > MAX_SOURCE as u64 {
        return Err("rockspec 必須是不超過 256KiB 的一般檔案".into());
    }
    let source = fs::read(file).map_err(|_| "rockspec 檔案不可讀")?;
    if source.len() > MAX_SOURCE {
        return Err("rockspec 來源超過限制".into());
    }
    let digest = crate::p17::package_sha256_bytes(&source)?;
    sandbox(&source, profile, b"=rockspec", |reader| {
        requested_identity(reader, profile, target, &abi.to_ascii_lowercase())?;
        let name = reader.global(b"package")?.text("package")?.to_owned();
        let version = reader.global(b"version")?.text("version")?.to_owned();
        segment(&name, "package")?;
        segment(&version, "version")?;
        let identity = PackageIdentity {
            name,
            version,
            lua_profile: profile.name().into(),
            target: target.to_owned(),
            abi: abi.to_ascii_lowercase(),
        };
        let runtime = dependency(reader.global(b"dependencies")?, "dependencies")?;
        let build_deps = dependency(reader.global(b"build_dependencies")?, "build_dependencies")?;
        let test = dependency(reader.global(b"test_dependencies")?, "test_dependencies")?;
        let source = reader.global(b"source")?;
        source_policy(&source)?;
        let build = reader.global(b"build")?;
        build.object("build")?;
        let platforms = reader.global(b"platforms")?;
        if !matches!(&platforms, Data::Null | Data::Object(_)) {
            return Err("platforms 必須是 table".into());
        }
        let supported = match reader.global(b"supported_platforms")? {
            Data::Object(values) if values.is_empty() => Data::Array(Vec::new()),
            other => other,
        };
        if !matches!(&supported, Data::Null | Data::Array(_)) {
            return Err("supported_platforms 必須是清單".into());
        }
        supported_target(&supported, target)?;
        let external = reader.global(b"external_dependencies")?;
        if !matches!(&external, Data::Null | Data::Object(_)) {
            return Err("external_dependencies 必須是 table".into());
        }
        check_system_lua(&external)?;
        check_system_lua(&build)?;
        check_system_lua(&platforms)?;
        let effective = effective_dependencies(&runtime, &build_deps, &test, &platforms, target)?;
        let mut deps = BTreeMap::new();
        deps.insert("runtime".into(), runtime);
        deps.insert("build".into(), build_deps);
        deps.insert("test".into(), test);
        let mut record = BTreeMap::new();
        record.insert("name".into(), Data::Text(identity.name.clone()));
        record.insert("version".into(), Data::Text(identity.version.clone()));
        record.insert(
            "lua_profile".into(),
            Data::Text(identity.lua_profile.clone()),
        );
        record.insert("target".into(), Data::Text(identity.target.clone()));
        record.insert("abi".into(), Data::Text(identity.abi.clone()));
        record.insert("dependencies".into(), Data::Object(deps));
        record.insert("source".into(), source);
        record.insert("build".into(), build);
        record.insert("platforms".into(), platforms);
        record.insert("supported_platforms".into(), supported);
        record.insert("external_dependencies".into(), external);
        record.insert("sha256".into(), Data::Text(digest.clone()));
        let mut output = String::new();
        Data::Object(record).json(&mut output);
        if output.len() > MAX_OUTPUT {
            return Err("rockspec 輸出超過限制".into());
        }
        Ok(Parsed {
            identity,
            dependencies: effective,
            sha256: digest,
            json: output,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::{Data, check_system_lua};
    use std::collections::BTreeMap;

    #[test]
    fn native_library_policy_distinguishes_lua_from_rivetlua() {
        for (library, reject) in [
            ("lua", true),
            ("luajit", true),
            ("-llua5.4", true),
            ("rivetlua", false),
        ] {
            let modules = BTreeMap::from([(
                "libraries".into(),
                Data::Array(vec![Data::Text(library.into())]),
            )]);
            assert_eq!(check_system_lua(&Data::Object(modules)).is_err(), reject);
        }
    }
}
