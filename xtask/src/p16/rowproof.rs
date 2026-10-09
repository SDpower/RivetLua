use super::manifest::Row;
use super::selection::{self, Applicability, Snapshot};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

pub(super) const FAILFALSE_ROW: &str = "lua55:lauxlib.h:macro:luaL_pushfail:172";
pub(super) const FAILFALSE_SOURCE: &str = "tests/p16/public_aux_error_a3.c";
const NIL_ROW: &str = "lua55:lauxlib.h:macro:luaL_pushfail:174";

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) enum ProofKey {
    Pinned(String),
    Surface(String),
    Layout(String),
    HeaderSelection(String),
    MacroEffects(String),
    HeaderValues(String),
    OfficialValues(String),
    CFixture {
        profile: String,
        source: String,
    },
    CFixtureFailFalse {
        profile: String,
    },
    RustNamed {
        profile: String,
        target: String,
        test: String,
    },
    RustCrossContract {
        profile: String,
        target: String,
        test: String,
    },
}

impl ProofKey {
    pub(super) fn id(&self) -> String {
        match self {
            Self::Pinned(profile) => format!("pinned:{profile}"),
            Self::Surface(profile) => format!("surface:{profile}"),
            Self::Layout(profile) => format!("layout:{profile}"),
            Self::HeaderSelection(profile) => format!("header-selection:{profile}"),
            Self::MacroEffects(profile) => format!("macro-effects:{profile}"),
            Self::HeaderValues(profile) => format!("header-values:{profile}"),
            Self::OfficialValues(profile) => format!("official-values:{profile}"),
            Self::CFixture { profile, source } => format!("c:{profile}:{source}"),
            Self::CFixtureFailFalse { profile } => {
                format!("c-failfalse:{profile}:{FAILFALSE_SOURCE}")
            }
            Self::RustNamed {
                profile,
                target,
                test,
            } => {
                format!("rust:{profile}:{target}:{test}")
            }
            Self::RustCrossContract {
                profile,
                target,
                test,
            } => {
                format!("rust-cross-contract:{profile}:{target}:{test}")
            }
        }
    }

    pub(super) fn profile(&self) -> &str {
        match self {
            Self::Pinned(profile)
            | Self::Surface(profile)
            | Self::Layout(profile)
            | Self::HeaderSelection(profile)
            | Self::MacroEffects(profile) => profile,
            Self::HeaderValues(profile) | Self::OfficialValues(profile) => profile,
            Self::CFixture { profile, .. }
            | Self::CFixtureFailFalse { profile }
            | Self::RustNamed { profile, .. }
            | Self::RustCrossContract { profile, .. } => profile,
        }
    }

    pub(super) fn kind(&self) -> &'static str {
        match self {
            Self::Pinned(_) => "PinnedHeaders",
            Self::Surface(_) => "SurfaceCompile",
            Self::Layout(_) => "LayoutRuntime",
            Self::HeaderSelection(_) => "HeaderSelection",
            Self::MacroEffects(_) => "MacroEffects",
            Self::HeaderValues(_) => "HeaderValues",
            Self::OfficialValues(_) => "OfficialValues",
            Self::CFixture { .. } => "CFixture",
            Self::CFixtureFailFalse { .. } => "CFixtureFailFalse",
            Self::RustNamed { .. } => "RustNamed",
            Self::RustCrossContract { .. } => "RustCrossContract",
        }
    }
}

pub(super) fn failfalse_command(
    root: &Path,
    profile: &str,
    library: &Path,
    binary: &Path,
    native_flags: &[String],
) -> Result<Vec<String>, String> {
    if profile != "lua55" {
        return Err("P16 failfalse C proof 僅支援 lua55".into());
    }
    let mut command = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        format!("-I{}", root.join("include/rivetlua/lua55").display()),
        format!("-I{}", root.join("include/rivetlua").display()),
        "-DLUA_FAILISFALSE".into(),
        root.join(FAILFALSE_SOURCE).display().to_string(),
        library.display().to_string(),
        "-o".into(),
        binary.display().to_string(),
    ];
    command.extend(native_flags.iter().cloned());
    Ok(command)
}

pub(super) fn needs_value(row: &Row) -> bool {
    matches!(row.kind.as_str(), "constant" | "layout_field")
        || (row.kind == "macro"
            && matches!(
                row.name.as_str(),
                "LUAI_IS32INT"
                    | "LUA_32BITS"
                    | "LUA_C89_NUMBERS"
                    | "LUA_INT_TYPE"
                    | "LUA_FLOAT_TYPE"
                    | "LUA_COMPAT_GLOBAL"
                    | "LUAI_MAXSTACK"
                    | "LUA_NUMBER"
                    | "LUAI_UACNUMBER"
                    | "LUAI_UACINT"
                    | "LUA_UNSIGNED"
                    | "LUA_INTEGER"
                    | "LUA_KCONTEXT"
                    | "LUAI_MAXALIGN"
            ))
}

fn layout_covered(row: &Row) -> bool {
    const TYPES: [&str; 14] = [
        "void *",
        "int",
        "long",
        "long long",
        "double",
        "long double",
        "size_t",
        "lua_Integer",
        "lua_Number",
        "lua_Unsigned",
        "lua_KContext",
        "lua_Debug",
        "luaL_Buffer",
        "luaL_Reg",
    ];
    match row.kind.as_str() {
        "size" | "alignment" | "layout" => {
            TYPES.contains(&row.name.as_str()) || row.name == "luaL_Stream"
        }
        "layout_field" => [
            "lua_Debug.short_src",
            "lua_Debug.i_ci",
            "luaL_Buffer.init",
            "luaL_Reg.func",
            "luaL_Stream.closef",
        ]
        .contains(&row.name.as_str()),
        _ => false,
    }
}

fn profile_scope(scope: &str, profile: &str) -> bool {
    scope == profile || scope == "lua55+lua54"
}

fn p17_official_module_future_marker(row: &Row, part: &str) -> bool {
    part == "OFFICIAL_MODULES:NOT_RUN"
        && row.kind == "function"
        && row.name == "luaL_testudata"
        && row.status == "IMPLEMENTED"
        && matches!(row.profile.as_str(), "lua54" | "lua55")
        && row.id == format!("{}:lauxlib.h:function:luaL_testudata:72", row.profile)
        && row.p17_use
            == format!(
                "tests/p16/surface_{}.c:COMPILE_ONLY; official-module:NOT_RUN",
                row.profile
            )
        && row
            .evidence
            .split(';')
            .filter(|tag| *tag == "OFFICIAL_MODULES:NOT_RUN")
            .count()
            == 1
}

// 僅供已具備逐符號 C ABI 效果檢查、但 manifest 沒有直接 Rust 測試的契約。
fn cross_contract(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match name {
        "luaL_argerror" | "luaL_typeerror" | "luaL_error" | "luaL_argcheck"
        | "luaL_argexpected" => (
            "public_callback_error",
            "public_sync_call_pcall_and_group_panic_binding",
        ),
        "lua_upvalueindex" => (
            "public_upvalue_a4b",
            "public_c_closure_pseudovalue_write_persists_a4b",
        ),
        "lua_call" | "lua_pcall" | "lua_error" => (
            "public_callback_error",
            "public_sync_call_pcall_and_group_panic_binding",
        ),
        "lua_yieldk" | "lua_yield" => (
            "public_yield_resume_a5",
            "suspended_c_upvalue_survives_gc_and_releases_child_charge_a5",
        ),
        "luaL_bufflen" | "luaL_buffaddr" | "luaL_addsize" | "luaL_buffsub" => (
            "aux_buffer",
            "aux_buffer_small_inline_binary_and_empty_appends",
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p16_testudata_future_official_marker_keeps_c_and_rust_obligations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = super::super::manifest::load(root).unwrap();
        assert!(super::super::matrix::IDS.contains(&"SDK-MODULE"));
        for profile in ["lua54", "lua55"] {
            let id = format!("{profile}:lauxlib.h:function:luaL_testudata:72");
            let row = manifest
                .rows
                .iter()
                .find(|row| row.id == id)
                .unwrap()
                .clone();
            assert!(p17_official_module_future_marker(
                &row,
                "OFFICIAL_MODULES:NOT_RUN"
            ));
            let proofs = required(root, &row).unwrap();
            assert!(proofs.contains(&ProofKey::CFixture {
                profile: profile.into(),
                source: "tests/p16/public_upvalue_a4b.c".into(),
            }));
            assert!(proofs.contains(&ProofKey::RustNamed {
                profile: profile.into(),
                target: "aux_userdata".into(),
                test: "aux_userdata_a31_matrix".into(),
            }));

            let mut missing_c = row.clone();
            missing_c.evidence = row
                .evidence
                .split(';')
                .filter(|part| !part.starts_with("tests/p16/") || !part.contains(":C_LINK_RUN:"))
                .collect::<Vec<_>>()
                .join(";");
            assert!(
                required(root, &missing_c)
                    .unwrap_err()
                    .contains("缺 C ABI 效果")
            );

            let mut missing_rust = row.clone();
            missing_rust.evidence = row
                .evidence
                .split(';')
                .filter(|part| !part.starts_with("crates/rivetlua-capi/tests/aux_userdata.rs:"))
                .collect::<Vec<_>>()
                .join(";");
            assert!(
                required(root, &missing_rust)
                    .unwrap_err()
                    .contains("具名 Rust test")
            );
        }
    }

    #[test]
    fn p16_testudata_future_marker_cannot_move_or_hide_other_not_run() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = super::super::manifest::load(root).unwrap();
        let row = manifest
            .rows
            .iter()
            .find(|row| row.id == "lua55:lauxlib.h:function:luaL_testudata:72")
            .unwrap()
            .clone();
        let mut wrong_id = row.clone();
        wrong_id.id = wrong_id.id.replace(":72", ":73");
        assert!(!p17_official_module_future_marker(
            &wrong_id,
            "OFFICIAL_MODULES:NOT_RUN"
        ));
        assert!(
            required(root, &wrong_id)
                .unwrap_err()
                .contains("OFFICIAL_MODULES:NOT_RUN")
        );

        let mut wrong_profile = row.clone();
        wrong_profile.profile = "lua54".into();
        wrong_profile.id = "lua54:lauxlib.h:function:luaL_testudata:72".into();
        assert!(!p17_official_module_future_marker(
            &wrong_profile,
            "OFFICIAL_MODULES:NOT_RUN"
        ));

        let mut wrong_kind = row.clone();
        wrong_kind.kind = "macro".into();
        wrong_kind.id = "lua55:lauxlib.h:macro:luaL_testudata:72".into();
        assert!(!p17_official_module_future_marker(
            &wrong_kind,
            "OFFICIAL_MODULES:NOT_RUN"
        ));

        let mut wrong_p17 = row.clone();
        wrong_p17.p17_use = wrong_p17
            .p17_use
            .replace("official-module:NOT_RUN", "official-module:PASS");
        assert!(
            required(root, &wrong_p17)
                .unwrap_err()
                .contains("OFFICIAL_MODULES:NOT_RUN")
        );

        let mut duplicate = row.clone();
        duplicate.evidence.push_str(";OFFICIAL_MODULES:NOT_RUN");
        assert!(
            required(root, &duplicate)
                .unwrap_err()
                .contains("OFFICIAL_MODULES:NOT_RUN")
        );

        let mut unknown = row.clone();
        unknown.evidence.push_str(";OTHER_PHASE:NOT_RUN");
        assert!(
            required(root, &unknown)
                .unwrap_err()
                .contains("OTHER_PHASE:NOT_RUN")
        );

        let mut moved = manifest
            .rows
            .iter()
            .find(|candidate| candidate.id == "lua55:lauxlib.h:function:luaL_checkudata:73")
            .unwrap()
            .clone();
        moved.evidence.push_str(";OFFICIAL_MODULES:NOT_RUN");
        assert!(!p17_official_module_future_marker(
            &moved,
            "OFFICIAL_MODULES:NOT_RUN"
        ));
        assert!(required(root, &moved).is_err());
    }

    #[test]
    fn p16_api_corpus_requires_named_body_assertion() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = super::super::manifest::load(root).unwrap();
        let mut row = manifest
            .rows
            .iter()
            .find(|row| row.profile == "lua55" && row.name == "luaL_fileresult")
            .unwrap()
            .clone();
        row.evidence
            .push_str(";tests/p16/acceptance/api_effects.c:C_LINK_RUN:lua55:PASS");
        let proofs = required(root, &row).unwrap();
        assert!(proofs.contains(&ProofKey::CFixture {
            profile: "lua55".into(),
            source: "tests/p16/acceptance/api_effects.c".into()
        }));
        row.name = "luaL_testudata".into();
        row.id = row.id.replace("luaL_fileresult", "luaL_testudata");
        assert!(required(root, &row).unwrap_err().contains("個別斷言"));
    }

    #[test]
    fn p16_only_explicit_c_effects_gain_cross_contract() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
        let manifest = super::super::manifest::load(root).unwrap();
        for name in [
            "luaL_argerror",
            "lua_yieldk",
            "lua_upvalueindex",
            "luaL_bufflen",
        ] {
            let mut row = manifest
                .rows
                .iter()
                .find(|row| row.profile == "lua55" && row.name == name)
                .unwrap()
                .clone();
            row.evidence = "tests/p16/acceptance/api_effects.c:C_LINK_RUN:lua55:PASS".into();
            let proofs = required(root, &row).unwrap();
            assert!(
                proofs
                    .iter()
                    .any(|proof| matches!(proof, ProofKey::RustCrossContract { .. })),
                "{name}"
            );
            assert!(proofs.contains(&ProofKey::CFixture {
                profile: "lua55".into(),
                source: "tests/p16/acceptance/api_effects.c".into()
            }));
            row.evidence = "tests/p16/public_callback_error_a2.c:C_LINK_RUN:lua55:PASS".into();
            assert!(required(root, &row).is_err(), "{name}");
        }
        let mut row = manifest
            .rows
            .iter()
            .find(|row| row.profile == "lua55" && row.name == "luaL_fileresult")
            .unwrap()
            .clone();
        row.evidence = "tests/p16/acceptance/api_effects.c:C_LINK_RUN:lua55:PASS".into();
        assert!(required(root, &row).unwrap_err().contains("具名 Rust test"));
    }
}

pub(super) fn required(root: &Path, row: &Row) -> Result<Vec<ProofKey>, String> {
    let observed =
        if row.status == "HEADER_ONLY" && matches!(row.kind.as_str(), "macro" | "constant") {
            Some(selection::capture(root, &row.profile)?)
        } else {
            None
        };
    required_with(root, row, observed.as_ref())
}

pub(super) fn required_with(
    root: &Path,
    row: &Row,
    selection: Option<&Snapshot>,
) -> Result<Vec<ProofKey>, String> {
    let id_fields = row.id.split(':').collect::<Vec<_>>();
    if !matches!(row.profile.as_str(), "lua54" | "lua55")
        || id_fields.len() != 5
        || id_fields[0] != row.profile
        || id_fields[2] != row.kind
        || id_fields[3] != row.name
    {
        return Err("manifest profile/ID 不符".into());
    }
    if row.id == FAILFALSE_ROW {
        if row.definition != "#define luaL_pushfail(L) lua_pushboolean(L, 0)"
            || row.condition != "#ifndef lauxlib_h && #if defined(LUA_FAILISFALSE)"
        {
            return Err("luaL_pushfail false 分支定義／條件不符".into());
        }
    } else if row.profile == "lua55"
        && row.kind == "macro"
        && row.name == "luaL_pushfail"
        && row.definition == "#define luaL_pushfail(L) lua_pushboolean(L, 0)"
    {
        return Err("luaL_pushfail false 分支 ID 不符".into());
    }
    if row.id == NIL_ROW
        && (row.definition != "#define luaL_pushfail(L) lua_pushnil(L)"
            || row.condition != "#ifndef lauxlib_h && #else")
    {
        return Err("luaL_pushfail nil 分支定義／條件不符".into());
    }
    if row.status == "NOT_IMPLEMENTED" || row.evidence.contains("NOT_IMPLEMENTED") {
        return Err("實作標記 NOT_IMPLEMENTED".into());
    }
    let profile = row.profile.clone();
    let mut required = BTreeSet::new();
    if row.status == "HEADER_ONLY" {
        let expected = format!("tests/p16/surface_{profile}.c:COMPILE_ONLY");
        if row.evidence != expected
            || !row
                .mapping
                .starts_with(&format!("include/rivetlua/{profile}/"))
        {
            return Err("HEADER_ONLY 固定 surface/header 對應不符".into());
        }
        let mut selected = false;
        if matches!(row.kind.as_str(), "macro" | "constant") {
            let snapshot = selection.ok_or("HEADER_ONLY 巨集／常數缺 selection 證據")?;
            let applicability = selection::classify(snapshot, row)?;
            selected = matches!(applicability, Applicability::Selected(_));
            required.insert(ProofKey::HeaderSelection(profile.clone()));
            if row.kind == "macro"
                && row
                    .definition
                    .starts_with(&format!("#define {}(", row.name))
                && matches!(applicability, Applicability::Selected(_))
            {
                required.insert(ProofKey::MacroEffects(profile.clone()));
            }
        }
        if needs_value(row) && (selected || row.kind == "layout_field") {
            required.insert(ProofKey::HeaderValues(profile.clone()));
            required.insert(ProofKey::OfficialValues(profile.clone()));
        }
        required.insert(ProofKey::Pinned(profile.clone()));
        required.insert(ProofKey::Surface(profile.clone()));
        required.insert(ProofKey::Layout(profile.clone()));
        if matches!(row.kind.as_str(), "size" | "alignment" | "layout") {
            if !layout_covered(row) {
                return Err("layout 不在 current_identity 37 欄".into());
            }
        }
        return Ok(required.into_iter().collect());
    }
    if row.status == "IMPLEMENTED" && row.kind == "opaque_type" && row.name == "lua_State" {
        if row.mapping != "rivetlua-capi::stack::lua_State"
            || row.evidence
                != "crates/rivetlua-capi/tests/stack_lifecycle.rs:stack_lifecycle_state_layout_extraspace_and_move:lua55+lua54:PASS"
        {
            return Err("lua_State opaque C/Rust 固定 proof ref 不符".into());
        }
        required.insert(ProofKey::Pinned(profile.clone()));
        required.insert(ProofKey::Surface(profile.clone()));
        required.insert(ProofKey::Layout(profile.clone()));
        required.insert(ProofKey::RustNamed {
            profile,
            target: "stack_lifecycle".into(),
            test: "stack_lifecycle_state_layout_extraspace_and_move".into(),
        });
        return Ok(required.into_iter().collect());
    }
    if row.status != "IMPLEMENTED" || !matches!(row.kind.as_str(), "function" | "macro") {
        return Err("實作類型無固定 runtime 對應".into());
    }
    let mut c_count = 0;
    let mut c_refs_without_direct_call = 0;
    let mut rust_count = 0;
    let mut legacy_unresolved = Vec::new();
    for part in row.evidence.split(';') {
        let fields = part.split(':').collect::<Vec<_>>();
        let c_path = part.starts_with("tests/p16/")
            && (part.contains(":C_LINK_RUN:")
                || part.contains(":C_LINK_CALL:")
                || part.ends_with(":COMPILE_LINK_RUN_PASS"));
        if c_path
            && !((fields.len() == 3
                && profile_scope(fields[1], &row.profile)
                && fields[2] == "COMPILE_LINK_RUN_PASS")
                || (fields.len() == 4
                    && matches!(fields[1], "C_LINK_RUN" | "C_LINK_CALL")
                    && matches!(fields[3], "PASS" | "NOT_RUN")
                    && profile_scope(fields[2], &row.profile))
                || (fields.len() == 3
                    && matches!(fields[1], "C_LINK_RUN" | "C_LINK_CALL")
                    && matches!(fields[2], "PASS" | "NOT_RUN")))
        {
            return Err("C fixture 狀態或 profile 不符".into());
        }
        if part.starts_with("crates/rivetlua-capi/tests/")
            && (part.ends_with(":PASS") || part.ends_with(":NOT_RUN"))
            && (fields.len() != 4 || !profile_scope(fields[2], &row.profile))
        {
            return Err("Rust named proof profile/格式不符".into());
        }
        if part.ends_with(":NOT_RUN")
            && !c_path
            && !part.starts_with("crates/rivetlua-capi/tests/")
            && !matches!(
                part,
                "C_LINK_CALL:NOT_RUN"
                    | "C_RUNTIME_CALL:NOT_RUN"
                    | "RIVETLUA_C_LINK_CALL:NOT_RUN"
                    | "A48_RUNTIME_VERIFICATION:NOT_RUN"
            )
            && !p17_official_module_future_marker(row, part)
        {
            legacy_unresolved.push(part.to_owned());
        }
        if c_path {
            let path = fields[0];
            if !path.ends_with(".c")
                || path.contains("..")
                || (path.starts_with("tests/p16/acceptance/")
                    && path != "tests/p16/acceptance/api_effects.c")
            {
                return Err("C fixture 路徑不在固定 corpus".into());
            }
            let source = fs::read_to_string(root.join(path))
                .map_err(|_| "manifest C fixture 缺失".to_owned())?;
            if path == "tests/p16/acceptance/api_effects.c"
                && !source.contains(&format!("CHECK(\"{}\",", row.name))
            {
                return Err("P16 acceptance C corpus 缺該符號個別斷言".into());
            }
            if !source.contains(&format!("{}(", row.name)) {
                c_refs_without_direct_call += 1;
                continue;
            }
            if row.id == FAILFALSE_ROW {
                if path != FAILFALSE_SOURCE {
                    return Err("luaL_pushfail false 分支 C fixture 不符".into());
                }
                required.insert(ProofKey::CFixtureFailFalse {
                    profile: profile.clone(),
                });
            } else {
                required.insert(ProofKey::CFixture {
                    profile: profile.clone(),
                    source: path.into(),
                });
            }
            c_count += 1;
        } else if fields.len() == 4
            && fields[0].starts_with("crates/rivetlua-capi/tests/")
            && matches!(fields[3], "PASS" | "NOT_RUN")
            && profile_scope(fields[2], &row.profile)
        {
            let path = fields[0];
            if !path.ends_with(".rs") || path.contains("..") {
                return Err("Rust named proof 路徑無效".into());
            }
            let target = path
                .trim_start_matches("crates/rivetlua-capi/tests/")
                .trim_end_matches(".rs");
            let test = fields[1];
            if !target
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || !test.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err("Rust named proof 名稱無效".into());
            }
            let source = fs::read_to_string(root.join(path))
                .map_err(|_| "manifest Rust test 檔缺失".to_owned())?;
            if !source.contains(&format!("fn {test}(")) {
                return Err("manifest Rust named test 缺失".into());
            }
            required.insert(ProofKey::RustNamed {
                profile: profile.clone(),
                target: target.into(),
                test: test.into(),
            });
            rust_count += 1;
        }
    }
    if c_count == 0 && c_refs_without_direct_call > 0 {
        return Err("C fixture 未直接呼叫該符號".into());
    }
    if !legacy_unresolved.is_empty() {
        return Err(format!(
            "歷史 NOT_RUN 缺固定 typed proof：{}",
            legacy_unresolved.join(",")
        ));
    }
    if c_count > 0 && rust_count == 0 {
        if let Some((target, test)) = cross_contract(&row.name) {
            if !required.contains(&ProofKey::CFixture {
                profile: profile.clone(),
                source: "tests/p16/acceptance/api_effects.c".into(),
            }) {
                return Err("跨契約列缺 P16 個別 C ABI effect corpus".into());
            }
            let source =
                fs::read_to_string(root.join(format!("crates/rivetlua-capi/tests/{target}.rs")))
                    .map_err(|_| "跨契約 Rust test 檔缺失".to_owned())?;
            if !source.contains(&format!("fn {test}(")) {
                return Err("跨契約 Rust named test 缺失".into());
            }
            required.insert(ProofKey::RustCrossContract {
                profile: profile.clone(),
                target: target.into(),
                test: test.into(),
            });
            rust_count += 1;
        }
    }
    if c_count == 0 || rust_count == 0 {
        return Err("可呼叫符號缺 C ABI 效果 fixture 或具名 Rust test".into());
    }
    required.insert(ProofKey::Pinned(profile));
    Ok(required.into_iter().collect())
}
