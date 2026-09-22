use rivetlua_compiler::{
    CompileLimits, DiagnosticCode, LanguageProfile, ResolvedExpr, ResolvedName, ResolvedStmt, lex,
    parse, resolve,
};
use std::{env, fs, path::PathBuf};

fn selected_profile() -> (LanguageProfile, &'static str) {
    match env::var("RIVETLUA_P04_PROFILE").as_deref() {
        Ok("lua55-i64f64") | Err(_) => (LanguageProfile::Lua55, "lua55-i64f64"),
        Ok("lua54-i64f64") => (LanguageProfile::Lua54, "lua54-i64f64"),
        Ok(_) => panic!("P04 case profile 不合法"),
    }
}

fn expectations() -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().and_then(|path| path.parent()).unwrap();
    fs::read_to_string(root.join("tests/p04/resolver-expectations.fixture"))
        .expect("P04 expectations fixture 必須存在")
}

fn expected(key: &str) -> String {
    expectations()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .find_map(|line| line.split_once('=').filter(|(name, _)| *name == key))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_else(|| panic!("P04 expectations fixture 缺少 {key}"))
}

fn expected_bool(key: &str) -> bool {
    match expected(key).as_str() {
        "true" => true,
        "false" => false,
        value => panic!("P04 expectations fixture 的 {key} 不是 bool：{value}"),
    }
}

fn record(id: &str, input: &[u8], actual: &impl core::fmt::Debug) {
    if !expected_bool(&format!("{id}.enabled")) {
        return;
    }
    let input = String::from_utf8_lossy(input)
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    let actual = format!("{actual:?}")
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    println!("P04_CASE\t{id}\t{input}\t{actual}");
}

fn resolved(
    input: &[u8],
    profile: LanguageProfile,
    limits: &CompileLimits,
) -> rivetlua_compiler::ResolvedModule {
    let chunk = lex(input, profile, limits).unwrap();
    let module = parse(&chunk, profile, limits).unwrap();
    resolve(&module, &chunk, profile, limits).unwrap()
}

fn resolve_error(
    input: &[u8],
    profile: LanguageProfile,
    limits: &CompileLimits,
) -> rivetlua_compiler::Diagnostic {
    let chunk = lex(input, profile, limits).unwrap();
    let module = parse(&chunk, profile, limits).unwrap();
    resolve(&module, &chunk, profile, limits).unwrap_err()
}

#[test]
fn p04_contract_cases_for_one_profile() {
    let (profile, full_profile) = selected_profile();
    assert_eq!(expected(&format!("profile.{full_profile}")), full_profile);
    let limits = CompileLimits::default();

    let input = b"local x=5; do local x=x+1 end; return x";
    let module = resolved(input, profile, &limits);
    let ResolvedStmt::Local {
        bindings: outer, ..
    } = &module.root.statements[0]
    else {
        panic!("outer local 必須存在")
    };
    let ResolvedStmt::Do { body, .. } = &module.root.statements[2] else {
        panic!("do 必須存在")
    };
    let ResolvedStmt::Local {
        bindings: inner,
        values,
        ..
    } = &body.statements[0]
    else {
        panic!("inner local 必須存在")
    };
    let ResolvedStmt::Return {
        values: returned, ..
    } = &module.root.statements[4]
    else {
        panic!("return 必須存在")
    };
    let distinct = outer[0] != inner[0]
        && matches!(values.as_slice(), [ResolvedExpr::Binary { left, .. }] if matches!(left.as_ref(), ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. } if *id == outer[0]))
        && matches!(returned.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. }] if *id == outer[0]);
    assert_eq!(distinct, expected_bool("RES-001.distinct_bindings"));
    record("RES-001", input, &module);

    let input = b"local x <const> = 1; x = 2";
    let error = resolve_error(input, profile, &limits);
    assert_eq!(error.code, DiagnosticCode::Resolve);
    record("RES-002", input, &error);

    let input = b"goto L; local x=1; ::L:: return x";
    let error = resolve_error(input, profile, &limits);
    assert_eq!(error.code, DiagnosticCode::Resolve);
    record("RES-003", input, &error);

    let input = if profile == LanguageProfile::Lua55 {
        b"global x; return y".as_slice()
    } else {
        b"return free".as_slice()
    };
    if profile == LanguageProfile::Lua55 {
        let error = resolve_error(input, profile, &limits);
        assert_eq!(error.code, DiagnosticCode::Resolve);
        assert_eq!(true, expected_bool("RES-004.lua55.reject_undeclared"));
        record("RES-004", input, &error);
    } else {
        let module = resolved(input, profile, &limits);
        assert!(
            matches!(module.root.statements.as_slice(), [ResolvedStmt::Return { values, .. }] if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::EnvField { name, .. }, .. }] if name == b"free"))
        );
        record("RES-004", input, &module);
    }

    let input = b"for i=1,1 do i=2 end";
    if profile == LanguageProfile::Lua55 {
        let error = resolve_error(input, profile, &limits);
        assert_eq!(error.code, DiagnosticCode::Resolve);
        record("RES-005", input, &error);
    } else {
        let module = resolved(input, profile, &limits);
        assert!(
            matches!(module.root.statements.as_slice(), [ResolvedStmt::NumericFor { name, body, .. }] if matches!(body.statements.as_slice(), [ResolvedStmt::Assignment { targets, .. }] if matches!(targets.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. }] if *id == name.binding)))
        );
        record("RES-005", input, &module);
    }

    let input = b"local x; local function f() local function g() return x end; return g end";
    let module = resolved(input, profile, &limits);
    let ResolvedStmt::LocalFunction { body: f, .. } = &module.root.statements[2] else {
        panic!("f 必須存在")
    };
    let ResolvedStmt::LocalFunction { body: g, .. } = &f.body.statements[0] else {
        panic!("g 必須存在")
    };
    assert!(
        matches!(g.body.statements.as_slice(), [ResolvedStmt::Return { values, .. }] if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Upvalue(_), .. }]))
    );
    record("RES-006", input, &module);

    let input = b"return free";
    let module = resolved(input, profile, &limits);
    assert!(
        matches!(module.root.statements.as_slice(), [ResolvedStmt::Return { values, .. }] if matches!(values.as_slice(), [ResolvedExpr::Name { resolution, .. }] if matches!(resolution, ResolvedName::Global(_)) == (profile == LanguageProfile::Lua55)))
    );
    record("RES-007", input, &module);

    let input = b"break";
    let error = resolve_error(input, profile, &limits);
    assert_eq!(error.code, DiagnosticCode::Resolve);
    record("RES-ERR-001", input, &error);

    let input = b"do do do end end end";
    let depth_limits = CompileLimits {
        max_scope_depth: expected("RES-ERR-002.max_scope_depth").parse().unwrap(),
        ..limits
    };
    let error = resolve_error(input, profile, &depth_limits);
    assert_eq!(error.code, DiagnosticCode::CompileLimit);
    let goto_limits = CompileLimits {
        max_gotos: expected("RES-ERR-002.max_gotos").parse().unwrap(),
        ..limits
    };
    let goto_error = resolve_error(b"goto L; ::L::", profile, &goto_limits);
    assert_eq!(goto_error.code, DiagnosticCode::CompileLimit);
    let upvalue_limits = CompileLimits {
        max_upvalues_per_function: expected("RES-ERR-002.max_upvalues").parse().unwrap(),
        ..limits
    };
    let upvalue_error = resolve_error(
        b"local x; local function f() return x end",
        profile,
        &upvalue_limits,
    );
    assert_eq!(upvalue_error.code, DiagnosticCode::CompileLimit);
    record(
        "RES-ERR-002",
        b"do do do end end end | goto L; ::L:: | local x; local function f() return x end",
        &(error, goto_error, upvalue_error),
    );
}
