use rivetlua_compiler::{
    BindingKind, CompileLimits, Diagnostic, DiagnosticCode, LanguageProfile, ResolvedExpr,
    ResolvedModule, ResolvedName, ResolvedStmt, lex, parse, resolve,
};

fn resolved(source: &[u8]) -> Result<ResolvedModule, Diagnostic> {
    let limits = CompileLimits::default();
    let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
    let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
    resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits)
}

#[test]
fn explicit_const_wildcard_survives_later_named_global_declarations() {
    let source = b"global <const> *; global a; return _VERSION";
    let module = resolved(source).unwrap();
    let Some(ResolvedStmt::Return { values, .. }) = module.root.statements.last() else {
        panic!("必須保留 return")
    };
    let [
        ResolvedExpr::Name {
            resolution: ResolvedName::Global(binding),
            ..
        },
    ] = values.as_slice()
    else {
        panic!("_VERSION 應解析為 global")
    };
    assert!(module.functions[0].bindings.iter().any(|meta| {
        meta.id == *binding
            && meta.kind == BindingKind::Global
            && meta.name == b"_VERSION"
            && meta.readonly
    }));

    for source in [
        b"global *; global a; a=3; free=4; return a,free".as_slice(),
        b"global<const>*; global z; z=3; return z,_VERSION",
        b"global z; global<const>*; z=3; return z",
        b"global<const>*; local function f() return _VERSION end; return f()",
        b"global<const>*; global a; local function f() return _VERSION end; return f()",
        b"global *; do global<const>* end; free=3; return free",
        b"global<const>*; do global *; free=3 end; return free",
        b"global<const>*; do local _ENV={x=1}; _ENV.x=2; return x end",
    ] {
        resolved(source).unwrap_or_else(|error| {
            panic!(
                "合法 wildcard source 應解析：{} {error:?}",
                String::from_utf8_lossy(source)
            )
        });
    }
}

#[test]
fn explicit_wildcard_and_named_readonly_reject_direct_name_writes() {
    for source in [
        b"global<const>*; _VERSION='bad'".as_slice(),
        b"global<const>*; global a; free=1",
        b"global<const>*; local function f() free=1 end",
        b"global<const>*; global a; local function f() free=1 end",
        b"global<const>*; do local _ENV={x=1}; x=2 end",
        b"global<const>*; do global *; free=1 end; free=2",
        b"global *; do global<const>*; free=1 end",
        b"global z<const>; global *; z=3",
        b"global z<const>; do local _ENV={z=1}; z=5 end",
        b"global<const> z; z=3",
    ] {
        let error = resolved(source).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Resolve, "{source:?}");
        assert!(error.message.contains("readonly"), "{source:?}: {error:?}");
    }
}

#[test]
fn wildcard_attributes_reject_close_and_unknown_names() {
    for source in [b"global<close>*".as_slice(), b"global<close> a"] {
        let error = resolved(source).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Resolve);
        assert!(error.message.contains("close"), "{error:?}");
    }
    for source in [b"global<unknown>*".as_slice(), b"global<unknown> a"] {
        let error = resolved(source).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Resolve);
        assert!(error.message.contains("attribute"), "{error:?}");
    }
}

#[test]
fn wildcard_preserves_implicit_restriction_profile_and_limits() {
    let error = resolved(b"global a; return undeclared").unwrap_err();
    assert_eq!(error.code, DiagnosticCode::Resolve);
    let source = b"global<const>*; read=1";
    let error = resolved(source).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::Resolve);
    assert_eq!(
        error.span.start_byte,
        source
            .windows(4)
            .position(|bytes| bytes == b"read")
            .unwrap()
    );

    let limits = CompileLimits {
        max_bindings_per_function: 1,
        ..CompileLimits::default()
    };
    let source = b"global<const>*; return free";
    let chunk = lex(source, LanguageProfile::Lua55, &limits).unwrap();
    let parsed = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
    assert_eq!(
        resolve(&parsed, &chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );

    let chunk = lex(b"global<const>*", LanguageProfile::Lua54, &limits).unwrap();
    assert!(parse(&chunk, LanguageProfile::Lua54, &limits).is_err());
}
