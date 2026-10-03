use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, VerifyLimits};

#[test]
fn source_root_is_variadic_but_nested_fixed_function_is_not() {
    for (language, runtime) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let limits = CompileLimits::default();
        for source in [b"return ...".as_slice(), b"return {...}".as_slice()] {
            let lexed = lex(source, language, &limits).unwrap();
            let parsed = parse(&lexed, language, &limits).unwrap();
            let resolved = resolve(&parsed, &lexed, language, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let root = &ir.prototypes[0];
            assert_eq!(root.parameter_count, 0);
            assert!(root.is_variadic);
            let encoded = emit(&ir, &VerifyLimits::default()).unwrap();
            assert_eq!(encoded.verified().profile(), runtime);
        }

        let source = b"return function() return ... end";
        let lexed = lex(source, language, &limits).unwrap();
        let parsed = parse(&lexed, language, &limits).unwrap();
        assert!(resolve(&parsed, &lexed, language, &limits).is_err());
    }
}
