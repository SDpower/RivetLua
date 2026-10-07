use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{Instruction, VerifyLimits};

#[test]
fn native_debug_uses_lexical_function_definition_lines() {
    let source = b"local function local_multi(a)\n  return a\nend\nlocal expression_one = function() return 1 end\nfunction statement_multi(x)\n  return x\nend\nlocal function local_one() return 2 end\nreturn local_multi(1), expression_one(), statement_multi(3), local_one()\n";
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let limits = CompileLimits::default();
        let lexed = lex(source, profile, &limits).unwrap();
        let ast = parse(&lexed, profile, &limits).unwrap();
        let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        let encoded = emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@definition-lines.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
        let debug = encoded.verified().native_debug().unwrap();
        let root = debug.prototype(ir.prototypes[0].id).unwrap();
        assert_eq!(
            (root.line_defined, root.last_line_defined),
            (0, 0),
            "{profile:?}"
        );
        let mut actual: Vec<_> = debug
            .prototypes()
            .iter()
            .filter(|prototype| prototype.prototype != root.prototype)
            .map(|prototype| (prototype.line_defined, prototype.last_line_defined))
            .collect();
        actual.sort_unstable();
        assert_eq!(actual, [(1, 3), (4, 4), (5, 7), (8, 8)], "{profile:?}");
    }
}

fn check_implicit_return_lines(profile: LanguageProfile) {
    let source = b"local function h()\n  local x=1\nend\nlocal function f()\n  return 1\nend\nlocal function g()\n  return f()\nend\nh()\n";
    let limits = CompileLimits::default();
    let lexed = lex(source, profile, &limits).unwrap();
    let ast = parse(&lexed, profile, &limits).unwrap();
    let resolved = resolve(&ast, &lexed, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    let encoded = emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@return-lines.lua",
        &VerifyLimits::default(),
    )
    .unwrap();
    let verified = encoded.verified();
    let debug = verified.native_debug().unwrap();
    for (defined, last, expected_line, tail) in
        [(1, 3, 3, false), (4, 6, 5, false), (7, 9, 8, true)]
    {
        let entry = debug
            .prototypes()
            .iter()
            .find(|entry| entry.line_defined == defined)
            .unwrap();
        assert_eq!(entry.last_line_defined, last, "{profile:?}");
        assert_eq!(entry.lines.last(), Some(&expected_line), "{profile:?}");
        let proto = verified
            .module()
            .prototypes
            .iter()
            .find(|proto| proto.id == entry.prototype)
            .unwrap();
        assert!(
            matches!(
                proto.instructions.last().unwrap().instruction,
                Instruction::TailCall { .. } if tail
            ) || matches!(
                proto.instructions.last().unwrap().instruction,
                Instruction::Return { .. } if !tail
            )
        );
    }
    let root = debug.prototype(ir.prototypes[0].id).unwrap();
    assert_eq!((root.line_defined, root.last_line_defined), (0, 0));
    assert_eq!(root.lines.last(), Some(&10), "{profile:?}");
}

#[test]
fn implicit_return_uses_function_end_line_lua54() {
    check_implicit_return_lines(LanguageProfile::Lua54);
}

#[test]
fn implicit_return_uses_function_end_line_lua55() {
    check_implicit_return_lines(LanguageProfile::Lua55);
}
