use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::VerifyLimits;

#[test]
fn p17_sequential_statements_reuse_temporary_registers() {
    let source = b"local x = 0\nx = 1\nx = 2\nreturn x\n";
    let limits = CompileLimits::default();
    let register_limits = IrLimits {
        max_registers: 8,
        ..IrLimits::default()
    };
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let tokens = lex(source, profile, &limits).unwrap();
        let syntax = parse(&tokens, profile, &limits).unwrap();
        let resolved = resolve(&syntax, &tokens, profile, &limits).unwrap();
        let ir = lower(&resolved, &register_limits).unwrap();
        assert!(ir.prototypes[0].register_count <= 8);
        emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@p17-register-pressure.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
    }
}

#[test]
fn p17_helper_private_slots_survive_statement_reuse() {
    let source =
        b"local function f() return 1, 2 end\nlocal t = {f()}\nlocal x = 3\nreturn t[1], t[2], x\n";
    let limits = CompileLimits::default();
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let tokens = lex(source, profile, &limits).unwrap();
        let syntax = parse(&tokens, profile, &limits).unwrap();
        let resolved = resolve(&syntax, &tokens, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        assert_eq!(
            ir.prototypes
                .iter()
                .map(|prototype| prototype.native_list_writes.len())
                .sum::<usize>(),
            1,
        );
        emit_with_native_debug(
            &ir,
            &resolved,
            source,
            b"@p17-helper-private-reuse.lua",
            &VerifyLimits::default(),
        )
        .unwrap();
    }
}
