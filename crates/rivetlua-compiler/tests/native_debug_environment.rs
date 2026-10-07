use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{
    NativeDebugCandidate, OfficialWorkBudget, VerifyLimits,
    bytecode::native_debug::NativeSemanticUpvalue, verify_native_debug,
};

fn compile(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let tokens = lex(source, language, &limits).unwrap();
    let parsed = parse(&tokens, language, &limits).unwrap();
    let resolved = resolve(&parsed, &tokens, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@env.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

#[test]
fn native_lua55_environment_is_semantic_after_guest_and_before_hidden_helper() {
    let source = b"local debug=debug\nfunction g(...) local arg={...}; local z=debug.getinfo(g,'u'); return arg[1],z.nups end\nreturn g";
    let verified = compile(source, LanguageProfile::Lua55);
    let proto = verified
        .module()
        .prototypes
        .iter()
        .find(|proto| proto.parent.is_some())
        .unwrap();
    let debug = verified.native_debug().unwrap();
    let plan = verified.official_execution().unwrap();
    let map = plan.upvalue_map(proto.id).unwrap();
    assert_eq!(map.guest_count, 1);
    assert_eq!(proto.upvalues.len(), 2);
    assert_eq!(debug.semantic_upvalue_count(proto.id), Some(2));
    assert_eq!(
        debug.semantic_upvalue(proto.id, 0),
        Some(NativeSemanticUpvalue::Closure(rivetlua_core::UpvalueId(0)))
    );
    assert_eq!(
        debug.semantic_upvalue(proto.id, 1),
        Some(NativeSemanticUpvalue::Environment)
    );
    assert_eq!(debug.semantic_upvalue(proto.id, 2), None);
    assert_eq!(
        debug.semantic_upvalue_name(proto.id, 0),
        Some(Some(b"debug".as_slice()))
    );
    assert_eq!(
        debug.semantic_upvalue_name(proto.id, 1),
        Some(Some(b"_ENV".as_slice()))
    );
    assert_eq!(debug.prototype(proto.id).unwrap().upvalue_names[2], None);

    let mut forged = NativeDebugCandidate {
        source_name: debug.source_name().to_vec(),
        prototypes: debug.prototypes().to_vec(),
        temporaries: Vec::new(),
        initializer_temporaries: Vec::new(),
        non_counted_pcs: Vec::new(),
    };
    forged
        .prototypes
        .iter_mut()
        .find(|entry| entry.prototype == proto.id)
        .unwrap()
        .upvalue_names[2] = Some(b"RawListWrite".to_vec());
    let mut work = OfficialWorkBudget::for_limits(&VerifyLimits::default()).unwrap();
    assert!(verify_native_debug(&verified, forged, &VerifyLimits::default(), &mut work).is_err());
}

#[test]
fn native_environment_semantics_require_direct_global_access() {
    for (source, expected) in [
        (b"function g() return 1 end\nreturn g".as_slice(), 0),
        (
            b"function g() return math.abs(-1) end\nreturn g".as_slice(),
            1,
        ),
    ] {
        let verified = compile(source, LanguageProfile::Lua55);
        let proto = verified
            .module()
            .prototypes
            .iter()
            .find(|proto| proto.parent.is_some())
            .unwrap();
        assert_eq!(proto.upvalues.len(), 0);
        let debug = verified.native_debug().unwrap();
        assert_eq!(debug.semantic_upvalue_count(proto.id), Some(expected));
    }
    let verified = compile(
        b"return function() return math.abs(-1) end",
        LanguageProfile::Lua54,
    );
    let proto = verified
        .module()
        .prototypes
        .iter()
        .find(|proto| proto.parent.is_some())
        .unwrap();
    assert_eq!(
        verified
            .native_debug()
            .unwrap()
            .semantic_upvalue_count(proto.id),
        Some(1)
    );
    assert_eq!(
        verified
            .native_debug()
            .unwrap()
            .semantic_upvalue(proto.id, 0),
        Some(NativeSemanticUpvalue::Closure(rivetlua_core::UpvalueId(0)))
    );
}
