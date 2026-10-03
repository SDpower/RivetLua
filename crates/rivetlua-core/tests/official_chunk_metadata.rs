use rivetlua_core::bytecode::official::{OfficialChunkLimits, decode_official_chunk};
use rivetlua_core::bytecode::official_translation::{
    OfficialRvluPc, OfficialWorkBudget, translate_official_chunk,
    translate_official_chunk_with_work,
};
use rivetlua_core::{
    LuaProfile, ModuleOrigin, OfficialPlanCandidate, ProtoId, VerifyLimits, decode_module,
    encode_module, verify_module, verify_official_execution_plan,
};

#[test]
fn official_import_preserves_original_chunk_and_bidirectional_pc_mapping() {
    for (profile, bytes) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-debug.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-debug.luac").as_slice(),
        ),
    ] {
        let source =
            decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
        let verified = translation.verified();
        assert_eq!(verified.origin(), ModuleOrigin::OfficialImport);
        let artifact = verified.official_artifact().unwrap();
        assert_eq!(artifact.chunk(), &source);
        assert_eq!(
            artifact.pc_mappings().len(),
            verified.module().prototypes.len()
        );

        for (index, map) in artifact.pc_mappings().iter().enumerate() {
            let prototype = &verified.module().prototypes[index];
            assert_eq!(map.prototype(), prototype.id);
            assert_eq!(map.rvlu_to_official().len(), prototype.instructions.len());
            for (official_pc, target) in map.official_to_rvlu().iter().enumerate() {
                if let Some(target) = target {
                    assert_eq!(
                        map.rvlu_to_official()[target.0 as usize],
                        OfficialRvluPc::Anchor(official_pc as u32)
                    );
                }
            }
        }
        assert_eq!(artifact.pc_mappings()[0].prototype(), ProtoId(0));

        let encoded =
            encode_module(verified.module().clone(), profile, &VerifyLimits::default()).unwrap();
        let decoded = decode_module(encoded.bytes(), profile, &VerifyLimits::default()).unwrap();
        assert_eq!(decoded.origin(), ModuleOrigin::NativeRvlu);
        assert!(decoded.official_artifact().is_none());
    }
}

#[test]
fn plan_only_candidate_cannot_claim_official_import_or_splice_source() {
    let profile = LuaProfile::Lua55;
    let source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        profile,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    let translation = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let original = translation.verified();
    let plan = original.official_execution().unwrap();
    let candidate = OfficialPlanCandidate {
        root_bindings: plan.root_bindings().to_vec(),
        upvalue_maps: original
            .module()
            .prototypes
            .iter()
            .map(|prototype| plan.upvalue_map(prototype.id).unwrap().clone())
            .collect(),
        frame_inputs: original
            .module()
            .prototypes
            .iter()
            .flat_map(|prototype| plan.frame_inputs(prototype.id).copied())
            .collect(),
        calls: translation
            .internal_calls()
            .iter()
            .map(|call| plan.call(call.prototype(), call.call_pc()).unwrap().clone())
            .collect(),
    };
    let native =
        verify_module(original.module().clone(), profile, &VerifyLimits::default()).unwrap();
    let planned =
        verify_official_execution_plan(native, candidate, &VerifyLimits::default()).unwrap();
    assert!(planned.official_execution().is_some());
    assert_eq!(planned.origin(), ModuleOrigin::NativeRvlu);
    assert!(planned.official_artifact().is_none());
}

#[test]
fn original_name_bytes_are_immutable_and_malformed_debug_is_rejected() {
    let profile = LuaProfile::Lua55;
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        profile,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    source.main.source = Some(b"@\xff.lua".to_vec());
    if let Some(Some(name)) = source.main.debug.upvalue_names.first_mut() {
        *name = b"uv\xfe".to_vec();
    }
    let translated = translate_official_chunk(&source, &VerifyLimits::default()).unwrap();
    let artifact = translated.verified().official_artifact().unwrap();
    assert_eq!(
        artifact.chunk().main.source.as_deref(),
        Some(&b"@\xff.lua"[..])
    );
    source.main.source.as_mut().unwrap().clear();
    assert_eq!(
        artifact.chunk().main.source.as_deref(),
        Some(&b"@\xff.lua"[..])
    );

    let mut malformed = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        profile,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    malformed.main.debug.line_info.pop();
    assert!(translate_official_chunk(&malformed, &VerifyLimits::default()).is_err());
}

#[test]
fn explicit_work_budget_fails_at_multiple_phases_and_sufficient_budget_is_equivalent() {
    let source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    let limits = VerifyLimits::default();
    let expected = translate_official_chunk(&source, &limits).unwrap();
    let mut sufficient = OfficialWorkBudget::for_limits(&limits).unwrap();
    let actual = translate_official_chunk_with_work(&source, &limits, &mut sufficient).unwrap();
    assert_eq!(actual, expected);
    let consumed = sufficient.consumed();
    assert!(consumed > 100);

    let mut zero = OfficialWorkBudget::new(0);
    assert!(translate_official_chunk_with_work(&source, &limits, &mut zero).is_err());
    assert_eq!(zero.consumed(), 0);
    for allocation in [100, consumed / 2, consumed - 1] {
        let mut insufficient = OfficialWorkBudget::new(allocation);
        let error =
            translate_official_chunk_with_work(&source, &limits, &mut insufficient).unwrap_err();
        assert!(error.detail.contains("work 額度耗盡"));
        assert!(insufficient.consumed() <= allocation);
        assert!(insufficient.consumed() > 0);
    }

    let mut impossible = limits;
    impossible.max_module_bytes = usize::MAX;
    impossible.max_instructions = usize::MAX;
    impossible.max_prototypes = usize::MAX;
    assert!(OfficialWorkBudget::for_limits(&impossible).is_err());
}

#[test]
fn debug_metadata_uses_artifact_quota_without_consuming_translated_module_quota() {
    let mut source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    source.main.source = Some(vec![b'x'; 8192]);
    let mut limits = VerifyLimits::default();
    limits.max_module_bytes = 4096;
    let translated = translate_official_chunk(&source, &limits).unwrap();
    assert_eq!(
        translated
            .verified()
            .official_artifact()
            .unwrap()
            .chunk()
            .main
            .source
            .as_ref()
            .unwrap()
            .len(),
        8192
    );

    limits.max_artifact_bytes = 4096;
    let error = translate_official_chunk(&source, &limits).unwrap_err();
    assert!(error.detail.contains("artifact"));
}

#[test]
fn multiple_private_helpers_are_precharged_before_plan_scans() {
    let source = decode_official_chunk(
        include_bytes!("official_chunk_fixtures/lua55-many-helpers.luac"),
        LuaProfile::Lua55,
        &OfficialChunkLimits::default(),
    )
    .unwrap();
    let limits = VerifyLimits::default();
    let mut enough = OfficialWorkBudget::for_limits(&limits).unwrap();
    let translated = translate_official_chunk_with_work(&source, &limits, &mut enough).unwrap();
    assert!(translated.internal_calls().len() >= 3);
    let mut short = OfficialWorkBudget::new(enough.consumed() - 1);
    let error = translate_official_chunk_with_work(&source, &limits, &mut short).unwrap_err();
    assert!(error.detail.contains("work 額度耗盡"));
    assert!(short.consumed() < enough.consumed());
}
