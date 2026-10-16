use std::collections::BTreeSet;

use rivetlua_core::{
    BoardConfig, Endian, ExecMemoryPolicy, LuaProfile, RVLU_NUMERIC_I64_F64, TargetDescriptor,
    TargetError,
};

#[test]
fn p21_target_and_board_schemas_roundtrip_and_reject_identity_changes() {
    let descriptor = TargetDescriptor {
        target_triple: "aarch64-apple-darwin".into(),
        isa: "aarch64".into(),
        cpu_features: BTreeSet::from(["crc".into(), "neon".into()]),
        os: "macos".into(),
        abi: "darwin".into(),
        endian: Endian::Little,
        lua_profile: LuaProfile::Lua55,
        numeric_config: RVLU_NUMERIC_I64_F64,
        flash_cap: None,
        ram_cap: 65_536,
        code_cap: 65_536,
        exec_memory_policy: ExecMemoryPolicy::MapJit,
        runtime_version: "runtime-test".into(),
        compiler_version: "compiler-test".into(),
        build_provenance: "synthetic-p21-test-only".into(),
    };
    let board = BoardConfig {
        schema_version: 1,
        board_id: "test-m4".into(),
        cpu: "cortex-m4".into(),
        thumb: true,
        fpu: Some("fpv4-sp-d16".into()),
        float_abi: "hard".into(),
        linker_map_digest: [0x5a; 32],
        allocator: "system".into(),
        panic_strategy: "abort".into(),
        entry: "Reset".into(),
        clock: "test-clock".into(),
        timer: "test-timer".into(),
    };

    assert_eq!(descriptor.validate(), Ok(()));
    assert_eq!(board.validate(), Ok(()));
    let descriptor_bytes = descriptor.to_bytes().unwrap();
    let board_bytes = board.to_bytes().unwrap();
    assert_eq!(TargetDescriptor::from_bytes(&descriptor_bytes).unwrap(), descriptor);
    assert_eq!(BoardConfig::from_bytes(&board_bytes).unwrap(), board);

    let with_features = |features: &[&str]| {
        let mut candidate = descriptor.clone();
        candidate.cpu_features = features.iter().map(|feature| (*feature).into()).collect();
        candidate
    };
    assert_eq!(
        with_features(&["crc", "neon"]).to_bytes().unwrap(),
        with_features(&["neon", "crc"]).to_bytes().unwrap()
    );

    let assert_mismatch = |candidate: &TargetDescriptor| {
        assert!(matches!(
            descriptor.ensure_matches(candidate),
            Err(TargetError::Mismatch(_))
        ));
    };
    let mut changed = descriptor.clone();
    changed.abi = "other-abi".into();
    assert_mismatch(&changed);
    changed = descriptor.clone();
    changed.lua_profile = LuaProfile::Lua54;
    assert_mismatch(&changed);
    changed = descriptor.clone();
    changed.numeric_config = 0;
    assert_eq!(
        descriptor.ensure_matches(&changed),
        Err(TargetError::InvalidField("numeric_config"))
    );
    changed = descriptor.clone();
    changed.flash_cap = Some(1);
    assert_mismatch(&changed);
    changed = descriptor.clone();
    changed.ram_cap += 1;
    assert_mismatch(&changed);
    changed = descriptor.clone();
    changed.code_cap += 1;
    assert_mismatch(&changed);
    let mut changed_board = board.clone();
    changed_board.allocator = "arena".into();
    assert!(matches!(
        board.ensure_matches(&changed_board),
        Err(TargetError::Mismatch(_))
    ));

    let mut truncated_descriptor = descriptor_bytes.clone();
    truncated_descriptor.pop();
    assert_eq!(
        TargetDescriptor::from_bytes(&truncated_descriptor),
        Err(TargetError::Malformed)
    );
    let mut truncated_board = board_bytes.clone();
    truncated_board.pop();
    assert_eq!(
        BoardConfig::from_bytes(&truncated_board),
        Err(TargetError::Malformed)
    );
    let mut unknown_descriptor_version = descriptor_bytes;
    unknown_descriptor_version[4] = 2;
    assert_eq!(
        TargetDescriptor::from_bytes(&unknown_descriptor_version),
        Err(TargetError::Malformed)
    );
    let mut unknown_board_version = board_bytes;
    unknown_board_version[4] = 2;
    assert_eq!(
        BoardConfig::from_bytes(&unknown_board_version),
        Err(TargetError::Malformed)
    );
}
