use rivetlua_core::bytecode::official::{
    OfficialAbsLine, OfficialChunkLimits, OfficialConstant, decode_official_chunk,
    encode_official_chunk,
};
use rivetlua_core::{
    LuaProfile, OfficialWorkBudget, VerifyLimits, preflight_official_chunk,
    translate_official_chunk_with_work,
};

fn fixture(profile: LuaProfile, strip: bool) -> &'static [u8] {
    match (profile, strip) {
        (LuaProfile::Lua55, false) => include_bytes!("official_chunk_fixtures/lua55-debug.luac"),
        (LuaProfile::Lua55, true) => include_bytes!("official_chunk_fixtures/lua55-strip.luac"),
        (LuaProfile::Lua54, false) => include_bytes!("official_chunk_fixtures/lua54-debug.luac"),
        (LuaProfile::Lua54, true) => include_bytes!("official_chunk_fixtures/lua54-strip.luac"),
    }
}

fn assert_stripped(
    original: &rivetlua_core::OfficialPrototype,
    stripped: &rivetlua_core::OfficialPrototype,
) {
    assert_eq!(original.line_defined, stripped.line_defined);
    assert_eq!(original.last_line_defined, stripped.last_line_defined);
    assert_eq!(original.num_params, stripped.num_params);
    assert_eq!(original.flags, stripped.flags);
    assert_eq!(original.max_stack_size, stripped.max_stack_size);
    assert_eq!(original.code, stripped.code);
    assert_eq!(original.constants, stripped.constants);
    assert_eq!(original.upvalues, stripped.upvalues);
    assert_eq!(original.children.len(), stripped.children.len());
    assert!(stripped.source.is_none());
    assert!(stripped.debug.line_info.is_empty());
    assert!(stripped.debug.abs_line_info.is_empty());
    assert!(stripped.debug.locals.is_empty());
    assert!(stripped.debug.upvalue_names.is_empty());
    for (original_child, stripped_child) in original.children.iter().zip(&stripped.children) {
        assert_stripped(original_child, stripped_child);
    }
}

#[test]
fn official_luac_fixtures_roundtrip_both_profiles_and_strip() {
    let limits = OfficialChunkLimits::default();
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        for strip in [false, true] {
            let input = fixture(profile, strip);
            let chunk =
                decode_official_chunk(input, profile, &limits).expect("官方 luac 產物需可讀取");
            assert_eq!(chunk.profile, profile);
            assert_eq!(usize::from(chunk.root_upvalues), chunk.main.upvalues.len());
            assert!(!chunk.main.code.is_empty());
            assert!(!chunk.main.children.is_empty());
            if strip {
                assert!(chunk.main.debug.line_info.is_empty());
                assert!(chunk.main.debug.locals.is_empty());
            } else {
                assert!(!chunk.main.debug.line_info.is_empty());
                assert!(!chunk.main.debug.locals.is_empty());
            }
            let output =
                encode_official_chunk(&chunk, strip, &limits).expect("官方 chunk 可重新輸出");
            let decoded = decode_official_chunk(&output, profile, &limits).expect("輸出需可讀取");
            assert_eq!(decoded, chunk);
        }
    }
}

#[test]
fn official_preflight_accepts_both_profiles_and_strip_without_allocation() {
    let limits = OfficialChunkLimits::default();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for strip in [false, true] {
            let input = fixture(profile, strip);
            let stats = preflight_official_chunk(input, profile, &limits, &VerifyLimits::default())
                .expect("官方 fixture 應通過無配置預掃描");
            assert!(stats.prototypes > 0);
            assert!(stats.instructions > 0);
            assert!(stats.subsequent_work > 0);
            let decoded = decode_official_chunk(input, profile, &limits).unwrap();
            let mut work = OfficialWorkBudget::new(u64::MAX);
            let translated =
                translate_official_chunk_with_work(&decoded, &VerifyLimits::default(), &mut work)
                    .unwrap();
            let instructions = translated
                .verified()
                .module()
                .prototypes
                .iter()
                .map(|prototype| prototype.instructions.len())
                .sum::<usize>();
            assert!(instructions <= stats.expanded_instructions);
            assert!(work.consumed() <= stats.subsequent_work);
        }
    }
}

#[test]
fn official_codec_removes_debug_from_unstripped_chunk_without_changing_structure() {
    let limits = OfficialChunkLimits::default();
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let original = decode_official_chunk(fixture(profile, false), profile, &limits).unwrap();
        let output = encode_official_chunk(&original, true, &limits).unwrap();
        let stripped = decode_official_chunk(&output, profile, &limits).unwrap();
        assert_eq!(original.root_upvalues, stripped.root_upvalues);
        assert_stripped(&original.main, &stripped.main);
    }
}

#[test]
fn official_codec_preserves_integer_extremes_and_float_bits() {
    let limits = OfficialChunkLimits::default();
    let integers = [i64::MIN, i64::MAX, 0, -1, 1];
    let floats = [
        0.0_f64.to_bits(),
        (-0.0_f64).to_bits(),
        f64::INFINITY.to_bits(),
        f64::NEG_INFINITY.to_bits(),
        0x7ff8_1234_5678_9abc,
    ];
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut chunk = decode_official_chunk(fixture(profile, true), profile, &limits).unwrap();
        chunk.main.constants = integers
            .iter()
            .copied()
            .map(OfficialConstant::Integer)
            .chain(
                floats
                    .iter()
                    .copied()
                    .map(|bits| OfficialConstant::Number(f64::from_bits(bits))),
            )
            .collect();
        let output = encode_official_chunk(&chunk, true, &limits).unwrap();
        let decoded = decode_official_chunk(&output, profile, &limits).unwrap();
        for (index, expected) in integers.iter().enumerate() {
            assert!(matches!(
                decoded.main.constants[index],
                OfficialConstant::Integer(actual) if actual == *expected
            ));
        }
        for (offset, expected_bits) in floats.iter().enumerate() {
            assert!(matches!(
                decoded.main.constants[integers.len() + offset],
                OfficialConstant::Number(actual) if actual.to_bits() == *expected_bits
            ));
        }
    }
}

#[test]
fn lua54_int_count_matches_official_reader_bound() {
    let limits = OfficialChunkLimits::default();
    let mut chunk =
        decode_official_chunk(fixture(LuaProfile::Lua54, true), LuaProfile::Lua54, &limits)
            .unwrap();
    chunk.main.line_defined = i32::MAX as u32;
    chunk.main.last_line_defined = i32::MAX as u32;
    assert!(encode_official_chunk(&chunk, true, &limits).is_err());
}

#[test]
fn official_chunk_rejects_header_profile_sentinel_truncation_and_trailing_bytes() {
    let limits = OfficialChunkLimits::default();
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let input = fixture(profile, false);
        let other = match profile {
            LuaProfile::Lua55 => LuaProfile::Lua54,
            LuaProfile::Lua54 => LuaProfile::Lua55,
        };
        assert!(decode_official_chunk(input, other, &limits).is_err());
        assert!(preflight_official_chunk(input, other, &limits, &VerifyLimits::default()).is_err());
        for index in [0, 4, 5, 6, 13, 14] {
            let mut corrupted = input.to_vec();
            corrupted[index] ^= 0x7f;
            assert!(decode_official_chunk(&corrupted, profile, &limits).is_err());
            assert!(
                preflight_official_chunk(&corrupted, profile, &limits, &VerifyLimits::default())
                    .is_err()
            );
        }
        for len in 0..input.len() {
            assert!(decode_official_chunk(&input[..len], profile, &limits).is_err());
            assert!(
                preflight_official_chunk(&input[..len], profile, &limits, &VerifyLimits::default())
                    .is_err()
            );
        }
        let mut trailing = input.to_vec();
        trailing.push(0);
        assert!(decode_official_chunk(&trailing, profile, &limits).is_err());
        assert!(
            preflight_official_chunk(&trailing, profile, &limits, &VerifyLimits::default())
                .is_err()
        );
    }
}

fn minimal_lua55(source: &[u8]) -> Vec<u8> {
    let mut bytes = fixture(LuaProfile::Lua55, true)[..41].to_vec();
    bytes[40] = 0;
    bytes.extend_from_slice(&[0, 0, 0, 0, 2, 1]);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&[1, 4, 2, b'x', 0, 0, 0]);
    bytes.extend_from_slice(source);
    bytes.extend_from_slice(&[0, 0, 0, 0]);
    bytes
}

#[test]
fn lua55_backward_string_reference_and_forward_reference_rejection() {
    let limits = OfficialChunkLimits::default();
    let good = minimal_lua55(&[0, 1]);
    assert!(
        preflight_official_chunk(&good, LuaProfile::Lua55, &limits, &VerifyLimits::default())
            .is_ok()
    );
    let chunk = decode_official_chunk(&good, LuaProfile::Lua55, &limits).unwrap();
    assert_eq!(chunk.main.source.as_deref(), Some(b"x".as_slice()));
    assert!(matches!(
        &chunk.main.constants[0],
        OfficialConstant::String { bytes, .. } if bytes == b"x"
    ));
    let encoded = encode_official_chunk(&chunk, false, &limits).unwrap();
    assert_eq!(
        decode_official_chunk(&encoded, LuaProfile::Lua55, &limits).unwrap(),
        chunk
    );

    let bad = minimal_lua55(&[0, 2]);
    assert!(decode_official_chunk(&bad, LuaProfile::Lua55, &limits).is_err());
    assert!(
        preflight_official_chunk(&bad, LuaProfile::Lua55, &limits, &VerifyLimits::default())
            .is_err()
    );
    let mut limited = limits;
    limited.max_total_string_bytes = 1;
    assert!(decode_official_chunk(&good, LuaProfile::Lua55, &limited).is_err());
    assert!(
        preflight_official_chunk(&good, LuaProfile::Lua55, &limited, &VerifyLimits::default())
            .is_err()
    );
}

#[test]
fn lua55_debug_absolute_line_marker_must_match_its_pc() {
    let limits = OfficialChunkLimits::default();
    let mut chunk =
        decode_official_chunk(&minimal_lua55(&[0, 1]), LuaProfile::Lua55, &limits).unwrap();
    chunk.main.debug.line_info = vec![-128];
    chunk.main.debug.abs_line_info = vec![OfficialAbsLine { pc: 0, line: 1 }];
    let valid = encode_official_chunk(&chunk, false, &limits).unwrap();
    assert!(decode_official_chunk(&valid, LuaProfile::Lua55, &limits).is_ok());

    let marker = valid
        .windows(3)
        .rposition(|bytes| bytes == [1, 0x80, 1])
        .unwrap()
        + 1;
    let mut corrupted = valid;
    corrupted[marker] = 0;
    assert!(decode_official_chunk(&corrupted, LuaProfile::Lua55, &limits).is_err());
}

#[test]
fn official_chunk_rejects_varint_overflow_and_non_main_root_is_accepted() {
    let limits = OfficialChunkLimits::default();
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut malformed = fixture(profile, false).to_vec();
        let varint_start = if profile == LuaProfile::Lua55 { 41 } else { 32 };
        let byte = if profile == LuaProfile::Lua55 {
            0xff
        } else {
            0x7f
        };
        malformed[varint_start..varint_start + 10].fill(byte);
        assert!(decode_official_chunk(&malformed, profile, &limits).is_err());

        let closure = match profile {
            LuaProfile::Lua55 => {
                include_bytes!("official_chunk_fixtures/lua55-closure.luac").as_slice()
            }
            LuaProfile::Lua54 => {
                include_bytes!("official_chunk_fixtures/lua54-closure.luac").as_slice()
            }
        };
        let chunk = decode_official_chunk(closure, profile, &limits).unwrap();
        assert_eq!(chunk.root_upvalues, 1);
        assert!(!chunk.main.upvalues[0].in_stack);
        let encoded = encode_official_chunk(&chunk, false, &limits).unwrap();
        assert_eq!(
            decode_official_chunk(&encoded, profile, &limits).unwrap(),
            chunk
        );
    }
}

#[test]
fn official_chunk_limits_and_parent_child_references_are_checked() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let input = fixture(profile, false);
        let defaults = OfficialChunkLimits::default();
        let chunk = decode_official_chunk(input, profile, &defaults).unwrap();

        let mut limits = defaults;
        limits.max_bytes = input.len() - 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_depth = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_prototypes = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_instructions = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_constants = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_upvalues = 0;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_debug_entries = 0;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_string_bytes = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_allocated_bytes = 1;
        assert!(decode_official_chunk(input, profile, &limits).is_err());
        limits = defaults;
        limits.max_bytes = input.len() - 1;
        assert!(encode_official_chunk(&chunk, false, &limits).is_err());
        limits = defaults;
        limits.max_allocated_bytes = 1;
        assert!(encode_official_chunk(&chunk, false, &limits).is_err());

        let mut bad = chunk.clone();
        bad.root_upvalues = bad.root_upvalues.saturating_add(1);
        assert!(encode_official_chunk(&bad, false, &defaults).is_err());

        let mut bad = chunk.clone();
        bad.main.children[0].upvalues[0].index = u8::MAX;
        assert!(encode_official_chunk(&bad, false, &defaults).is_err());

        let mut bad = chunk.clone();
        bad.main.debug.locals[0].end_pc = u32::MAX;
        assert!(encode_official_chunk(&bad, false, &defaults).is_err());

        let mut bad = chunk.clone();
        bad.main.debug.line_info[0] = -128;
        bad.main.debug.abs_line_info.clear();
        assert!(encode_official_chunk(&bad, false, &defaults).is_err());

        let mut bad = chunk.clone();
        bad.main.debug.line_info[0] = -128;
        bad.main.debug.abs_line_info = vec![
            OfficialAbsLine { pc: 0, line: 1 },
            OfficialAbsLine { pc: 0, line: 2 },
        ];
        assert!(encode_official_chunk(&bad, false, &defaults).is_err());

        let mut deep = chunk.clone();
        deep.main.children.clear();
        let mut node = chunk.main.children[0].clone();
        node.children.clear();
        node.upvalues.clear();
        node.debug.upvalue_names.clear();
        let mut chain = node.clone();
        for _ in 0..64 {
            let mut parent = node.clone();
            parent.children = vec![chain];
            chain = parent;
        }
        deep.main.children.push(chain);
        let mut raised = defaults;
        raised.max_depth = usize::MAX;
        assert!(encode_official_chunk(&deep, false, &raised).is_err());
    }
}

#[test]
#[ignore = "須提供本機建置的官方 lua/luac oracle 環境變數"]
fn official_oracle_accepts_reencoded_debug_strip_and_nested_closure() {
    use std::process::Command;

    let limits = OfficialChunkLimits::default();
    let output_dir = std::env::var_os("RIVETLUA_OFFICIAL_ORACLE_OUTPUT_DIR").unwrap();
    std::fs::create_dir_all(&output_dir).unwrap();
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let luac = std::env::var_os(match profile {
            LuaProfile::Lua55 => "RIVETLUA_LUA55_LUAC",
            LuaProfile::Lua54 => "RIVETLUA_LUA54_LUAC",
        })
        .unwrap();
        for (name, input, strip) in [
            ("debug", fixture(profile, false), false),
            ("strip", fixture(profile, true), true),
            ("debug-to-strip", fixture(profile, false), true),
            (
                "closure",
                match profile {
                    LuaProfile::Lua55 => {
                        include_bytes!("official_chunk_fixtures/lua55-closure.luac").as_slice()
                    }
                    LuaProfile::Lua54 => {
                        include_bytes!("official_chunk_fixtures/lua54-closure.luac").as_slice()
                    }
                },
                false,
            ),
        ] {
            let chunk = decode_official_chunk(input, profile, &limits).unwrap();
            let encoded = encode_official_chunk(&chunk, strip, &limits).unwrap();
            if strip {
                let stripped = decode_official_chunk(&encoded, profile, &limits).unwrap();
                assert_stripped(&chunk.main, &stripped.main);
            }
            let prefix = if profile == LuaProfile::Lua55 {
                "lua55"
            } else {
                "lua54"
            };
            let output = std::path::Path::new(&output_dir).join(format!("{prefix}-{name}.luac"));
            std::fs::write(&output, encoded).unwrap();
            assert!(
                Command::new(&luac)
                    .arg("-p")
                    .arg(&output)
                    .status()
                    .unwrap()
                    .success()
            );
            let restripped = std::path::Path::new(&output_dir)
                .join(format!("{prefix}-{name}-official-strip.luac"));
            assert!(
                Command::new(&luac)
                    .args(["-s", "-o"])
                    .arg(&restripped)
                    .arg(&output)
                    .status()
                    .unwrap()
                    .success()
            );
        }
    }
}
