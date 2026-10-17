use rivetlua_compiler::{
    CompileLimits, DiagnosticCode, LanguageProfile, Literal, SourcePosition, Span, lex,
};

#[test]
fn strings_fixture_unicode_escape_is_lexed_for_both_profiles() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let chunk = lex(b"\"\\u{234}\"", profile, &CompileLimits::default()).unwrap();

        assert_eq!(
            chunk.tokens[0].literal,
            Some(Literal::String(vec![0xc8, 0xb4]))
        );
    }
}

#[test]
fn unicode_short_escapes_encode_lua_utf8_boundaries_for_both_profiles() {
    let cases: &[(&[u8], &[u8])] = &[
        (b"\"\\u{0}\"", b"\x00"),
        (b"\"\\u{00000000}\"", b"\x00"),
        (b"\"\\u{7F}\"", b"\x7f"),
        (b"\"\\u{80}\"", b"\xc2\x80"),
        (b"\"\\u{00000080}\"", b"\xc2\x80"),
        (b"\"\\u{7FF}\"", b"\xdf\xbf"),
        (b"\"\\u{800}\"", b"\xe0\xa0\x80"),
        (b"\"\\u{FFFF}\"", b"\xef\xbf\xbf"),
        (b"\"\\u{D800}\"", b"\xed\xa0\x80"),
        (b"\"\\u{DFFF}\"", b"\xed\xbf\xbf"),
        (b"\"\\u{10000}\"", b"\xf0\x90\x80\x80"),
        (b"\"\\u{1FFFFF}\"", b"\xf7\xbf\xbf\xbf"),
        (b"\"\\u{200000}\"", b"\xf8\x88\x80\x80\x80"),
        (b"\"\\u{3FFFFFF}\"", b"\xfb\xbf\xbf\xbf\xbf"),
        (b"\"\\u{4000000}\"", b"\xfc\x84\x80\x80\x80\x80"),
        (b"\"\\u{7FFFFFFF}\"", b"\xfd\xbf\xbf\xbf\xbf\xbf"),
    ];

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for &(source, expected) in cases {
            let chunk = lex(source, profile, &CompileLimits::default()).unwrap();

            assert_eq!(
                chunk.tokens[0].literal,
                Some(Literal::String(expected.to_vec())),
                "profile={profile:?}, source={source:?}"
            );
        }
    }
}

#[test]
fn malformed_unicode_and_unknown_short_escapes_are_rejected_for_both_profiles() {
    let invalid: &[&[u8]] = &[
        b"\"\\q\"",
        b"\"\\u11r\"",
        b"\"\\u\"",
        b"\"\\u{}\"",
        b"\"\\u{11r\"",
        b"\"\\u{11\"",
        b"\"\\u{r\"",
        b"\"\\u{80000000}\"",
        b"\"\\u{100000000}\"",
    ];

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for &source in invalid {
            assert_eq!(
                lex(source, profile, &CompileLimits::default())
                    .unwrap_err()
                    .code,
                DiagnosticCode::Lex,
                "profile={profile:?}, source={source:?}"
            );
        }
    }
}

#[test]
fn unicode_escape_overflow_reports_the_string_and_offending_digit_span() {
    let source = b"local value = \"\\u{80000000}\"";
    let start_byte = b"local value = ".len();
    let end_byte = source.iter().rposition(|&byte| byte == b'0').unwrap();

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let diagnostic = lex(source, profile, &CompileLimits::default()).unwrap_err();

        assert_eq!(diagnostic.code, DiagnosticCode::Lex);
        assert_eq!(
            diagnostic.span,
            Span {
                start_byte,
                end_byte
            }
        );
        assert_eq!(
            diagnostic.start,
            SourcePosition {
                line: 1,
                column: start_byte + 1
            }
        );
        assert_eq!(
            diagnostic.end,
            SourcePosition {
                line: 1,
                column: end_byte + 1
            }
        );
    }
}

#[test]
fn unicode_short_escapes_respect_source_and_token_limits() {
    let source = b"\"\\u{234}\"";

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let source_limited = CompileLimits {
            max_source_bytes: source.len() - 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            lex(source, profile, &source_limited).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );

        let token_limited = CompileLimits {
            max_token_bytes: source.len() - 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            lex(source, profile, &token_limited).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );
    }
}
