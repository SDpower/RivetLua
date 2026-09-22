use rivetlua_compiler::{
    CompileLimits, DiagnosticCode, Keyword, LanguageProfile, Literal, SourcePosition, Span, Symbol,
    TokenKind, lex,
};
use rivetlua_core::Number;

#[test]
fn public_entry_reports_eof_and_source_limit() {
    let chunk = lex(b"", LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    assert_eq!(chunk.profile, LanguageProfile::Lua55);
    assert_eq!(chunk.source_len, 0);
    assert_eq!(chunk.tokens[0].kind, TokenKind::Eof);
    assert_eq!(
        chunk.tokens[0].span,
        Span {
            start_byte: 0,
            end_byte: 0
        }
    );
    assert_eq!(chunk.tokens[0].start, SourcePosition { line: 1, column: 1 });

    let limits = CompileLimits {
        max_source_bytes: 0,
        ..CompileLimits::default()
    };
    assert_eq!(
        lex(b"x", LanguageProfile::Lua55, &limits).unwrap_err().code,
        DiagnosticCode::CompileLimit
    );
}

#[test]
fn public_lexer_keeps_profile_source_length_and_numeral_boundaries() {
    let chunk = lex(
        b"9223372036854775808 0xffffffffffffffff",
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(chunk.profile, LanguageProfile::Lua54);
    assert_eq!(
        chunk.source_len,
        b"9223372036854775808 0xffffffffffffffff".len()
    );
    assert_eq!(
        chunk.tokens[0].literal,
        Some(Literal::Float(Number::Float(9_223_372_036_854_775_808.0)))
    );
    assert_eq!(
        chunk.tokens[1].literal,
        Some(Literal::Integer(Number::Integer(-1)))
    );
}

#[test]
fn public_lexer_covers_p02_short_elements_for_both_profiles() {
    let chunk = lex(
        b"local x = 0x10 -- comment\n \"\\x41\\000B\" // .. ... == <= >= ~= << >> ::",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(chunk.tokens[0].kind, TokenKind::Keyword(Keyword::Local));
    assert_eq!(chunk.tokens[1].literal, Some(Literal::Name(b"x".to_vec())));
    assert_eq!(chunk.tokens[2].kind, TokenKind::Symbol(Symbol::Assign));
    assert_eq!(
        chunk.tokens[3].literal,
        Some(Literal::Integer(Number::Integer(16)))
    );
    assert_eq!(
        chunk.tokens[4].literal,
        Some(Literal::String(vec![0x41, 0x00, 0x42]))
    );
    assert_eq!(chunk.tokens.last().unwrap().kind, TokenKind::Eof);

    let lua55 = lex(b"global", LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let lua54 = lex(b"global", LanguageProfile::Lua54, &CompileLimits::default()).unwrap();
    assert_eq!(lua55.tokens[0].kind, TokenKind::Keyword(Keyword::Global));
    assert_eq!(lua54.tokens[0].kind, TokenKind::Name);
    assert_eq!(
        lua54.tokens[0].literal,
        Some(Literal::Name(b"global".to_vec()))
    );
}

#[test]
fn public_lexer_stops_on_bad_short_elements_and_token_limit() {
    for input in [b"'unterminated".as_slice(), b"\"\\q\"", b"123abc", b"1e+"] {
        assert_eq!(
            lex(input, LanguageProfile::Lua55, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Lex
        );
    }
    let limits = CompileLimits {
        max_tokens: 2,
        ..CompileLimits::default()
    };
    assert_eq!(
        lex(b"a b", LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
}

#[test]
fn public_lexer_matches_long_delimiters_exactly() {
    let chunk = lex(
        b"[=[abc]=] --[==[comment]==]x",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        chunk.tokens[0].literal,
        Some(Literal::String(b"abc".to_vec()))
    );
    assert_eq!(chunk.tokens[1].kind, TokenKind::Name);
    assert_eq!(chunk.tokens[1].literal, Some(Literal::Name(b"x".to_vec())));

    let normalized = lex(
        b"[[\r\nfirst\rsecond\nthird\n\rfourth]]",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        normalized.tokens[0].literal,
        Some(Literal::String(b"first\nsecond\nthird\nfourth".to_vec()))
    );
}

#[test]
fn public_lexer_rejects_bad_or_unfinished_long_delimiters() {
    for input in [b"[=[abc]]".as_slice(), b"[=x", b"--[=[comment"] {
        assert_eq!(
            lex(input, LanguageProfile::Lua55, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Lex
        );
    }
    let limits = CompileLimits {
        max_token_bytes: 4,
        ..CompileLimits::default()
    };
    assert_eq!(
        lex(b"[[abc]]", LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );

    let oversized_name = vec![b'a'; CompileLimits::default().max_token_bytes + 1];
    assert_eq!(
        lex(
            &oversized_name,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::CompileLimit
    );
}
