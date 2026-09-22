use std::env;
use std::fs;
use std::path::Path;

use rivetlua_compiler::{
    CompileLimits, DiagnosticCode, Keyword, LanguageProfile, Literal, Symbol, TokenKind, lex,
};
use rivetlua_core::Number;

const CASES: [&str; 11] = [
    "LEX-001",
    "LEX-002",
    "LEX-003",
    "LEX-004",
    "LEX-005",
    "LEX-006",
    "LEX-LONG-001",
    "LEX-ERR-001",
    "LEX-ERR-002",
    "LEX-ERR-003",
    "LEX-ERR-004",
];

fn profile() -> Option<LanguageProfile> {
    match env::var("RIVETLUA_P02_PROFILE").as_deref() {
        Ok("lua55-i64f64") => Some(LanguageProfile::Lua55),
        Ok("lua54-i64f64") => Some(LanguageProfile::Lua54),
        Ok(_) => panic!("P02 profile 不合法"),
        Err(_) => None,
    }
}

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
}

fn pass<T: core::fmt::Debug>(id: &str, input: &[u8], actual: &T) {
    let input = escape_record(&String::from_utf8_lossy(input));
    let actual = escape_record(&format!("{actual:?}"));
    println!("P02_CASE\t{id}\t{input}\t{actual}");
}

fn escape_record(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

#[test]
fn p02_contract_cases_are_complete_for_one_profile() {
    let Some(profile) = profile() else {
        return;
    };
    let limits = CompileLimits::default();

    let chunk = lex(b"local x = 0x10", profile, &limits).unwrap();
    assert_eq!(chunk.tokens[0].kind, TokenKind::Keyword(Keyword::Local));
    assert_eq!(chunk.tokens[1].literal, Some(Literal::Name(b"x".to_vec())));
    assert_eq!(
        chunk.tokens[3].literal,
        Some(Literal::Integer(Number::Integer(16)))
    );
    pass("LEX-001", b"local x = 0x10", &chunk.tokens);

    let chunk = lex(b"\"\\x41\\000B\"", profile, &limits).unwrap();
    assert_eq!(
        chunk.tokens[0].literal,
        Some(Literal::String(vec![0x41, 0, 0x42]))
    );
    pass("LEX-002", b"\"\\x41\\000B\"", &chunk.tokens);

    let chunk = lex(b"[=[abc]=]", profile, &limits).unwrap();
    assert_eq!(
        chunk.tokens[0].literal,
        Some(Literal::String(b"abc".to_vec()))
    );
    pass("LEX-003", b"[=[abc]=]", &chunk.tokens);

    let chunk = lex(b"global", profile, &limits).unwrap();
    match profile {
        LanguageProfile::Lua55 => {
            assert_eq!(chunk.tokens[0].kind, TokenKind::Keyword(Keyword::Global))
        }
        LanguageProfile::Lua54 => {
            assert_eq!(chunk.tokens[0].kind, TokenKind::Name);
            assert_eq!(
                chunk.tokens[0].literal,
                Some(Literal::Name(b"global".to_vec()))
            );
        }
    }
    pass("LEX-004", b"global", &chunk.tokens);

    let chunk = lex(b"a\nb\rc\r\nd\n\re", profile, &limits).unwrap();
    assert_eq!(chunk.tokens[4].start.line, 5);
    assert_eq!(chunk.tokens[4].start.column, 1);
    pass("LEX-005", b"a\nb\rc\r\nd\n\re", &chunk.tokens);

    let chunk = lex(
        b"-- comment\n// .. ... == <= >= ~= << >> ::",
        profile,
        &limits,
    )
    .unwrap();
    assert_eq!(chunk.tokens[0].kind, TokenKind::Symbol(Symbol::FloorSlash));
    assert_eq!(chunk.tokens[9].kind, TokenKind::Symbol(Symbol::DoubleColon));
    pass(
        "LEX-006",
        b"-- comment\n// .. ... == <= >= ~= << >> ::",
        &chunk.tokens,
    );

    let chunk = lex(b"--[==[comment]==]x", profile, &limits).unwrap();
    assert_eq!(chunk.tokens[0].literal, Some(Literal::Name(b"x".to_vec())));
    pass("LEX-LONG-001", b"--[==[comment]==]x", &chunk.tokens);

    let fixture =
        fs::read_to_string(root().join("tests/p02/fixtures/wrong-long-delimiter.fixture")).unwrap();
    let input = fixture
        .lines()
        .find_map(|line| line.strip_prefix("input="))
        .unwrap();
    let expected = fixture
        .lines()
        .find_map(|line| line.strip_prefix("expected="))
        .unwrap();
    let result = lex(input.as_bytes(), profile, &limits);
    match expected {
        "E_LEX" => {
            let error = result.unwrap_err();
            assert_eq!(error.code, DiagnosticCode::Lex);
            pass("LEX-ERR-001", input.as_bytes(), &error);
        }
        "String" => {
            assert!(matches!(result, Ok(chunk) if chunk.tokens[0].kind == TokenKind::String))
        }
        _ => panic!("P02 long delimiter fixture expected 不合法"),
    }

    let error = lex(b"'unterminated", profile, &limits).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::Lex);
    pass("LEX-ERR-002", b"'unterminated", &error);

    let error_inputs = [b"\"\\q\"".as_slice(), b"1e+", b"123abc"];
    let errors: Vec<_> = error_inputs
        .iter()
        .map(|input| {
            let error = lex(input, profile, &limits).unwrap_err();
            assert_eq!(error.code, DiagnosticCode::Lex);
            error
        })
        .collect();
    pass("LEX-ERR-003", b"\"\\q\";1e+;123abc", &errors);

    let source_limit = CompileLimits {
        max_source_bytes: 3,
        ..limits
    };
    let source_error = lex(b"abcd", profile, &source_limit).unwrap_err();
    assert_eq!(source_error.code, DiagnosticCode::CompileLimit);
    let oversized_name = vec![b'a'; CompileLimits::default().max_token_bytes + 1];
    let oversized_error = lex(&oversized_name, profile, &CompileLimits::default()).unwrap_err();
    assert_eq!(oversized_error.code, DiagnosticCode::CompileLimit);
    let token_fixture =
        fs::read_to_string(root().join("tests/p02/fixtures/oversized-token.fixture")).unwrap();
    let token_input = token_fixture
        .lines()
        .find_map(|line| line.strip_prefix("input="))
        .unwrap();
    let token_limit = CompileLimits {
        max_token_bytes: token_fixture
            .lines()
            .find_map(|line| line.strip_prefix("max_token_bytes="))
            .unwrap()
            .parse()
            .unwrap(),
        ..limits
    };
    let token_expected = token_fixture
        .lines()
        .find_map(|line| line.strip_prefix("expected="))
        .unwrap();
    let token_result = lex(token_input.as_bytes(), profile, &token_limit);
    match token_expected {
        "E_COMPILE_LIMIT" => {
            let token_error = token_result.unwrap_err();
            assert_eq!(token_error.code, DiagnosticCode::CompileLimit);
            pass(
                "LEX-ERR-004",
                token_input.as_bytes(),
                &(source_error, token_error, oversized_error),
            );
        }
        "PASS" => assert!(token_result.is_ok()),
        _ => panic!("P02 oversized token fixture expected 不合法"),
    }

    assert_eq!(CASES.len(), 11);
}
