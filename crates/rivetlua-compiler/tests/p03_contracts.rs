use rivetlua_compiler::{
    BinaryOp, CompileLimits, DiagnosticCode, Expr, LanguageProfile, Stmt, lex, parse,
};
use std::{env, fs, path::PathBuf};

fn selected_profile() -> (LanguageProfile, &'static str) {
    match env::var("RIVETLUA_P03_PROFILE").as_deref() {
        Ok("lua55-i64f64") | Err(_) => (LanguageProfile::Lua55, "lua55-i64f64"),
        Ok("lua54-i64f64") => (LanguageProfile::Lua54, "lua54-i64f64"),
        Ok(_) => panic!("P03 case profile 不合法"),
    }
}

fn expectations() -> String {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("compiler crate 必須位於 workspace 內");
    fs::read_to_string(root.join("tests/p03/parser-expectations.fixture"))
        .expect("P03 expectations fixture 必須存在")
}

fn expected(key: &str) -> String {
    expectations()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .find_map(|line| line.split_once('=').filter(|(name, _)| *name == key))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_else(|| panic!("P03 expectations fixture 缺少 {key}"))
}

fn expected_bool(key: &str) -> bool {
    match expected(key).as_str() {
        "true" => true,
        "false" => false,
        value => panic!("P03 expectations fixture 的 {key} 不是 bool：{value}"),
    }
}

fn record(id: &str, input: &[u8], actual: &impl core::fmt::Debug) {
    if !expected_bool(&format!("{id}.enabled")) {
        return;
    }
    let input = String::from_utf8_lossy(input)
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    let actual = format!("{actual:?}")
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    println!("P03_CASE\t{id}\t{input}\t{actual}");
}

fn parsed(
    input: &[u8],
    profile: LanguageProfile,
    limits: &CompileLimits,
) -> rivetlua_compiler::Module {
    let chunk = lex(input, profile, limits).unwrap();
    parse(&chunk, profile, limits).unwrap()
}

fn returned(module: &rivetlua_compiler::Module) -> &[Expr] {
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("P03 contract 必須產生 return");
    };
    values
}

#[test]
fn p03_contract_cases_for_one_profile() {
    let (profile, full_profile) = selected_profile();
    assert_eq!(
        expected(&format!("profile.{full_profile}")),
        full_profile,
        "P03 fixture profile 對應不符"
    );
    let limits = CompileLimits::default();

    let input = b"return -2^2";
    let module = parsed(input, profile, &limits);
    assert!(matches!(
        &returned(&module)[0],
        Expr::Unary {
            op: rivetlua_compiler::UnaryOp::Negate,
            expression,
            ..
        } if matches!(expression.as_ref(), Expr::Binary { op: BinaryOp::Power, .. })
    ));
    record("PARSE-001", input, &module);

    let input = b"return 2^3^2";
    let module = parsed(input, profile, &limits);
    let actual_right_associative = matches!(
        &returned(&module)[0],
        Expr::Binary {
            op: BinaryOp::Power,
            right,
            ..
        } if matches!(right.as_ref(), Expr::Binary { op: BinaryOp::Power, .. })
    );
    assert_eq!(
        actual_right_associative,
        expected_bool("PARSE-002.right_associative"),
        "PARSE-002 右結合樹形不符 fixture"
    );
    record("PARSE-002", input, &module);

    let input = b"return 2^-2";
    let module = parsed(input, profile, &limits);
    assert!(matches!(
        &returned(&module)[0],
        Expr::Binary {
            op: BinaryOp::Power,
            right,
            ..
        } if matches!(right.as_ref(), Expr::Unary { .. })
    ));
    record("PARSE-003", input, &module);

    let input = b"return (f())";
    let module = parsed(input, profile, &limits);
    let actual_paren_call = matches!(
        &returned(&module)[0],
        Expr::Paren { expression, span }
            if span.start_byte == 7
                && span.end_byte == input.len()
                && matches!(expression.as_ref(), Expr::Call { span, .. } if span.start_byte == 8 && span.end_byte == 11)
    );
    assert_eq!(
        actual_paren_call,
        expected_bool("PARSE-004.paren_call"),
        "PARSE-004 Paren(Call) 樹形不符 fixture"
    );
    record("PARSE-004", input, &module);

    let input = if profile == LanguageProfile::Lua55 {
        b"local x<const> global a function f(... args) end".as_slice()
    } else {
        b"local x<const> function f(...) end"
    };
    let module = parsed(input, profile, &limits);
    assert!(matches!(
        module.root.statements.first(),
        Some(Stmt::Local { .. })
    ));
    assert!(module.root.statements.iter().any(
        |statement| matches!(statement, Stmt::Function { body, .. } if body.vararg.is_some())
    ));
    if profile == LanguageProfile::Lua55 {
        assert!(
            module
                .root
                .statements
                .iter()
                .any(|statement| matches!(statement, Stmt::Global { .. }))
        );
        assert!(matches!(
            module.root.statements.last(),
            Some(Stmt::Function { body, .. })
                if matches!(&body.vararg, Some(vararg) if matches!(&vararg.table_name, Some(name) if name.name == b"args"))
        ));
    }
    record("PARSE-005", input, &module);

    let input = b"return f(),9";
    let module = parsed(input, profile, &limits);
    let reverse = parsed(b"return 9,f()", profile, &limits);
    assert!(
        matches!(returned(&module), [Expr::Call { span, .. }, Expr::Literal { .. }] if span.start_byte == 7 && span.end_byte == 10)
    );
    assert!(
        matches!(returned(&reverse), [Expr::Literal { .. }, Expr::Call { span, .. }] if span.start_byte == 9 && span.end_byte == 12)
    );
    record("PARSE-006", input, &(module, reverse));

    let input = b"if true then";
    let chunk = lex(input, profile, &limits).unwrap();
    let error = parse(&chunk, profile, &limits).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::Parse);
    record("PARSE-ERR-001", input, &error);

    let input = b"a+b";
    let chunk = lex(input, profile, &limits).unwrap();
    let error = parse(&chunk, profile, &limits).unwrap_err();
    assert_eq!(error.code, DiagnosticCode::Parse);
    record("PARSE-ERR-002", input, &error);

    let depth_input = b"do do do end end end";
    let depth_limits = CompileLimits {
        max_parse_depth: expected("PARSE-ERR-003.max_parse_depth").parse().unwrap(),
        ..limits
    };
    let chunk = lex(depth_input, profile, &limits).unwrap();
    let depth_error = parse(&chunk, profile, &depth_limits).unwrap_err();
    assert_eq!(depth_error.code, DiagnosticCode::CompileLimit);
    let list_input = b"return 1,2";
    let list_limits = CompileLimits {
        max_list_entries: expected("PARSE-ERR-003.max_list_entries").parse().unwrap(),
        ..limits
    };
    let chunk = lex(list_input, profile, &limits).unwrap();
    let list_error = parse(&chunk, profile, &list_limits).unwrap_err();
    assert_eq!(list_error.code, DiagnosticCode::CompileLimit);
    record(
        "PARSE-ERR-003",
        b"do do do end end end | return 1,2",
        &(depth_error, list_error),
    );

    let input = b"global x";
    let chunk = lex(input, profile, &limits).unwrap();
    if profile == LanguageProfile::Lua54 {
        let error = parse(&chunk, profile, &limits).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Parse);
        record("PARSE-ERR-004", input, &error);
    } else {
        let module = parse(&chunk, profile, &limits).unwrap();
        assert!(matches!(
            module.root.statements.as_slice(),
            [Stmt::Global { .. }]
        ));
        record("PARSE-ERR-004", input, &module);
    }
}
