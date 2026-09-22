use rivetlua_compiler::{
    Block, CompileLimits, DiagnosticCode, Expr, FieldSeparator, FunctionBody, LanguageProfile,
    LocalName, Span, Stmt, TableField, Vararg, lex, parse,
};

#[test]
fn public_parser_keeps_empty_module_span_and_profile() {
    let chunk = lex(b"", LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    assert_eq!(module.profile, LanguageProfile::Lua55);
    assert_eq!(module.span.start_byte, 0);
    assert_eq!(module.span.end_byte, 0);
    assert!(module.root.statements.is_empty());
}

#[test]
fn public_parser_keeps_return_literal_and_name() {
    let chunk = lex(
        b"return 1, value",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, span } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    assert_eq!(span.start_byte, 0);
    assert_eq!(span.end_byte, 15);
    assert!(matches!(values[0], Expr::Literal { .. }));
    assert!(matches!(&values[1], Expr::Name { name, .. } if name == b"value"));
}

#[test]
fn public_parser_rejects_profile_mismatch() {
    let chunk = lex(
        b"return 1",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua54, &CompileLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::Parse
    );
}

#[test]
fn public_parser_keeps_power_right_associative_and_unary_lower() {
    let chunk = lex(
        b"return -2^3^2",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    let Expr::Unary { expression, .. } = &values[0] else {
        panic!("一元必須低於次方");
    };
    let Expr::Binary { right, .. } = expression.as_ref() else {
        panic!("必須為次方");
    };
    assert!(matches!(right.as_ref(), Expr::Binary { .. }));
}

#[test]
fn public_ast_schema_owns_function_body_and_vararg_table() {
    let span = Span {
        start_byte: 0,
        end_byte: 1,
    };
    let name = LocalName {
        name: b"args".to_vec(),
        attribute: None,
        span,
    };
    let body = FunctionBody {
        parameters: vec![],
        vararg: Some(Vararg {
            table_name: Some(name),
            span,
        }),
        body: Block {
            statements: vec![],
            terminator: Some(span),
            span,
        },
        span,
    };
    assert!(body.vararg.unwrap().table_name.is_some());
    let field = TableField::Array {
        value: Expr::Name {
            name: b"x".to_vec(),
            span,
        },
        separator: Some(FieldSeparator::Comma),
        span,
    };
    assert!(matches!(
        field,
        TableField::Array {
            separator: Some(FieldSeparator::Comma),
            ..
        }
    ));
}

#[test]
fn public_parser_keeps_postfix_chain_and_raw_span() {
    let input = b"return a.b[1](x):m()";
    let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    assert!(matches!(values[0], Expr::MethodCall { .. }));
    assert_eq!(values[0].span().start_byte, 7);
    assert_eq!(values[0].span().end_byte, input.len());
}

#[test]
fn public_parser_stops_at_ast_and_depth_limits() {
    let chunk = lex(
        b"return 1+2",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_ast_nodes: 2,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
    let chunk = lex(
        b"return (((1)))",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_parse_depth: 2,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
}

#[test]
fn public_parser_keeps_table_field_kinds_and_function_span() {
    let input = b"return {1, x=2, [3]=4}, function(a) end";
    let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    assert!(matches!(values[0], Expr::TableConstructor { ref fields, .. } if fields.len()==3));
    assert!(matches!(values[1], Expr::Function { .. }));
}

#[test]
fn public_parser_stops_postfix_and_list_limits_and_keeps_nonempty_function_body() {
    let chunk = lex(
        b"return a.b.c",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_ast_nodes: 2,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
    let chunk = lex(
        b"return 1,2",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_list_entries: 1,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
    let chunk = lex(
        b"return function() return 1 end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    assert!(matches!(&values[0], Expr::Function { body, .. } if !body.body.statements.is_empty()));
}

#[test]
fn public_parser_keeps_named_vararg_only_for_lua55() {
    let chunk = lex(
        b"return function(... args) end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Return { values, .. } = &module.root.statements[0] else {
        panic!("必須為 return");
    };
    assert!(
        matches!(&values[0], Expr::Function { body, .. } if body.vararg.as_ref().unwrap().table_name.is_some())
    );
    let chunk = lex(
        b"return function(... args) end",
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua54, &CompileLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::Parse
    );
}

#[test]
fn public_parser_keeps_local_attributes_and_paren_call() {
    let chunk = lex(
        b"local a<const>, b<close> = (f()), f()",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    let Stmt::Local { names, values, .. } = &module.root.statements[0] else {
        panic!("必須為 local");
    };
    assert_eq!(names.len(), 2);
    assert!(names.iter().all(|name| name.attribute.is_some()));
    assert!(
        matches!(values[0], Expr::Paren { ref expression, .. } if matches!(expression.as_ref(), Expr::Call { .. }))
    );
    assert!(matches!(values[1], Expr::Call { .. }));
}

#[test]
fn public_parser_keeps_return_order_call_span_and_rejects_unclosed_attribute() {
    for input in [b"return f(),9".as_slice(), b"return 9,f()"] {
        let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        let Stmt::Return { values, .. } = &module.root.statements[0] else {
            panic!("必須為 return");
        };
        let call_index = if input.starts_with(b"return f") { 0 } else { 1 };
        assert!(matches!(values[call_index], Expr::Call { .. }));
        assert_eq!(
            values[call_index].span().end_byte,
            if call_index == 0 { 10 } else { 12 }
        );
    }
    let chunk = lex(
        b"local x<const",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::Parse
    );
}

#[test]
fn public_parser_keeps_blocks_and_rejects_missing_terminators() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = b"do while true do break end; repeat break until true end";
        let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
        let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
        assert!(
            matches!(module.root.statements[0], Stmt::Do { ref body, .. } if !body.statements.is_empty() && body.terminator.is_some())
        );
        let chunk = lex(b"if true then", profile, &CompileLimits::default()).unwrap();
        assert_eq!(
            parse(&chunk, profile, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Parse
        );
        let chunk = lex(b"repeat break", profile, &CompileLimits::default()).unwrap();
        assert_eq!(
            parse(&chunk, profile, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Parse
        );
    }
}

#[test]
fn public_parser_keeps_numeric_and_generic_for_blocks() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let chunk = lex(
            b"for i=1,3,1 do break end for k,v in a,b do break end",
            profile,
            &CompileLimits::default(),
        )
        .unwrap();
        let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
        assert!(
            matches!(module.root.statements[0], Stmt::NumericFor { ref step, ref body, .. } if step.is_some() && body.terminator.is_some())
        );
        assert!(
            matches!(module.root.statements[1], Stmt::GenericFor { ref names, ref values, ref body, .. } if names.len()==2 && values.len()==2 && body.terminator.is_some())
        );
    }
}

#[test]
fn public_parser_keeps_function_declarations_and_rejects_missing_parts() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let chunk = lex(
            b"function f() end function a.b() end function a:b() end local function g() end",
            profile,
            &CompileLimits::default(),
        )
        .unwrap();
        let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
        assert!(
            matches!(module.root.statements[0], Stmt::Function { method: None, ref body, .. } if body.body.terminator.is_some())
        );
        assert!(matches!(
            module.root.statements[1],
            Stmt::Function { method: None, .. }
        ));
        assert!(
            matches!(module.root.statements[2], Stmt::Function { method: Some(ref method), .. } if method.name==b"b")
        );
        assert!(matches!(
            module.root.statements[3],
            Stmt::LocalFunction { .. }
        ));
        for input in [
            b"function () end".as_slice(),
            b"function f end",
            b"function f()",
        ] {
            let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
            assert_eq!(
                parse(&chunk, profile, &CompileLimits::default())
                    .unwrap_err()
                    .code,
                DiagnosticCode::Parse
            );
        }
    }
}

#[test]
fn public_parser_keeps_strict_global_and_lua54_name_assignment() {
    let chunk = lex(
        b"global <const> a<x>, b = 1,2 global <const> *",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
    assert!(
        matches!(module.root.statements[0], Stmt::Global { ref declaration, .. } if matches!(declaration, rivetlua_compiler::GlobalDeclaration::Names { names, values, prefix_attribute: Some(_), .. } if names.len()==2 && values.len()==2))
    );
    let chunk = lex(
        b"global = 1",
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        parse(&chunk, LanguageProfile::Lua54, &CompileLimits::default())
            .unwrap()
            .root
            .statements[0],
        Stmt::Assignment { .. }
    ));
    let chunk = lex(
        b"global function f() end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default())
            .unwrap()
            .root
            .statements[0],
        Stmt::Global {
            declaration: rivetlua_compiler::GlobalDeclaration::Function { .. },
            ..
        }
    ));
    let chunk = lex(
        b"global <const> function f() end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::Parse
    );
    for input in [
        b"global x".as_slice(),
        b"global *",
        b"global function f() end",
    ] {
        let chunk = lex(input, LanguageProfile::Lua54, &CompileLimits::default()).unwrap();
        assert_eq!(
            parse(&chunk, LanguageProfile::Lua54, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Parse
        );
    }
}

#[test]
fn public_parser_gives_global_declarations_complete_spans() {
    let limits = CompileLimits::default();
    for input in [b"global *".as_slice(), b"global <const> *"] {
        let chunk = lex(input, LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let Stmt::Global { declaration, span } = &module.root.statements[0] else {
            panic!("global * 必須保留 strict global declaration");
        };
        assert_eq!((span.start_byte, span.end_byte), (0, input.len()));
        let rivetlua_compiler::GlobalDeclaration::Star {
            prefix_attribute,
            span: declaration_span,
        } = declaration
        else {
            panic!("global * 必須為 Star");
        };
        assert_eq!(
            (declaration_span.start_byte, declaration_span.end_byte),
            (0, input.len())
        );
        assert_eq!(prefix_attribute.is_some(), input.contains(&b'<'));
    }

    for input in [b"global x=1".as_slice(), b"global <const> x<const> = 1"] {
        let chunk = lex(input, LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let Stmt::Global { declaration, span } = &module.root.statements[0] else {
            panic!("global name 必須保留 strict global declaration");
        };
        assert_eq!((span.start_byte, span.end_byte), (0, input.len()));
        let rivetlua_compiler::GlobalDeclaration::Names {
            names,
            values,
            prefix_attribute,
            span: declaration_span,
        } = declaration
        else {
            panic!("global name 必須為 Names");
        };
        assert_eq!(
            (declaration_span.start_byte, declaration_span.end_byte),
            (0, input.len())
        );
        assert_eq!(names.len(), 1);
        assert_eq!(values.len(), 1);
        assert_eq!(prefix_attribute.is_some(), input.contains(&b'<'));
        assert_eq!(
            names[0].attribute.is_some(),
            input.windows(6).any(|w| w == b"<const")
        );
    }

    let input = b"global function f() end";
    let chunk = lex(input, LanguageProfile::Lua55, &limits).unwrap();
    let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
    let Stmt::Global { declaration, span } = &module.root.statements[0] else {
        panic!("global function 必須保留 strict global declaration");
    };
    assert_eq!((span.start_byte, span.end_byte), (0, input.len()));
    let rivetlua_compiler::GlobalDeclaration::Function {
        name,
        body,
        span: declaration_span,
    } = declaration
    else {
        panic!("global function 必須為 Function");
    };
    assert_eq!(name, b"f");
    assert_eq!(body.span.end_byte, input.len());
    assert_eq!(
        (declaration_span.start_byte, declaration_span.end_byte),
        (0, input.len())
    );
}

#[test]
fn public_parser_keeps_assignable_lhs_and_call_statements() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let chunk = lex(
            b"a.b,t[i]=1,2 f() a:m()",
            profile,
            &CompileLimits::default(),
        )
        .unwrap();
        let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
        assert!(
            matches!(module.root.statements[0], Stmt::Assignment { ref targets, ref values, .. } if targets.len()==2 && values.len()==2)
        );
        assert!(matches!(module.root.statements[1], Stmt::Call { .. }));
        assert!(matches!(module.root.statements[2], Stmt::Call { .. }));
        for input in [
            b"a+b=1".as_slice(),
            b"f()=1",
            b"(a)=1",
            b"a+b",
            b"a",
            b"1",
            b"{}",
        ] {
            let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
            assert_eq!(
                parse(&chunk, profile, &CompileLimits::default())
                    .unwrap_err()
                    .code,
                DiagnosticCode::Parse
            );
        }
    }
}

#[test]
fn public_parser_keeps_string_and_table_call_shorthand() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        for (input, method, table_argument) in [
            (b"f\"x\"".as_slice(), false, false),
            (b"f{}".as_slice(), false, true),
            (b"obj:m\"x\"".as_slice(), true, false),
            (b"obj:m{}".as_slice(), true, true),
        ] {
            let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
            let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
            let Stmt::Call { call, span } = &module.root.statements[0] else {
                panic!("簡寫呼叫必須為 call statement");
            };
            assert_eq!(span.start_byte, 0);
            assert_eq!(span.end_byte, input.len());
            match (method, call) {
                (
                    false,
                    Expr::Call {
                        callee,
                        arguments,
                        span,
                    },
                ) => {
                    assert!(matches!(callee.as_ref(), Expr::Name { name, .. } if name == b"f"));
                    assert_eq!(arguments.len(), 1);
                    assert_eq!(span.start_byte, 0);
                    assert_eq!(span.end_byte, input.len());
                    assert_eq!(
                        matches!(arguments[0], Expr::TableConstructor { .. }),
                        table_argument
                    );
                }
                (
                    true,
                    Expr::MethodCall {
                        receiver,
                        method,
                        arguments,
                        span,
                    },
                ) => {
                    assert!(matches!(receiver.as_ref(), Expr::Name { name, .. } if name == b"obj"));
                    assert_eq!(method, b"m");
                    assert_eq!(arguments.len(), 1);
                    assert_eq!(span.start_byte, 0);
                    assert_eq!(span.end_byte, input.len());
                    assert_eq!(
                        matches!(arguments[0], Expr::TableConstructor { .. }),
                        table_argument
                    );
                }
                _ => panic!("簡寫呼叫 AST kind 錯誤"),
            }
        }
    }
}

#[test]
fn public_parser_limits_shorthand_arguments_and_assignment_targets() {
    let limits = CompileLimits {
        max_list_entries: 0,
        ..CompileLimits::default()
    };
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        for input in [b"f\"x\"".as_slice(), b"f{}", b"obj:m\"x\"", b"obj:m{}"] {
            let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
            assert_eq!(
                parse(&chunk, profile, &limits).unwrap_err().code,
                DiagnosticCode::CompileLimit
            );
        }
        let chunk = lex(b"a,b=1,2", profile, &CompileLimits::default()).unwrap();
        let target_limits = CompileLimits {
            max_list_entries: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            parse(&chunk, profile, &target_limits).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );
    }
}

#[test]
fn public_parser_keeps_label_span_and_rejects_unclosed_label() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let chunk = lex(b"::next::", profile, &CompileLimits::default()).unwrap();
        let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
        assert!(
            matches!(module.root.statements[0],Stmt::Label { ref name, name_span, .. } if name==b"next" && name_span.start_byte==2)
        );
        let chunk = lex(b"::next", profile, &CompileLimits::default()).unwrap();
        assert_eq!(
            parse(&chunk, profile, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Parse
        );
    }
}

#[test]
fn public_parser_requires_return_to_end_block() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        for input in [b"return".as_slice(), b"return;", b"do return end"] {
            let chunk = lex(input, profile, &CompileLimits::default()).unwrap();
            assert!(parse(&chunk, profile, &CompileLimits::default()).is_ok());
        }
        let chunk = lex(b"return 1; local x=2", profile, &CompileLimits::default()).unwrap();
        assert_eq!(
            parse(&chunk, profile, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Parse
        );
    }
}

#[test]
fn public_parser_rejects_empty_token_stream_without_panic() {
    let chunk = rivetlua_compiler::LexedChunk {
        profile: LanguageProfile::Lua55,
        source_len: 0,
        tokens: vec![],
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &CompileLimits::default())
            .unwrap_err()
            .code,
        DiagnosticCode::Parse
    );
}

#[test]
fn public_parser_stops_nested_blocks_and_statements_at_limits() {
    let chunk = lex(
        b"do do do break end end end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_parse_depth: 2,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
    let chunk = lex(
        b"break; break",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_statements: 1,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
}

#[test]
fn public_parser_stops_global_and_vararg_children_at_node_limit() {
    for input in [
        b"global a<x>, b = 1,2".as_slice(),
        b"return function(a,... args) end",
    ] {
        let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        let limits = CompileLimits {
            max_ast_nodes: 3,
            ..CompileLimits::default()
        };
        assert_eq!(
            parse(&chunk, LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
    }
}

#[test]
fn public_parser_stops_every_major_ast_shape_at_node_limit() {
    for input in [
        b"break".as_slice(),
        b"return {1,2}",
        b"return 1+2",
        b"return a.b()",
        b"do break end",
    ] {
        let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        let limits = CompileLimits {
            max_ast_nodes: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            parse(&chunk, LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
    }
}

#[test]
fn public_parser_stops_all_lists_before_partial_ast() {
    for input in [
        b"local a,b".as_slice(),
        b"global a,b",
        b"for a,b in x do end",
        b"if true then elseif false then end",
        b"f(1,2)",
        b"return 1,2",
        b"a,b=1,2",
        b"return {1,2}",
    ] {
        let chunk = lex(input, LanguageProfile::Lua55, &CompileLimits::default()).unwrap();
        let limits = CompileLimits {
            max_list_entries: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            parse(&chunk, LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
    }
    let chunk = lex(
        b"return function(a,b) end",
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let limits = CompileLimits {
        max_parameters: 1,
        ..CompileLimits::default()
    };
    assert_eq!(
        parse(&chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
}
