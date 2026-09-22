use rivetlua_compiler::{
    BindingKind, CompileLimits, DiagnosticCode, ExitKind, LanguageProfile, ResolvedExpr,
    ResolvedName, ResolvedStmt, lex, parse, resolve,
};

fn parsed(
    input: &[u8],
    profile: LanguageProfile,
) -> (rivetlua_compiler::Module, rivetlua_compiler::LexedChunk) {
    let limits = CompileLimits::default();
    let chunk = lex(input, profile, &limits).unwrap();
    let module = parse(&chunk, profile, &limits).unwrap();
    (module, chunk)
}

#[test]
fn public_resolver_keeps_owned_empty_schema_and_span() {
    let (module, chunk) = parsed(b"", LanguageProfile::Lua55);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert_eq!(resolved.profile, LanguageProfile::Lua55);
    assert_eq!(resolved.span, module.span);
    assert!(resolved.root.statements.is_empty());
    assert_eq!(resolved.functions.len(), 1);
    assert!(matches!(
        resolved.functions[0].bindings.as_slice(),
        [binding] if binding.kind == BindingKind::Environment && binding.name == b"_ENV"
    ));
}

#[test]
fn public_resolver_assigns_local_binding_and_name_use() {
    let input = b"local x=1; return x";
    let (module, chunk) = parsed(input, LanguageProfile::Lua55);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local { bindings, span, .. } = &resolved.root.statements[0] else {
        panic!("local 必須有 resolved statement");
    };
    assert_eq!(
        *span,
        rivetlua_compiler::Span {
            start_byte: 0,
            end_byte: 9
        }
    );
    assert_eq!(bindings.len(), 1);
    let binding = bindings[0];
    assert_eq!(
        resolved.functions[0]
            .bindings
            .iter()
            .find(|meta| meta.id == binding)
            .unwrap()
            .name,
        b"x"
    );
    let Some(ResolvedStmt::Return { values, span, .. }) = resolved
        .root
        .statements
        .iter()
        .find(|statement| matches!(statement, ResolvedStmt::Return { .. }))
    else {
        panic!("return 必須有 resolved statement");
    };
    assert_eq!(span.end_byte, input.len());
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. }] if *id == binding
    ));
}

#[test]
fn public_resolver_keeps_same_spelling_as_distinct_binding_ids() {
    let (module, chunk) = parsed(b"local x, x", LanguageProfile::Lua55);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
        panic!("local 必須有 resolved statement");
    };
    assert_eq!(bindings.len(), 2);
    assert_ne!(bindings[0], bindings[1]);
    assert_eq!(
        resolved.functions[0]
            .bindings
            .iter()
            .filter(|meta| meta.name == b"x")
            .count(),
        2
    );
}

#[test]
fn public_resolver_stops_on_profile_eof_and_source_length_mismatch() {
    let (module, chunk) = parsed(b"local x", LanguageProfile::Lua55);
    assert_eq!(
        resolve(
            &module,
            &chunk,
            LanguageProfile::Lua54,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
    let mut no_eof = chunk.clone();
    no_eof.tokens.pop();
    assert_eq!(
        resolve(
            &module,
            &no_eof,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
    let mut wrong_len = chunk;
    wrong_len.source_len += 1;
    assert_eq!(
        resolve(
            &module,
            &wrong_len,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
}

#[test]
fn public_resolver_stops_before_binding_limit_output() {
    let (module, chunk) = parsed(b"local x", LanguageProfile::Lua55);
    let limits = CompileLimits {
        max_bindings_per_function: 0,
        ..CompileLimits::default()
    };
    assert_eq!(
        resolve(&module, &chunk, LanguageProfile::Lua55, &limits)
            .unwrap_err()
            .code,
        DiagnosticCode::CompileLimit
    );
}

#[test]
fn public_resolver_exposes_full_owned_p03_mirror_schema() {
    use rivetlua_compiler::{
        Attribute, BinaryOp, BindingId, BindingKind, ClosePath, ExitKind, FieldSeparator,
        FunctionId, MethodName, ResolvedBlock, ResolvedExpr, ResolvedFunctionBody,
        ResolvedGlobalDeclaration, ResolvedIfClause, ResolvedLocalName, ResolvedStmt,
        ResolvedTableField, ResolvedVararg, ScopeId, Span, UnaryOp, UpvalueSource,
    };

    let span = Span {
        start_byte: 0,
        end_byte: 1,
    };
    let binding = BindingId {
        function: FunctionId(1),
        ordinal: 2,
    };
    let local = ResolvedLocalName {
        binding,
        name: b"x".to_vec(),
        attribute: Some(Attribute {
            name: b"const".to_vec(),
            span,
        }),
        span,
    };
    let block = ResolvedBlock {
        scope: ScopeId(3),
        statements: vec![],
        terminator: Some(span),
        span,
        normal_close_path: ClosePath {
            kind: ExitKind::Normal,
            span,
            from_scope: ScopeId(3),
            target_scope: Some(ScopeId(1)),
            bindings: vec![binding],
        },
        error_close_path: ClosePath {
            kind: ExitKind::Error,
            span,
            from_scope: ScopeId(3),
            target_scope: None,
            bindings: vec![binding],
        },
    };
    let body = ResolvedFunctionBody {
        function: FunctionId(4),
        parameters: vec![local.clone()],
        vararg: Some(ResolvedVararg {
            table_binding: Some(binding),
            span,
        }),
        body: Box::new(block.clone()),
        span,
    };
    let expression = ResolvedExpr::Paren {
        expression: Box::new(ResolvedExpr::Function {
            body: body.clone(),
            span,
        }),
        span,
    };
    let table = ResolvedExpr::TableConstructor {
        fields: vec![ResolvedTableField::Named {
            name: b"x".to_vec(),
            value: expression.clone(),
            separator: Some(FieldSeparator::Comma),
            span,
        }],
        span,
    };
    let statements = vec![
        ResolvedStmt::If {
            clauses: vec![ResolvedIfClause {
                condition: table,
                body: block.clone(),
            }],
            else_block: Some(block.clone()),
            span,
        },
        ResolvedStmt::GenericFor {
            names: vec![local.clone()],
            values: vec![expression],
            body: block.clone(),
            span,
        },
        ResolvedStmt::Global {
            declaration: ResolvedGlobalDeclaration::Names {
                names: vec![local.clone()],
                values: vec![],
                prefix_attribute: None,
                span,
            },
            span,
        },
    ];
    assert_eq!(statements.len(), 3);
    let name = ResolvedExpr::Name {
        name: b"x".to_vec(),
        resolution: rivetlua_compiler::ResolvedName::Local(binding),
        span,
    };
    let _all_expr_variants = (
        ResolvedExpr::Nil { span },
        ResolvedExpr::Bool { value: true, span },
        ResolvedExpr::Vararg {
            binding: Some(binding),
            span,
        },
        ResolvedExpr::Unary {
            op: UnaryOp::Not,
            expression: Box::new(name.clone()),
            span,
        },
        ResolvedExpr::Binary {
            op: BinaryOp::Add,
            left: Box::new(name.clone()),
            right: Box::new(name.clone()),
            span,
        },
        ResolvedExpr::Index {
            base: Box::new(name.clone()),
            index: Box::new(name.clone()),
            span,
        },
        ResolvedExpr::Field {
            base: Box::new(name.clone()),
            name: b"field".to_vec(),
            span,
        },
        ResolvedExpr::Call {
            callee: Box::new(name.clone()),
            arguments: vec![name.clone()],
            span,
        },
        ResolvedExpr::MethodCall {
            receiver: Box::new(name.clone()),
            method: b"m".to_vec(),
            arguments: vec![name.clone()],
            span,
        },
        ResolvedExpr::TableConstructor {
            fields: vec![
                ResolvedTableField::Array {
                    value: name.clone(),
                    separator: Some(FieldSeparator::Semicolon),
                    span,
                },
                ResolvedTableField::Indexed {
                    key: name.clone(),
                    value: name.clone(),
                    separator: None,
                    span,
                },
            ],
            span,
        },
    );
    let break_path = ClosePath {
        kind: ExitKind::Break,
        span,
        from_scope: ScopeId(3),
        target_scope: Some(ScopeId(2)),
        bindings: vec![binding],
    };
    let _all_stmt_variants = (
        ResolvedStmt::Empty { span },
        ResolvedStmt::Assignment {
            targets: vec![name.clone()],
            values: vec![name.clone()],
            span,
        },
        ResolvedStmt::Call {
            call: name.clone(),
            span,
        },
        ResolvedStmt::Break {
            close_path: break_path,
            span,
        },
        ResolvedStmt::Goto {
            name: b"L".to_vec(),
            name_span: span,
            close_path: ClosePath {
                kind: ExitKind::Goto,
                span,
                from_scope: ScopeId(3),
                target_scope: Some(ScopeId(1)),
                bindings: vec![binding],
            },
            span,
        },
        ResolvedStmt::Label {
            name: b"L".to_vec(),
            name_span: span,
            span,
        },
        ResolvedStmt::Do {
            body: block.clone(),
            span,
        },
        ResolvedStmt::While {
            condition: name.clone(),
            body: block.clone(),
            span,
        },
        ResolvedStmt::Repeat {
            body: block.clone(),
            condition: name.clone(),
            span,
        },
        ResolvedStmt::NumericFor {
            name: local.clone(),
            initial: name.clone(),
            limit: name.clone(),
            step: Some(name.clone()),
            body: block.clone(),
            span,
        },
        ResolvedStmt::Function {
            name: name.clone(),
            method: Some(MethodName {
                name: b"m".to_vec(),
                colon_span: span,
                span,
            }),
            body: body.clone(),
            span,
        },
        ResolvedStmt::LocalFunction {
            name: local.clone(),
            body: body.clone(),
            span,
        },
    );
    let _global_variants = (
        ResolvedGlobalDeclaration::Star {
            prefix_attribute: None,
            span,
        },
        ResolvedGlobalDeclaration::Function {
            binding,
            name: b"g".to_vec(),
            body,
            span,
        },
        BindingKind::GenericFor,
        ExitKind::Normal,
        ExitKind::Return,
        ExitKind::Error,
    );
    assert!(matches!(
        UpvalueSource::ParentLocal(binding),
        UpvalueSource::ParentLocal(id) if id == binding
    ));
}

#[test]
fn public_resolver_checks_public_module_statement_limit_before_allocation() {
    use rivetlua_compiler::{Block, Module, Span, Stmt};

    let limits = CompileLimits::default();
    let chunk = lex(b"", LanguageProfile::Lua55, &limits).unwrap();
    let module = Module {
        profile: LanguageProfile::Lua55,
        span: Span {
            start_byte: 0,
            end_byte: 0,
        },
        root: Block {
            statements: vec![
                Stmt::Empty {
                    span: Span {
                        start_byte: 0,
                        end_byte: 0,
                    },
                };
                2_000
            ],
            terminator: None,
            span: Span {
                start_byte: 0,
                end_byte: 0,
            },
        },
    };
    for limits in [
        CompileLimits {
            max_statements: 1,
            ..CompileLimits::default()
        },
        CompileLimits {
            max_ast_nodes: 1,
            ..CompileLimits::default()
        },
    ] {
        assert_eq!(
            resolve(&module, &chunk, LanguageProfile::Lua55, &limits)
                .unwrap_err()
                .code,
            DiagnosticCode::CompileLimit
        );
    }
}

#[test]
fn public_resolver_keeps_local_initializer_shadow_and_block_exit_order() {
    let input = b"local x=5; do local x=x+1 end; return x";
    let (module, chunk) = parsed(input, LanguageProfile::Lua54);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local {
        bindings: outer_bindings,
        ..
    } = &resolved.root.statements[0]
    else {
        panic!("outer local 必須存在");
    };
    let outer = outer_bindings[0];
    let ResolvedStmt::Do { body, .. } = resolved
        .root
        .statements
        .iter()
        .find(|statement| matches!(statement, ResolvedStmt::Do { .. }))
        .unwrap()
    else {
        panic!("do block 必須存在");
    };
    assert_ne!(resolved.root.scope, body.scope);
    let ResolvedStmt::Local {
        bindings: inner_bindings,
        values,
        ..
    } = &body.statements[0]
    else {
        panic!("inner local 必須存在");
    };
    assert_ne!(outer, inner_bindings[0]);
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Binary { left, .. }]
            if matches!(left.as_ref(), ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. } if *id == outer)
    ));
    let Some(ResolvedStmt::Return { values, .. }) = resolved
        .root
        .statements
        .iter()
        .find(|statement| matches!(statement, ResolvedStmt::Return { .. }))
    else {
        panic!("outer return 必須存在");
    };
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Name { resolution: ResolvedName::Local(id), .. }] if *id == outer
    ));
}

#[test]
fn public_resolver_keeps_lua54_environment_and_lua55_implicit_global() {
    for (profile, expect_global) in [
        (LanguageProfile::Lua54, false),
        (LanguageProfile::Lua55, true),
    ] {
        let (module, chunk) = parsed(b"return free", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let Some(ResolvedStmt::Return { values, .. }) = resolved.root.statements.first() else {
            panic!("free name 必須位於 return");
        };
        assert_eq!(
            matches!(
                values.as_slice(),
                [ResolvedExpr::Name {
                    resolution: ResolvedName::Global(_),
                    ..
                }]
            ),
            expect_global
        );
        assert_eq!(
            matches!(
                values.as_slice(),
                [ResolvedExpr::Name {
                    resolution: ResolvedName::EnvField { .. },
                    ..
                }]
            ),
            !expect_global
        );
    }

    let (module, chunk) = parsed(b"local _ENV; return free", LanguageProfile::Lua54);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
        panic!("local _ENV 必須存在");
    };
    let local_env = bindings[0];
    let Some(ResolvedStmt::Return { values, .. }) = resolved
        .root
        .statements
        .iter()
        .find(|statement| matches!(statement, ResolvedStmt::Return { .. }))
    else {
        panic!("return 必須存在");
    };
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Name { resolution: ResolvedName::EnvField { env, .. }, .. }] if *env == local_env
    ));
}

#[test]
fn public_resolver_gives_lua55_implicit_globals_distinct_stable_bindings() {
    let (module, chunk) = parsed(
        b"do return alpha, alpha, beta end; do return beta end; local alpha; return alpha",
        LanguageProfile::Lua55,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let env = resolved.functions[0]
        .bindings
        .iter()
        .find(|binding| binding.kind == BindingKind::Environment)
        .unwrap()
        .id;
    let Some(ResolvedStmt::Do { body, .. }) = resolved.root.statements.first() else {
        panic!("第一個 do block 必須存在");
    };
    let Some(ResolvedStmt::Return { values, .. }) = body.statements.first() else {
        panic!("第一個 return 必須存在");
    };
    let [
        ResolvedExpr::Name {
            resolution: ResolvedName::Global(alpha_first),
            ..
        },
        ResolvedExpr::Name {
            resolution: ResolvedName::Global(alpha_second),
            ..
        },
        ResolvedExpr::Name {
            resolution: ResolvedName::Global(beta),
            ..
        },
    ] = values.as_slice()
    else {
        panic!("lua55 free name 必須解析為 global binding");
    };
    assert_eq!(alpha_first, alpha_second, "同名 global 必須重用 BindingId");
    assert_ne!(alpha_first, beta, "不同 global name 必須有不同 BindingId");
    assert_ne!(alpha_first, &env, "global binding 不得重用 _ENV binding");
    assert_ne!(beta, &env, "global binding 不得重用 _ENV binding");
    assert!(resolved.functions[0].bindings.iter().any(|binding| {
        binding.id == *alpha_first
            && binding.kind == BindingKind::Global
            && binding.name == b"alpha"
    }));
    assert!(resolved.functions[0].bindings.iter().any(|binding| {
        binding.id == *beta && binding.kind == BindingKind::Global && binding.name == b"beta"
    }));
    let Some(ResolvedStmt::Return { values, .. }) = resolved.root.statements.last() else {
        panic!("local shadow 後的 return 必須存在");
    };
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Name {
            resolution: ResolvedName::Local(_),
            ..
        }]
    ));
}

#[test]
fn public_resolver_keeps_two_level_capture_as_parent_local_then_upvalue() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let input = b"local x; local function f() local function g() return x end end";
        let (module, chunk) = parsed(input, profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
            panic!("outer x 必須存在");
        };
        let outer_x = bindings[0];
        let ResolvedStmt::LocalFunction { body: f_body, .. } = &resolved.root.statements[2] else {
            panic!("f 必須存在");
        };
        let ResolvedStmt::LocalFunction { body: g_body, .. } = &f_body.body.statements[0] else {
            panic!("g 必須存在");
        };
        let ResolvedStmt::Return { values, .. } = &g_body.body.statements[0] else {
            panic!("g 的 return 必須存在");
        };
        assert!(matches!(
            values.as_slice(),
            [ResolvedExpr::Name { resolution: ResolvedName::Upvalue(id), span, .. }]
                if id.0 == 0 && span.start_byte == input.iter().rposition(|byte| *byte == b'x').unwrap()
        ));
        let f = resolved
            .functions
            .iter()
            .find(|function| function.id == f_body.function)
            .unwrap();
        let g = resolved
            .functions
            .iter()
            .find(|function| function.id == g_body.function)
            .unwrap();
        assert!(matches!(
            f.upvalues.as_slice(),
            [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == outer_x
        ));
        assert!(matches!(
            g.upvalues.as_slice(),
            [rivetlua_compiler::UpvalueSource::ParentUpvalue(id)] if id.0 == 0
        ));
    }
}

#[test]
fn public_resolver_keeps_shared_and_shadowed_capture_origins_distinct() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(
            b"local x; local function a() return x end; local function b() return x end",
            profile,
        );
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
            panic!("outer x 必須存在");
        };
        let outer_x = bindings[0];
        for statement in &resolved.root.statements[2..] {
            let ResolvedStmt::LocalFunction { body, .. } = statement else {
                continue;
            };
            let function = resolved
                .functions
                .iter()
                .find(|function| function.id == body.function)
                .unwrap();
            assert!(matches!(
                function.upvalues.as_slice(),
                [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == outer_x
            ));
        }

        let (module, chunk) = parsed(
            b"local x; local function a() local x; local function b() return x end end; local function c() return x end",
            profile,
        );
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
            panic!("outer x 必須存在");
        };
        let outer_x = bindings[0];
        let ResolvedStmt::LocalFunction { body: a_body, .. } = &resolved.root.statements[2] else {
            panic!("a 必須存在");
        };
        let ResolvedStmt::Local { bindings, .. } = &a_body.body.statements[0] else {
            panic!("a 的 shadow x 必須存在");
        };
        let inner_x = bindings[0];
        let ResolvedStmt::LocalFunction { body: b_body, .. } = &a_body.body.statements[2] else {
            panic!("b 必須存在");
        };
        let ResolvedStmt::LocalFunction { body: c_body, .. } = &resolved.root.statements[4] else {
            panic!("c 必須存在");
        };
        let b = resolved
            .functions
            .iter()
            .find(|function| function.id == b_body.function)
            .unwrap();
        let c = resolved
            .functions
            .iter()
            .find(|function| function.id == c_body.function)
            .unwrap();
        assert!(matches!(
            b.upvalues.as_slice(),
            [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == inner_x
        ));
        assert!(matches!(
            c.upvalues.as_slice(),
            [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == outer_x
        ));
        assert_ne!(outer_x, inner_x);
    }
}

#[test]
fn public_resolver_forwards_environment_and_stops_at_upvalue_limit() {
    let (module, chunk) = parsed(
        b"local _ENV; local function f() local function g() return free end end",
        LanguageProfile::Lua54,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
        panic!("outer _ENV 必須存在");
    };
    let outer_env = bindings[0];
    let ResolvedStmt::LocalFunction { body: f_body, .. } = &resolved.root.statements[2] else {
        panic!("f 必須存在");
    };
    let ResolvedStmt::LocalFunction { body: g_body, .. } = &f_body.body.statements[0] else {
        panic!("g 必須存在");
    };
    let ResolvedStmt::Return { values, .. } = &g_body.body.statements[0] else {
        panic!("g 的 return 必須存在");
    };
    assert!(matches!(
        values.as_slice(),
        [ResolvedExpr::Name { resolution: ResolvedName::EnvField { env, name }, .. }]
            if *env == outer_env && name == b"free"
    ));
    let f = resolved
        .functions
        .iter()
        .find(|function| function.id == f_body.function)
        .unwrap();
    let g = resolved
        .functions
        .iter()
        .find(|function| function.id == g_body.function)
        .unwrap();
    assert!(matches!(
        f.upvalues.as_slice(),
        [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == outer_env
    ));
    assert!(matches!(
        g.upvalues.as_slice(),
        [rivetlua_compiler::UpvalueSource::ParentUpvalue(id)] if id.0 == 0
    ));

    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(b"local a,b; local function f() return a+b end", profile);
        let limits = CompileLimits {
            max_upvalues_per_function: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            resolve(&module, &chunk, profile, &limits).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );

        let (module, chunk) = parsed(
            b"local a,z; local function f() local y=z; local function g() return a end end",
            profile,
        );
        let limits = CompileLimits {
            max_upvalues_per_function: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            resolve(&module, &chunk, profile, &limits).unwrap_err().code,
            DiagnosticCode::CompileLimit,
            "中間 function 建立 ParentUpvalue 前也須檢查 limit"
        );
    }
}

#[test]
fn public_resolver_predeclares_local_function_and_parameter_environment() {
    let (module, chunk) = parsed(b"local function f() return f end", LanguageProfile::Lua54);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::LocalFunction { name, body, .. } = &resolved.root.statements[0] else {
        panic!("local function 必須存在");
    };
    assert!(matches!(
        body.body.statements.as_slice(),
        [ResolvedStmt::Return { values, .. }]
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Upvalue(id), .. }] if id.0 == 0)
    ));
    let function = resolved
        .functions
        .iter()
        .find(|function| function.id == body.function)
        .unwrap();
    assert_eq!(function.parent, Some(name.binding.function));
    assert!(matches!(
        function.upvalues.as_slice(),
        [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == name.binding
    ));

    let (module, chunk) = parsed(
        b"local function f(_ENV) return free end",
        LanguageProfile::Lua54,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::LocalFunction { body, .. } = &resolved.root.statements[0] else {
        panic!("local function 必須存在");
    };
    let parameter_env = body.parameters[0].binding;
    assert!(matches!(
        body.body.statements.as_slice(),
        [ResolvedStmt::Return { values, .. }]
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::EnvField { env, .. }, .. }] if *env == parameter_env)
    ));

    let (module, chunk) = parsed(
        b"local _ENV; local function f() return free end",
        LanguageProfile::Lua54,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua54,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Local { bindings, .. } = &resolved.root.statements[0] else {
        panic!("outer _ENV 必須存在");
    };
    let outer_env = bindings[0];
    let ResolvedStmt::LocalFunction { body, .. } = &resolved.root.statements[2] else {
        panic!("local function 必須存在");
    };
    assert!(matches!(
        body.body.statements.as_slice(),
        [ResolvedStmt::Return { values, .. }]
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::EnvField { env, name }, .. }] if *env == outer_env && name == b"free")
    ));
    let function = resolved
        .functions
        .iter()
        .find(|function| function.id == body.function)
        .unwrap();
    assert!(matches!(
        function.upvalues.as_slice(),
        [rivetlua_compiler::UpvalueSource::ParentLocal(binding)] if *binding == outer_env
    ));
}

#[test]
fn public_resolver_keeps_explicit_global_for_p04_5() {
    let (module, chunk) = parsed(b"global x; return y", LanguageProfile::Lua55);
    assert_eq!(
        resolve(
            &module,
            &chunk,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
}

#[test]
fn public_resolver_resolves_lua55_explicit_global_scope() {
    let (module, chunk) = parsed(b"global x; return x", LanguageProfile::Lua55);
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Global {
        declaration: rivetlua_compiler::ResolvedGlobalDeclaration::Names { names, .. },
        ..
    } = &resolved.root.statements[0]
    else {
        panic!("global x 必須保留宣告 metadata");
    };
    assert_eq!(names.len(), 1);
    assert!(matches!(
        &resolved.root.statements[2],
        ResolvedStmt::Return { values, .. }
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Global(id), .. }] if *id == names[0].binding)
    ));
    assert_eq!(
        resolve(
            &parsed(b"global x; return y", LanguageProfile::Lua55).0,
            &parsed(b"global x; return y", LanguageProfile::Lua55).1,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );

    let (module, chunk) = parsed(
        b"do global x; return x end; return outside",
        LanguageProfile::Lua55,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::Do { body, .. } = &resolved.root.statements[0] else {
        panic!("explicit global nested block 必須存在");
    };
    assert!(matches!(
        body.statements.as_slice(),
        [ResolvedStmt::Global { .. }, ResolvedStmt::Empty { .. }, ResolvedStmt::Return { values, .. }]
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Global(_), .. }])
    ));
    assert!(matches!(
        &resolved.root.statements[2],
        ResolvedStmt::Return { values, .. }
            if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Global(_), .. }])
    ));

    let (module, chunk) = parsed(
        b"global *; global function f() return f end",
        LanguageProfile::Lua55,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        resolved.root.statements.as_slice(),
        [ResolvedStmt::Global { declaration: rivetlua_compiler::ResolvedGlobalDeclaration::Star { .. }, .. }, ResolvedStmt::Empty { .. }, ResolvedStmt::Global { declaration: rivetlua_compiler::ResolvedGlobalDeclaration::Function { binding, body, .. }, .. }]
            if matches!(body.body.statements.as_slice(), [ResolvedStmt::Return { values, .. }] if matches!(values.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Global(id), .. }] if *id == *binding))
    ));

    let (mut module, mut chunk) = parsed(b"global x", LanguageProfile::Lua55);
    module.profile = LanguageProfile::Lua54;
    chunk.profile = LanguageProfile::Lua54;
    assert_eq!(
        resolve(
            &module,
            &chunk,
            LanguageProfile::Lua54,
            &CompileLimits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
    let (mut module, mut chunk) = parsed(b"return function(... args) end", LanguageProfile::Lua55);
    module.profile = LanguageProfile::Lua54;
    chunk.profile = LanguageProfile::Lua54;
    assert_eq!(
        resolve(
            &module,
            &chunk,
            LanguageProfile::Lua54,
            &CompileLimits::default()
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve
    );
}

#[test]
fn public_resolver_checks_readonly_and_numeric_for_by_profile() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(b"local x <const> = 1; x = 2", profile);
        assert_eq!(
            resolve(&module, &chunk, profile, &CompileLimits::default())
                .unwrap_err()
                .code,
            DiagnosticCode::Resolve
        );
    }
    for (profile, readonly) in [
        (LanguageProfile::Lua54, false),
        (LanguageProfile::Lua55, true),
    ] {
        let (module, chunk) = parsed(b"for i=1,1 do i=2 end", profile);
        let result = resolve(&module, &chunk, profile, &CompileLimits::default());
        if readonly {
            assert_eq!(result.unwrap_err().code, DiagnosticCode::Resolve);
            continue;
        }
        let resolved = result.unwrap();
        let ResolvedStmt::NumericFor { name, body, .. } = &resolved.root.statements[0] else {
            panic!("numeric for 必須存在");
        };
        assert!(matches!(
            body.statements.as_slice(),
            [ResolvedStmt::Assignment { targets, .. }]
                if matches!(targets.as_slice(), [ResolvedExpr::Name { resolution: ResolvedName::Local(binding), .. }] if *binding == name.binding)
        ));
        let binding = resolved.functions[0]
            .bindings
            .iter()
            .find(|binding| binding.id == name.binding)
            .unwrap();
        assert!(!binding.readonly);
        assert_eq!(binding.kind, BindingKind::NumericFor);
    }
}

#[test]
fn public_resolver_keeps_close_paths_for_return_break_and_goto() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(
            b"do local a <close>; do local b <close>; return b end end",
            profile,
        );
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Do { body: outer, .. } = &resolved.root.statements[0] else {
            panic!("outer do 必須存在");
        };
        let ResolvedStmt::Local { bindings: a, .. } = &outer.statements[0] else {
            panic!("close a 必須存在");
        };
        let ResolvedStmt::Do { body: inner, .. } = &outer.statements[2] else {
            panic!("inner do 必須存在");
        };
        let ResolvedStmt::Local { bindings: b, .. } = &inner.statements[0] else {
            panic!("close b 必須存在");
        };
        let ResolvedStmt::Return { close_path, .. } = &inner.statements[2] else {
            panic!("return 必須存在");
        };
        assert_eq!(close_path.kind, ExitKind::Return);
        assert_eq!(close_path.bindings, vec![b[0], a[0]]);
        assert_eq!(close_path.span.start_byte, 40);
        assert_eq!(inner.normal_close_path.kind, ExitKind::Normal);
        assert_eq!(inner.normal_close_path.bindings, vec![b[0]]);
        assert_eq!(outer.normal_close_path.kind, ExitKind::Normal);
        assert_eq!(outer.normal_close_path.bindings, vec![a[0]]);
        assert_eq!(inner.error_close_path.kind, ExitKind::Error);
        assert_eq!(inner.error_close_path.bindings, vec![b[0], a[0]]);
        assert!(
            resolved.functions[0]
                .bindings
                .iter()
                .find(|binding| binding.id == a[0])
                .and_then(|binding| binding.close_marker)
                .is_some()
        );

        let (module, chunk) = parsed(b"do local a <close>; goto L end; ::L::", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Do { body, .. } = &resolved.root.statements[0] else {
            panic!("do 必須存在");
        };
        let ResolvedStmt::Local { bindings, .. } = &body.statements[0] else {
            panic!("close local 必須存在");
        };
        let ResolvedStmt::Goto { close_path, .. } = &body.statements[2] else {
            panic!("goto 必須存在");
        };
        assert_eq!(close_path.kind, ExitKind::Goto);
        assert_eq!(close_path.bindings, vec![bindings[0]]);
        assert_eq!(close_path.target_scope, Some(resolved.root.scope));

        let (module, chunk) = parsed(b"::L:: do goto L; ::L:: end", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Do { body, .. } = &resolved.root.statements[1] else {
            panic!("shadow label 的 do block 必須存在");
        };
        let ResolvedStmt::Goto { close_path, .. } = &body.statements[0] else {
            panic!("inner goto 必須存在");
        };
        assert_eq!(close_path.target_scope, Some(body.scope));

        let (module, chunk) = parsed(b"while true do local a <close>; break end", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::While { body, .. } = &resolved.root.statements[0] else {
            panic!("while 必須存在");
        };
        let ResolvedStmt::Local { bindings, .. } = &body.statements[0] else {
            panic!("close local 必須存在");
        };
        let ResolvedStmt::Break { close_path, .. } = &body.statements[2] else {
            panic!("break 必須存在");
        };
        assert_eq!(close_path.kind, ExitKind::Break);
        assert_eq!(close_path.bindings, vec![bindings[0]]);
    }
}

#[test]
fn public_resolver_rejects_invalid_control_flow_and_stops_at_limits() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for input in [
            b"break".as_slice(),
            b"goto L; local x <close>; ::L:: return x",
            b"do goto L end; local x=1; ::L::",
            b"goto missing",
        ] {
            let (module, chunk) = parsed(input, profile);
            assert_eq!(
                resolve(&module, &chunk, profile, &CompileLimits::default())
                    .unwrap_err()
                    .code,
                DiagnosticCode::Resolve
            );
        }
        let (module, chunk) = parsed(b"::L::", profile);
        let limits = CompileLimits {
            max_labels: 0,
            ..CompileLimits::default()
        };
        assert_eq!(
            resolve(&module, &chunk, profile, &limits).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );
        let (module, chunk) = parsed(b"goto L; ::L::", profile);
        let limits = CompileLimits {
            max_gotos: 0,
            ..CompileLimits::default()
        };
        assert_eq!(
            resolve(&module, &chunk, profile, &limits).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );
        let (module, chunk) = parsed(b"do do end end", profile);
        let limits = CompileLimits {
            max_scope_depth: 1,
            ..CompileLimits::default()
        };
        assert_eq!(
            resolve(&module, &chunk, profile, &limits).unwrap_err().code,
            DiagnosticCode::CompileLimit
        );
    }
}

#[test]
fn public_resolver_does_not_treat_loop_controls_as_outer_goto_locals() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for input in [
            b"goto L; for i=1,1 do end; ::L::".as_slice(),
            b"goto L; for k in pairs({}) do end; ::L::",
        ] {
            let (module, chunk) = parsed(input, profile);
            resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        }
    }
}

#[test]
fn public_resolver_keeps_remaining_expression_function_and_table_shapes() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(
            b"local t={1; named=2, [3]=4}; local f=function(x, ...) return {x, named=x, [x]=...} end; f(t.named, t[1])",
            profile,
        );
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::Local { values, .. } = &resolved.root.statements[0] else {
            panic!("table local 必須存在");
        };
        assert!(matches!(
            values.as_slice(),
            [ResolvedExpr::TableConstructor { fields, .. }]
                if matches!(fields.as_slice(), [
                    rivetlua_compiler::ResolvedTableField::Array { .. },
                    rivetlua_compiler::ResolvedTableField::Named { .. },
                    rivetlua_compiler::ResolvedTableField::Indexed { .. },
                ])
        ));
        let ResolvedStmt::Local { values, .. } = &resolved.root.statements[2] else {
            panic!("function expression local 必須存在");
        };
        let [ResolvedExpr::Function { body, .. }] = values.as_slice() else {
            panic!("function expression 必須保留");
        };
        assert_eq!(body.parameters.len(), 1);
        assert!(matches!(
            body.body.statements.as_slice(),
            [ResolvedStmt::Return { values, .. }]
                if matches!(values.as_slice(), [ResolvedExpr::TableConstructor { fields, .. }]
                    if matches!(fields.as_slice(), [
                        rivetlua_compiler::ResolvedTableField::Array { .. },
                        rivetlua_compiler::ResolvedTableField::Named { .. },
                        rivetlua_compiler::ResolvedTableField::Indexed { .. },
                    ]))
        ));
        let ResolvedStmt::Call { call, .. } = &resolved.root.statements[4] else {
            panic!("call statement 必須存在");
        };
        assert!(matches!(
            call,
            ResolvedExpr::Call { arguments, .. }
                if matches!(arguments.as_slice(), [ResolvedExpr::Field { .. }, ResolvedExpr::Index { .. }])
        ));

        let (module, chunk) = parsed(b"local t={}; t:m(t[1])", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        assert!(matches!(
            resolved.root.statements.last(),
            Some(ResolvedStmt::Call { call: ResolvedExpr::MethodCall { arguments, .. }, .. })
                if matches!(arguments.as_slice(), [ResolvedExpr::Index { .. }])
        ));

        let (module, chunk) = parsed(b"function a.b(x) return x end", profile);
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        assert!(matches!(
            resolved.root.statements.as_slice(),
            [ResolvedStmt::Function { name: ResolvedExpr::Field { .. }, body, .. }]
                if body.parameters.len() == 1
        ));
    }
}

#[test]
fn public_resolver_keeps_if_repeat_generic_for_and_named_vararg_metadata() {
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        let (module, chunk) = parsed(
            b"local t={}; if true then local x=1 elseif false then local y=2 else local z=3 end; repeat local r=1 until true; for k,v in pairs(t) do break end",
            profile,
        );
        let resolved = resolve(&module, &chunk, profile, &CompileLimits::default()).unwrap();
        let ResolvedStmt::If {
            clauses,
            else_block,
            ..
        } = &resolved.root.statements[2]
        else {
            panic!("if 必須存在");
        };
        assert_eq!(clauses.len(), 2);
        assert!(else_block.is_some());
        assert!(matches!(
            &resolved.root.statements[4],
            ResolvedStmt::Repeat { body, condition: ResolvedExpr::Bool { value: true, .. }, .. }
                if body.normal_close_path.kind == ExitKind::Normal
                    && body.error_close_path.kind == ExitKind::Error
        ));
        let ResolvedStmt::GenericFor { names, body, .. } = &resolved.root.statements[6] else {
            panic!("generic for 必須存在");
        };
        assert_eq!(names.len(), 2);
        assert!(names.iter().all(|name| {
            resolved.functions[0]
                .bindings
                .iter()
                .find(|binding| binding.id == name.binding)
                .is_some_and(|binding| binding.kind == BindingKind::GenericFor)
        }));
        assert!(matches!(
            body.statements.as_slice(),
            [ResolvedStmt::Break { close_path, .. }] if close_path.kind == ExitKind::Break
        ));
    }

    let (module, chunk) = parsed(
        b"local function f(... args) return args end",
        LanguageProfile::Lua55,
    );
    let resolved = resolve(
        &module,
        &chunk,
        LanguageProfile::Lua55,
        &CompileLimits::default(),
    )
    .unwrap();
    let ResolvedStmt::LocalFunction { body, .. } = &resolved.root.statements[0] else {
        panic!("named vararg function 必須存在");
    };
    let table_binding = body
        .vararg
        .as_ref()
        .and_then(|vararg| vararg.table_binding)
        .unwrap();
    assert!(
        resolved
            .functions
            .iter()
            .find(|function| function.id == body.function)
            .and_then(|function| function
                .bindings
                .iter()
                .find(|binding| binding.id == table_binding))
            .is_some_and(|binding| binding.kind == BindingKind::VarargTable && binding.readonly)
    );

    let (module, chunk) = parsed(
        b"local function f(... args) args=...; return args end",
        LanguageProfile::Lua55,
    );
    assert_eq!(
        resolve(
            &module,
            &chunk,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
        )
        .unwrap_err()
        .code,
        DiagnosticCode::Resolve,
        "named vararg table 是 readonly binding"
    );
}
