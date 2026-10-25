//! Lua token parser；語法 continuation 由唯一 owning frame stack 保存。
use crate::{CompileLimits, Diagnostic, DiagnosticCode, LanguageProfile, LexedChunk, SourcePosition, Span, Token};
use rivetlua_alloc::{AllocationRecovery, GlobalAllocation};
use crate::ast::Module;
use crate::resolve::meaning::{AstOnly, Unmetered};


mod incremental;
pub(crate) use incremental::{ParseProgress, ParserState, frame_size};

pub(crate) enum ParseError<E> {
    Diagnostic(Diagnostic),
    Recovery(E),
    AllocationFailed,
}

impl<E> From<Diagnostic> for ParseError<E> {
    fn from(value: Diagnostic) -> Self { Self::Diagnostic(value) }
}

pub fn parse(chunk: &LexedChunk, expected_profile: LanguageProfile, limits: &CompileLimits)
    -> Result<Module, Diagnostic> {
    parse_with_metrics(chunk, expected_profile, limits).map(|(module, _)| module)
}

pub(crate) fn parse_with_metrics(chunk: &LexedChunk, expected_profile: LanguageProfile,
    limits: &CompileLimits) -> Result<(Module, usize), Diagnostic> {
    match parse_with_metrics_with_recovery(chunk, expected_profile, limits, &mut GlobalAllocation) {
        Ok(value) => Ok(value),
        Err(ParseError::Diagnostic(error)) => Err(error),
        Err(ParseError::Recovery(never)) => match never {},
        Err(ParseError::AllocationFailed) => Err(Diagnostic {
            code: DiagnosticCode::CompileLimit,
            span: Span { start_byte: 0, end_byte: 0 },
            start: SourcePosition { line: 1, column: 1 },
            end: SourcePosition { line: 1, column: 1 },
            message: "parser 配置失敗",
        }),
    }
}

pub(crate) fn parse_with_metrics_with_recovery<R: AllocationRecovery>(
    chunk: &LexedChunk, expected_profile: LanguageProfile, limits: &CompileLimits,
    recovery: &mut R,
) -> Result<(Module, usize), ParseError<R::Error>> {
    if chunk.tokens.is_empty() {
        return Err(diagnostic(None, DiagnosticCode::Parse, "token 串流缺少 EOF").into());
    }
    if chunk.profile != expected_profile {
        return Err(diagnostic(chunk.tokens.first(), DiagnosticCode::Parse, "語言 profile 不符").into());
    }
    let mut parser = ParserState::borrowed(chunk, *limits, recovery.allocator());
    let mut context = AstOnly;
    match parser.advance(&mut context, &mut Unmetered(recovery))? {
        ParseProgress::Complete(module) => Ok((module, parser.nodes())),
        ParseProgress::NeedToken => Err(diagnostic(None, DiagnosticCode::Parse, "token 串流缺少 EOF").into()),
    }
}

fn join(a: Span, b: Span) -> Span { Span { start_byte: a.start_byte, end_byte: b.end_byte } }
fn diagnostic(t: Option<&Token>, code: DiagnosticCode, message: &'static str) -> Diagnostic {
    let (span, start, end) = t.map(|t| (t.span, t.start, t.end)).unwrap_or((
        Span { start_byte: 0, end_byte: 0 },
        SourcePosition { line: 1, column: 1 },
        SourcePosition { line: 1, column: 1 },
    ));
    Diagnostic { code, span, start, end, message }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p17_lua55_prefixed_local_attribute_uses_postfix_override() {
        let limits = CompileLimits::default();
        for (source, expected) in [
            (
                b"local <const> first, second <close>, third <const> = 1, nil, 3".as_slice(),
                &[b"const".as_slice(), b"close", b"const"] as &[&[u8]],
            ),
            (
                b"local <close> first <const>, second = 1, nil".as_slice(),
                &[b"const".as_slice(), b"close"] as &[&[u8]],
            ),
        ] {
            let chunk = crate::lex(source, LanguageProfile::Lua55, &limits).unwrap();
            let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let Stmt::Local { names, .. } = &module.root.statements[0] else {
                panic!("前置 attribute local 未保留為宣告");
            };
            assert_eq!(names.len(), expected.len());
            for (name, expected_attribute) in names.iter().zip(expected.iter()) {
                assert_eq!(
                    name.attribute.as_ref().unwrap().name.as_slice(),
                    *expected_attribute
                );
            }
        }
        let source = b"local <unknown> value <const> = 1";
        let chunk = crate::lex(source, LanguageProfile::Lua55, &limits).unwrap();
        let error = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Parse);
        assert_eq!(error.message, "未知 local attribute");
    }

    #[test]
    fn p17_lua54_rejects_prefixed_local_attribute() {
        let limits = CompileLimits::default();
        let prefixed = b"local <const> value = 1";
        let chunk = crate::lex(prefixed, LanguageProfile::Lua54, &limits).unwrap();
        let error = parse(&chunk, LanguageProfile::Lua54, &limits).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Parse);
        assert_eq!(error.message, "預期名稱");

        let postfixed = b"local value <const> = 1";
        let chunk = crate::lex(postfixed, LanguageProfile::Lua54, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua54, &limits).unwrap();
        let Stmt::Local { names, .. } = &module.root.statements[0] else {
            panic!("Lua 5.4 後置 attribute local 未保留為宣告");
        };
        assert_eq!(
            names[0].attribute.as_ref().unwrap().name.as_slice(),
            b"const"
        );
    }

    #[test]
    fn p17_lua55_fixed_return_limit_keeps_open_last() {
        let limits = CompileLimits::default();
        let mut fixed_254 = b"return 10".to_vec();
        for _ in 1..254 {
            fixed_254.extend_from_slice(b",10");
        }
        let chunk = crate::lex(&fixed_254, LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let Stmt::Return { values, .. } = &module.root.statements[0] else {
            panic!("254 fixed return expressions were not parsed");
        };
        assert_eq!(values.len(), 254);

        let mut fixed_255 = fixed_254.clone();
        fixed_255.extend_from_slice(b",10");
        let chunk = crate::lex(&fixed_255, LanguageProfile::Lua55, &limits).unwrap();
        let error = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Parse);
        assert_eq!(error.message, "too many returns");
        assert_eq!(error.span.start_byte, fixed_255.len() - 2);
        assert_eq!(error.span.end_byte, fixed_255.len());

        for last in [b"f()".as_slice(), b"obj:m()", b"..."] {
            let mut source = fixed_254.clone();
            source.extend_from_slice(b",");
            source.extend_from_slice(last);
            let chunk = crate::lex(&source, LanguageProfile::Lua55, &limits).unwrap();
            let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
            let Stmt::Return { values, .. } = &module.root.statements[0] else {
                panic!("open last return expression was not parsed: {last:?}");
            };
            assert_eq!(values.len(), 255);
        }

        let mut parenthesized = fixed_254.clone();
        parenthesized.extend_from_slice(b",(f())");
        let chunk = crate::lex(&parenthesized, LanguageProfile::Lua55, &limits).unwrap();
        let error = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap_err();
        assert_eq!(error.code, DiagnosticCode::Parse);
        assert_eq!(error.message, "too many returns");

        let chunk = crate::lex(&fixed_255, LanguageProfile::Lua54, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua54, &limits).unwrap();
        let Stmt::Return { values, .. } = &module.root.statements[0] else {
            panic!("Lua 5.4 fixed return expressions were not parsed");
        };
        assert_eq!(values.len(), 255);
    }

    #[test]
    fn invalid_expression_prefix_reports_unexpected_symbol() {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for source in [b"*a = 123".as_slice(), b")".as_slice()] {
                let limits = CompileLimits::default();
                let chunk = crate::lex(source, profile, &limits).unwrap();
                let error = parse(&chunk, profile, &limits).unwrap_err();
                assert_eq!(error.code, DiagnosticCode::Parse, "{profile:?} {source:?}");
                assert_eq!(error.message, "unexpected symbol", "{profile:?} {source:?}");
                assert_eq!(error.span.start_byte, 0, "{profile:?} {source:?}");
                assert_eq!(error.span.end_byte, 1, "{profile:?} {source:?}");
            }
        }
    }

    #[test]
    fn nested_return_at_eof_reports_missing_block_terminator() {
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            for input in [
                b"do return".as_slice(),
                b"function f() return",
                b"if true then return",
            ] {
                let chunk = crate::lex(input, profile, &CompileLimits::default()).unwrap();
                let error = parse(&chunk, profile, &CompileLimits::default()).unwrap_err();

                assert_eq!(error.code, DiagnosticCode::Parse);
                assert_eq!(error.message, "缺少 block 結束關鍵字");
                assert_eq!(error.span.end_byte, input.len());
            }
        }
    }

    #[test]
    fn return_last_contract_still_accepts_root_and_rejects_following_statement() {
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            let chunk = crate::lex(b"return", profile, &CompileLimits::default()).unwrap();
            assert!(parse(&chunk, profile, &CompileLimits::default()).is_ok());

            let chunk = crate::lex(
                b"do return; local x=2 end",
                profile,
                &CompileLimits::default(),
            )
            .unwrap();
            let error = parse(&chunk, profile, &CompileLimits::default()).unwrap_err();
            assert_eq!(error.code, DiagnosticCode::Parse);
            assert_eq!(error.message, "return 必須為 block 最後陳述式");
        }
    }

    #[test]
    fn p17_prefix_call_eligibility_respects_lua_prefix_expression() {
        for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
            let input = b"a = nil\n(function (x) a=x end)(23)";
            let chunk = crate::lex(input, profile, &CompileLimits::default()).unwrap();
            let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
            assert_eq!(module.root.statements.len(), 2, "{profile:?}");
            let Stmt::Assignment { values, .. } = &module.root.statements[0] else {
                panic!("nil assignment was not kept as its own statement ({profile:?})");
            };
            assert_eq!(values.len(), 1, "{profile:?}");
            assert!(matches!(&values[0], Expr::Nil { .. }), "{profile:?}");
            let Stmt::Call {
                call: Expr::Call {
                    callee, arguments, ..
                },
                ..
            } = &module.root.statements[1]
            else {
                panic!("parenthesized anonymous call was not a call statement ({profile:?})");
            };
            assert!(
                matches!(
                    callee.as_ref(),
                    Expr::Paren { expression, .. } if matches!(expression.as_ref(), Expr::Function { .. })
                ),
                "{profile:?}"
            );
            assert_eq!(arguments.len(), 1, "{profile:?}");

            let input = b"local result = (function(x) return x end)(23)";
            let chunk = crate::lex(input, profile, &CompileLimits::default()).unwrap();
            let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
            let Stmt::Local { values, .. } = &module.root.statements[0] else {
                panic!("parenthesized function local was not parsed ({profile:?})");
            };
            let Expr::Call {
                callee, arguments, ..
            } = &values[0]
            else {
                panic!("parenthesized function did not remain callable ({profile:?})");
            };
            assert!(
                matches!(
                    callee.as_ref(),
                    Expr::Paren { expression, .. } if matches!(expression.as_ref(), Expr::Function { .. })
                ),
                "{profile:?}"
            );
            assert_eq!(arguments.len(), 1, "{profile:?}");

            let input = b"local result = f\n(23)";
            let chunk = crate::lex(input, profile, &CompileLimits::default()).unwrap();
            let module = parse(&chunk, profile, &CompileLimits::default()).unwrap();
            let Stmt::Local { values, .. } = &module.root.statements[0] else {
                panic!("identifier call across a newline was not parsed ({profile:?})");
            };
            let Expr::Call {
                callee, arguments, ..
            } = &values[0]
            else {
                panic!("identifier across a newline did not remain callable ({profile:?})");
            };
            assert!(matches!(callee.as_ref(), Expr::Name { .. }), "{profile:?}");
            assert_eq!(arguments.len(), 1, "{profile:?}");

            let input = b"1()";
            let chunk = crate::lex(input, profile, &CompileLimits::default()).unwrap();
            let error = parse(&chunk, profile, &CompileLimits::default()).unwrap_err();
            assert_eq!(error.code, DiagnosticCode::Parse, "{profile:?}");
            assert_eq!(error.message, "只有函式呼叫可作獨立陳述式", "{profile:?}");
            assert_eq!(error.span.start_byte, 1, "{profile:?}");
        }
    }
}
