//! P03 token parser；只消費 P02 token 串流。
use crate::ast::{BinaryOp, Expr, GlobalDeclaration, Module, Stmt, UnaryOp};
use crate::{
    CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, LexedChunk, Literal,
    SourcePosition, Span, Symbol, Token, TokenKind,
};

pub fn parse(
    chunk: &LexedChunk,
    expected_profile: LanguageProfile,
    limits: &CompileLimits,
) -> Result<Module, Diagnostic> {
    if chunk.tokens.is_empty() {
        return Err(diagnostic(
            None,
            DiagnosticCode::Parse,
            "token 串流缺少 EOF",
        ));
    }
    if chunk.profile != expected_profile {
        return Err(diagnostic(
            chunk.tokens.first(),
            DiagnosticCode::Parse,
            "語言 profile 不符",
        ));
    }
    Parser {
        tokens: &chunk.tokens,
        index: 0,
        limits,
        nodes: 0,
        depth: 0,
        statements: 0,
        profile: expected_profile,
    }
    .module(expected_profile, chunk.source_len)
}
struct Parser<'a> {
    tokens: &'a [Token],
    index: usize,
    limits: &'a CompileLimits,
    nodes: usize,
    depth: usize,
    statements: usize,
    profile: LanguageProfile,
}
impl<'a> Parser<'a> {
    fn module(
        &mut self,
        profile: LanguageProfile,
        source_len: usize,
    ) -> Result<Module, Diagnostic> {
        self.reserve_node()?;
        let mut statements = Vec::new();
        while !self.eof() {
            self.statements += 1;
            if self.statements > self.limits.max_statements {
                return Err(self.limit("陳述式數超過編譯限制"));
            }
            let statement = self.statement()?;
            let returned = matches!(statement, Stmt::Return { .. });
            statements.push(statement);
            if returned {
                self.take_symbol(Symbol::Semicolon);
                if !self.eof() {
                    return Err(self.error("return 必須為 block 最後陳述式"));
                }
            }
        }
        self.reserve_node()?;
        Ok(Module {
            profile,
            span: Span {
                start_byte: 0,
                end_byte: source_len,
            },
            root: crate::ast::Block {
                statements,
                terminator: None,
                span: Span {
                    start_byte: 0,
                    end_byte: source_len,
                },
            },
        })
    }
    fn statement(&mut self) -> Result<Stmt, Diagnostic> {
        self.reserve_node()?;
        let start = self.current().span;
        if self.take_symbol(Symbol::DoubleColon) {
            let name_span = self.current().span;
            let name = self.name()?;
            self.expect(Symbol::DoubleColon)?;
            self.reserve_node()?;
            return Ok(Stmt::Label {
                name,
                name_span,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::Function) {
            let (name, method) = self.function_name()?;
            let body = self.function_body(start)?;
            return Ok(Stmt::Function {
                name,
                method,
                body,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::Do) {
            let body = self.block_until(&[Keyword::End])?;
            self.expect_keyword(Keyword::End)?;
            return Ok(Stmt::Do {
                span: join(start, self.previous().span),
                body,
            });
        }
        if self.take_keyword(Keyword::While) {
            let condition = self.expr(0)?;
            self.expect_keyword(Keyword::Do)?;
            let body = self.block_until(&[Keyword::End])?;
            self.expect_keyword(Keyword::End)?;
            return Ok(Stmt::While {
                condition,
                body,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::Repeat) {
            let body = self.block_until(&[Keyword::Until])?;
            self.expect_keyword(Keyword::Until)?;
            let condition = self.expr(0)?;
            return Ok(Stmt::Repeat {
                body,
                condition,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::If) {
            let condition = self.expr(0)?;
            self.expect_keyword(Keyword::Then)?;
            let body = self.block_until(&[Keyword::ElseIf, Keyword::Else, Keyword::End])?;
            let mut clauses = vec![(condition, body)];
            while self.take_keyword(Keyword::ElseIf) {
                let c = self.expr(0)?;
                self.expect_keyword(Keyword::Then)?;
                let b = self.block_until(&[Keyword::ElseIf, Keyword::Else, Keyword::End])?;
                if clauses.len() >= self.limits.max_list_entries {
                    return Err(self.limit("list 超過編譯限制"));
                }
                clauses.push((c, b));
            }
            let else_block = if self.take_keyword(Keyword::Else) {
                Some(self.block_until(&[Keyword::End])?)
            } else {
                None
            };
            self.expect_keyword(Keyword::End)?;
            return Ok(Stmt::If {
                clauses,
                else_block,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::For) {
            let name_start = self.current().span;
            let name = self.name()?;
            self.reserve_node()?;
            let local = crate::ast::LocalName {
                name,
                attribute: None,
                span: name_start,
            };
            if self.take_symbol(Symbol::Assign) {
                let initial = self.expr(0)?;
                self.expect(Symbol::Comma)?;
                let limit = self.expr(0)?;
                let step = if self.take_symbol(Symbol::Comma) {
                    Some(self.expr(0)?)
                } else {
                    None
                };
                self.expect_keyword(Keyword::Do)?;
                let body = self.block_until(&[Keyword::End])?;
                self.expect_keyword(Keyword::End)?;
                return Ok(Stmt::NumericFor {
                    name: local,
                    initial,
                    limit,
                    step,
                    body,
                    span: join(start, self.previous().span),
                });
            }
            let mut names = vec![local];
            while self.take_symbol(Symbol::Comma) {
                if names.len() >= self.limits.max_list_entries {
                    return Err(self.limit("list 超過編譯限制"));
                }
                let s = self.current().span;
                self.reserve_node()?;
                names.push(crate::ast::LocalName {
                    name: self.name()?,
                    attribute: None,
                    span: s,
                });
            }
            self.expect_keyword(Keyword::In)?;
            let values = self.list_expr()?;
            self.expect_keyword(Keyword::Do)?;
            let body = self.block_until(&[Keyword::End])?;
            self.expect_keyword(Keyword::End)?;
            return Ok(Stmt::GenericFor {
                names,
                values,
                body,
                span: join(start, self.previous().span),
            });
        }
        if self.take_keyword(Keyword::Return) {
            let values = if self.eof()
                || self.current().kind == TokenKind::Symbol(Symbol::Semicolon)
                || matches!(
                    self.current().kind,
                    TokenKind::Keyword(
                        Keyword::End | Keyword::Else | Keyword::ElseIf | Keyword::Until
                    )
                ) {
                Vec::new()
            } else {
                self.list_expr()?
            };
            return Ok(Stmt::Return {
                values,
                span: self.finish(start),
            });
        }
        if self.take_keyword(Keyword::Break) {
            return Ok(Stmt::Break {
                span: self.finish(start),
            });
        }
        if self.take_keyword(Keyword::Goto) {
            let name = self.name()?;
            let name_span = self.previous().span;
            return Ok(Stmt::Goto {
                name,
                name_span,
                span: self.finish(start),
            });
        }
        if self.take_symbol(Symbol::Semicolon) {
            return Ok(Stmt::Empty { span: start });
        }
        if self.take_keyword(Keyword::Local) {
            if self.take_keyword(Keyword::Function) {
                let t = self.current().clone();
                let name = self.name()?;
                self.reserve_node()?;
                let local = crate::ast::LocalName {
                    name,
                    attribute: None,
                    span: t.span,
                };
                let body = self.function_body(start)?;
                return Ok(Stmt::LocalFunction {
                    name: local,
                    body,
                    span: join(start, self.previous().span),
                });
            }
            let mut names = Vec::new();
            loop {
                if names.len() >= self.limits.max_list_entries {
                    return Err(self.limit("list 超過編譯限制"));
                }
                let name_start = self.current().span;
                let name = self.name()?;
                let attribute = if self.take_symbol(Symbol::Less) {
                    let attr_start = self.current().span;
                    let attr = self.name()?;
                    self.expect(Symbol::Greater)?;
                    self.reserve_node()?;
                    Some(crate::ast::Attribute {
                        name: attr,
                        span: join(attr_start, self.previous().span),
                    })
                } else {
                    None
                };
                self.reserve_node()?;
                names.push(crate::ast::LocalName {
                    name,
                    attribute,
                    span: join(name_start, self.previous().span),
                });
                if !self.take_symbol(Symbol::Comma) {
                    break;
                }
            }
            let values = if self.take_symbol(Symbol::Assign) {
                self.list_expr()?
            } else {
                Vec::new()
            };
            return Ok(Stmt::Local {
                names,
                values,
                span: self.finish(start),
            });
        }
        if self.take_keyword(Keyword::Global) {
            let prefix_attribute = if self.take_symbol(Symbol::Less) {
                let s = self.current().span;
                let name = self.name()?;
                self.expect(Symbol::Greater)?;
                Some(crate::ast::Attribute {
                    name,
                    span: join(s, self.previous().span),
                })
            } else {
                None
            };
            if self.take_symbol(Symbol::Star) {
                let span = self.finish(start);
                self.reserve_node()?;
                return Ok(Stmt::Global {
                    declaration: GlobalDeclaration::Star {
                        prefix_attribute,
                        span,
                    },
                    span,
                });
            }
            if self.take_keyword(Keyword::Function) {
                if prefix_attribute.is_some() {
                    return Err(self.error("global function 不接受前置 attribute"));
                }
                let n = self.name()?;
                let body = self.function_body(start)?;
                let span = self.finish(start);
                self.reserve_node()?;
                return Ok(Stmt::Global {
                    declaration: GlobalDeclaration::Function {
                        name: n,
                        body,
                        span,
                    },
                    span,
                });
            }
            let mut names = Vec::new();
            loop {
                if names.len() >= self.limits.max_list_entries {
                    return Err(self.limit("list 超過編譯限制"));
                }
                let span = self.current().span;
                let name = self.name()?;
                let attribute = if self.take_symbol(Symbol::Less) {
                    let a = self.current().span;
                    let name = self.name()?;
                    self.expect(Symbol::Greater)?;
                    Some(crate::ast::Attribute {
                        name,
                        span: join(a, self.previous().span),
                    })
                } else {
                    None
                };
                self.reserve_node()?;
                names.push(crate::ast::LocalName {
                    name,
                    attribute,
                    span,
                });
                if !self.take_symbol(Symbol::Comma) {
                    break;
                }
            }
            let values = if self.take_symbol(Symbol::Assign) {
                self.list_expr()?
            } else {
                Vec::new()
            };
            let span = self.finish(start);
            self.reserve_node()?;
            return Ok(Stmt::Global {
                declaration: GlobalDeclaration::Names {
                    names,
                    values,
                    prefix_attribute,
                    span,
                },
                span,
            });
        }
        let first = self.expr(0)?;
        let mut targets = vec![first];
        while self.take_symbol(Symbol::Comma) {
            if targets.len() >= self.limits.max_list_entries {
                return Err(self.limit("list 超過編譯限制"));
            }
            targets.push(self.expr(0)?);
        }
        if self.take_symbol(Symbol::Assign) {
            let values = self.list_expr()?;
            if targets.iter().any(|target| {
                !matches!(
                    target,
                    Expr::Name { .. } | Expr::Field { .. } | Expr::Index { .. }
                )
            }) {
                return Err(self.error("assignment 左側不可指派"));
            }
            return Ok(Stmt::Assignment {
                targets,
                values,
                span: self.finish(start),
            });
        }
        if targets.len() != 1 {
            return Err(self.error("只有函式呼叫可作獨立陳述式"));
        }
        match targets.pop().unwrap() {
            call @ (Expr::Call { .. } | Expr::MethodCall { .. }) => Ok(Stmt::Call {
                call,
                span: self.finish(start),
            }),
            _ => Err(self.error("只有函式呼叫可作獨立陳述式")),
        }
    }
    fn block_until(&mut self, terminators: &[Keyword]) -> Result<crate::ast::Block, Diagnostic> {
        self.reserve_node()?;
        self.depth += 1;
        if self.depth > self.limits.max_parse_depth {
            return Err(self.limit("解析深度超過編譯限制"));
        }
        let start = self.current().span;
        let mut statements = Vec::new();
        while !self.eof()
            && !terminators
                .iter()
                .any(|k| self.current().kind == TokenKind::Keyword(*k))
        {
            self.statements += 1;
            if self.statements > self.limits.max_statements {
                return Err(self.limit("陳述式數超過編譯限制"));
            }
            let statement = self.statement()?;
            let returned = matches!(statement, Stmt::Return { .. });
            statements.push(statement);
            if returned {
                self.take_symbol(Symbol::Semicolon);
                if !terminators
                    .iter()
                    .any(|k| self.current().kind == TokenKind::Keyword(*k))
                {
                    return Err(self.error("return 必須為 block 最後陳述式"));
                }
            }
        }
        if self.eof() {
            return Err(self.error("缺少 block 結束關鍵字"));
        }
        self.depth -= 1;
        Ok(crate::ast::Block {
            span: join(start, self.current().span),
            statements,
            terminator: Some(self.current().span),
        })
    }
    fn list_expr(&mut self) -> Result<Vec<Expr>, Diagnostic> {
        let mut out = Vec::new();
        if self.eof() {
            return Ok(out);
        };
        loop {
            if out.len() >= self.limits.max_list_entries {
                return Err(self.limit("list 超過編譯限制"));
            }
            out.push(self.expr(0)?);
            if !self.take_symbol(Symbol::Comma) {
                break;
            }
        }
        Ok(out)
    }
    fn expr(&mut self, min: u8) -> Result<Expr, Diagnostic> {
        self.depth += 1;
        if self.depth > self.limits.max_parse_depth {
            return Err(self.limit("解析深度超過編譯限制"));
        }
        let mut left = self.prefix()?;
        left = self.postfix(left)?;
        loop {
            let Some((op, prec, right)) = self.binary() else {
                break;
            };
            if prec < min {
                break;
            }
            self.advance();
            let rhs = self.expr(if right { prec } else { prec + 1 })?;
            self.reserve_node()?;
            let span = join(left.span(), rhs.span());
            left = Expr::Binary {
                op,
                left: Box::new(left),
                right: Box::new(rhs),
                span,
            };
        }
        self.depth -= 1;
        Ok(left)
    }
    fn postfix(&mut self, mut base: Expr) -> Result<Expr, Diagnostic> {
        loop {
            if self.take_symbol(Symbol::OpenParen) {
                let arguments = if self.take_symbol(Symbol::CloseParen) {
                    Vec::new()
                } else {
                    let values = self.list_expr()?;
                    self.expect(Symbol::CloseParen)?;
                    values
                };
                base = Expr::Call {
                    span: join(base.span(), self.previous().span),
                    callee: Box::new(base),
                    arguments,
                };
                self.reserve_node()?;
            } else if matches!(
                self.current().kind,
                TokenKind::String | TokenKind::Symbol(Symbol::OpenBrace)
            ) {
                if self.limits.max_list_entries == 0 {
                    return Err(self.limit("list 超過編譯限制"));
                }
                let argument = self.prefix()?;
                self.reserve_node()?;
                base = Expr::Call {
                    span: join(base.span(), argument.span()),
                    callee: Box::new(base),
                    arguments: vec![argument],
                };
            } else if self.take_symbol(Symbol::Dot) {
                let name = self.name()?;
                base = Expr::Field {
                    span: join(base.span(), self.previous().span),
                    base: Box::new(base),
                    name,
                };
                self.reserve_node()?;
            } else if self.take_symbol(Symbol::OpenBracket) {
                let index = self.expr(0)?;
                self.expect(Symbol::CloseBracket)?;
                base = Expr::Index {
                    span: join(base.span(), self.previous().span),
                    base: Box::new(base),
                    index: Box::new(index),
                };
                self.reserve_node()?;
            } else if self.take_symbol(Symbol::Colon) {
                let method = self.name()?;
                let arguments = if self.take_symbol(Symbol::OpenParen) {
                    if self.take_symbol(Symbol::CloseParen) {
                        Vec::new()
                    } else {
                        let values = self.list_expr()?;
                        self.expect(Symbol::CloseParen)?;
                        values
                    }
                } else if matches!(
                    self.current().kind,
                    TokenKind::String | TokenKind::Symbol(Symbol::OpenBrace)
                ) {
                    if self.limits.max_list_entries == 0 {
                        return Err(self.limit("list 超過編譯限制"));
                    }
                    vec![self.prefix()?]
                } else {
                    return Err(self.error("方法呼叫缺少引數"));
                };
                base = Expr::MethodCall {
                    span: join(base.span(), self.previous().span),
                    receiver: Box::new(base),
                    method,
                    arguments,
                };
                self.reserve_node()?;
            } else {
                break;
            }
        }
        Ok(base)
    }
    fn prefix(&mut self) -> Result<Expr, Diagnostic> {
        self.reserve_node()?;
        let t = self.current().clone();
        match t.kind {
            TokenKind::Name => {
                self.advance();
                match t.literal {
                    Some(Literal::Name(name)) => Ok(Expr::Name { name, span: t.span }),
                    _ => Err(self.error("名稱 token 不完整")),
                }
            }
            TokenKind::Integer | TokenKind::Float | TokenKind::String => {
                self.advance();
                Ok(Expr::Literal {
                    literal: t.literal.unwrap(),
                    span: t.span,
                })
            }
            TokenKind::Keyword(Keyword::Nil) => {
                self.advance();
                Ok(Expr::Nil { span: t.span })
            }
            TokenKind::Keyword(Keyword::True) => {
                self.advance();
                Ok(Expr::Bool {
                    value: true,
                    span: t.span,
                })
            }
            TokenKind::Keyword(Keyword::False) => {
                self.advance();
                Ok(Expr::Bool {
                    value: false,
                    span: t.span,
                })
            }
            TokenKind::Symbol(Symbol::Vararg) => {
                self.advance();
                Ok(Expr::Vararg { span: t.span })
            }
            TokenKind::Symbol(Symbol::Minus) => {
                self.advance();
                let e = self.expr(12)?;
                Ok(Expr::Unary {
                    op: UnaryOp::Negate,
                    span: join(t.span, e.span()),
                    expression: Box::new(e),
                })
            }
            TokenKind::Keyword(Keyword::Not) => {
                self.advance();
                let e = self.expr(12)?;
                Ok(Expr::Unary {
                    op: UnaryOp::Not,
                    span: join(t.span, e.span()),
                    expression: Box::new(e),
                })
            }
            TokenKind::Symbol(Symbol::Hash) => {
                self.advance();
                let e = self.expr(12)?;
                Ok(Expr::Unary {
                    op: UnaryOp::Length,
                    span: join(t.span, e.span()),
                    expression: Box::new(e),
                })
            }
            TokenKind::Symbol(Symbol::Tilde) => {
                self.advance();
                let e = self.expr(12)?;
                Ok(Expr::Unary {
                    op: UnaryOp::BitNot,
                    span: join(t.span, e.span()),
                    expression: Box::new(e),
                })
            }
            TokenKind::Symbol(Symbol::OpenParen) => {
                self.advance();
                let e = self.expr(0)?;
                self.expect(Symbol::CloseParen)?;
                Ok(Expr::Paren {
                    span: join(t.span, self.previous().span),
                    expression: Box::new(e),
                })
            }
            TokenKind::Symbol(Symbol::OpenBrace) => self.table(),
            TokenKind::Keyword(Keyword::Function) => self.function_expr(),
            _ => Err(self.error("預期運算式")),
        }
    }
    fn table(&mut self) -> Result<Expr, Diagnostic> {
        let start = self.current().span;
        self.advance();
        let mut fields = Vec::new();
        while !self.take_symbol(Symbol::CloseBrace) {
            if self.eof() {
                return Err(self.error("缺少 table 結束符號"));
            }
            if fields.len() >= self.limits.max_list_entries {
                return Err(self.limit("list 超過編譯限制"));
            }
            let field_start = self.current().span;
            let mut field = if self.take_symbol(Symbol::OpenBracket) {
                let key = self.expr(0)?;
                self.expect(Symbol::CloseBracket)?;
                self.expect(Symbol::Assign)?;
                let value = self.expr(0)?;
                self.reserve_node()?;
                crate::ast::TableField::Indexed {
                    span: join(field_start, value.span()),
                    key,
                    value,
                    separator: None,
                }
            } else if self.current().kind == TokenKind::Name
                && self.tokens.get(self.index + 1).map(|t| t.kind)
                    == Some(TokenKind::Symbol(Symbol::Assign))
            {
                let name = self.name()?;
                self.expect(Symbol::Assign)?;
                let value = self.expr(0)?;
                self.reserve_node()?;
                crate::ast::TableField::Named {
                    span: join(field_start, value.span()),
                    name,
                    value,
                    separator: None,
                }
            } else {
                let value = self.expr(0)?;
                self.reserve_node()?;
                crate::ast::TableField::Array {
                    span: join(field_start, value.span()),
                    value,
                    separator: None,
                }
            };
            if self.take_symbol(Symbol::Comma) {
                field.set_separator(crate::ast::FieldSeparator::Comma);
            } else if self.take_symbol(Symbol::Semicolon) {
                field.set_separator(crate::ast::FieldSeparator::Semicolon);
            } else {
                self.expect(Symbol::CloseBrace)?;
                fields.push(field);
                break;
            }
            fields.push(field);
        }
        self.reserve_node()?;
        Ok(Expr::TableConstructor {
            span: join(start, self.previous().span),
            fields,
        })
    }
    fn function_expr(&mut self) -> Result<Expr, Diagnostic> {
        let start = self.current().span;
        self.advance();
        let body = self.function_body(start)?;
        let span = join(start, self.previous().span);
        self.reserve_node()?;
        Ok(Expr::Function { span, body })
    }
    fn function_name(&mut self) -> Result<(Expr, Option<crate::ast::MethodName>), Diagnostic> {
        let token = self.current().clone();
        let mut value = Expr::Name {
            name: self.name()?,
            span: token.span,
        };
        let mut method = None;
        loop {
            if self.take_symbol(Symbol::Dot) {
                let token = self.current().clone();
                let name = self.name()?;
                value = Expr::Field {
                    span: join(value.span(), token.span),
                    base: Box::new(value),
                    name,
                };
            } else if self.take_symbol(Symbol::Colon) {
                let colon_span = self.previous().span;
                let token = self.current().clone();
                let name = self.name()?;
                method = Some(crate::ast::MethodName {
                    name: name.clone(),
                    colon_span,
                    span: token.span,
                });
                value = Expr::Field {
                    span: join(value.span(), token.span),
                    base: Box::new(value),
                    name,
                };
                break;
            } else {
                break;
            }
        }
        Ok((value, method))
    }
    fn function_body(&mut self, start: Span) -> Result<crate::ast::FunctionBody, Diagnostic> {
        self.expect(Symbol::OpenParen)?;
        let mut params = Vec::new();
        let mut vararg = None;
        while !self.take_symbol(Symbol::CloseParen) {
            if params.len() >= self.limits.max_parameters {
                return Err(self.limit("參數超過編譯限制"));
            }
            if self.take_symbol(Symbol::Vararg) {
                let span = self.previous().span;
                let table_name = if self.current().kind == TokenKind::Name {
                    if self.profile != LanguageProfile::Lua55 {
                        return Err(self.error("具名 vararg table 僅支援 lua55"));
                    }
                    let t = self.current().clone();
                    Some(crate::ast::LocalName {
                        name: self.name()?,
                        attribute: None,
                        span: t.span,
                    })
                } else {
                    None
                };
                self.reserve_node()?;
                vararg = Some(crate::ast::Vararg { table_name, span });
                self.expect(Symbol::CloseParen)?;
                break;
            }
            let t = self.current().clone();
            let name = self.name()?;
            self.reserve_node()?;
            params.push(crate::ast::LocalName {
                name,
                attribute: None,
                span: t.span,
            });
            if !self.take_symbol(Symbol::Comma) {
                self.expect(Symbol::CloseParen)?;
                break;
            }
        }
        let body = self.block_until(&[Keyword::End])?;
        self.expect_keyword(Keyword::End)?;
        let span = join(start, self.previous().span);
        Ok(crate::ast::FunctionBody {
            parameters: params,
            vararg,
            body,
            span,
        })
    }
    fn binary(&self) -> Option<(BinaryOp, u8, bool)> {
        let TokenKind::Symbol(s) = self.current().kind else {
            return match self.current().kind {
                TokenKind::Keyword(Keyword::Or) => Some((BinaryOp::Or, 1, false)),
                TokenKind::Keyword(Keyword::And) => Some((BinaryOp::And, 2, false)),
                _ => None,
            };
        };
        Some(match s {
            Symbol::Caret => (BinaryOp::Power, 13, true),
            Symbol::Concat => (BinaryOp::Concat, 8, true),
            Symbol::Plus => (BinaryOp::Add, 9, false),
            Symbol::Minus => (BinaryOp::Subtract, 9, false),
            Symbol::Star => (BinaryOp::Multiply, 10, false),
            Symbol::Slash => (BinaryOp::Divide, 10, false),
            Symbol::FloorSlash => (BinaryOp::FloorDivide, 10, false),
            Symbol::Percent => (BinaryOp::Modulo, 10, false),
            Symbol::EqualEqual => (BinaryOp::Equal, 3, false),
            Symbol::NotEqual => (BinaryOp::NotEqual, 3, false),
            Symbol::Less => (BinaryOp::Less, 3, false),
            Symbol::LessEqual => (BinaryOp::LessEqual, 3, false),
            Symbol::Greater => (BinaryOp::Greater, 3, false),
            Symbol::GreaterEqual => (BinaryOp::GreaterEqual, 3, false),
            Symbol::Pipe => (BinaryOp::Pipe, 4, false),
            Symbol::Tilde => (BinaryOp::BitXor, 5, false),
            Symbol::Ampersand => (BinaryOp::Ampersand, 6, false),
            Symbol::ShiftLeft => (BinaryOp::ShiftLeft, 7, false),
            Symbol::ShiftRight => (BinaryOp::ShiftRight, 7, false),
            _ => return None,
        })
    }
    fn name(&mut self) -> Result<Vec<u8>, Diagnostic> {
        let t = self.current().clone();
        if t.kind != TokenKind::Name {
            return Err(self.error("預期名稱"));
        }
        self.advance();
        match t.literal {
            Some(Literal::Name(n)) => Ok(n),
            _ => Err(self.error("名稱 token 不完整")),
        }
    }
    fn reserve_node(&mut self) -> Result<(), Diagnostic> {
        self.nodes += 1;
        if self.nodes > self.limits.max_ast_nodes {
            Err(self.limit("AST node 超過編譯限制"))
        } else {
            Ok(())
        }
    }
    fn take_keyword(&mut self, k: Keyword) -> bool {
        if self.current().kind == TokenKind::Keyword(k) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn take_symbol(&mut self, s: Symbol) -> bool {
        if self.current().kind == TokenKind::Symbol(s) {
            self.advance();
            true
        } else {
            false
        }
    }
    fn expect(&mut self, s: Symbol) -> Result<(), Diagnostic> {
        if self.take_symbol(s) {
            Ok(())
        } else {
            Err(self.error("缺少結束符號"))
        }
    }
    fn expect_keyword(&mut self, k: Keyword) -> Result<(), Diagnostic> {
        if self.take_keyword(k) {
            Ok(())
        } else {
            Err(self.error("缺少結束關鍵字"))
        }
    }
    fn current(&self) -> &Token {
        &self.tokens[self.index.min(self.tokens.len() - 1)]
    }
    fn previous(&self) -> &Token {
        &self.tokens[self.index.saturating_sub(1)]
    }
    fn advance(&mut self) {
        if !self.eof() {
            self.index += 1
        }
    }
    fn eof(&self) -> bool {
        self.current().kind == TokenKind::Eof
    }
    fn finish(&self, start: Span) -> Span {
        join(start, self.previous().span)
    }
    fn error(&self, message: &'static str) -> Diagnostic {
        diagnostic(Some(self.current()), DiagnosticCode::Parse, message)
    }
    fn limit(&self, message: &'static str) -> Diagnostic {
        diagnostic(Some(self.current()), DiagnosticCode::CompileLimit, message)
    }
}
fn join(a: Span, b: Span) -> Span {
    Span {
        start_byte: a.start_byte,
        end_byte: b.end_byte,
    }
}
fn diagnostic(t: Option<&Token>, code: DiagnosticCode, message: &'static str) -> Diagnostic {
    let (span, start, end) = t.map(|t| (t.span, t.start, t.end)).unwrap_or((
        Span {
            start_byte: 0,
            end_byte: 0,
        },
        SourcePosition { line: 1, column: 1 },
        SourcePosition { line: 1, column: 1 },
    ));
    Diagnostic {
        code,
        span,
        start,
        end,
        message,
    }
}
