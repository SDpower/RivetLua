use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{AllocationRecovery, ReserveError, StateAllocator, try_reserve_exact_with, try_shared_uninit_with};

use crate::ast::{
    AstBox, AstName, AstVec, Attribute, BinaryOp, Block, Expr, FieldSeparator, FunctionBody,
    GlobalDeclaration, LocalName, MethodName, Module, Stmt, TableField, UnaryOp, Vararg,
};
use crate::{CompileLimits, Diagnostic, DiagnosticCode, Keyword, LanguageProfile, LexedChunk,
    Literal, Span, Symbol, Token, TokenKind};
use crate::resolve::BindingKind;
use crate::resolve::meaning::{MeaningContext, MeaningEvent, MeaningMeter, classify_attribute};
use crate::official_failure::{OfficialFailure, OfficialFailureNear, OfficialFailureReason};
use super::{ParseError, diagnostic, join};

enum TokenStorage<'a> {
    Borrowed(&'a [Token]),
    Owned(AllocVec<Token, StateAllocator>),
}

impl TokenStorage<'_> {
    fn as_slice(&self) -> &[Token] {
        match self { Self::Borrowed(tokens) => tokens, Self::Owned(tokens) => tokens }
    }
}

pub(crate) enum ParseProgress {
    NeedToken,
    Complete(Module),
}

pub(crate) const fn frame_size() -> usize { core::mem::size_of::<Frame>() }

enum Value {
    Module(Module),
    Block(Block),
    Statement(Stmt),
    Expression(Expr),
    Expressions(AstVec<Expr>),
    Names(AstVec<LocalName>),
    Parameters(AstVec<LocalName>, Option<Vararg>),
    FunctionName(Expr, Option<MethodName>),
}

enum Action {
    Continue(Frame),
    Push(Frame, Frame),
    Complete(Value),
    NeedToken(Frame),
}

enum Frame {
    Block(BlockFrame),
    Statement(StatementFrame),
    Expression(ExpressionFrame),
    Expressions(ExpressionListFrame),
    Parameters(ParameterFrame),
    FunctionName(FunctionNameFrame),
    Declarations(DeclarationFrame),
    Table(TableFrame),
}

impl Frame {
    fn level(&self) -> usize {
        match self {
            Self::Statement(_) => 1,
            Self::Expression(frame) => frame.level,
            Self::Expressions(frame) => frame.level,
            _ => 0,
        }
    }

    fn needs_token(&self) -> bool {
        match self {
            Self::Block(frame) => matches!(frame.phase,
                BlockPhase::Start | BlockPhase::Check | BlockPhase::AfterReturn | BlockPhase::CheckReturn),
            Self::Statement(frame) => !matches!(frame.phase,
                StatementPhase::FunctionName | StatementPhase::FunctionParams { .. }
                | StatementPhase::FunctionBody { .. } | StatementPhase::DoBody
                | StatementPhase::WhileCondition | StatementPhase::WhileBody { .. }
                | StatementPhase::RepeatBody | StatementPhase::RepeatCondition { .. }
                | StatementPhase::IfCondition { .. } | StatementPhase::IfBody { .. }
                | StatementPhase::IfElseBody { .. } | StatementPhase::NumericInitial { .. }
                | StatementPhase::NumericLimit { .. } | StatementPhase::NumericStep { .. }
                | StatementPhase::NumericBody { .. } | StatementPhase::GenericValues { .. }
                | StatementPhase::GenericBody { .. } | StatementPhase::ReturnValues
                | StatementPhase::LocalValues { .. }
                | StatementPhase::LocalFunctionParams { .. } | StatementPhase::LocalFunctionBody { .. }
                | StatementPhase::GlobalValues { .. }
                | StatementPhase::GlobalFunctionParams { .. } | StatementPhase::GlobalFunctionBody { .. }
                | StatementPhase::TargetFirst | StatementPhase::TargetNext { .. }
                | StatementPhase::AssignmentValues { .. }),
            Self::Expression(frame) => !matches!(frame.phase,
                ExpressionPhase::Unary { .. } | ExpressionPhase::Paren { .. }
                | ExpressionPhase::Table | ExpressionPhase::FunctionParams { .. }
                | ExpressionPhase::FunctionBody { .. } | ExpressionPhase::CallArgs { .. }
                | ExpressionPhase::Shorthand { .. } | ExpressionPhase::Index { .. }
                | ExpressionPhase::MethodArgs { .. } | ExpressionPhase::MethodShorthand { .. }
                | ExpressionPhase::BinaryRight { .. }),
            Self::Expressions(frame) => !matches!(frame.phase, ListPhase::AfterExpression),
            Self::Parameters(_) | Self::FunctionName(_) | Self::Declarations(_) => true,
            Self::Table(frame) => !matches!(frame.phase,
                TablePhase::IndexedKey { .. } | TablePhase::Value { .. }),
        }
    }
}

struct BlockFrame {
    root: bool,
    scope: bool,
    terminal_labels: bool,
    start: Option<Span>,
    terminators: u8,
    statements: AstVec<Stmt>,
    phase: BlockPhase,
}

#[derive(Clone, Copy)]
enum BlockPhase { Start, Check, AfterStatement, AfterReturn, CheckReturn }

struct StatementFrame { start: Option<Span>, phase: StatementPhase }

enum StatementPhase {
    Start,
    LabelName,
    LabelClose { name: AstName, name_span: Span },
    GotoName,
    FunctionName,
    FunctionParams { name: Expr, method: Option<MethodName> },
    FunctionBody { name: Expr, method: Option<MethodName>, params: AstVec<LocalName>, vararg: Option<Vararg> },
    FunctionEnd { name: Expr, method: Option<MethodName>, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block },
    FunctionAfterEnd { name: Expr, method: Option<MethodName>, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block, span: Span },
    DoBody,
    DoEnd { body: Block },
    WhileCondition,
    WhileDo { condition: Expr },
    WhileBody { condition: Expr },
    WhileEnd { condition: Expr, body: Block },
    RepeatBody,
    RepeatUntil { body: Block },
    RepeatCondition { body: Block },
    IfCondition { clauses: AstVec<(Expr, Block)> },
    IfThen { clauses: AstVec<(Expr, Block)>, condition: Expr },
    IfBody { clauses: AstVec<(Expr, Block)>, condition: Expr },
    IfBranch { clauses: AstVec<(Expr, Block)> },
    IfElseBody { clauses: AstVec<(Expr, Block)> },
    IfEnd { clauses: AstVec<(Expr, Block)>, else_block: Option<Block> },
    ForName,
    ForKind { first: LocalName },
    NumericInitial { name: LocalName },
    NumericComma { name: LocalName, initial: Expr },
    NumericLimit { name: LocalName, initial: Expr },
    NumericStepCheck { name: LocalName, initial: Expr, limit: Expr },
    NumericStep { name: LocalName, initial: Expr, limit: Expr },
    NumericDo { name: LocalName, initial: Expr, limit: Expr, step: Option<Expr> },
    NumericBody { name: LocalName, initial: Expr, limit: Expr, step: Option<Expr> },
    NumericEnd { name: LocalName, initial: Expr, limit: Expr, step: Option<Expr>, body: Block },
    GenericNames { names: AstVec<LocalName> },
    GenericName { names: AstVec<LocalName>, span: Span },
    GenericValues { names: AstVec<LocalName> },
    GenericDo { names: AstVec<LocalName>, values: AstVec<Expr> },
    GenericBody { names: AstVec<LocalName>, values: AstVec<Expr> },
    GenericEnd { names: AstVec<LocalName>, values: AstVec<Expr>, body: Block },
    ReturnStart,
    ReturnValues,
    LocalCheck,
    LocalPrefixName,
    LocalPrefixEnd { attribute: AstName, marker: Token },
    LocalPrefixValidated { attribute: AstName, marker: Token, span: Span },
    LocalNames { prefix: Option<Attribute> },
    LocalValuesCheck,
    LocalValues { names: AstVec<LocalName> },
    LocalFunctionName,
    LocalFunctionParams { name: LocalName },
    LocalFunctionBody { name: LocalName, params: AstVec<LocalName>, vararg: Option<Vararg> },
    LocalFunctionEnd { name: LocalName, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block },
    LocalFunctionAfterEnd { name: LocalName, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block, span: Span },
    GlobalPrefixCheck,
    GlobalPrefixName { span: Span },
    GlobalPrefixEnd { attribute: AstName, span: Span },
    GlobalPrefixValidated { attribute: AstName, span: Span, end: Span },
    GlobalKind { prefix: Option<Attribute> },
    GlobalNames { prefix: Option<Attribute> },
    GlobalValuesCheck { prefix: Option<Attribute> },
    GlobalAfterEquals { names: AstVec<LocalName>, prefix: Option<Attribute> },
    GlobalValues { names: AstVec<LocalName>, prefix: Option<Attribute> },
    GlobalFunctionName,
    GlobalFunctionAfterName { name: AstName, span: Span },
    GlobalFunctionParams { name: AstName },
    GlobalFunctionBody { name: AstName, params: AstVec<LocalName>, vararg: Option<Vararg> },
    GlobalFunctionEnd { name: AstName, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block },
    GlobalFunctionAfterEnd { name: AstName, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block, span: Span },
    TargetFirst,
    TargetMore { targets: AstVec<Expr> },
    TargetNext { targets: AstVec<Expr> },
    AssignmentValues { targets: AstVec<Expr> },
}

struct ExpressionFrame {
    min: u8,
    level: usize,
    prefix_only: bool,
    suffixed_only: bool,
    phase: ExpressionPhase,
}

enum ExpressionPhase {
    Start,
    NameAfterToken { name: AstName, span: Span },
    Unary { op: UnaryOp, start: Span },
    Paren { start: Span },
    ParenEnd { start: Span, value: Expr },
    Table,
    FunctionParams { start: Span },
    FunctionBody { start: Span, params: AstVec<LocalName>, vararg: Option<Vararg> },
    FunctionEnd { start: Span, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block },
    FunctionAfterEnd { start: Span, params: AstVec<LocalName>, vararg: Option<Vararg>, body: Block, span: Span },
    Postfix { value: Expr },
    CallCheck { value: Expr },
    CallArgs { value: Expr },
    CallEnd { value: Expr, args: AstVec<Expr> },
    Shorthand { value: Expr },
    FieldName { value: Expr },
    Index { value: Expr },
    IndexEnd { value: Expr, index: Expr },
    MethodName { value: Expr },
    MethodArgsCheck { value: Expr, method: AstName },
    MethodParenCheck { value: Expr, method: AstName },
    MethodArgs { value: Expr, method: AstName },
    MethodEnd { value: Expr, method: AstName, args: AstVec<Expr> },
    MethodShorthand { value: Expr, method: AstName },
    Binary { value: Expr },
    BinaryRight { value: Expr, op: BinaryOp },
}

struct ExpressionListFrame { values: AstVec<Expr>, phase: ListPhase, level: usize }
#[derive(Clone, Copy)]
enum ListPhase { Start, AfterExpression, Separator }

struct ParameterFrame { params: AstVec<LocalName>, vararg: Option<Vararg>, phase: ParameterPhase }
#[derive(Clone, Copy)]
enum ParameterPhase { Open, Check { allow_empty: bool }, Name, Separator, VarargName { span: Span }, VarargClose }

struct FunctionNameFrame { value: Option<Expr>, method: Option<MethodName>, phase: FunctionNamePhase }
enum FunctionNamePhase { First, FirstAfterToken { name: AstName, span: Span }, Check, DotName, ColonName { colon: Span } }

struct DeclarationFrame {
    local: bool,
    prefix: Option<Attribute>,
    names: AstVec<LocalName>,
    phase: DeclarationPhase,
}
enum DeclarationPhase {
    Name,
    AttributeCheck { name: AstName, start: Span },
    AttributeName { name: AstName, start: Span, attr_start: Span },
    AttributeEnd { name: AstName, start: Span, attr: AstName, attr_start: Span },
    AttributeResolved { name: AstName, start: Span, attribute: Attribute },
    Separator,
}

struct TableFrame {
    start: Option<Span>,
    fields: AstVec<TableField>,
    phase: TablePhase,
}
enum TablePhase {
    Open,
    Check,
    NamedLookahead { start: Span },
    NamedAssign { start: Span, name: AstName },
    IndexedKey { start: Span },
    IndexedClose { start: Span, key: Expr },
    IndexedAssign { start: Span, key: Expr },
    Value { start: Span, kind: FieldKind },
    Separator { field: TableField },
}
enum FieldKind { Array, Named(AstName), Indexed(Expr) }

pub(crate) struct ParserState<'a> {
    tokens: TokenStorage<'a>,
    index: usize,
    limits: CompileLimits,
    profile: LanguageProfile,
    source_len: Option<usize>,
    frames: AllocVec<Frame, StateAllocator>,
    result: Option<Value>,
    started: bool,
    complete: bool,
    nodes: usize,
    depth: usize,
    statements: usize,
    failure: Option<OfficialFailure>,
}

impl<'a> ParserState<'a> {
    pub(crate) fn owned(profile: LanguageProfile, limits: CompileLimits, allocator: StateAllocator) -> Self {
        Self { tokens: TokenStorage::Owned(AllocVec::new_in(allocator.clone())), index: 0,
            limits, profile, source_len: None, frames: AllocVec::new_in(allocator), result: None, started: false,
            complete: false, nodes: 0, depth: 0, statements: 0, failure: None }
    }

    pub(crate) fn borrowed(chunk: &'a LexedChunk, limits: CompileLimits, allocator: StateAllocator) -> Self {
        Self { tokens: TokenStorage::Borrowed(&chunk.tokens), index: 0, limits,
            profile: chunk.profile, source_len: Some(chunk.source_len), frames: AllocVec::new_in(allocator),
            result: None, started: false, complete: false, nodes: 0, depth: 0, statements: 0,
            failure: None }
    }

    pub(crate) fn nodes(&self) -> usize { self.nodes }
    pub(crate) fn token_count(&self) -> usize { self.tokens.as_slice().len() }
    pub(crate) fn last_token(&self) -> Option<&Token> { self.tokens.as_slice().last() }
    pub(crate) fn take_official_failure(&mut self) -> Option<OfficialFailure> {
        self.failure.take()
    }

    pub(crate) fn push_token<R: AllocationRecovery>(
        &mut self, token: Token, recovery: &mut R,
    ) -> Result<(), ParseError<R::Error>> {
        let TokenStorage::Owned(tokens) = &mut self.tokens else {
            return Err(diagnostic(None, DiagnosticCode::Parse, "parser token 狀態不完整").into());
        };
        if tokens.len() >= self.limits.max_tokens {
            return Err(diagnostic(Some(&token), DiagnosticCode::CompileLimit, "token 數超過編譯限制").into());
        }
        if tokens.len() == tokens.capacity() {
            let target = tokens.capacity().saturating_mul(2).max(4).min(self.limits.max_tokens);
            let additional = target - tokens.len();
            try_reserve_exact_with(tokens, additional, recovery).map_err(reserve_error)?;
        }
        tokens.push(token);
        Ok(())
    }

    pub(crate) fn into_lexed(self, source_len: usize) -> Result<LexedChunk, Diagnostic> {
        let TokenStorage::Owned(tokens) = self.tokens else {
            return Err(diagnostic(None, DiagnosticCode::Parse, "parser token 狀態不完整"));
        };
        Ok(LexedChunk { profile: self.profile, source_len, tokens })
    }

    pub(crate) fn advance<C: MeaningContext, R: MeaningMeter>(&mut self,
        context: &mut C, recovery: &mut R)
        -> Result<ParseProgress, ParseError<R::Error>> {
        if self.complete { return Err(diagnostic(None, DiagnosticCode::Parse, "parser 已完成").into()); }
        if !self.started {
            if self.current().is_none() { return Ok(ParseProgress::NeedToken); }
            self.emit(context, MeaningEvent::Root(self.span()), recovery)?;
            self.push(Frame::Block(BlockFrame { root: true, scope: false, terminal_labels: true,
                start: None, terminators: 0, statements: self.new_list(),
                phase: BlockPhase::Start }), recovery)?;
            self.started = true;
        }
        loop {
            let frame = self.frames.pop().ok_or_else(|| self.error("parser frame 狀態不完整"))?;
            if self.current().is_none() && frame.needs_token() {
                self.frames.push(frame);
                return Ok(ParseProgress::NeedToken);
            }
            let level = frame.level();
            let action = match frame {
                Frame::Block(frame) => self.block(frame, context, recovery)?,
                Frame::Statement(frame) => self.statement(frame, context, recovery)?,
                Frame::Expression(frame) => self.expression(frame, context, recovery)?,
                Frame::Expressions(frame) => self.expressions(frame, recovery)?,
                Frame::Parameters(frame) => self.parameters(frame, recovery)?,
                Frame::FunctionName(frame) => self.function_name(frame, context, recovery)?,
                Frame::Declarations(frame) => self.declarations(frame, context, recovery)?,
                Frame::Table(frame) => self.table(frame, recovery)?,
            };
            match action {
                Action::Continue(frame) => {
                    self.frames.push(frame);
                }
                Action::NeedToken(frame) => {
                    self.frames.push(frame);
                    return Ok(ParseProgress::NeedToken);
                }
                Action::Push(parent, child) => {
                    self.frames.push(parent);
                    self.push(child, recovery)?;
                }
                Action::Complete(value) => {
                    self.depth -= level;
                    if self.frames.is_empty() {
                        let Value::Module(module) = value else { return Err(self.error("parser root 狀態不完整")); };
                        self.complete = true;
                        return Ok(ParseProgress::Complete(module));
                    }
                    self.result = Some(value);
                }
            }
        }
    }

    fn push<R: AllocationRecovery>(&mut self, frame: Frame, recovery: &mut R)
        -> Result<(), ParseError<R::Error>> {
        let next = self.depth.checked_add(frame.level()).ok_or_else(|| self.limit("解析深度超過編譯限制"))?;
        if next > self.limits.max_parse_depth { return Err(self.limit("解析深度超過編譯限制")); }
        if self.frames.len() == self.frames.capacity() {
            let target = self.frames.capacity().saturating_mul(2).max(4);
            let additional = target - self.frames.len();
            try_reserve_exact_with(&mut self.frames, additional, recovery).map_err(reserve_error)?;
        }
        self.frames.push(frame);
        self.depth = next;
        Ok(())
    }

    fn new_list<T>(&self) -> AstVec<T> { AstVec::new_in(self.frames.allocator().clone()) }

    fn push_list<T, R: AllocationRecovery>(&mut self, values: &mut AstVec<T>, value: T, recovery: &mut R)
        -> Result<(), ParseError<R::Error>> {
        if values.len() == values.capacity() {
            let target = values.capacity().saturating_mul(2).max(4);
            let additional = target - values.len();
            try_reserve_exact_with(values, additional, recovery).map_err(reserve_error)?;
        }
        values.push(value);
        Ok(())
    }

    fn one_list<T, R: AllocationRecovery>(&mut self, value: T, recovery: &mut R)
        -> Result<AstVec<T>, ParseError<R::Error>> {
        let mut out = self.new_list();
        self.push_list(&mut out, value, recovery)?;
        Ok(out)
    }

    fn box_expr<R: AllocationRecovery>(&mut self, value: Expr, recovery: &mut R)
        -> Result<AstBox<Expr>, ParseError<R::Error>> {
        let owner = try_shared_uninit_with::<Expr, _>(recovery, 0).map_err(reserve_error)?;
        Ok(owner.write(value))
    }

    fn reserve_node<R: AllocationRecovery>(&mut self) -> Result<(), ParseError<R::Error>> {
        self.nodes += 1;
        let available = if matches!(&self.tokens, TokenStorage::Owned(_)) {
            self.token_count().saturating_mul(4).saturating_add(4)
        } else { self.limits.max_ast_nodes };
        if self.nodes > self.limits.max_ast_nodes.min(available) {
            Err(self.limit("AST node 超過編譯限制"))
        } else { Ok(()) }
    }

    fn current(&self) -> Option<&Token> { self.tokens.as_slice().get(self.index) }
    fn kind(&self) -> TokenKind { self.current().map_or(TokenKind::Eof, |token| token.kind) }
    fn span(&self) -> Span { self.current().map_or(Span { start_byte: 0, end_byte: 0 }, |token| token.span) }
    fn previous(&self) -> &Token { &self.tokens.as_slice()[self.index.saturating_sub(1)] }
    fn finish(&self, start: Span) -> Span { join(start, self.previous().span) }
    fn consume(&mut self) { if self.kind() != TokenKind::Eof { self.index += 1; } }
    fn take_symbol(&mut self, symbol: Symbol) -> bool {
        if self.kind() == TokenKind::Symbol(symbol) { self.consume(); true } else { false }
    }
    fn take_keyword(&mut self, keyword: Keyword) -> bool {
        if self.kind() == TokenKind::Keyword(keyword) { self.consume(); true } else { false }
    }
    fn expect_symbol<E>(&mut self, symbol: Symbol) -> Result<(), ParseError<E>> {
        if self.take_symbol(symbol) { Ok(()) } else {
            Err(self.expected(TokenKind::Symbol(symbol), None, "缺少結束符號"))
        }
    }
    fn expect_keyword<E>(&mut self, keyword: Keyword) -> Result<(), ParseError<E>> {
        if self.take_keyword(keyword) { Ok(()) } else {
            Err(self.expected(TokenKind::Keyword(keyword), None, "缺少結束關鍵字"))
        }
    }
    fn name<E>(&mut self) -> Result<AstName, ParseError<E>> {
        if self.current().is_none() || self.kind() != TokenKind::Name {
            return Err(self.expected(TokenKind::Name, None, "預期名稱"));
        }
        let Some(token) = self.current() else {
            return Err(self.expected(TokenKind::Name, None, "預期名稱"));
        };
        let Some(Literal::Name(name)) = token.literal.as_ref() else { return Err(self.error("名稱 token 不完整")); };
        let name = name.clone();
        self.consume();
        Ok(name)
    }
    fn error<E>(&self, message: &'static str) -> ParseError<E> {
        diagnostic(self.current(), DiagnosticCode::Parse, message).into()
    }
    fn expected<E>(&mut self, token: TokenKind, opener: Option<(TokenKind, usize)>,
        message: &'static str) -> ParseError<E> {
        let near = self.current().cloned().map_or(OfficialFailureNear::None,
            OfficialFailureNear::Token);
        let line = self.current().map(|token| token.end.line)
            .or_else(|| self.tokens.as_slice().last().map(|token| token.end.line))
            .unwrap_or(1);
        self.failure = Some(OfficialFailure {
            reason: OfficialFailureReason::Expected { token, opener }, line, near,
        });
        self.error(message)
    }
    fn syntax_error<E>(&mut self, reason: &'static [u8], message: &'static str) -> ParseError<E> {
        let near = self.current().cloned().map_or(OfficialFailureNear::None,
            OfficialFailureNear::Token);
        let line = self.current().map(|token| token.end.line)
            .or_else(|| self.tokens.as_slice().last().map(|token| token.end.line))
            .unwrap_or(1);
        self.failure = Some(OfficialFailure {
            reason: OfficialFailureReason::Text(reason), line, near,
        });
        self.error(message)
    }
    fn block_opener(&self) -> Option<(TokenKind, usize)> {
        self.frames.last().and_then(|parent| match parent {
            Frame::Statement(statement) => {
                let start = statement.start?;
                if matches!(&statement.phase,
                    StatementPhase::LocalFunctionBody { .. }
                    | StatementPhase::GlobalFunctionBody { .. }) {
                    self.tokens.as_slice().iter()
                        .find(|token| token.span.start_byte > start.start_byte
                            && token.kind == TokenKind::Keyword(Keyword::Function))
                        .map(|token| token.span)
                } else { Some(start) }
            }
            Frame::Expression(expression) => match &expression.phase {
                ExpressionPhase::FunctionBody { start, .. } => Some(*start),
                _ => None,
            },
            _ => None,
        }).and_then(|span| self.tokens.as_slice().iter()
            .find(|token| token.span.start_byte == span.start_byte)
            .map(|token| (token.kind, token.start.line)))
    }

    fn record_attribute_failure(&mut self, attribute: &Attribute, global: bool) {
        let source_line = self.current().map(|token| token.start.line).unwrap_or(1);
        let last_line = self.tokens.as_slice().iter()
            .find(|token| token.span.end_byte == attribute.span.end_byte)
            .map(|token| token.start.line).unwrap_or(source_line);
        self.failure = Some(OfficialFailure {
            reason: if global && attribute.name.as_slice() == b"close" {
                OfficialFailureReason::Text(b"global variables cannot be to-be-closed")
            } else {
                OfficialFailureReason::UnknownAttribute { name: attribute.name.clone() }
            },
            line: if self.profile == LanguageProfile::Lua55 { last_line } else { source_line },
            near: OfficialFailureNear::None,
        });
    }
    fn limit<E>(&self, message: &'static str) -> ParseError<E> {
        diagnostic(self.current(), DiagnosticCode::CompileLimit, message).into()
    }

    fn take_block<E>(&mut self) -> Result<Block, ParseError<E>> {
        match self.result.take() { Some(Value::Block(value)) => Ok(value), _ => Err(self.error("parser block 狀態不完整")) }
    }
    fn take_statement<E>(&mut self) -> Result<Stmt, ParseError<E>> {
        match self.result.take() { Some(Value::Statement(value)) => Ok(value), _ => Err(self.error("parser statement 狀態不完整")) }
    }
    fn take_expression<E>(&mut self) -> Result<Expr, ParseError<E>> {
        match self.result.take() { Some(Value::Expression(value)) => Ok(value), _ => Err(self.error("parser expression 狀態不完整")) }
    }
    fn take_expressions<E>(&mut self) -> Result<AstVec<Expr>, ParseError<E>> {
        match self.result.take() { Some(Value::Expressions(value)) => Ok(value), _ => Err(self.error("parser list 狀態不完整")) }
    }
    fn take_names<E>(&mut self) -> Result<AstVec<LocalName>, ParseError<E>> {
        match self.result.take() { Some(Value::Names(value)) => Ok(value), _ => Err(self.error("parser names 狀態不完整")) }
    }
    fn take_parameters<E>(&mut self) -> Result<(AstVec<LocalName>, Option<Vararg>), ParseError<E>> {
        match self.result.take() { Some(Value::Parameters(params, vararg)) => Ok((params, vararg)), _ => Err(self.error("parser parameters 狀態不完整")) }
    }
    fn take_function_name<E>(&mut self) -> Result<(Expr, Option<MethodName>), ParseError<E>> {
        match self.result.take() { Some(Value::FunctionName(value, method)) => Ok((value, method)), _ => Err(self.error("parser function name 狀態不完整")) }
    }

    fn expr_frame(&self, min: u8, level: usize, prefix_only: bool) -> Frame {
        Frame::Expression(ExpressionFrame { min, level, prefix_only, suffixed_only: false,
            phase: ExpressionPhase::Start })
    }
    fn suffixed_frame(&self, level: usize) -> Frame {
        Frame::Expression(ExpressionFrame { min: 0, level, prefix_only: false, suffixed_only: true,
            phase: ExpressionPhase::Start })
    }
    fn list_frame(&self, level: usize) -> Frame {
        Frame::Expressions(ExpressionListFrame { values: self.new_list(), phase: ListPhase::Start, level })
    }
    fn block_frame(&self, terminators: u8) -> Frame {
        Frame::Block(BlockFrame { root: false, scope: true, terminal_labels: true,
            start: None, terminators,
            statements: self.new_list(), phase: BlockPhase::Start })
    }

    fn function_block_frame(&self) -> Frame {
        Frame::Block(BlockFrame { root: false, scope: false, terminal_labels: true,
            start: None, terminators: 1, statements: self.new_list(), phase: BlockPhase::Start })
    }

    fn repeat_block_frame(&self) -> Frame {
        Frame::Block(BlockFrame { root: false, scope: false, terminal_labels: false,
            start: None, terminators: 2, statements: self.new_list(), phase: BlockPhase::Start })
    }

    fn emit<C: MeaningContext, R: MeaningMeter>(&self, context: &mut C,
        event: MeaningEvent<'_>, meter: &mut R) -> Result<(), ParseError<R::Error>> {
        context.event(event, self.tokens.as_slice(), meter)
    }
    fn statement_frame(&self) -> Frame {
        Frame::Statement(StatementFrame { start: None, phase: StatementPhase::Start })
    }
    fn params_frame(&self) -> Frame {
        Frame::Parameters(ParameterFrame { params: self.new_list(), vararg: None, phase: ParameterPhase::Open })
    }

    fn block<C: MeaningContext, R: MeaningMeter>(&mut self, mut frame: BlockFrame,
        context: &mut C, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        match frame.phase {
            BlockPhase::Start => {
                self.reserve_node::<R>()?;
                frame.start = Some(if frame.root { Span { start_byte: 0, end_byte: 0 } } else { self.span() });
                if frame.scope {
                    self.emit(context, MeaningEvent::EnterScope(self.span()), recovery)?;
                }
                frame.phase = BlockPhase::Check;
                Ok(Action::Continue(Frame::Block(frame)))
            }
            BlockPhase::Check => {
                let at_follow = self.kind() == TokenKind::Eof || terminates(frame.terminators, self.kind());
                if !matches!(self.kind(), TokenKind::Symbol(Symbol::DoubleColon | Symbol::Semicolon)) {
                    self.emit(context, MeaningEvent::FlushLabels {
                        terminal: at_follow && frame.terminal_labels,
                    }, recovery)?;
                }
                if frame.root && self.kind() == TokenKind::Eof {
                    self.emit(context, MeaningEvent::LeaveFunction(self.span()), recovery)?;
                    self.reserve_node::<R>()?;
                    let source_len = self.source_len.unwrap_or(self.span().end_byte);
                    return Ok(Action::Complete(Value::Module(Module { profile: self.profile,
                        span: Span { start_byte: 0, end_byte: source_len },
                        root: Block { statements: frame.statements, terminator: None,
                            span: Span { start_byte: 0, end_byte: source_len } } })));
                }
                if !frame.root {
                    if self.kind() == TokenKind::Eof {
                        let opener = self.block_opener();
                        let expected = if frame.terminators == 2 { Keyword::Until } else { Keyword::End };
                        return Err(self.expected(TokenKind::Keyword(expected), opener,
                            "缺少 block 結束關鍵字"));
                    }
                    if terminates(frame.terminators, self.kind()) {
                        let span = self.span();
                        let start = frame.start.ok_or_else(|| self.error("parser block 狀態不完整"))?;
                        if frame.scope {
                            self.emit(context, MeaningEvent::LeaveScope {
                                span, terminal: frame.terminal_labels,
                            }, recovery)?;
                        }
                        return Ok(Action::Complete(Value::Block(Block {
                            span: join(start, span), statements: frame.statements,
                            terminator: Some(span),
                        })));
                    }
                }
                self.statements += 1;
                if self.statements > self.limits.max_statements { return Err(self.limit("陳述式數超過編譯限制")); }
                frame.phase = BlockPhase::AfterStatement;
                Ok(Action::Push(Frame::Block(frame), self.statement_frame()))
            }
            BlockPhase::AfterStatement => {
                let statement = self.take_statement()?;
                let returned = matches!(statement, Stmt::Return { .. });
                self.push_list(&mut frame.statements, statement, recovery)?;
                frame.phase = if returned { BlockPhase::AfterReturn } else { BlockPhase::Check };
                Ok(Action::Continue(Frame::Block(frame)))
            }
            BlockPhase::AfterReturn => {
                self.take_symbol(Symbol::Semicolon);
                frame.phase = BlockPhase::CheckReturn;
                Ok(Action::Continue(Frame::Block(frame)))
            }
            BlockPhase::CheckReturn => {
                if self.kind() != TokenKind::Eof && !terminates(frame.terminators, self.kind()) {
                    let (expected, opener) = if frame.root {
                        (TokenKind::Eof, None)
                    } else if frame.terminators == 2 {
                        (TokenKind::Keyword(Keyword::Until), self.block_opener())
                    } else {
                        (TokenKind::Keyword(Keyword::End), self.block_opener())
                    };
                    return Err(self.expected(expected, opener,
                        "return 必須為 block 最後陳述式"));
                }
                frame.phase = BlockPhase::Check;
                Ok(Action::Continue(Frame::Block(frame)))
            }
        }
    }

    fn statement<C: MeaningContext, R: MeaningMeter>(&mut self, frame: StatementFrame,
        context: &mut C, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        let start = frame.start.unwrap_or(self.span());
        let next = |phase| Action::Continue(Frame::Statement(StatementFrame { start: Some(start), phase }));
        let push = |phase, child| Action::Push(Frame::Statement(StatementFrame { start: Some(start), phase }), child);
        match frame.phase {
            StatementPhase::Start => {
                self.reserve_node::<R>()?;
                if self.take_symbol(Symbol::DoubleColon) { return Ok(next(StatementPhase::LabelName)); }
                if self.take_keyword(Keyword::Function) {
                    return Ok(push(StatementPhase::FunctionName,
                        Frame::FunctionName(FunctionNameFrame { value: None, method: None, phase: FunctionNamePhase::First })));
                }
                if self.take_keyword(Keyword::Do) {
                    return Ok(push(StatementPhase::DoBody, self.block_frame(1)));
                }
                if self.take_keyword(Keyword::While) {
                    return Ok(push(StatementPhase::WhileCondition, self.expr_frame(0, 1, false)));
                }
                if self.take_keyword(Keyword::Repeat) {
                    self.emit(context, MeaningEvent::EnterScope(start), recovery)?;
                    self.emit(context, MeaningEvent::EnterLoop, recovery)?;
                    return Ok(push(StatementPhase::RepeatBody, self.repeat_block_frame()));
                }
                if self.take_keyword(Keyword::If) {
                    return Ok(push(StatementPhase::IfCondition { clauses: self.new_list() }, self.expr_frame(0, 1, false)));
                }
                if self.take_keyword(Keyword::For) { return Ok(next(StatementPhase::ForName)); }
                if self.take_keyword(Keyword::Return) { return Ok(next(StatementPhase::ReturnStart)); }
                if self.kind() == TokenKind::Keyword(Keyword::Break) {
                    self.emit(context, MeaningEvent::CheckBreak(start), recovery)?;
                    self.consume();
                    return Ok(Action::Complete(Value::Statement(Stmt::Break { span: self.finish(start) })));
                }
                if self.take_keyword(Keyword::Goto) { return Ok(next(StatementPhase::GotoName)); }
                if self.take_symbol(Symbol::Semicolon) {
                    return Ok(Action::Complete(Value::Statement(Stmt::Empty { span: start })));
                }
                if self.take_keyword(Keyword::Local) { return Ok(next(StatementPhase::LocalCheck)); }
                if self.take_keyword(Keyword::Global) { return Ok(next(StatementPhase::GlobalPrefixCheck)); }
                Ok(push(StatementPhase::TargetFirst, self.suffixed_frame(0)))
            }
            StatementPhase::LabelName => {
                let name_span = self.span();
                let name = self.name()?;
                Ok(next(StatementPhase::LabelClose { name, name_span }))
            }
            StatementPhase::LabelClose { name, name_span } => {
                self.expect_symbol(Symbol::DoubleColon)?;
                self.emit(context, MeaningEvent::QueueLabel { name: &name, span: name_span }, recovery)?;
                self.reserve_node::<R>()?;
                Ok(Action::Complete(Value::Statement(Stmt::Label {
                    name, name_span, span: self.finish(start),
                })))
            }
            StatementPhase::GotoName => {
                let name = self.name()?;
                let name_span = self.previous().span;
                self.emit(context, MeaningEvent::Goto { name: &name, span: name_span }, recovery)?;
                Ok(Action::Complete(Value::Statement(Stmt::Goto {
                    name, name_span, span: self.finish(start),
                })))
            }
            StatementPhase::FunctionName => {
                let (name, method) = self.take_function_name()?;
                if self.profile == LanguageProfile::Lua55 {
                    self.emit(context, MeaningEvent::WriteTarget(&name), recovery)?;
                }
                Ok(push(StatementPhase::FunctionParams { name, method }, self.params_frame()))
            }
            StatementPhase::FunctionParams { name, method } => {
                let (params, vararg) = self.take_parameters()?;
                self.emit(context, MeaningEvent::EnterFunction {
                    parameters: &params, vararg: vararg.as_ref().and_then(|value| value.table_name.as_ref()),
                    variadic: vararg.is_some(), method: method.as_ref().map(|value| value.colon_span), span: start,
                }, recovery)?;
                Ok(push(StatementPhase::FunctionBody { name, method, params, vararg }, self.function_block_frame()))
            }
            StatementPhase::FunctionBody { name, method, params, vararg } => {
                let body = self.take_block()?;
                Ok(next(StatementPhase::FunctionEnd { name, method, params, vararg, body }))
            }
            StatementPhase::FunctionEnd { name, method, params, vararg, body } => {
                self.expect_keyword(Keyword::End)?;
                let span = self.finish(start);
                Ok(next(StatementPhase::FunctionAfterEnd { name, method, params, vararg, body, span }))
            }
            StatementPhase::FunctionAfterEnd { name, method, params, vararg, body, span } => {
                self.emit(context, MeaningEvent::LeaveFunction(span), recovery)?;
                if self.profile == LanguageProfile::Lua54 {
                    self.emit(context, MeaningEvent::WriteTarget(&name), recovery)?;
                }
                Ok(Action::Complete(Value::Statement(Stmt::Function {
                    name, method, body: FunctionBody { parameters: params, vararg, body, span }, span,
                })))
            }
            StatementPhase::DoBody => {
                let body = self.take_block()?;
                Ok(next(StatementPhase::DoEnd { body }))
            }
            StatementPhase::DoEnd { body } => {
                self.expect_keyword(Keyword::End)?;
                Ok(Action::Complete(Value::Statement(Stmt::Do { body, span: self.finish(start) })))
            }
            StatementPhase::WhileCondition => {
                let condition = self.take_expression()?;
                Ok(next(StatementPhase::WhileDo { condition }))
            }
            StatementPhase::WhileDo { condition } => {
                self.expect_keyword(Keyword::Do)?;
                self.emit(context, MeaningEvent::EnterLoop, recovery)?;
                Ok(push(StatementPhase::WhileBody { condition }, self.block_frame(1)))
            }
            StatementPhase::WhileBody { condition } => {
                let body = self.take_block()?;
                self.emit(context, MeaningEvent::LeaveLoop, recovery)?;
                Ok(next(StatementPhase::WhileEnd { condition, body }))
            }
            StatementPhase::WhileEnd { condition, body } => {
                self.expect_keyword(Keyword::End)?;
                Ok(Action::Complete(Value::Statement(Stmt::While {
                    condition, body, span: self.finish(start),
                })))
            }
            StatementPhase::RepeatBody => {
                let body = self.take_block()?;
                Ok(next(StatementPhase::RepeatUntil { body }))
            }
            StatementPhase::RepeatUntil { body } => {
                self.expect_keyword(Keyword::Until)?;
                Ok(push(StatementPhase::RepeatCondition { body }, self.expr_frame(0, 1, false)))
            }
            StatementPhase::RepeatCondition { body } => {
                let condition = self.take_expression()?;
                self.emit(context, MeaningEvent::LeaveLoop, recovery)?;
                self.emit(context, MeaningEvent::LeaveScope { span: self.finish(start), terminal: false }, recovery)?;
                Ok(Action::Complete(Value::Statement(Stmt::Repeat {
                    body, condition, span: self.finish(start),
                })))
            }
            StatementPhase::IfCondition { clauses } => {
                let condition = self.take_expression()?;
                Ok(next(StatementPhase::IfThen { clauses, condition }))
            }
            StatementPhase::IfThen { clauses, condition } => {
                self.expect_keyword(Keyword::Then)?;
                Ok(push(StatementPhase::IfBody { clauses, condition }, self.block_frame(1 | 4 | 8)))
            }
            StatementPhase::IfBody { mut clauses, condition } => {
                let body = self.take_block()?;
                if !clauses.is_empty() && clauses.len() >= self.limits.max_list_entries {
                    return Err(self.limit("list 超過編譯限制"));
                }
                self.push_list(&mut clauses, (condition, body), recovery)?;
                Ok(next(StatementPhase::IfBranch { clauses }))
            }
            StatementPhase::IfBranch { clauses } => {
                if self.take_keyword(Keyword::ElseIf) {
                    return Ok(push(StatementPhase::IfCondition { clauses }, self.expr_frame(0, 1, false)));
                }
                if self.take_keyword(Keyword::Else) {
                    return Ok(push(StatementPhase::IfElseBody { clauses }, self.block_frame(1)));
                }
                Ok(next(StatementPhase::IfEnd { clauses, else_block: None }))
            }
            StatementPhase::IfElseBody { clauses } => {
                let else_block = Some(self.take_block()?);
                Ok(next(StatementPhase::IfEnd { clauses, else_block }))
            }
            StatementPhase::IfEnd { clauses, else_block } => {
                self.expect_keyword(Keyword::End)?;
                Ok(Action::Complete(Value::Statement(Stmt::If {
                    clauses, else_block, span: self.finish(start),
                })))
            }
            StatementPhase::ForName => {
                let name_start = self.span();
                let name = self.name()?;
                self.reserve_node::<R>()?;
                Ok(next(StatementPhase::ForKind { first: LocalName { name, attribute: None, span: name_start } }))
            }
            StatementPhase::ForKind { first } => {
                if self.take_symbol(Symbol::Assign) {
                    return Ok(push(StatementPhase::NumericInitial { name: first }, self.expr_frame(0, 1, false)));
                }
                let names = self.one_list(first, recovery)?;
                Ok(next(StatementPhase::GenericNames { names }))
            }
            StatementPhase::NumericInitial { name } => {
                let initial = self.take_expression()?;
                Ok(next(StatementPhase::NumericComma { name, initial }))
            }
            StatementPhase::NumericComma { name, initial } => {
                self.expect_symbol(Symbol::Comma)?;
                Ok(push(StatementPhase::NumericLimit { name, initial }, self.expr_frame(0, 1, false)))
            }
            StatementPhase::NumericLimit { name, initial } => {
                let limit = self.take_expression()?;
                Ok(next(StatementPhase::NumericStepCheck { name, initial, limit }))
            }
            StatementPhase::NumericStepCheck { name, initial, limit } => {
                if self.take_symbol(Symbol::Comma) {
                    Ok(push(StatementPhase::NumericStep { name, initial, limit }, self.expr_frame(0, 1, false)))
                } else { Ok(next(StatementPhase::NumericDo { name, initial, limit, step: None })) }
            }
            StatementPhase::NumericStep { name, initial, limit } => {
                let step = Some(self.take_expression()?);
                Ok(next(StatementPhase::NumericDo { name, initial, limit, step }))
            }
            StatementPhase::NumericDo { name, initial, limit, step } => {
                self.expect_keyword(Keyword::Do)?;
                self.emit(context, MeaningEvent::EnterScope(start), recovery)?;
                self.emit(context, MeaningEvent::Declare { name: &name, attribute: None,
                    kind: BindingKind::NumericFor,
                    readonly: self.profile.rules().readonly_for_control }, recovery)?;
                self.emit(context, MeaningEvent::EnterLoop, recovery)?;
                Ok(push(StatementPhase::NumericBody { name, initial, limit, step }, self.block_frame(1)))
            }
            StatementPhase::NumericBody { name, initial, limit, step } => {
                let body = self.take_block()?;
                self.emit(context, MeaningEvent::LeaveLoop, recovery)?;
                self.emit(context, MeaningEvent::LeaveScope { span: body.span, terminal: true }, recovery)?;
                Ok(next(StatementPhase::NumericEnd { name, initial, limit, step, body }))
            }
            StatementPhase::NumericEnd { name, initial, limit, step, body } => {
                self.expect_keyword(Keyword::End)?;
                Ok(Action::Complete(Value::Statement(Stmt::NumericFor {
                    name, initial, limit, step, body, span: self.finish(start),
                })))
            }
            StatementPhase::GenericNames { names } => {
                if self.take_symbol(Symbol::Comma) {
                    if names.len() >= self.limits.max_list_entries { return Err(self.limit("list 超過編譯限制")); }
                    let span = self.span();
                    return Ok(next(StatementPhase::GenericName { names, span }));
                }
                self.expect_keyword(Keyword::In)?;
                Ok(push(StatementPhase::GenericValues { names }, self.list_frame(0)))
            }
            StatementPhase::GenericName { mut names, span } => {
                self.reserve_node::<R>()?;
                let name = self.name()?;
                self.push_list(&mut names, LocalName { name, attribute: None, span }, recovery)?;
                Ok(next(StatementPhase::GenericNames { names }))
            }
            StatementPhase::GenericValues { names } => {
                let values = self.take_expressions()?;
                Ok(next(StatementPhase::GenericDo { names, values }))
            }
            StatementPhase::GenericDo { names, values } => {
                self.expect_keyword(Keyword::Do)?;
                self.emit(context, MeaningEvent::EnterScope(start), recovery)?;
                self.emit(context, MeaningEvent::GenericForClose(
                    values.get(3).map(Expr::span).unwrap_or(start)), recovery)?;
                for (index, name) in names.iter().enumerate() {
                    self.emit(context, MeaningEvent::Declare { name, attribute: None,
                        kind: BindingKind::GenericFor,
                        readonly: index == 0 && self.profile.rules().readonly_for_control,
                    }, recovery)?;
                }
                self.emit(context, MeaningEvent::EnterLoop, recovery)?;
                Ok(push(StatementPhase::GenericBody { names, values }, self.block_frame(1)))
            }
            StatementPhase::GenericBody { names, values } => {
                let body = self.take_block()?;
                self.emit(context, MeaningEvent::LeaveLoop, recovery)?;
                self.emit(context, MeaningEvent::LeaveScope { span: body.span, terminal: true }, recovery)?;
                Ok(next(StatementPhase::GenericEnd { names, values, body }))
            }
            StatementPhase::GenericEnd { names, values, body } => {
                self.expect_keyword(Keyword::End)?;
                Ok(Action::Complete(Value::Statement(Stmt::GenericFor {
                    names, values, body, span: self.finish(start),
                })))
            }
            StatementPhase::ReturnStart => {
                if self.kind() == TokenKind::Eof || self.kind() == TokenKind::Symbol(Symbol::Semicolon)
                    || matches!(self.kind(), TokenKind::Keyword(Keyword::End | Keyword::Else | Keyword::ElseIf | Keyword::Until)) {
                    return Ok(Action::Complete(Value::Statement(Stmt::Return {
                        values: self.new_list(), span: self.finish(start),
                    })));
                }
                Ok(push(StatementPhase::ReturnValues, self.list_frame(0)))
            }
            StatementPhase::ReturnValues => {
                let values = self.take_expressions()?;
                if self.profile == LanguageProfile::Lua55 && values.len() > 254
                    && !matches!(values.last(), Some(Expr::Call { .. } | Expr::MethodCall { .. } | Expr::Vararg { .. })) {
                    return Err(diagnostic(Some(self.previous()), DiagnosticCode::Parse, "too many returns").into());
                }
                Ok(Action::Complete(Value::Statement(Stmt::Return { values, span: self.finish(start) })))
            }
            StatementPhase::LocalCheck => {
                if self.take_keyword(Keyword::Function) { return Ok(next(StatementPhase::LocalFunctionName)); }
                if self.profile == LanguageProfile::Lua55 && self.take_symbol(Symbol::Less) {
                    return Ok(next(StatementPhase::LocalPrefixName));
                }
                Ok(next(StatementPhase::LocalNames { prefix: None }))
            }
            StatementPhase::LocalPrefixName => {
                let current = self.current().ok_or_else(|| self.error("預期名稱"))?;
                let marker = Token { kind: current.kind, span: current.span, start: current.start,
                    end: current.end, literal: None };
                let attribute = self.name()?;
                Ok(next(StatementPhase::LocalPrefixEnd { attribute, marker }))
            }
            StatementPhase::LocalPrefixEnd { attribute, marker } => {
                self.expect_symbol(Symbol::Greater)?;
                Ok(next(StatementPhase::LocalPrefixValidated {
                    attribute, span: self.previous().span, marker,
                }))
            }
            StatementPhase::LocalPrefixValidated { attribute, marker, span } => {
                let prefix = Some(Attribute { name: attribute, span: join(marker.span, span) });
                if let Err(message) = classify_attribute(prefix.as_ref(), false) {
                    if let Some(attribute) = prefix.as_ref() {
                        self.record_attribute_failure(attribute, false);
                    }
                    return Err(diagnostic(Some(&marker), DiagnosticCode::Parse, message).into());
                }
                Ok(next(StatementPhase::LocalNames { prefix }))
            }
            StatementPhase::LocalNames { prefix } => {
                Ok(push(StatementPhase::LocalValuesCheck,
                    Frame::Declarations(DeclarationFrame { local: true, prefix,
                        names: self.new_list(), phase: DeclarationPhase::Name })))
            }
            StatementPhase::LocalValuesCheck => {
                let names = self.take_names()?;
                if self.take_symbol(Symbol::Assign) {
                    Ok(push(StatementPhase::LocalValues { names }, self.list_frame(0)))
                } else {
                    for name in &names {
                        self.emit(context, MeaningEvent::Declare { name,
                            attribute: name.attribute.as_ref(), kind: BindingKind::Local,
                            readonly: false }, recovery)?;
                    }
                    Ok(Action::Complete(Value::Statement(Stmt::Local {
                        names, values: self.new_list(), span: self.finish(start),
                    })))
                }
            }
            StatementPhase::LocalValues { names } => {
                let values = self.take_expressions()?;
                for name in &names {
                    self.emit(context, MeaningEvent::Declare { name,
                        attribute: name.attribute.as_ref(), kind: BindingKind::Local,
                        readonly: false }, recovery)?;
                }
                Ok(Action::Complete(Value::Statement(Stmt::Local { names, values, span: self.finish(start) })))
            }
            StatementPhase::LocalFunctionName => {
                let span = self.span();
                let name = self.name()?;
                self.reserve_node::<R>()?;
                let name = LocalName { name, attribute: None, span };
                self.emit(context, MeaningEvent::Declare { name: &name, attribute: None,
                    kind: BindingKind::LocalFunction, readonly: false }, recovery)?;
                Ok(push(StatementPhase::LocalFunctionParams { name }, self.params_frame()))
            }
            StatementPhase::LocalFunctionParams { name } => {
                let (params, vararg) = self.take_parameters()?;
                self.emit(context, MeaningEvent::EnterFunction {
                    parameters: &params, vararg: vararg.as_ref().and_then(|value| value.table_name.as_ref()),
                    variadic: vararg.is_some(), method: None, span: start,
                }, recovery)?;
                Ok(push(StatementPhase::LocalFunctionBody { name, params, vararg }, self.function_block_frame()))
            }
            StatementPhase::LocalFunctionBody { name, params, vararg } => {
                let body = self.take_block()?;
                Ok(next(StatementPhase::LocalFunctionEnd { name, params, vararg, body }))
            }
            StatementPhase::LocalFunctionEnd { name, params, vararg, body } => {
                self.expect_keyword(Keyword::End)?;
                let span = self.finish(start);
                Ok(next(StatementPhase::LocalFunctionAfterEnd { name, params, vararg, body, span }))
            }
            StatementPhase::LocalFunctionAfterEnd { name, params, vararg, body, span } => {
                self.emit(context, MeaningEvent::LeaveFunction(span), recovery)?;
                Ok(Action::Complete(Value::Statement(Stmt::LocalFunction {
                    name, body: FunctionBody { parameters: params, vararg, body, span }, span,
                })))
            }
            StatementPhase::GlobalPrefixCheck => {
                if self.take_symbol(Symbol::Less) {
                    let span = self.span();
                    return Ok(next(StatementPhase::GlobalPrefixName { span }));
                }
                Ok(next(StatementPhase::GlobalKind { prefix: None }))
            }
            StatementPhase::GlobalPrefixName { span } => {
                let attribute = self.name()?;
                Ok(next(StatementPhase::GlobalPrefixEnd { attribute, span }))
            }
            StatementPhase::GlobalPrefixEnd { attribute, span } => {
                self.expect_symbol(Symbol::Greater)?;
                Ok(next(StatementPhase::GlobalPrefixValidated {
                    attribute, span, end: self.previous().span,
                }))
            }
            StatementPhase::GlobalPrefixValidated { attribute, span, end } => {
                let prefix = Some(Attribute { name: attribute, span: join(span, end) });
                if let Err(message) = classify_attribute(prefix.as_ref(), true) {
                    if let Some(attribute) = prefix.as_ref() {
                        self.record_attribute_failure(attribute, true);
                    }
                    let token = self.tokens.as_slice().iter()
                        .find(|token| token.span.start_byte == span.start_byte);
                    return Err(diagnostic(token, DiagnosticCode::Parse, message).into());
                }
                Ok(next(StatementPhase::GlobalKind { prefix }))
            }
            StatementPhase::GlobalKind { prefix } => {
                if self.take_symbol(Symbol::Star) {
                    let span = self.finish(start);
                    self.emit(context, MeaningEvent::WildcardGlobalMode {
                        attribute: prefix.as_ref(), span }, recovery)?;
                    self.reserve_node::<R>()?;
                    return Ok(Action::Complete(Value::Statement(Stmt::Global {
                        declaration: GlobalDeclaration::Star { prefix_attribute: prefix, span }, span,
                    })));
                }
                if self.take_keyword(Keyword::Function) {
                    if prefix.is_some() { return Err(self.error("global function 不接受前置 attribute")); }
                    return Ok(next(StatementPhase::GlobalFunctionName));
                }
                Ok(next(StatementPhase::GlobalNames { prefix }))
            }
            StatementPhase::GlobalNames { prefix } => {
                let inherited = prefix.clone();
                Ok(push(StatementPhase::GlobalValuesCheck { prefix },
                    Frame::Declarations(DeclarationFrame { local: false, prefix: inherited,
                        names: self.new_list(), phase: DeclarationPhase::Name })))
            }
            StatementPhase::GlobalValuesCheck { prefix } => {
                let names = self.take_names()?;
                if self.take_symbol(Symbol::Assign) {
                    Ok(next(StatementPhase::GlobalAfterEquals { names, prefix }))
                } else {
                    self.emit(context, MeaningEvent::NamedGlobalMode, recovery)?;
                    for name in &names {
                        self.emit(context, MeaningEvent::Declare { name,
                            attribute: name.attribute.as_ref().or(prefix.as_ref()),
                            kind: BindingKind::Global, readonly: false }, recovery)?;
                    }
                    let span = self.finish(start);
                    self.reserve_node::<R>()?;
                    Ok(Action::Complete(Value::Statement(Stmt::Global {
                        declaration: GlobalDeclaration::Names { names, values: self.new_list(), prefix_attribute: prefix, span }, span,
                    })))
                }
            }
            StatementPhase::GlobalAfterEquals { names, prefix } => {
                for name in &names {
                    self.emit(context, MeaningEvent::GlobalTarget {
                        name: &name.name, span: name.span }, recovery)?;
                }
                let level = names.len();
                Ok(push(StatementPhase::GlobalValues { names, prefix }, self.list_frame(level)))
            }
            StatementPhase::GlobalValues { names, prefix } => {
                let values = self.take_expressions()?;
                self.emit(context, MeaningEvent::NamedGlobalMode, recovery)?;
                for name in &names {
                    self.emit(context, MeaningEvent::Declare { name,
                        attribute: name.attribute.as_ref().or(prefix.as_ref()),
                        kind: BindingKind::Global, readonly: false }, recovery)?;
                }
                let span = self.finish(start);
                self.reserve_node::<R>()?;
                Ok(Action::Complete(Value::Statement(Stmt::Global {
                    declaration: GlobalDeclaration::Names { names, values, prefix_attribute: prefix, span }, span,
                })))
            }
            StatementPhase::GlobalFunctionName => {
                let span = self.span();
                let name = self.name()?;
                Ok(next(StatementPhase::GlobalFunctionAfterName { name, span }))
            }
            StatementPhase::GlobalFunctionAfterName { name, span } => {
                let local = LocalName { name: name.clone(), attribute: None, span };
                self.emit(context, MeaningEvent::NamedGlobalMode, recovery)?;
                self.emit(context, MeaningEvent::Declare { name: &local, attribute: None,
                    kind: BindingKind::Global, readonly: false }, recovery)?;
                self.emit(context, MeaningEvent::GlobalTarget { name: &name, span }, recovery)?;
                Ok(push(StatementPhase::GlobalFunctionParams { name }, self.params_frame()))
            }
            StatementPhase::GlobalFunctionParams { name } => {
                let (params, vararg) = self.take_parameters()?;
                self.emit(context, MeaningEvent::EnterFunction {
                    parameters: &params, vararg: vararg.as_ref().and_then(|value| value.table_name.as_ref()),
                    variadic: vararg.is_some(), method: None, span: start,
                }, recovery)?;
                Ok(push(StatementPhase::GlobalFunctionBody { name, params, vararg }, self.function_block_frame()))
            }
            StatementPhase::GlobalFunctionBody { name, params, vararg } => {
                let body = self.take_block()?;
                Ok(next(StatementPhase::GlobalFunctionEnd { name, params, vararg, body }))
            }
            StatementPhase::GlobalFunctionEnd { name, params, vararg, body } => {
                self.expect_keyword(Keyword::End)?;
                let span = self.finish(start);
                Ok(next(StatementPhase::GlobalFunctionAfterEnd { name, params, vararg, body, span }))
            }
            StatementPhase::GlobalFunctionAfterEnd { name, params, vararg, body, span } => {
                self.emit(context, MeaningEvent::LeaveFunction(span), recovery)?;
                self.reserve_node::<R>()?;
                Ok(Action::Complete(Value::Statement(Stmt::Global {
                    declaration: GlobalDeclaration::Function {
                        name, body: FunctionBody { parameters: params, vararg, body, span }, span,
                    }, span,
                })))
            }
            StatementPhase::TargetFirst => {
                let first = self.take_expression()?;
                let targets = self.one_list(first, recovery)?;
                Ok(next(StatementPhase::TargetMore { targets }))
            }
            StatementPhase::TargetMore { targets } => {
                if self.kind() == TokenKind::Symbol(Symbol::Comma) {
                    if targets.iter().any(|target| !is_assignable(target)) {
                        return Err(self.syntax_error(b"syntax error", "assignment 左側不可指派"));
                    }
                    if targets.len() == 1 { if let Some(target) = targets.last() {
                        self.emit(context, MeaningEvent::WriteTarget(target), recovery)?;
                    } }
                    self.consume();
                    if targets.len() >= self.limits.max_list_entries { return Err(self.limit("list 超過編譯限制")); }
                    let level = targets.len() - 1;
                    return Ok(push(StatementPhase::TargetNext { targets }, self.suffixed_frame(level)));
                }
                if self.kind() == TokenKind::Symbol(Symbol::Assign) {
                    if targets.iter().any(|target| !is_assignable(target)) {
                        return Err(self.syntax_error(b"syntax error", "assignment 左側不可指派"));
                    }
                    if targets.len() == 1 { if let Some(target) = targets.last() {
                        self.emit(context, MeaningEvent::WriteTarget(target), recovery)?;
                    } }
                    self.consume();
                    let level = targets.len() - 1;
                    return Ok(push(StatementPhase::AssignmentValues { targets }, self.list_frame(level)));
                }
                if targets.len() != 1 {
                    return Err(self.expected(TokenKind::Symbol(Symbol::Assign), None,
                        "只有函式呼叫可作獨立陳述式"));
                }
                let call = targets.into_iter().next().ok_or_else(|| self.error("parser target 狀態不完整"))?;
                if !matches!(call, Expr::Call { .. } | Expr::MethodCall { .. }) {
                    return Err(self.syntax_error(b"syntax error",
                        "只有函式呼叫可作獨立陳述式"));
                }
                Ok(Action::Complete(Value::Statement(Stmt::Call { call, span: self.finish(start) })))
            }
            StatementPhase::TargetNext { mut targets } => {
                let target = self.take_expression()?;
                self.emit(context, MeaningEvent::WriteTarget(&target), recovery)?;
                self.push_list(&mut targets, target, recovery)?;
                Ok(next(StatementPhase::TargetMore { targets }))
            }
            StatementPhase::AssignmentValues { targets } => {
                let values = self.take_expressions()?;
                Ok(Action::Complete(Value::Statement(Stmt::Assignment {
                    targets, values, span: self.finish(start),
                })))
            }
        }
    }

    fn expressions<R: AllocationRecovery>(&mut self, mut frame: ExpressionListFrame, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        match frame.phase {
            ListPhase::Start => {
                if frame.values.len() >= self.limits.max_list_entries { return Err(self.limit("list 超過編譯限制")); }
                frame.phase = ListPhase::AfterExpression;
                Ok(Action::Push(Frame::Expressions(frame), self.expr_frame(0, 1, false)))
            }
            ListPhase::AfterExpression => {
                let value = self.take_expression()?;
                self.push_list(&mut frame.values, value, recovery)?;
                frame.phase = ListPhase::Separator;
                Ok(Action::Continue(Frame::Expressions(frame)))
            }
            ListPhase::Separator => {
                if self.take_symbol(Symbol::Comma) {
                    frame.phase = ListPhase::Start;
                    Ok(Action::Continue(Frame::Expressions(frame)))
                } else { Ok(Action::Complete(Value::Expressions(frame.values))) }
            }
        }
    }

    fn parameters<R: AllocationRecovery>(&mut self, mut frame: ParameterFrame, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        match frame.phase {
            ParameterPhase::Open => {
                self.expect_symbol(Symbol::OpenParen)?;
                frame.phase = ParameterPhase::Check { allow_empty: true };
                Ok(Action::Continue(Frame::Parameters(frame)))
            }
            ParameterPhase::Check { allow_empty } => {
                if allow_empty && self.take_symbol(Symbol::CloseParen) {
                    return Ok(Action::Complete(Value::Parameters(frame.params, frame.vararg)));
                }
                if frame.params.len() >= self.limits.max_parameters { return Err(self.limit("參數超過編譯限制")); }
                if self.take_symbol(Symbol::Vararg) {
                    frame.phase = ParameterPhase::VarargName { span: self.previous().span };
                } else { frame.phase = ParameterPhase::Name; }
                Ok(Action::Continue(Frame::Parameters(frame)))
            }
            ParameterPhase::Name => {
                let span = self.span();
                let name = self.name()?;
                self.reserve_node::<R>()?;
                self.push_list(&mut frame.params, LocalName { name, attribute: None, span }, recovery)?;
                frame.phase = ParameterPhase::Separator;
                Ok(Action::Continue(Frame::Parameters(frame)))
            }
            ParameterPhase::Separator => {
                if self.take_symbol(Symbol::Comma) {
                    frame.phase = ParameterPhase::Check { allow_empty: false };
                } else {
                    self.expect_symbol(Symbol::CloseParen)?;
                    return Ok(Action::Complete(Value::Parameters(frame.params, frame.vararg)));
                }
                Ok(Action::Continue(Frame::Parameters(frame)))
            }
            ParameterPhase::VarargName { span } => {
                let table_name = if self.kind() == TokenKind::Name {
                    if !self.profile.rules().named_vararg { return Err(self.error("具名 vararg table 僅支援 lua55")); }
                    let name_span = self.span();
                    Some(LocalName { name: self.name()?, attribute: None, span: name_span })
                } else { None };
                self.reserve_node::<R>()?;
                frame.vararg = Some(Vararg { table_name, span });
                frame.phase = ParameterPhase::VarargClose;
                Ok(Action::Continue(Frame::Parameters(frame)))
            }
            ParameterPhase::VarargClose => {
                self.expect_symbol(Symbol::CloseParen)?;
                Ok(Action::Complete(Value::Parameters(frame.params, frame.vararg)))
            }
        }
    }

    fn function_name<C: MeaningContext, R: MeaningMeter>(&mut self, mut frame: FunctionNameFrame,
        context: &mut C, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        let phase = core::mem::replace(&mut frame.phase, FunctionNamePhase::Check);
        match phase {
            FunctionNamePhase::First => {
                let span = self.span();
                let name = self.name()?;
                frame.phase = FunctionNamePhase::FirstAfterToken { name, span };
                Ok(Action::Continue(Frame::FunctionName(frame)))
            }
            FunctionNamePhase::FirstAfterToken { name, span } => {
                self.emit(context, MeaningEvent::Name { name: &name, span }, recovery)?;
                frame.value = Some(Expr::Name { name, span });
                frame.phase = FunctionNamePhase::Check;
                Ok(Action::Continue(Frame::FunctionName(frame)))
            }
            FunctionNamePhase::Check => {
                if self.take_symbol(Symbol::Dot) { frame.phase = FunctionNamePhase::DotName; }
                else if self.take_symbol(Symbol::Colon) {
                    frame.phase = FunctionNamePhase::ColonName { colon: self.previous().span };
                } else {
                    let value = frame.value.ok_or_else(|| self.error("parser function name 狀態不完整"))?;
                    return Ok(Action::Complete(Value::FunctionName(value, frame.method)));
                }
                Ok(Action::Continue(Frame::FunctionName(frame)))
            }
            FunctionNamePhase::DotName => {
                let span = self.span();
                let name = self.name()?;
                let value = frame.value.take().ok_or_else(|| self.error("parser function name 狀態不完整"))?;
                frame.value = Some(Expr::Field { span: join(value.span(), span),
                    base: self.box_expr(value, recovery)?, name });
                frame.phase = FunctionNamePhase::Check;
                Ok(Action::Continue(Frame::FunctionName(frame)))
            }
            FunctionNamePhase::ColonName { colon } => {
                let span = self.span();
                let name = self.name()?;
                let value = frame.value.take().ok_or_else(|| self.error("parser function name 狀態不完整"))?;
                frame.method = Some(MethodName { name: name.clone(), colon_span: colon, span });
                let value = Expr::Field { span: join(value.span(), span),
                    base: self.box_expr(value, recovery)?, name };
                Ok(Action::Complete(Value::FunctionName(value, frame.method)))
            }
        }
    }

    fn declarations<C: MeaningContext, R: MeaningMeter>(&mut self, mut frame: DeclarationFrame,
        context: &mut C, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        let phase = core::mem::replace(&mut frame.phase, DeclarationPhase::Separator);
        match phase {
            DeclarationPhase::Name => {
                if frame.names.is_empty() {
                    self.emit(context, MeaningEvent::BeginDeclarations, recovery)?;
                }
                if frame.names.len() >= self.limits.max_list_entries { return Err(self.limit("list 超過編譯限制")); }
                let start = self.span();
                let name = self.name()?;
                frame.phase = DeclarationPhase::AttributeCheck { name, start };
                Ok(Action::Continue(Frame::Declarations(frame)))
            }
            DeclarationPhase::AttributeCheck { name, start } => {
                if self.take_symbol(Symbol::Less) {
                    frame.phase = DeclarationPhase::AttributeName { name, start, attr_start: self.span() };
                    return Ok(Action::Continue(Frame::Declarations(frame)));
                }
                let attr = if frame.local { frame.prefix.clone() } else { None };
                self.finish_declaration(&mut frame, name, start, attr, context, recovery)?;
                Ok(Action::Continue(Frame::Declarations(frame)))
            }
            DeclarationPhase::AttributeName { name, start, attr_start } => {
                let attr = self.name()?;
                frame.phase = DeclarationPhase::AttributeEnd { name, start, attr, attr_start };
                Ok(Action::Continue(Frame::Declarations(frame)))
            }
            DeclarationPhase::AttributeEnd { name, start, attr, attr_start } => {
                self.expect_symbol(Symbol::Greater)?;
                frame.phase = DeclarationPhase::AttributeResolved {
                    name, start, attribute: Attribute { name: attr, span: join(attr_start, self.previous().span) },
                };
                Ok(Action::Continue(Frame::Declarations(frame)))
            }
            DeclarationPhase::AttributeResolved { name, start, attribute } => {
                self.finish_declaration(&mut frame, name, start, Some(attribute), context, recovery)?;
                Ok(Action::Continue(Frame::Declarations(frame)))
            }
            DeclarationPhase::Separator => {
                if self.take_symbol(Symbol::Comma) {
                    frame.phase = DeclarationPhase::Name;
                    Ok(Action::Continue(Frame::Declarations(frame)))
                } else { Ok(Action::Complete(Value::Names(frame.names))) }
            }
        }
    }

    fn finish_declaration<C: MeaningContext, R: MeaningMeter>(&mut self, frame: &mut DeclarationFrame,
        name: AstName, start: Span, attribute: Option<Attribute>, context: &mut C,
        recovery: &mut R)
        -> Result<(), ParseError<R::Error>> {
        let effective = attribute.as_ref().or(frame.prefix.as_ref());
        if let Err(message) = classify_attribute(effective, !frame.local) {
            if let Some(attribute) = effective {
                self.record_attribute_failure(attribute, !frame.local);
            }
            let token = effective.and_then(|attribute| self.tokens.as_slice().iter()
                .find(|token| token.span.start_byte == attribute.span.start_byte));
            return Err(diagnostic(token, DiagnosticCode::Parse, message).into());
        }
        self.emit(context, MeaningEvent::DeclarationAttribute {
            attribute: effective, global: !frame.local, span: start,
        }, recovery)?;
        if frame.local && attribute.is_some() { self.reserve_node::<R>()?; }
        self.reserve_node::<R>()?;
        let span = if frame.local { self.finish(start) } else { start };
        self.push_list(&mut frame.names, LocalName { name, attribute, span }, recovery)?;
        frame.phase = DeclarationPhase::Separator;
        Ok(())
    }

    fn expression<C: MeaningContext, R: MeaningMeter>(&mut self, frame: ExpressionFrame,
        context: &mut C, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        let min = frame.min;
        let level = frame.level;
        let prefix_only = frame.prefix_only;
        let suffixed_only = frame.suffixed_only;
        let next = |phase| Action::Continue(Frame::Expression(ExpressionFrame {
            min, level, prefix_only, suffixed_only, phase,
        }));
        let push = |phase, child| Action::Push(Frame::Expression(ExpressionFrame {
            min, level, prefix_only, suffixed_only, phase,
        }), child);
        match frame.phase {
            ExpressionPhase::Start => {
                self.reserve_node::<R>()?;
                let token = self.current().ok_or_else(|| self.error("unexpected symbol"))?.clone();
                if suffixed_only && !matches!(token.kind, TokenKind::Name | TokenKind::Symbol(Symbol::OpenParen)) {
                    return Err(self.syntax_error(b"unexpected symbol",
                        "只有函式呼叫或可指派目標可作陳述式"));
                }
                match token.kind {
                    TokenKind::Name => {
                        let Some(Literal::Name(name)) = token.literal else { return Err(self.error("名稱 token 不完整")); };
                        self.consume();
                        Ok(next(ExpressionPhase::NameAfterToken { name, span: token.span }))
                    }
                    TokenKind::Integer | TokenKind::Float | TokenKind::String => {
                        self.consume();
                        let literal = token.literal.ok_or_else(|| self.error("literal token 不完整"))?;
                        Ok(self.prefix_done(min, level, prefix_only, suffixed_only, Expr::Literal { literal, span: token.span }))
                    }
                    TokenKind::Keyword(Keyword::Nil) => {
                        self.consume();
                        Ok(self.prefix_done(min, level, prefix_only, suffixed_only, Expr::Nil { span: token.span }))
                    }
                    TokenKind::Keyword(Keyword::True | Keyword::False) => {
                        self.consume();
                        Ok(self.prefix_done(min, level, prefix_only, suffixed_only, Expr::Bool {
                            value: token.kind == TokenKind::Keyword(Keyword::True), span: token.span,
                        }))
                    }
                    TokenKind::Symbol(Symbol::Vararg) => {
                        self.emit(context, MeaningEvent::CheckVararg(token.span), recovery)?;
                        self.consume();
                        Ok(self.prefix_done(min, level, prefix_only, suffixed_only, Expr::Vararg { span: token.span }))
                    }
                    TokenKind::Symbol(Symbol::Minus | Symbol::Hash | Symbol::Tilde) | TokenKind::Keyword(Keyword::Not) => {
                        let op = match token.kind {
                            TokenKind::Symbol(Symbol::Minus) => UnaryOp::Negate,
                            TokenKind::Symbol(Symbol::Hash) => UnaryOp::Length,
                            TokenKind::Symbol(Symbol::Tilde) => UnaryOp::BitNot,
                            _ => UnaryOp::Not,
                        };
                        self.consume();
                        Ok(push(ExpressionPhase::Unary { op, start: token.span }, self.expr_frame(12, 1, false)))
                    }
                    TokenKind::Symbol(Symbol::OpenParen) => {
                        self.consume();
                        Ok(push(ExpressionPhase::Paren { start: token.span }, self.expr_frame(0, 1, false)))
                    }
                    TokenKind::Symbol(Symbol::OpenBrace) =>
                        Ok(push(ExpressionPhase::Table, Frame::Table(TableFrame {
                            start: None, fields: self.new_list(), phase: TablePhase::Open,
                        }))),
                    TokenKind::Keyword(Keyword::Function) => {
                        self.consume();
                        Ok(push(ExpressionPhase::FunctionParams { start: token.span }, self.params_frame()))
                    }
                    _ => Err(self.syntax_error(b"unexpected symbol", "unexpected symbol")),
                }
            }
            ExpressionPhase::NameAfterToken { name, span } => {
                self.emit(context, MeaningEvent::Name { name: &name, span }, recovery)?;
                Ok(self.prefix_done(min, level, prefix_only, suffixed_only, Expr::Name { name, span }))
            }
            ExpressionPhase::Unary { op, start } => {
                let expression = self.take_expression()?;
                let span = join(start, expression.span());
                let expression = Expr::Unary { op, span, expression: self.box_expr(expression, recovery)? };
                Ok(self.prefix_done(min, level, prefix_only, suffixed_only, expression))
            }
            ExpressionPhase::Paren { start } => {
                let value = self.take_expression()?;
                Ok(next(ExpressionPhase::ParenEnd { start, value }))
            }
            ExpressionPhase::ParenEnd { start, value } => {
                self.expect_symbol(Symbol::CloseParen)?;
                let value = Expr::Paren { span: self.finish(start), expression: self.box_expr(value, recovery)? };
                Ok(self.prefix_done(min, level, prefix_only, suffixed_only, value))
            }
            ExpressionPhase::Table => {
                let value = self.take_expression()?;
                Ok(self.prefix_done(min, level, prefix_only, suffixed_only, value))
            }
            ExpressionPhase::FunctionParams { start } => {
                let (params, vararg) = self.take_parameters()?;
                self.emit(context, MeaningEvent::EnterFunction {
                    parameters: &params, vararg: vararg.as_ref().and_then(|value| value.table_name.as_ref()),
                    variadic: vararg.is_some(), method: None, span: start,
                }, recovery)?;
                Ok(push(ExpressionPhase::FunctionBody { start, params, vararg }, self.function_block_frame()))
            }
            ExpressionPhase::FunctionBody { start, params, vararg } => {
                let body = self.take_block()?;
                Ok(next(ExpressionPhase::FunctionEnd { start, params, vararg, body }))
            }
            ExpressionPhase::FunctionEnd { start, params, vararg, body } => {
                self.expect_keyword(Keyword::End)?;
                let span = self.finish(start);
                Ok(next(ExpressionPhase::FunctionAfterEnd { start, params, vararg, body, span }))
            }
            ExpressionPhase::FunctionAfterEnd { start: _, params, vararg, body, span } => {
                self.emit(context, MeaningEvent::LeaveFunction(span), recovery)?;
                self.reserve_node::<R>()?;
                Ok(self.prefix_done(min, level, prefix_only, suffixed_only,
                    Expr::Function { span, body: FunctionBody { parameters: params, vararg, body, span } }))
            }
            ExpressionPhase::Postfix { value } => {
                if !is_prefix_expr(&value) {
                    return if suffixed_only { Ok(Action::Complete(Value::Expression(value))) }
                        else { Ok(next(ExpressionPhase::Binary { value })) };
                }
                if self.take_symbol(Symbol::OpenParen) { return Ok(next(ExpressionPhase::CallCheck { value })); }
                if matches!(self.kind(), TokenKind::String | TokenKind::Symbol(Symbol::OpenBrace)) {
                    if self.limits.max_list_entries == 0 { return Err(self.limit("list 超過編譯限制")); }
                    return Ok(push(ExpressionPhase::Shorthand { value }, self.expr_frame(0, 0, true)));
                }
                if self.take_symbol(Symbol::Dot) { return Ok(next(ExpressionPhase::FieldName { value })); }
                if self.take_symbol(Symbol::OpenBracket) {
                    return Ok(push(ExpressionPhase::Index { value }, self.expr_frame(0, 1, false)));
                }
                if self.take_symbol(Symbol::Colon) { return Ok(next(ExpressionPhase::MethodName { value })); }
                if suffixed_only { Ok(Action::Complete(Value::Expression(value))) }
                else { Ok(next(ExpressionPhase::Binary { value })) }
            }
            ExpressionPhase::CallCheck { value } => {
                if self.take_symbol(Symbol::CloseParen) {
                    let value = self.make_call(value, self.new_list(), recovery)?;
                    return Ok(next(ExpressionPhase::Postfix { value }));
                }
                Ok(push(ExpressionPhase::CallArgs { value }, self.list_frame(0)))
            }
            ExpressionPhase::CallArgs { value } => {
                let args = self.take_expressions()?;
                Ok(next(ExpressionPhase::CallEnd { value, args }))
            }
            ExpressionPhase::CallEnd { value, args } => {
                self.expect_symbol(Symbol::CloseParen)?;
                let value = self.make_call(value, args, recovery)?;
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::Shorthand { value } => {
                let argument = self.take_expression()?;
                self.reserve_node::<R>()?;
                let span = join(value.span(), argument.span());
                let value = Expr::Call { span, callee: self.box_expr(value, recovery)?,
                    arguments: self.one_list(argument, recovery)? };
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::FieldName { value } => {
                let name = self.name()?;
                let span = join(value.span(), self.previous().span);
                let value = Expr::Field { span, base: self.box_expr(value, recovery)?, name };
                self.reserve_node::<R>()?;
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::Index { value } => {
                let index = self.take_expression()?;
                Ok(next(ExpressionPhase::IndexEnd { value, index }))
            }
            ExpressionPhase::IndexEnd { value, index } => {
                self.expect_symbol(Symbol::CloseBracket)?;
                let span = join(value.span(), self.previous().span);
                let value = Expr::Index { span, base: self.box_expr(value, recovery)?,
                    index: self.box_expr(index, recovery)? };
                self.reserve_node::<R>()?;
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::MethodName { value } => {
                let method = self.name()?;
                Ok(next(ExpressionPhase::MethodArgsCheck { value, method }))
            }
            ExpressionPhase::MethodArgsCheck { value, method } => {
                if self.take_symbol(Symbol::OpenParen) {
                    return Ok(next(ExpressionPhase::MethodParenCheck { value, method }));
                }
                if matches!(self.kind(), TokenKind::String | TokenKind::Symbol(Symbol::OpenBrace)) {
                    if self.limits.max_list_entries == 0 { return Err(self.limit("list 超過編譯限制")); }
                    return Ok(push(ExpressionPhase::MethodShorthand { value, method }, self.expr_frame(0, 0, true)));
                }
                Err(self.syntax_error(b"function arguments expected", "方法呼叫缺少引數"))
            }
            ExpressionPhase::MethodParenCheck { value, method } => {
                if self.take_symbol(Symbol::CloseParen) {
                    let value = self.make_method(value, method, self.new_list(), recovery)?;
                    return Ok(next(ExpressionPhase::Postfix { value }));
                }
                Ok(push(ExpressionPhase::MethodArgs { value, method }, self.list_frame(0)))
            }
            ExpressionPhase::MethodArgs { value, method } => {
                let args = self.take_expressions()?;
                Ok(next(ExpressionPhase::MethodEnd { value, method, args }))
            }
            ExpressionPhase::MethodEnd { value, method, args } => {
                self.expect_symbol(Symbol::CloseParen)?;
                let value = self.make_method(value, method, args, recovery)?;
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::MethodShorthand { value, method } => {
                let argument = self.take_expression()?;
                let args = self.one_list(argument, recovery)?;
                let value = self.make_method(value, method, args, recovery)?;
                Ok(next(ExpressionPhase::Postfix { value }))
            }
            ExpressionPhase::Binary { value } => {
                let Some((op, prec, right)) = binary(self.kind()) else {
                    return Ok(Action::Complete(Value::Expression(value)));
                };
                if prec < min { return Ok(Action::Complete(Value::Expression(value))); }
                self.consume();
                Ok(push(ExpressionPhase::BinaryRight { value, op },
                    self.expr_frame(if right { prec } else { prec + 1 }, 1, false)))
            }
            ExpressionPhase::BinaryRight { value, op } => {
                let right = self.take_expression()?;
                self.reserve_node::<R>()?;
                let span = join(value.span(), right.span());
                let value = Expr::Binary { op, span, left: self.box_expr(value, recovery)?,
                    right: self.box_expr(right, recovery)? };
                Ok(next(ExpressionPhase::Binary { value }))
            }
        }
    }

    fn prefix_done(&self, min: u8, level: usize, prefix_only: bool, suffixed_only: bool, value: Expr) -> Action {
        if prefix_only { Action::Complete(Value::Expression(value)) }
        else { Action::Continue(Frame::Expression(ExpressionFrame {
            min, level, prefix_only, suffixed_only, phase: ExpressionPhase::Postfix { value },
        })) }
    }

    fn make_call<R: AllocationRecovery>(&mut self, callee: Expr, arguments: AstVec<Expr>, recovery: &mut R)
        -> Result<Expr, ParseError<R::Error>> {
        let span = join(callee.span(), self.previous().span);
        let callee = self.box_expr(callee, recovery)?;
        self.reserve_node::<R>()?;
        Ok(Expr::Call { callee, arguments, span })
    }

    fn make_method<R: AllocationRecovery>(&mut self, receiver: Expr, method: AstName,
        arguments: AstVec<Expr>, recovery: &mut R) -> Result<Expr, ParseError<R::Error>> {
        let span = join(receiver.span(), self.previous().span);
        let receiver = self.box_expr(receiver, recovery)?;
        self.reserve_node::<R>()?;
        Ok(Expr::MethodCall { receiver, method, arguments, span })
    }

    fn table<R: AllocationRecovery>(&mut self, mut frame: TableFrame, recovery: &mut R)
        -> Result<Action, ParseError<R::Error>> {
        let phase = core::mem::replace(&mut frame.phase, TablePhase::Check);
        match phase {
            TablePhase::Open => {
                frame.start = Some(self.span());
                self.expect_symbol(Symbol::OpenBrace)?;
                frame.phase = TablePhase::Check;
                Ok(Action::Continue(Frame::Table(frame)))
            }
            TablePhase::Check => {
                if self.take_symbol(Symbol::CloseBrace) {
                    self.reserve_node::<R>()?;
                    let start = frame.start.ok_or_else(|| self.error("parser table 狀態不完整"))?;
                    return Ok(Action::Complete(Value::Expression(Expr::TableConstructor {
                        fields: frame.fields, span: self.finish(start),
                    })));
                }
                if self.kind() == TokenKind::Eof {
                    let opener = frame.start.and_then(|span| self.tokens.as_slice().iter()
                        .find(|token| token.span.start_byte == span.start_byte)
                        .map(|token| (token.kind, token.start.line)));
                    return Err(self.expected(TokenKind::Symbol(Symbol::CloseBrace), opener,
                        "缺少 table 結束符號"));
                }
                if frame.fields.len() >= self.limits.max_list_entries { return Err(self.limit("list 超過編譯限制")); }
                let start = self.span();
                if self.take_symbol(Symbol::OpenBracket) {
                    frame.phase = TablePhase::IndexedKey { start };
                    return Ok(Action::Push(Frame::Table(frame), self.expr_frame(0, 1, false)));
                }
                if self.kind() == TokenKind::Name {
                    frame.phase = TablePhase::NamedLookahead { start };
                    return Ok(Action::Continue(Frame::Table(frame)));
                }
                frame.phase = TablePhase::Value { start, kind: FieldKind::Array };
                Ok(Action::Push(Frame::Table(frame), self.expr_frame(0, 1, false)))
            }
            TablePhase::NamedLookahead { start } => {
                let lookahead = self.index.checked_add(1).ok_or_else(|| self.limit("token 數超過編譯限制"))?;
                let Some(token) = self.tokens.as_slice().get(lookahead) else {
                    frame.phase = TablePhase::NamedLookahead { start };
                    return Ok(Action::NeedToken(Frame::Table(frame)));
                };
                if token.kind == TokenKind::Symbol(Symbol::Assign) {
                    let name = self.name()?;
                    frame.phase = TablePhase::NamedAssign { start, name };
                    Ok(Action::Continue(Frame::Table(frame)))
                } else {
                    frame.phase = TablePhase::Value { start, kind: FieldKind::Array };
                    Ok(Action::Push(Frame::Table(frame), self.expr_frame(0, 1, false)))
                }
            }
            TablePhase::NamedAssign { start, name } => {
                self.expect_symbol(Symbol::Assign)?;
                frame.phase = TablePhase::Value { start, kind: FieldKind::Named(name) };
                Ok(Action::Push(Frame::Table(frame), self.expr_frame(0, 1, false)))
            }
            TablePhase::IndexedKey { start } => {
                let key = self.take_expression()?;
                frame.phase = TablePhase::IndexedClose { start, key };
                Ok(Action::Continue(Frame::Table(frame)))
            }
            TablePhase::IndexedClose { start, key } => {
                self.expect_symbol(Symbol::CloseBracket)?;
                frame.phase = TablePhase::IndexedAssign { start, key };
                Ok(Action::Continue(Frame::Table(frame)))
            }
            TablePhase::IndexedAssign { start, key } => {
                self.expect_symbol(Symbol::Assign)?;
                frame.phase = TablePhase::Value { start, kind: FieldKind::Indexed(key) };
                Ok(Action::Push(Frame::Table(frame), self.expr_frame(0, 1, false)))
            }
            TablePhase::Value { start, kind } => {
                let value = self.take_expression()?;
                self.reserve_node::<R>()?;
                let span = join(start, value.span());
                let field = match kind {
                    FieldKind::Array => TableField::Array { value, separator: None, span },
                    FieldKind::Named(name) => TableField::Named { name, value, separator: None, span },
                    FieldKind::Indexed(key) => TableField::Indexed { key, value, separator: None, span },
                };
                frame.phase = TablePhase::Separator { field };
                Ok(Action::Continue(Frame::Table(frame)))
            }
            TablePhase::Separator { mut field } => {
                if self.take_symbol(Symbol::Comma) {
                    field.set_separator(FieldSeparator::Comma);
                    self.push_list(&mut frame.fields, field, recovery)?;
                    frame.phase = TablePhase::Check;
                    return Ok(Action::Continue(Frame::Table(frame)));
                }
                if self.take_symbol(Symbol::Semicolon) {
                    field.set_separator(FieldSeparator::Semicolon);
                    self.push_list(&mut frame.fields, field, recovery)?;
                    frame.phase = TablePhase::Check;
                    return Ok(Action::Continue(Frame::Table(frame)));
                }
                self.expect_symbol(Symbol::CloseBrace)?;
                self.push_list(&mut frame.fields, field, recovery)?;
                self.reserve_node::<R>()?;
                let start = frame.start.ok_or_else(|| self.error("parser table 狀態不完整"))?;
                Ok(Action::Complete(Value::Expression(Expr::TableConstructor {
                    fields: frame.fields, span: self.finish(start),
                })))
            }
        }
    }
}

fn is_prefix_expr(expression: &Expr) -> bool {
    matches!(expression, Expr::Name { .. } | Expr::Paren { .. } | Expr::Index { .. }
        | Expr::Field { .. } | Expr::Call { .. } | Expr::MethodCall { .. })
}

fn is_assignable(expression: &Expr) -> bool {
    matches!(expression, Expr::Name { .. } | Expr::Field { .. } | Expr::Index { .. })
}

fn binary(kind: TokenKind) -> Option<(BinaryOp, u8, bool)> {
    let symbol = match kind {
        TokenKind::Keyword(Keyword::Or) => return Some((BinaryOp::Or, 1, false)),
        TokenKind::Keyword(Keyword::And) => return Some((BinaryOp::And, 2, false)),
        TokenKind::Symbol(symbol) => symbol,
        _ => return None,
    };
    Some(match symbol {
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

fn terminates(mask: u8, kind: TokenKind) -> bool {
    let TokenKind::Keyword(keyword) = kind else { return false; };
    let bit = match keyword {
        Keyword::End => 1, Keyword::Until => 2, Keyword::ElseIf => 4, Keyword::Else => 8,
        _ => 0,
    };
    mask & bit != 0
}

fn reserve_error<E>(error: ReserveError<E>) -> ParseError<E> {
    match error {
        ReserveError::Recovery(error) => ParseError::Recovery(error),
        ReserveError::AllocatorMismatch | ReserveError::CallbackRefused | ReserveError::AllocationFailed => ParseError::AllocationFailed,
    }
}
