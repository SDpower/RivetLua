//! 編譯器的分段資源准入；不依賴執行期的 ledger 或 VM。

use core::mem::size_of;

use crate::ast::{
    Block, Expr, FunctionBody, GlobalDeclaration, LocalName, Module, Stmt, TableField,
};
use crate::ir::{IrClosePath, IrConstant, IrModule, IrPrototype};
use crate::resolve::{
    ClosePath, ResolvedBlock, ResolvedExpr, ResolvedFunctionBody, ResolvedGlobalDeclaration,
    ResolvedLocalName, ResolvedModule, ResolvedName, ResolvedStmt, ResolvedTableField,
};
use crate::{CompileLimits, Diagnostic, IrError, LexedChunk, Literal};

/// 呼叫端將三種申報映射到自己的燃料與配置帳本。
pub trait CompileBudgetSink {
    type Error;

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error>;
    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error>;
    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error>;
}

#[derive(Debug)]
pub enum BudgetedCompileError<E> {
    Budget(E),
    Frontend(Diagnostic),
    Ir(IrError),
    Bytecode(rivetlua_core::BytecodeError),
    AdmissionOverflow,
    AdmissionUnderestimated,
}

fn add<E>(left: usize, right: usize) -> Result<usize, BudgetedCompileError<E>> {
    left.checked_add(right)
        .ok_or(BudgetedCompileError::AdmissionOverflow)
}

fn mul<E>(left: usize, right: usize) -> Result<usize, BudgetedCompileError<E>> {
    left.checked_mul(right)
        .ok_or(BudgetedCompileError::AdmissionOverflow)
}

fn admit<E, S: CompileBudgetSink<Error = E>>(
    sink: &mut S,
    work: usize,
    temporary: usize,
) -> Result<(), BudgetedCompileError<E>> {
    sink.spend_work(work)
        .map_err(BudgetedCompileError::Budget)?;
    sink.claim_temporary(temporary)
        .map_err(BudgetedCompileError::Budget)
}

fn literal_bytes(literal: &Literal) -> usize {
    match literal {
        Literal::Name(value) | Literal::String(value) => value.capacity(),
        Literal::Integer(_) | Literal::Float(_) => 0,
    }
}

fn lexed_allocation_bytes<E>(chunk: &LexedChunk) -> Result<usize, BudgetedCompileError<E>> {
    let mut bytes = mul(chunk.tokens.capacity(), size_of::<crate::Token>())?;
    for token in &chunk.tokens {
        if let Some(literal) = &token.literal {
            bytes = add(bytes, literal_bytes(literal))?;
        }
    }
    Ok(bytes)
}

fn lex_admission<E>(
    source_len: usize,
    limits: &CompileLimits,
) -> Result<(usize, usize), BudgetedCompileError<E>> {
    let bytes = source_len;
    let token_slots = add(bytes, 1)?;
    // 每個 token 至少消耗一個來源 byte（另有 EOF）。Vec::push 首次
    // 配置至少四個元素，其後成倍成長；單 byte literal 的 Vec 最小容量
    // 八個 bytes。n 個來源 bytes 至多形成 n 個 literal，payload 總長
    // 不超過 n；掃描中另有一個最多 n bytes 的 scratch literal。
    let token_storage = mul(mul(token_slots, 2)?.max(4), size_of::<crate::Token>())?;
    let literals = add(mul(bytes, 12)?, 8)?;
    let temporary = add(token_storage, literals)?;
    // cursor 每 byte 單調前進；long delimiter 的 lookahead 最壞在每個
    // 位置重看剩餘來源。逐 byte 掃描及 numeral/keyword passes 線性。
    // 另預付 EOF、lexed capacity 遍歷與下一段 parse_admission 對
    // token/literal 的遍歷；這些在 parser 自身的 admit 之前發生。
    let work = add(mul(bytes, bytes)?, mul(token_slots, 12)?)?;
    let _ = limits;
    Ok((work, temporary))
}

fn parse_admission<E>(
    chunk: &LexedChunk,
    limits: &CompileLimits,
) -> Result<(usize, usize, CompileLimits), BudgetedCompileError<E>> {
    let tokens = chunk.tokens.len();
    // 29 個 reserve_node 呼叫點中，非 root 的節點各由至少一個 token
    // 觸發；每一個 token 最多同時形成 statement/expression/list/field
    // 四種節點。以動態 node 限額封住編譯路徑；正常 parser 的限制仍保留。
    let node_ceiling = add(mul(tokens, 4)?, 4)?.min(limits.max_ast_nodes);
    let mut local_limits = *limits;
    local_limits.max_ast_nodes = node_ceiling;
    let maximum_literal = chunk
        .tokens
        .iter()
        .filter_map(|token| token.literal.as_ref())
        .map(literal_bytes)
        .max()
        .unwrap_or(0);
    let node_storage = size_of::<Stmt>()
        + size_of::<Expr>()
        + size_of::<Block>()
        + size_of::<FunctionBody>()
        + size_of::<TableField>()
        + size_of::<LocalName>()
        + size_of::<GlobalDeclaration>();
    // 每一容器族的最小 Vec 容量為四個元素，其後成倍成長；每一節點
    // 至多保留一個 Box/element，name/literal 處理期間至多四個副本。
    let per_node = add(mul(node_storage, 4)?, mul(maximum_literal.max(8), 4)?)?;
    let temporary = mul(node_ceiling, per_node)?;
    // parser 的 token cursor 單調前進；巢狀 Pratt 呼叫最多重看 token
    // 串流，任何列表最多走完整串流。實際 AST 遍歷也包含在此界內。
    let work = add(mul(tokens, tokens)?, add(mul(tokens, 8)?, node_ceiling)?)?;
    Ok((work, temporary, local_limits))
}

pub(crate) struct BudgetedFrontend {
    pub(crate) lexed: LexedChunk,
    pub(crate) ast: Module,
    pub(crate) ast_nodes: usize,
}

pub(crate) fn lex_parse_with_budget<S: CompileBudgetSink>(
    source: &[u8],
    profile: crate::LanguageProfile,
    limits: &CompileLimits,
    sink: &mut S,
) -> Result<BudgetedFrontend, BudgetedCompileError<S::Error>> {
    if source.len() > limits.max_source_bytes {
        return Err(BudgetedCompileError::Frontend(
            crate::lex(source, profile, limits).unwrap_err(),
        ));
    }
    let (work, temporary) = lex_admission(source.len(), limits)?;
    admit(sink, work, temporary)?;
    let lexed = crate::lex(source, profile, limits).map_err(BudgetedCompileError::Frontend)?;
    if lexed_allocation_bytes(&lexed)? > temporary {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    let (work, temporary, local_limits) = parse_admission(&lexed, limits)?;
    admit(sink, work, temporary)?;
    let (ast, ast_nodes) = crate::parser::parse_with_metrics(&lexed, profile, &local_limits)
        .map_err(BudgetedCompileError::Frontend)?;
    if ast_nodes > local_limits.max_ast_nodes || ast_allocation_bytes(&ast)? > temporary {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    Ok(BudgetedFrontend {
        lexed,
        ast,
        ast_nodes,
    })
}

struct AstMeter {
    bytes: usize,
}

impl AstMeter {
    fn vec<T, E>(&mut self, values: &Vec<T>) -> Result<(), BudgetedCompileError<E>> {
        self.bytes = add(self.bytes, mul(values.capacity(), size_of::<T>())?)?;
        Ok(())
    }

    fn name<E>(&mut self, value: &Vec<u8>) -> Result<(), BudgetedCompileError<E>> {
        self.bytes = add(self.bytes, value.capacity())?;
        Ok(())
    }

    fn local<E>(&mut self, local: &LocalName) -> Result<(), BudgetedCompileError<E>> {
        self.name(&local.name)?;
        if let Some(attribute) = &local.attribute {
            self.name(&attribute.name)?;
        }
        Ok(())
    }

    fn locals<E>(&mut self, locals: &Vec<LocalName>) -> Result<(), BudgetedCompileError<E>> {
        self.vec(locals)?;
        for local in locals {
            self.local(local)?;
        }
        Ok(())
    }

    fn expressions<E>(&mut self, values: &Vec<Expr>) -> Result<(), BudgetedCompileError<E>> {
        self.vec(values)?;
        for value in values {
            self.expression(value)?;
        }
        Ok(())
    }

    fn function<E>(&mut self, function: &FunctionBody) -> Result<(), BudgetedCompileError<E>> {
        self.locals(&function.parameters)?;
        if let Some(local) = function
            .vararg
            .as_ref()
            .and_then(|arg| arg.table_name.as_ref())
        {
            self.local(local)?;
        }
        self.block(&function.body)
    }

    fn block<E>(&mut self, block: &Block) -> Result<(), BudgetedCompileError<E>> {
        self.vec(&block.statements)?;
        for statement in &block.statements {
            self.statement(statement)?;
        }
        Ok(())
    }

    fn statement<E>(&mut self, statement: &Stmt) -> Result<(), BudgetedCompileError<E>> {
        match statement {
            Stmt::Empty { .. } | Stmt::Break { .. } => {}
            Stmt::Return { values, .. } => self.expressions(values)?,
            Stmt::Assignment {
                targets, values, ..
            } => {
                self.expressions(targets)?;
                self.expressions(values)?;
            }
            Stmt::Call { call, .. } => self.expression(call)?,
            Stmt::Local { names, values, .. } => {
                self.locals(names)?;
                self.expressions(values)?;
            }
            Stmt::Global { declaration, .. } => self.global(declaration)?,
            Stmt::Goto { name, .. } | Stmt::Label { name, .. } => self.name(name)?,
            Stmt::Do { body, .. } => self.block(body)?,
            Stmt::If {
                clauses,
                else_block,
                ..
            } => {
                self.vec(clauses)?;
                for (condition, body) in clauses {
                    self.expression(condition)?;
                    self.block(body)?;
                }
                if let Some(body) = else_block {
                    self.block(body)?;
                }
            }
            Stmt::While {
                condition, body, ..
            }
            | Stmt::Repeat {
                condition, body, ..
            } => {
                self.expression(condition)?;
                self.block(body)?;
            }
            Stmt::NumericFor {
                name,
                initial,
                limit,
                step,
                body,
                ..
            } => {
                self.local(name)?;
                self.expression(initial)?;
                self.expression(limit)?;
                if let Some(step) = step {
                    self.expression(step)?;
                }
                self.block(body)?;
            }
            Stmt::GenericFor {
                names,
                values,
                body,
                ..
            } => {
                self.locals(names)?;
                self.expressions(values)?;
                self.block(body)?;
            }
            Stmt::Function {
                name, method, body, ..
            } => {
                self.expression(name)?;
                if let Some(method) = method {
                    self.name(&method.name)?;
                }
                self.function(body)?;
            }
            Stmt::LocalFunction { name, body, .. } => {
                self.local(name)?;
                self.function(body)?;
            }
        }
        Ok(())
    }

    fn global<E>(
        &mut self,
        declaration: &GlobalDeclaration,
    ) -> Result<(), BudgetedCompileError<E>> {
        match declaration {
            GlobalDeclaration::Names {
                names,
                values,
                prefix_attribute,
                ..
            } => {
                self.locals(names)?;
                self.expressions(values)?;
                if let Some(attribute) = prefix_attribute {
                    self.name(&attribute.name)?;
                }
            }
            GlobalDeclaration::Star {
                prefix_attribute, ..
            } => {
                if let Some(attribute) = prefix_attribute {
                    self.name(&attribute.name)?;
                }
            }
            GlobalDeclaration::Function { name, body, .. } => {
                self.name(name)?;
                self.function(body)?;
            }
        }
        Ok(())
    }

    fn expression<E>(&mut self, expression: &Expr) -> Result<(), BudgetedCompileError<E>> {
        match expression {
            Expr::Literal { literal, .. } => self.bytes = add(self.bytes, literal_bytes(literal))?,
            Expr::Nil { .. } | Expr::Bool { .. } | Expr::Vararg { .. } => {}
            Expr::Name { name, .. } => self.name(name)?,
            Expr::Unary { expression, .. } | Expr::Paren { expression, .. } => {
                self.bytes = add(self.bytes, size_of::<Expr>())?;
                self.expression(expression)?;
            }
            Expr::Binary { left, right, .. }
            | Expr::Index {
                base: left,
                index: right,
                ..
            } => {
                self.bytes = add(self.bytes, mul(2, size_of::<Expr>())?)?;
                self.expression(left)?;
                self.expression(right)?;
            }
            Expr::Field { base, name, .. } => {
                self.bytes = add(self.bytes, size_of::<Expr>())?;
                self.expression(base)?;
                self.name(name)?;
            }
            Expr::Call {
                callee, arguments, ..
            } => {
                self.bytes = add(self.bytes, size_of::<Expr>())?;
                self.expression(callee)?;
                self.expressions(arguments)?;
            }
            Expr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                self.bytes = add(self.bytes, size_of::<Expr>())?;
                self.expression(receiver)?;
                self.name(method)?;
                self.expressions(arguments)?;
            }
            Expr::Function { body, .. } => self.function(body)?,
            Expr::TableConstructor { fields, .. } => {
                self.vec(fields)?;
                for field in fields {
                    match field {
                        TableField::Array { value, .. } => self.expression(value)?,
                        TableField::Named { name, value, .. } => {
                            self.name(name)?;
                            self.expression(value)?;
                        }
                        TableField::Indexed { key, value, .. } => {
                            self.expression(key)?;
                            self.expression(value)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn ast_allocation_bytes<E>(module: &Module) -> Result<usize, BudgetedCompileError<E>> {
    let mut meter = AstMeter { bytes: 0 };
    meter.block(&module.root)?;
    Ok(meter.bytes)
}

fn resolve_admission<E>(
    frontend: &BudgetedFrontend,
) -> Result<(usize, usize), BudgetedCompileError<E>> {
    let nodes = frontend.ast_nodes;
    let tokens = frontend.lexed.tokens.len();
    let functions = add(
        frontend
            .lexed
            .tokens
            .iter()
            .filter(|token| token.kind == crate::TokenKind::Keyword(crate::Keyword::Function))
            .count(),
        1,
    )?;
    let max_name = frontend
        .lexed
        .tokens
        .iter()
        .filter_map(|token| token.literal.as_ref())
        .map(literal_bytes)
        .max()
        .unwrap_or(0)
        .max(8);
    // 每個 resolved node 至多帶一個 owned name/list，以及一個 close
    // path；close path 可包含該 function 的所有 binding，故總量 O(N²)。
    // 每個 nested function 可複製 visible binding/access map，至多 F*N
    // 筆；HashMap bucket 上界包含空 bucket 與 name clone。
    let node_storage = size_of::<ResolvedStmt>()
        + size_of::<ResolvedExpr>()
        + size_of::<ResolvedBlock>()
        + size_of::<ResolvedFunctionBody>()
        + size_of::<ResolvedTableField>()
        + size_of::<ResolvedLocalName>()
        + size_of::<ResolvedGlobalDeclaration>();
    let owned_nodes = mul(nodes, add(mul(node_storage, 4)?, mul(max_name, 4)?)?)?;
    let close_lists = mul(mul(nodes, nodes)?, mul(size_of::<crate::BindingId>(), 8)?)?;
    let map_entry = add(
        size_of::<(Vec<u8>, crate::BindingId)>(),
        add(size_of::<(crate::BindingId, usize)>(), max_name)?,
    )?;
    let maps = mul(mul(nodes, functions)?, mul(map_entry, 8)?)?;
    let temporary = add(add(owned_nodes, close_lists)?, maps)?;
    // AST walk 每 node 一次；goto/label/close 與 binding lookup 各最多
    // N²，祖先 capture 由 F 層走過，每層至多再查 N 個 metadata。
    // N³ 同時覆蓋巢狀 scope 與 parent-visible map 的重複搜尋。
    let n2 = mul(nodes, nodes)?;
    let structural_work = add(
        add(mul(n2, nodes)?, mul(n2, functions)?)?,
        add(mul(tokens, nodes)?, 1)?,
    )?;
    // HashMap key hash/equality、name clone 和 label/goto 比較都會走
    // name bytes；一次最多 source_len bytes，次數受 N² + F*N 約束。
    let byte_work = mul(
        frontend.lexed.source_len,
        add(add(n2, mul(functions, nodes)?)?, 1)?,
    )?;
    let work = add(structural_work, byte_work)?;
    Ok((work, temporary))
}

pub(crate) struct BudgetedResolved {
    pub(crate) lexed: LexedChunk,
    pub(crate) resolved: ResolvedModule,
    pub(crate) ast_nodes: usize,
}

pub(crate) fn resolve_with_budget<S: CompileBudgetSink>(
    frontend: BudgetedFrontend,
    profile: crate::LanguageProfile,
    limits: &CompileLimits,
    sink: &mut S,
) -> Result<BudgetedResolved, BudgetedCompileError<S::Error>> {
    let (work, temporary) = resolve_admission(&frontend)?;
    admit(sink, work, temporary)?;
    let resolved = crate::resolve(&frontend.ast, &frontend.lexed, profile, limits)
        .map_err(BudgetedCompileError::Frontend)?;
    if resolved_allocation_bytes(&resolved)? > temporary {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    Ok(BudgetedResolved {
        lexed: frontend.lexed,
        resolved,
        ast_nodes: frontend.ast_nodes,
    })
}

impl AstMeter {
    fn close_path<E>(&mut self, path: &ClosePath) -> Result<(), BudgetedCompileError<E>> {
        self.vec(&path.bindings)?;
        self.vec(&path.exited_bindings)
    }

    fn resolved_local<E>(
        &mut self,
        local: &ResolvedLocalName,
    ) -> Result<(), BudgetedCompileError<E>> {
        self.name(&local.name)?;
        if let Some(attribute) = &local.attribute {
            self.name(&attribute.name)?;
        }
        Ok(())
    }

    fn resolved_locals<E>(
        &mut self,
        values: &Vec<ResolvedLocalName>,
    ) -> Result<(), BudgetedCompileError<E>> {
        self.vec(values)?;
        for value in values {
            self.resolved_local(value)?;
        }
        Ok(())
    }

    fn resolved_expressions<E>(
        &mut self,
        values: &Vec<ResolvedExpr>,
    ) -> Result<(), BudgetedCompileError<E>> {
        self.vec(values)?;
        for value in values {
            self.resolved_expression(value)?;
        }
        Ok(())
    }

    fn resolved_function<E>(
        &mut self,
        body: &ResolvedFunctionBody,
    ) -> Result<(), BudgetedCompileError<E>> {
        self.resolved_locals(&body.parameters)?;
        self.bytes = add(self.bytes, size_of::<ResolvedBlock>())?;
        self.resolved_block(&body.body)
    }

    fn resolved_block<E>(&mut self, block: &ResolvedBlock) -> Result<(), BudgetedCompileError<E>> {
        self.vec(&block.statements)?;
        for stmt in &block.statements {
            self.resolved_statement(stmt)?;
        }
        self.close_path(&block.normal_close_path)?;
        self.close_path(&block.error_close_path)
    }

    fn resolved_statement<E>(
        &mut self,
        stmt: &ResolvedStmt,
    ) -> Result<(), BudgetedCompileError<E>> {
        match stmt {
            ResolvedStmt::Empty { .. } => {}
            ResolvedStmt::Return {
                values, close_path, ..
            } => {
                self.resolved_expressions(values)?;
                self.close_path(close_path)?;
            }
            ResolvedStmt::Assignment {
                targets, values, ..
            } => {
                self.resolved_expressions(targets)?;
                self.resolved_expressions(values)?;
            }
            ResolvedStmt::Call { call, .. } => self.resolved_expression(call)?,
            ResolvedStmt::Local {
                bindings,
                names,
                values,
                ..
            } => {
                self.vec(bindings)?;
                self.resolved_locals(names)?;
                self.resolved_expressions(values)?;
            }
            ResolvedStmt::Global { declaration, .. } => self.resolved_global(declaration)?,
            ResolvedStmt::Break { close_path, .. } => self.close_path(close_path)?,
            ResolvedStmt::Goto {
                name, close_path, ..
            } => {
                self.name(name)?;
                self.close_path(close_path)?;
            }
            ResolvedStmt::Label { name, .. } => self.name(name)?,
            ResolvedStmt::Do { body, .. } => self.resolved_block(body)?,
            ResolvedStmt::If {
                clauses,
                else_block,
                ..
            } => {
                self.vec(clauses)?;
                for clause in clauses {
                    self.resolved_expression(&clause.condition)?;
                    self.resolved_block(&clause.body)?;
                }
                if let Some(body) = else_block {
                    self.resolved_block(body)?;
                }
            }
            ResolvedStmt::While {
                condition, body, ..
            }
            | ResolvedStmt::Repeat {
                condition, body, ..
            } => {
                self.resolved_expression(condition)?;
                self.resolved_block(body)?;
            }
            ResolvedStmt::NumericFor {
                name,
                initial,
                limit,
                step,
                body,
                ..
            } => {
                self.resolved_local(name)?;
                self.resolved_expression(initial)?;
                self.resolved_expression(limit)?;
                if let Some(step) = step {
                    self.resolved_expression(step)?;
                }
                self.resolved_block(body)?;
            }
            ResolvedStmt::GenericFor {
                names,
                values,
                body,
                close_path,
                ..
            } => {
                self.resolved_locals(names)?;
                self.resolved_expressions(values)?;
                self.resolved_block(body)?;
                self.close_path(close_path)?;
            }
            ResolvedStmt::Function {
                name, method, body, ..
            } => {
                self.resolved_expression(name)?;
                if let Some(method) = method {
                    self.name(&method.name)?;
                }
                self.resolved_function(body)?;
            }
            ResolvedStmt::LocalFunction { name, body, .. } => {
                self.resolved_local(name)?;
                self.resolved_function(body)?;
            }
        }
        Ok(())
    }

    fn resolved_global<E>(
        &mut self,
        global: &ResolvedGlobalDeclaration,
    ) -> Result<(), BudgetedCompileError<E>> {
        match global {
            ResolvedGlobalDeclaration::Names {
                names,
                values,
                prefix_attribute,
                ..
            } => {
                self.resolved_locals(names)?;
                self.resolved_expressions(values)?;
                if let Some(attribute) = prefix_attribute {
                    self.name(&attribute.name)?;
                }
            }
            ResolvedGlobalDeclaration::Star {
                prefix_attribute, ..
            } => {
                if let Some(attribute) = prefix_attribute {
                    self.name(&attribute.name)?;
                }
            }
            ResolvedGlobalDeclaration::Function { name, body, .. } => {
                self.name(name)?;
                self.resolved_function(body)?;
            }
        }
        Ok(())
    }

    fn resolved_expression<E>(
        &mut self,
        expression: &ResolvedExpr,
    ) -> Result<(), BudgetedCompileError<E>> {
        match expression {
            ResolvedExpr::Literal { literal, .. } => {
                self.bytes = add(self.bytes, literal_bytes(literal))?
            }
            ResolvedExpr::Nil { .. } | ResolvedExpr::Bool { .. } | ResolvedExpr::Vararg { .. } => {}
            ResolvedExpr::Name {
                name, resolution, ..
            } => {
                self.name(name)?;
                if let ResolvedName::EnvField { name, .. } = resolution {
                    self.name(name)?;
                }
            }
            ResolvedExpr::Unary { expression, .. } | ResolvedExpr::Paren { expression, .. } => {
                self.bytes = add(self.bytes, size_of::<ResolvedExpr>())?;
                self.resolved_expression(expression)?;
            }
            ResolvedExpr::Binary { left, right, .. }
            | ResolvedExpr::Index {
                base: left,
                index: right,
                ..
            } => {
                self.bytes = add(self.bytes, mul(2, size_of::<ResolvedExpr>())?)?;
                self.resolved_expression(left)?;
                self.resolved_expression(right)?;
            }
            ResolvedExpr::Field { base, name, .. } => {
                self.bytes = add(self.bytes, size_of::<ResolvedExpr>())?;
                self.resolved_expression(base)?;
                self.name(name)?;
            }
            ResolvedExpr::Call {
                callee, arguments, ..
            } => {
                self.bytes = add(self.bytes, size_of::<ResolvedExpr>())?;
                self.resolved_expression(callee)?;
                self.resolved_expressions(arguments)?;
            }
            ResolvedExpr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                self.bytes = add(self.bytes, size_of::<ResolvedExpr>())?;
                self.resolved_expression(receiver)?;
                self.name(method)?;
                self.resolved_expressions(arguments)?;
            }
            ResolvedExpr::Function { body, .. } => self.resolved_function(body)?,
            ResolvedExpr::TableConstructor { fields, .. } => {
                self.vec(fields)?;
                for field in fields {
                    match field {
                        ResolvedTableField::Array { value, .. } => {
                            self.resolved_expression(value)?
                        }
                        ResolvedTableField::Named { name, value, .. } => {
                            self.name(name)?;
                            self.resolved_expression(value)?;
                        }
                        ResolvedTableField::Indexed { key, value, .. } => {
                            self.resolved_expression(key)?;
                            self.resolved_expression(value)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

fn resolved_allocation_bytes<E>(module: &ResolvedModule) -> Result<usize, BudgetedCompileError<E>> {
    let mut meter = AstMeter { bytes: 0 };
    meter.vec(&module.functions)?;
    for function in &module.functions {
        meter.vec(&function.bindings)?;
        for binding in &function.bindings {
            meter.name(&binding.name)?;
            if let Some(attribute) = &binding.attribute {
                meter.name(&attribute.name)?;
            }
        }
        meter.vec(&function.upvalues)?;
    }
    meter.resolved_block(&module.root)?;
    Ok(meter.bytes)
}

fn lower_admission<E>(
    resolved: &BudgetedResolved,
    limits: &rivetlua_core::IrLimits,
) -> Result<(usize, usize, rivetlua_core::IrLimits), BudgetedCompileError<E>> {
    let nodes = resolved.ast_nodes;
    let functions = resolved.resolved.functions.len();
    let bindings = resolved
        .resolved
        .functions
        .iter()
        .try_fold(0usize, |sum, function| add(sum, function.bindings.len()))?;
    let max_name = resolved
        .lexed
        .tokens
        .iter()
        .filter_map(|token| token.literal.as_ref())
        .map(literal_bytes)
        .max()
        .unwrap_or(0)
        .max(8);
    // Builder 每個 AST node 的固定 opcode 產生點少於 32；close 操作
    // 可逐一處理當前 function 中的每個 binding。以現有 emit 限額先
    // 約束輸出，編譯期驗證不會在申報之外附加新 opcode。
    let close_events = mul(nodes, add(bindings, 1)?)?;
    let structural_ceiling = add(mul(close_events, 32)?, mul(functions, 8)?)?;
    let instruction_ceiling = structural_ceiling.min(mul(functions, limits.max_instructions)?);
    let mut local_limits = *limits;
    local_limits.max_instructions = structural_ceiling.min(limits.max_instructions);
    let instruction_storage = mul(
        mul(instruction_ceiling, 2)?,
        size_of::<crate::ir::IrInstruction>(),
    )?;
    let constant_storage = mul(
        mul(add(instruction_ceiling, functions)?, 2)?,
        add(size_of::<IrConstant>(), max_name)?,
    )?;
    let close_unit = add(
        size_of::<IrClosePath>(),
        mul(
            bindings,
            add(
                size_of::<crate::BindingId>(),
                size_of::<rivetlua_core::Register>(),
            )?,
        )?,
    )?;
    let close_storage = mul(mul(close_events, 4)?, close_unit)?;
    let prototypes = mul(functions.max(4), mul(size_of::<IrPrototype>(), 4)?)?;
    let scratch = mul(
        nodes.max(4),
        mul(
            add(crate::codegen::lower_scratch_unit_bytes(), max_name)?,
            4,
        )?,
    )?;
    let metadata_unit = add(
        size_of::<crate::ir::IrUpvalue>(),
        add(size_of::<crate::ir::IrNativeLocal>(), max_name)?,
    )?;
    let metadata = mul(mul(functions, add(bindings, 1)?)?, mul(metadata_unit, 4)?)?;
    // lower 首先複製 P04 functions metadata，並與輸出的 IR 和 builder
    // scratch 同時存活；以整個已測量 ResolvedModule 覆蓋此複本。
    let function_clone = resolved_allocation_bytes(&resolved.resolved)?;
    let temporary = add(
        add(
            add(instruction_storage, constant_storage)?,
            add(close_storage, prototypes)?,
        )?,
        add(add(scratch, metadata)?, function_clone)?,
    )?;
    let n2 = mul(nodes, nodes)?;
    let structural_work = add(
        add(mul(n2, nodes)?, mul(n2, add(functions, 1)?)?)?,
        add(
            mul(instruction_ceiling, add(add(nodes, bindings)?, functions)?)?,
            1,
        )?,
    )?;
    // functions.clone()、label/goto name 與 constant name 複製按實際
    // source bytes 計；一次比較/複製最多 source_len，數量至多 N²+F*N。
    let byte_work = mul(
        resolved.lexed.source_len,
        add(add(n2, mul(functions, nodes)?)?, 1)?,
    )?;
    let work = add(structural_work, byte_work)?;
    Ok((work, temporary, local_limits))
}

pub(crate) struct BudgetedIr {
    pub(crate) resolved: ResolvedModule,
    pub(crate) ir: IrModule,
}

pub(crate) fn lower_with_budget<S: CompileBudgetSink>(
    resolved: BudgetedResolved,
    limits: &rivetlua_core::IrLimits,
    sink: &mut S,
) -> Result<BudgetedIr, BudgetedCompileError<S::Error>> {
    let (work, temporary, local_limits) = lower_admission(&resolved, limits)?;
    admit(sink, work, temporary)?;
    let ir = crate::lower(&resolved.resolved, &local_limits).map_err(BudgetedCompileError::Ir)?;
    if ir_allocation_bytes(&ir)? > temporary {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    Ok(BudgetedIr {
        resolved: resolved.resolved,
        ir,
    })
}

fn ir_close_path<E>(
    meter: &mut AstMeter,
    close: &IrClosePath,
) -> Result<(), BudgetedCompileError<E>> {
    meter.vec(&close.bindings)?;
    meter.vec(&close.registers)
}

fn ir_allocation_bytes<E>(module: &IrModule) -> Result<usize, BudgetedCompileError<E>> {
    let mut meter = AstMeter { bytes: 0 };
    meter.vec(&module.function_prototypes)?;
    meter.vec(&module.prototypes)?;
    for prototype in &module.prototypes {
        meter.vec(&prototype.binding_registers)?;
        meter.vec(&prototype.constants)?;
        for constant in &prototype.constants {
            match constant {
                IrConstant::Literal(literal) => {
                    meter.bytes = add(meter.bytes, literal_bytes(literal))?
                }
                IrConstant::Name(name) => meter.name(name)?,
                IrConstant::Boolean(_) => {}
            }
        }
        meter.vec(&prototype.upvalues)?;
        meter.vec(&prototype.instructions)?;
        for instruction in &prototype.instructions {
            if let Some(close) = &instruction.close_path {
                ir_close_path(&mut meter, close)?;
            }
        }
        meter.vec(&prototype.close_paths)?;
        for close in &prototype.close_paths {
            ir_close_path(&mut meter, close)?;
        }
        if let Some(debug) = &prototype.native_debug {
            meter.vec(&debug.locals)?;
        }
        meter.vec(&prototype.native_list_writes)?;
    }
    Ok(meter.bytes)
}

fn vec_upper<E>(len: usize, element_size: usize) -> Result<usize, BudgetedCompileError<E>> {
    if len == 0 {
        return Ok(0);
    }
    mul(mul(len, 2)?.max(4), element_size)
}

fn close_candidate_upper<E>(close: &IrClosePath) -> Result<usize, BudgetedCompileError<E>> {
    add(
        size_of::<rivetlua_core::BytecodeClosePath>(),
        add(
            vec_upper(
                close.bindings.len(),
                size_of::<rivetlua_core::BytecodeBindingId>(),
            )?,
            vec_upper(close.registers.len(), size_of::<rivetlua_core::Register>())?,
        )?,
    )
}

fn candidate_upper<E>(ir: &IrModule) -> Result<usize, BudgetedCompileError<E>> {
    let mut total = add(
        size_of::<rivetlua_core::BytecodeModule>(),
        add(
            vec_upper(
                ir.prototypes.len(),
                size_of::<rivetlua_core::BytecodePrototype>(),
            )?,
            vec_upper(
                ir.function_prototypes.len(),
                size_of::<(u32, rivetlua_core::ProtoId)>(),
            )?,
        )?,
    )?;
    for proto in &ir.prototypes {
        let arrays = [
            vec_upper(
                proto.binding_registers.len(),
                size_of::<(rivetlua_core::BytecodeBindingId, rivetlua_core::Register)>(),
            )?,
            vec_upper(
                proto.constants.len(),
                size_of::<rivetlua_core::BytecodeConstant>(),
            )?,
            vec_upper(
                proto.upvalues.len(),
                size_of::<rivetlua_core::BytecodeUpvalue>(),
            )?,
            vec_upper(
                proto.instructions.len(),
                size_of::<rivetlua_core::BytecodeInstruction>(),
            )?,
            vec_upper(
                proto.close_paths.len(),
                size_of::<rivetlua_core::BytecodeClosePath>(),
            )?,
        ];
        for bytes in arrays {
            total = add(total, bytes)?;
        }
        for constant in &proto.constants {
            match constant {
                IrConstant::Literal(literal) => total = add(total, literal_bytes(literal))?,
                IrConstant::Name(name) => total = add(total, name.len())?,
                IrConstant::Boolean(_) => {}
            }
        }
        for close in &proto.close_paths {
            total = add(total, close_candidate_upper(close)?)?;
        }
        for instruction in &proto.instructions {
            if let Some(close) = &instruction.close_path {
                total = add(total, close_candidate_upper(close)?)?;
            }
        }
    }
    Ok(total)
}

pub(crate) struct BudgetedCandidate {
    pub(crate) resolved: ResolvedModule,
    pub(crate) ir: IrModule,
    pub(crate) bytecode: rivetlua_core::BytecodeModule,
}

pub(crate) fn candidate_with_budget<S: CompileBudgetSink>(
    lowered: BudgetedIr,
    sink: &mut S,
) -> Result<BudgetedCandidate, BudgetedCompileError<S::Error>> {
    let upper = candidate_upper(&lowered.ir)?;
    // candidate clone、實際容量核對、wire 上界及後段 emit admission
    // 的唯讀掃描共至多四次走訪；每次所見元素/bytes 均包含於 upper。
    admit(sink, mul(upper, 4)?, upper)?;
    let bytecode =
        crate::codegen::bytecode_module(&lowered.ir).map_err(BudgetedCompileError::Bytecode)?;
    let actual = rivetlua_core::bytecode_module_allocation_bytes(&bytecode)
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    if actual > upper {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    Ok(BudgetedCandidate {
        resolved: lowered.resolved,
        ir: lowered.ir,
        bytecode,
    })
}

fn emit_admission<E>(
    candidate: &BudgetedCandidate,
    source: &[u8],
    chunk_name: &[u8],
) -> Result<(usize, usize, usize, usize), BudgetedCompileError<E>> {
    let wire = rivetlua_core::bytecode_wire_upper_bytes(&candidate.bytecode)
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    let base = rivetlua_core::bytecode_module_allocation_bytes(&candidate.bytecode)
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    let mut instructions = 0usize;
    let mut constants = 0usize;
    let mut bindings = 0usize;
    let mut upvalues = 0usize;
    let mut close_entries = 0usize;
    let mut helper_calls = 0usize;
    for proto in &candidate.ir.prototypes {
        instructions = add(instructions, proto.instructions.len())?;
        constants = add(constants, proto.constants.len())?;
        bindings = add(bindings, proto.binding_registers.len())?;
        upvalues = add(upvalues, proto.upvalues.len())?;
        helper_calls = add(helper_calls, proto.native_list_writes.len())?;
        for close in &proto.close_paths {
            close_entries = add(close_entries, close.bindings.len())?;
        }
        for instruction in &proto.instructions {
            if let Some(close) = &instruction.close_path {
                close_entries = add(close_entries, close.bindings.len())?;
            }
        }
    }
    let functions = candidate.ir.prototypes.len();
    let max_name = candidate
        .resolved
        .functions
        .iter()
        .flat_map(|function| function.bindings.iter())
        .map(|binding| binding.name.len())
        .max()
        .unwrap_or(0)
        .max(source.len());
    // debug candidate: source name、每個 prototype 的 lines/local/upvalue
    // 名稱；驗證衍生的 storage interval 最多 B*I，close group 最多 I，
    // 每個 close group 最多 B 個 operand。Arc header 與對齊另計。
    let debug_header = add(
        size_of::<rivetlua_core::NativeDebug>(),
        add(
            mul(2, size_of::<usize>())?,
            core::mem::align_of::<rivetlua_core::NativeDebug>(),
        )?,
    )?;
    let mut debug = add(debug_header, add(mul(chunk_name.len(), 2)?, 8)?)?;
    let debug_parts = [
        vec_upper(functions, size_of::<rivetlua_core::NativePrototypeDebug>())?,
        vec_upper(instructions, size_of::<u32>())?,
        vec_upper(bindings, size_of::<rivetlua_core::NativeLocal>())?,
        mul(bindings, max_name)?,
        vec_upper(upvalues, size_of::<Option<Vec<u8>>>())?,
        mul(upvalues, max_name)?,
        mul(
            functions,
            mul(
                4,
                size_of::<Vec<rivetlua_core::bytecode::native_debug::NativeStorageInterval>>(),
            )?,
        )?,
        mul(
            mul(bindings, instructions)?,
            mul(
                2,
                size_of::<rivetlua_core::bytecode::native_debug::NativeStorageInterval>(),
            )?,
        )?,
        vec_upper(
            instructions,
            size_of::<rivetlua_core::bytecode::native_debug::NativeCloseGroup>(),
        )?,
        mul(
            mul(close_entries, bindings.max(1))?,
            mul(2, size_of::<(rivetlua_core::Register, u16)>())?,
        )?,
    ];
    for part in debug_parts {
        debug = add(debug, part)?;
    }
    // native helper 計畫有每-prototype map/hidden slot 與逐 Call 的
    // 三個固定 input；候選和驗證暫存同時存活時再計入一次 peak。
    let plan = if helper_calls == 0 {
        0
    } else {
        let parts = [
            vec_upper(1, size_of::<rivetlua_core::OfficialPlanRootBinding>())?,
            vec_upper(
                functions,
                size_of::<rivetlua_core::OfficialPlanUpvalueMap>(),
            )?,
            mul(
                functions,
                vec_upper(
                    1,
                    size_of::<(rivetlua_core::OfficialPlanBuiltin, rivetlua_core::UpvalueId)>(),
                )?,
            )?,
            vec_upper(helper_calls, size_of::<rivetlua_core::OfficialPlanCall>())?,
            mul(
                helper_calls,
                vec_upper(3, size_of::<rivetlua_core::Register>())?,
            )?,
        ];
        parts.into_iter().try_fold(0usize, add)?
    };
    let arc_verified = add(
        mul(2, size_of::<usize>())?,
        core::mem::align_of::<rivetlua_core::VerifiedModule>(),
    )?;
    let verified_overhead = size_of::<rivetlua_core::VerifiedModule>()
        .checked_sub(size_of::<rivetlua_core::BytecodeModule>())
        .ok_or(BudgetedCompileError::AdmissionOverflow)?;
    let retained = add(
        add(add(base, verified_overhead)?, debug)?,
        add(plan, arc_verified)?,
    )?;
    // 三個 writer buffer（單一 proto、section、module）可同時存活，
    // 各個 Vec 最多成長到 2*wire。NumericFor gate 最多 I+Prepare，
    // 沿用 codec 實際核對的 768*I CFG/dominator 上界；Prepare/pair
    // 索引在進入 dominator 時仍存活，另依其實際核對預留 256*I。
    // debug line 起點
    // 暫存與其候選/驗證衍生資料、native plan 候選同時存活。
    let verifier_scratch = add(
        add(
            mul(instructions, 1024)?,
            mul(bindings, mul(8, size_of::<usize>())?)?,
        )?,
        add(
            mul(upvalues, mul(8, size_of::<usize>())?)?,
            mul(functions, mul(16, size_of::<usize>())?)?,
        )?,
    )?;
    let temporary = add(
        add(mul(wire, 6)?, verifier_scratch)?,
        add(
            add(debug, plan)?,
            mul(add(source.len(), 1)?, size_of::<usize>())?,
        )?,
    )?;
    // codec writer 每 byte 最多三份；verify 的 prototype/metadata/CFG
    // 順序搜尋由 P²、I²、B²、I*B 界住。NumericFor dominator 另有
    // codec 內部至多 128*I 的已限迴圈；debug/local/parent 名稱走訪
    // 另受來源 bytes 與 F/B/U 次數所界；native helper 驗證 C*I。
    let square = |value| mul::<E>(value, value);
    let structural = add(
        add(
            add(square(functions)?, square(instructions)?)?,
            square(bindings)?,
        )?,
        add(
            mul(instructions, bindings)?,
            mul(helper_calls, instructions)?,
        )?,
    )?;
    let debug_name_work = add(
        add(mul(source.len(), 4)?, chunk_name.len())?,
        add(
            mul(instructions, usize::BITS as usize)?,
            mul(mul(upvalues, functions)?, add(bindings, max_name)?)?,
        )?,
    )?;
    // 每個 local 的 CFG 最多 8*I state；每個 state 查 close group
    // 至多 I、每個 group operand 查 storage 至多 B，Closure capture
    // 至多掃 F+U。包含 Core 內部明定的 32*I/local 基本 charge。
    let per_local_cfg = add(
        mul(instructions, 32)?,
        mul(
            mul(instructions, 8)?,
            add(
                add(functions, upvalues)?,
                add(instructions, mul(bindings, bindings)?)?,
            )?,
        )?,
    )?;
    let debug_work = add(
        debug_name_work,
        add(
            mul(bindings, per_local_cfg)?,
            mul(bindings, mul(2, usize::BITS as usize)?)?,
        )?,
    )?;
    let helper_work = mul(mul(helper_calls, instructions)?, functions.max(1))?;
    let work = add(
        add(
            add(mul(wire, 12)?, mul(structural, 8)?)?,
            mul(instructions, 128)?,
        )?,
        add(add(debug_work, helper_work)?, constants)?,
    )?;
    Ok((work, temporary, retained, wire))
}

pub fn compile_with_budget<S: CompileBudgetSink>(
    source: &[u8],
    chunk_name: &[u8],
    profile: crate::LanguageProfile,
    compile_limits: &CompileLimits,
    ir_limits: &rivetlua_core::IrLimits,
    verify_limits: &rivetlua_core::VerifyLimits,
    sink: &mut S,
) -> Result<rivetlua_core::VerifiedModule, BudgetedCompileError<S::Error>> {
    let frontend = lex_parse_with_budget(source, profile, compile_limits, sink)?;
    let resolved = resolve_with_budget(frontend, profile, compile_limits, sink)?;
    let lowered = lower_with_budget(resolved, ir_limits, sink)?;
    let candidate = candidate_with_budget(lowered, sink)?;
    let (work, temporary, retained, wire) = emit_admission(&candidate, source, chunk_name)?;
    admit(sink, work, temporary)?;
    sink.claim_module_allocation(retained)
        .map_err(BudgetedCompileError::Budget)?;
    let encoded = crate::codegen::emit_with_native_debug_candidate(
        &candidate.ir,
        &candidate.resolved,
        source,
        chunk_name,
        verify_limits,
        candidate.bytecode,
    )
    .map_err(BudgetedCompileError::Bytecode)?;
    let actual = rivetlua_core::verified_module_allocation_bytes(encoded.verified())
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    if actual > retained || encoded.encoded_bytes_capacity() > mul(wire, 2)? {
        return Err(BudgetedCompileError::AdmissionUnderestimated);
    }
    Ok(encoded.into_verified())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LanguageProfile;

    struct Probe {
        work: usize,
        temporary: usize,
        work_limit: usize,
        temporary_limit: usize,
    }

    impl Probe {
        fn unlimited() -> Self {
            Self {
                work: 0,
                temporary: 0,
                work_limit: usize::MAX,
                temporary_limit: usize::MAX,
            }
        }
    }

    impl CompileBudgetSink for Probe {
        type Error = ();

        fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
            self.work = self.work.checked_add(units).ok_or(())?;
            (self.work <= self.work_limit).then_some(()).ok_or(())
        }

        fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
            self.temporary = self.temporary.checked_add(bytes).ok_or(())?;
            (self.temporary <= self.temporary_limit)
                .then_some(())
                .ok_or(())
        }

        fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn lex_parse_admits_before_stage_and_checks_actual_capacity() {
        let samples: &[&[u8]] = &[
            b"",
            b"return 7",
            b"return 'a', 'b', 'c', 'd'",
            b"local x = {a=1, [2]='abc', 3}; return function(y) return x.a+y end",
            b"::again:: local x <close> = resource(); if x then goto again end",
            b"return [=[long ]==] string]=], 0x1.fp+2",
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for source in samples {
                let mut ample = Probe::unlimited();
                let result =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut ample);
                let frontend = result.unwrap();
                assert!(frontend.ast_nodes > 0);
                assert_eq!(frontend.lexed.source_len, source.len());
                assert!(ample.work > 0 && ample.temporary > 0);
                let mut exact = Probe::unlimited();
                exact.work_limit = ample.work;
                exact.temporary_limit = ample.temporary;
                assert!(
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut exact)
                        .is_ok()
                );
                let mut short_work = Probe::unlimited();
                short_work.work_limit = ample.work - 1;
                assert!(matches!(
                    lex_parse_with_budget(
                        source,
                        profile,
                        &CompileLimits::default(),
                        &mut short_work
                    ),
                    Err(BudgetedCompileError::Budget(()))
                ));
                let mut short_temporary = Probe::unlimited();
                short_temporary.temporary_limit = ample.temporary - 1;
                assert!(matches!(
                    lex_parse_with_budget(
                        source,
                        profile,
                        &CompileLimits::default(),
                        &mut short_temporary
                    ),
                    Err(BudgetedCompileError::Budget(()))
                ));
            }
        }
    }

    #[test]
    fn resolve_admits_nested_metadata_and_close_paths_before_stage() {
        let source = b"local x <close> = f(); local function g(a) if a then return x end return function(b) return a+b end end; return g(3)";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut ample = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let resolved =
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            assert_eq!(resolved.resolved.functions.len(), 3);
            assert!(resolved.ast_nodes > 0);
            assert!(resolved.lexed.tokens.len() > 1);
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut exact)
                    .unwrap();
            assert!(
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut exact)
                    .is_ok()
            );
            let mut short_work = Probe::unlimited();
            short_work.work_limit = ample.work - 1;
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut short_work)
                    .unwrap();
            assert!(matches!(
                resolve_with_budget(
                    frontend,
                    profile,
                    &CompileLimits::default(),
                    &mut short_work
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temporary = Probe::unlimited();
            short_temporary.temporary_limit = ample.temporary - 1;
            let frontend = lex_parse_with_budget(
                source,
                profile,
                &CompileLimits::default(),
                &mut short_temporary,
            )
            .unwrap();
            assert!(matches!(
                resolve_with_budget(
                    frontend,
                    profile,
                    &CompileLimits::default(),
                    &mut short_temporary
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }

    #[test]
    fn lower_admits_ir_and_builder_scratch_before_stage() {
        let source = b"local x=7; local function f(y) return x+y end; return f(5)";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut ample = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let resolved =
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let lowered =
                lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut ample)
                    .unwrap();
            assert_eq!(lowered.ir.prototypes.len(), 2);
            assert_eq!(lowered.resolved.functions.len(), 2);
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut exact)
                    .unwrap();
            let resolved =
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut exact)
                    .unwrap();
            assert!(
                lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut exact)
                    .is_ok()
            );
            let mut short_work = Probe::unlimited();
            short_work.work_limit = ample.work - 1;
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut short_work)
                    .unwrap();
            let resolved = resolve_with_budget(
                frontend,
                profile,
                &CompileLimits::default(),
                &mut short_work,
            )
            .unwrap();
            assert!(matches!(
                lower_with_budget(
                    resolved,
                    &rivetlua_core::IrLimits::default(),
                    &mut short_work
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temporary = Probe::unlimited();
            short_temporary.temporary_limit = ample.temporary - 1;
            let frontend = lex_parse_with_budget(
                source,
                profile,
                &CompileLimits::default(),
                &mut short_temporary,
            )
            .unwrap();
            let resolved = resolve_with_budget(
                frontend,
                profile,
                &CompileLimits::default(),
                &mut short_temporary,
            )
            .unwrap();
            assert!(matches!(
                lower_with_budget(
                    resolved,
                    &rivetlua_core::IrLimits::default(),
                    &mut short_temporary
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }

    #[test]
    fn candidate_clone_is_admitted_before_allocation() {
        let source = b"local x <close> = f(); return function(y) return x,y end";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut ample = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let resolved =
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let lowered =
                lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut ample)
                    .unwrap();
            let candidate = candidate_with_budget(lowered, &mut ample).unwrap();
            assert_eq!(candidate.bytecode.prototypes.len(), 2);
            assert_eq!(candidate.resolved.functions.len(), 2);
            assert_eq!(candidate.ir.prototypes.len(), 2);
        }
    }
}
