//! 編譯器的分段資源准入；不依賴執行期的 ledger 或 VM。

use core::mem::size_of;

use crate::ast::{
    Block, Expr, FunctionBody, GlobalDeclaration, LocalName, Module, Stmt, TableField,
};
use crate::ir::{IrClosePath, IrConstant, IrModule, IrPrototype};
use crate::lexer::{NumericBudget, NumericCharge, ScanError};
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

struct SinkNumericBudget<'a, S>(&'a mut S);

impl<S: CompileBudgetSink> NumericBudget for SinkNumericBudget<'_, S> {
    type Error = BudgetedCompileError<S::Error>;

    fn before_conversion(&mut self, charge: NumericCharge) -> Result<(), Self::Error> {
        // 分類器只走訪已複製的 numeral bytes，不配置；這次 metadata pass
        // 已由 LEX 的 288*(source bytes+1) 支付。以下只預付實際轉換。
        // Rust 1.98.1 的 fast subset 至多 19 個數字、精確 53-bit 尾數與
        // [-22,22] 有效指數；固定 512 加 64/byte 覆蓋其乘除、指數剖析。
        // 其餘 decimal 走保守路徑：dec2flt 的 decimal_point 初值
        // 限於 [-324,309]；get_shift 的 1..18 表滿足
        // 2^shift <= 10^n < 2^(shift+1)，n>=19 取 60，且
        // 10^18 < 2^60 < 10^19。因此左右 shift 合計至多 21 次，
        // subnormal 至多 3 次、rounding 至多 2 次，共 26 次。
        // 每次 shift 至多 2*768+42+60+20+32=1694 個有界迭代；
        // 16*26*1694=704704，小於固定 1000000。
        // 額外 64/byte 支付 numeral 解析與長尾數走訪。hex powi 的
        // compiler-rt i32 指數迴圈至多 32 次，固定 512 預付。
        let work = match charge {
            NumericCharge::DecimalFast(bytes) => add(512, mul(bytes, 64)?)?,
            NumericCharge::DecimalConservative(bytes) => add(1_000_000, mul(bytes, 64)?)?,
            NumericCharge::HexPowi => 512,
        };
        self.0
            .spend_work(work)
            .map_err(BudgetedCompileError::Budget)
    }
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
    // Cursor 只向前 advance，每次至少消耗一 byte（CRLF 可消耗兩 byte），
    // 所有 scanner 主迴圈、escape、literal push、token emit 與座標更新
    // 依消耗位置攤銷至多 48 單位。keyword 只有 23 個固定 ASCII 形式，
    // 最長 8 byte；每個 identifier token 至多 23 次長度及 8 byte
    // 比對，以 208 單位覆蓋。兩個 identifier 必有至少一個分隔 byte，
    // 故 I<=((bytes+1)/2)，這部分至多 104*(bytes+1)。numeral 的
    // 手動文字掃描、UTF-8/形式判斷、指數/尾數 metadata 與 i64 parse
    // 至多 16 次 byte pass，且各 numeral 所屬來源區間不重疊；
    // std f64 轉換與 hex powi 的額外工作由轉換前 NumericBudget 預付。
    // long opener 的 '=' 前瞻若成功即由 separator 消耗，若帶 '='
    // 卻失敗則立即診斷結束；long closer 只在 ']' 前瞻，其後 '=' run
    // 在各候選 ']' 間互不重疊，成功 separator 也被消耗。兩類前瞻
    // 合計至多 4 單位/byte。lexed 實際容量遍歷以 4 單位/token 支付。
    // 下一段 parse_admission 在其 admit 前只有一趟 kind/literal metadata
    // 遍歷：至多兩層 enum dispatch、固定 kind membership 判斷、
    // 四個 checked counter 更新、literal 檢查/capacity/加總；
    // 保守取 64 單位/token。EOF 與固定檢查另取 16*(bytes+1)。
    // 因 token 數<=bytes+1，總上界 48+104+16+4+4+64+16=256 單位/
    // (bytes+1)，低於實際 288；全部乘加仍 checked 拒絕溢位。
    let work = mul(token_slots, 288)?;
    let _ = limits;
    Ok((work, temporary))
}

#[derive(Default)]
struct ParseTokenBounds {
    literal_bytes: usize,
    statement_elements: usize,
    block_containers: usize,
    expression_elements: usize,
    local_names: usize,
    table_opens: usize,
    separators: usize,
    if_clauses: usize,
    if_containers: usize,
    box_triggers: usize,
}

fn bump<E>(value: &mut usize) -> Result<(), BudgetedCompileError<E>> {
    *value = add(*value, 1)?;
    Ok(())
}

fn parse_token_bounds<E>(chunk: &LexedChunk) -> Result<ParseTokenBounds, BudgetedCompileError<E>> {
    use crate::{Keyword as K, Symbol as S, TokenKind as T};

    let mut bounds = ParseTokenBounds {
        block_containers: 1, // root Block
        ..ParseTokenBounds::default()
    };
    // 這一趟 metadata 掃描只讀 kind 與 literal.capacity()；LEX admission
    // 已預付 parse_admission 的 token/literal 遍歷，無 payload byte scan。
    for token in &chunk.tokens {
        if let Some(literal) = token.literal.as_ref() {
            bounds.literal_bytes = add(bounds.literal_bytes, literal_bytes(literal))?;
        }
        match token.kind {
            T::Name => {
                bump(&mut bounds.local_names)?;
                bump(&mut bounds.expression_elements)?;
            }
            T::String => {
                bump(&mut bounds.expression_elements)?;
                bump(&mut bounds.statement_elements)?;
                bump(&mut bounds.box_triggers)?;
            }
            T::Integer | T::Float => bump(&mut bounds.expression_elements)?,
            T::Keyword(keyword) => match keyword {
                K::Function => {
                    bump(&mut bounds.statement_elements)?;
                    bump(&mut bounds.block_containers)?;
                    bump(&mut bounds.expression_elements)?;
                }
                K::Do | K::Repeat => {
                    bump(&mut bounds.statement_elements)?;
                    bump(&mut bounds.block_containers)?;
                }
                K::While | K::For | K::Return | K::Break | K::Goto | K::Local | K::Global => {
                    bump(&mut bounds.statement_elements)?;
                }
                K::If => {
                    bump(&mut bounds.statement_elements)?;
                    bump(&mut bounds.if_clauses)?;
                    bump(&mut bounds.if_containers)?;
                }
                K::ElseIf => bump(&mut bounds.if_clauses)?,
                K::Then | K::Else => bump(&mut bounds.block_containers)?,
                K::Nil | K::True | K::False => bump(&mut bounds.expression_elements)?,
                K::Not => {
                    bump(&mut bounds.expression_elements)?;
                    bump(&mut bounds.box_triggers)?;
                }
                K::And | K::Or => bump(&mut bounds.box_triggers)?,
                _ => {}
            },
            T::Symbol(symbol) => {
                // 所有 Box<Expr> 均由 symbol、string argument 或
                // and/or/not 建立；任一觸發 token 最多建立兩個 Box。
                bump(&mut bounds.box_triggers)?;
                match symbol {
                    S::DoubleColon | S::Assign | S::Colon => {
                        bump(&mut bounds.statement_elements)?;
                    }
                    S::Semicolon => {
                        bump(&mut bounds.statement_elements)?;
                        bump(&mut bounds.separators)?;
                    }
                    S::OpenParen => {
                        bump(&mut bounds.statement_elements)?;
                        bump(&mut bounds.expression_elements)?;
                    }
                    S::OpenBrace => {
                        bump(&mut bounds.statement_elements)?;
                        bump(&mut bounds.expression_elements)?;
                        bump(&mut bounds.table_opens)?;
                    }
                    S::Vararg | S::Minus | S::Hash | S::Tilde => {
                        bump(&mut bounds.expression_elements)?;
                    }
                    S::Comma => bump(&mut bounds.separators)?,
                    _ => {}
                }
            }
            T::Eof => {}
        }
    }
    Ok(bounds)
}

fn parse_vec_bytes<E>(
    elements: usize,
    containers: usize,
    width: usize,
) -> Result<(usize, usize), BudgetedCompileError<E>> {
    // Rust Vec 的非空最小容量為 4，之後倍增：每容器 cap<=2*len+2。
    // grow 時舊 buffer 的 cap<=該族既有 element 數；回傳 retained
    // 容量及單次 grow 期間另需保留的舊 buffer 上界。
    let slots = add(mul(elements, 2)?, mul(containers, 2)?)?;
    Ok((mul(slots, width)?, mul(elements, width)?))
}

fn parse_admission<E>(
    chunk: &LexedChunk,
    limits: &CompileLimits,
) -> Result<(usize, usize, CompileLimits), BudgetedCompileError<E>> {
    let tokens = chunk.tokens.len();
    // 原有動態節點限額與 parser 自身限制保持不變。function_name 的
    // FieldExpr/Box 並未 reserve_node，故 heap 上界另外依 token 建立。
    let node_ceiling = add(mul(tokens, 4)?, 4)?.min(limits.max_ast_nodes);
    let mut local_limits = *limits;
    local_limits.max_ast_nodes = node_ceiling;
    let bounds = parse_token_bounds(chunk)?;

    // 每個 StmtVec element 有一個獨有的 statement keyword、label/empty
    // 符號，或 assignment/call 的 =、(、:、string/{ 觸發 token。
    // ExprVec element 有獨有 prefix token；LocalNameVec element 有 name。
    // TableFieldVec 每 table 最後一欄以 { 支付，其餘以 separator 支付；
    // IfClauseVec 由 if/elseif 支付。各非空容器至少有一個 element。
    let table_elements = if bounds.table_opens == 0 {
        0
    } else {
        add(bounds.table_opens, bounds.separators)?
    };
    let families = [
        parse_vec_bytes(
            bounds.statement_elements,
            bounds.block_containers,
            size_of::<Stmt>(),
        )?,
        parse_vec_bytes(
            bounds.expression_elements,
            bounds.expression_elements,
            size_of::<Expr>(),
        )?,
        parse_vec_bytes(
            bounds.local_names,
            bounds.local_names,
            size_of::<LocalName>(),
        )?,
        parse_vec_bytes(table_elements, bounds.table_opens, size_of::<TableField>())?,
        parse_vec_bytes(
            bounds.if_clauses,
            bounds.if_containers,
            size_of::<(Expr, Block)>(),
        )?,
    ];
    let mut vec_storage = 0;
    let mut growth_scratch = 0;
    for (retained, old_buffer) in families {
        vec_storage = add(vec_storage, retained)?;
        growth_scratch = growth_scratch.max(old_buffer);
    }
    let boxes = mul(mul(bounds.box_triggers, 2)?, size_of::<Expr>())?;
    // Token::clone/name() 所有名稱與字串取自 lexed payload；
    // MethodName 額外 clone 一次。四份 aggregate capacity 同時覆蓋
    // retained AST、暫存 token/name 與該 clone，不按最大 literal 重複乘節點。
    let payload = mul(bounds.literal_bytes, 4)?;
    // 同一時刻至多一個 Vec grow，舊＋新 buffer 由 vec_storage 加上
    // 各族最大的 growth_scratch 覆蓋；Box 與 payload 另計。
    let temporary = add(
        add(add(vec_storage, growth_scratch)?, add(boxes, payload)?)?,
        256,
    )?;
    // Cursor、Pratt、list 與 AstMeter 皆對 token/AST 單調走訪；每
    // token 512 單位覆蓋固定判斷與結構 walk。Vec element 建構/傳回、
    // push 及倍增舊 buffer 搬移合計不超過 2*vec_storage；Box
    // 建構與移入不超過 2*boxes；byte clone/走訪由 16*aggregate
    // payload capacity 支付。所有值都先 checked，再送 BudgetSink。
    let work = add(
        add(
            mul(tokens, 512)?,
            add(mul(vec_storage, 2)?, mul(boxes, 2)?)?,
        )?,
        mul(bounds.literal_bytes, 16)?,
    )?;
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
    let lexed = crate::lexer::lex_with_numeric_budget(
        source,
        profile,
        limits,
        &mut SinkNumericBudget(sink),
    )
    .map_err(|error| match error {
        ScanError::Diagnostic(diagnostic) => BudgetedCompileError::Frontend(diagnostic),
        ScanError::Budget(error) => error,
    })?;
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

#[derive(Default)]
struct ResolveShape {
    blocks: usize,
    functions: usize,
    declarations: usize,
    references: usize,
    labels: usize,
    gotos: usize,
    close_paths: usize,
    generic_fors: usize,
    name_bytes: usize,
    key_bytes: usize,
    literal_bytes: usize,
    current_bindings: usize,
    current_close_paths: usize,
    current_key_bytes: usize,
    inherited_bindings: usize,
    inherited_key_bytes: usize,
    inherited_sum: usize,
    inherited_square_sum: usize,
    inherited_key_sum: usize,
    close_binding_pairs: usize,
    depth: usize,
    max_depth: usize,
}

impl ResolveShape {
    fn root() -> Self {
        Self {
            functions: 1,
            current_bindings: 1, // resolver 在 AST 前宣告 root _ENV
            current_key_bytes: 8,
            depth: 1,
            max_depth: 1,
            ..Self::default()
        }
    }

    fn binding<E>(&mut self) -> Result<(), BudgetedCompileError<E>> {
        bump(&mut self.declarations)?;
        bump(&mut self.current_bindings)
    }

    fn add_close_paths<E>(&mut self, count: usize) -> Result<(), BudgetedCompileError<E>> {
        self.close_paths = add(self.close_paths, count)?;
        self.current_close_paths = add(self.current_close_paths, count)?;
        Ok(())
    }

    fn name<E>(&mut self, name: &Vec<u8>) -> Result<(), BudgetedCompileError<E>> {
        self.name_bytes = add(self.name_bytes, name.capacity())?;
        Ok(())
    }

    fn key_name<E>(&mut self, name: &Vec<u8>) -> Result<(), BudgetedCompileError<E>> {
        self.name(name)?;
        self.key_bytes = add(self.key_bytes, name.capacity())?;
        self.current_key_bytes = add(self.current_key_bytes, name.capacity())?;
        Ok(())
    }

    fn declaration<E>(&mut self, local: &LocalName) -> Result<(), BudgetedCompileError<E>> {
        self.binding()?;
        self.key_name(&local.name)?;
        if let Some(attribute) = &local.attribute {
            self.name(&attribute.name)?;
        }
        Ok(())
    }

    fn declarations<E>(&mut self, names: &[LocalName]) -> Result<(), BudgetedCompileError<E>> {
        for name in names {
            self.declaration(name)?;
        }
        Ok(())
    }

    fn expressions<E>(&mut self, expressions: &[Expr]) -> Result<(), BudgetedCompileError<E>> {
        for expression in expressions {
            self.expression(expression)?;
        }
        Ok(())
    }

    fn function<E>(
        &mut self,
        body: &FunctionBody,
        method: bool,
    ) -> Result<(), BudgetedCompileError<E>> {
        bump(&mut self.functions)?;
        // child 的兩張 parent map 只含建立當下的祖先 prefix。兄弟
        // function 的宣告、參照與 close path 不會進入該 child。
        let inherited = add(self.inherited_bindings, self.current_bindings)?;
        let inherited_keys = add(self.inherited_key_bytes, self.current_key_bytes)?;
        self.inherited_sum = add(self.inherited_sum, inherited)?;
        self.inherited_square_sum = add(self.inherited_square_sum, mul(inherited, inherited)?)?;
        self.inherited_key_sum = add(self.inherited_key_sum, inherited_keys)?;
        let saved = (
            self.inherited_bindings,
            self.inherited_key_bytes,
            self.current_bindings,
            self.current_close_paths,
            self.current_key_bytes,
            self.depth,
        );
        self.inherited_bindings = inherited;
        self.inherited_key_bytes = inherited_keys;
        self.current_bindings = 0;
        self.current_close_paths = 0;
        self.current_key_bytes = 0;
        self.depth = add(self.depth, 1)?;
        self.max_depth = self.max_depth.max(self.depth);
        if method {
            self.binding()?; // 隱含 self parameter
            // resolver 把產生的 "self" 放進 scope map；其一般複製由
            // generated_names 支付，child 的 parent-visible prefix 另須
            // 計入每層可繼承的 key bytes（實際名稱長 4，保守計 8）。
            self.current_key_bytes = add(self.current_key_bytes, 8)?;
        }
        self.declarations(&body.parameters)?;
        if let Some(name) = body
            .vararg
            .as_ref()
            .and_then(|vararg| vararg.table_name.as_ref())
        {
            self.declaration(name)?;
        }
        self.block(&body.body)?;
        self.close_binding_pairs = add(
            self.close_binding_pairs,
            mul(self.current_close_paths, self.current_bindings)?,
        )?;
        (
            self.inherited_bindings,
            self.inherited_key_bytes,
            self.current_bindings,
            self.current_close_paths,
            self.current_key_bytes,
            self.depth,
        ) = saved;
        Ok(())
    }

    fn block<E>(&mut self, block: &Block) -> Result<(), BudgetedCompileError<E>> {
        bump(&mut self.blocks)?;
        self.add_close_paths(2)?; // normal 與 error
        for statement in &block.statements {
            self.statement(statement)?;
        }
        Ok(())
    }

    fn statement<E>(&mut self, statement: &Stmt) -> Result<(), BudgetedCompileError<E>> {
        match statement {
            Stmt::Empty { .. } => {}
            Stmt::Return { values, .. } => {
                self.add_close_paths(1)?;
                self.expressions(values)?;
            }
            Stmt::Assignment {
                targets, values, ..
            } => {
                self.expressions(targets)?;
                self.expressions(values)?;
            }
            Stmt::Call { call, .. } => self.expression(call)?,
            Stmt::Local { names, values, .. } => {
                self.declarations(names)?;
                self.expressions(values)?;
            }
            Stmt::Global { declaration, .. } => match declaration {
                GlobalDeclaration::Names {
                    names,
                    values,
                    prefix_attribute,
                    ..
                } => {
                    self.declarations(names)?;
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
                    self.binding()?;
                    self.key_name(name)?;
                    self.function(body, false)?;
                }
            },
            Stmt::Break { .. } => self.add_close_paths(1)?,
            Stmt::Goto { name, .. } => {
                bump(&mut self.gotos)?;
                self.add_close_paths(1)?;
                self.key_name(name)?;
            }
            Stmt::Label { name, .. } => {
                bump(&mut self.labels)?;
                self.key_name(name)?;
            }
            Stmt::Do { body, .. } => self.block(body)?,
            Stmt::If {
                clauses,
                else_block,
                ..
            } => {
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
                self.declaration(name)?;
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
                bump(&mut self.generic_fors)?;
                self.binding()?; // 隱藏的 generic-for close binding
                self.add_close_paths(1)?;
                self.declarations(names)?;
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
                self.function(body, method.is_some())?;
            }
            Stmt::LocalFunction { name, body, .. } => {
                self.declaration(name)?;
                self.function(body, false)?;
            }
        }
        Ok(())
    }

    fn expression<E>(&mut self, expression: &Expr) -> Result<(), BudgetedCompileError<E>> {
        match expression {
            Expr::Literal { literal, .. } => {
                self.literal_bytes = add(self.literal_bytes, literal_bytes(literal))?;
            }
            Expr::Nil { .. } | Expr::Bool { .. } | Expr::Vararg { .. } => {}
            Expr::Name { name, .. } => {
                bump(&mut self.references)?;
                bump(&mut self.current_bindings)?;
                self.key_name(name)?;
            }
            Expr::Unary { expression, .. } | Expr::Paren { expression, .. } => {
                self.expression(expression)?;
            }
            Expr::Binary { left, right, .. } => {
                self.expression(left)?;
                self.expression(right)?;
            }
            Expr::Index { base, index, .. } => {
                self.expression(base)?;
                self.expression(index)?;
            }
            Expr::Field { base, name, .. } => {
                self.expression(base)?;
                self.name(name)?;
            }
            Expr::Call {
                callee, arguments, ..
            } => {
                self.expression(callee)?;
                self.expressions(arguments)?;
            }
            Expr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                self.expression(receiver)?;
                self.name(method)?;
                self.expressions(arguments)?;
            }
            Expr::Function { body, .. } => self.function(body, false)?,
            Expr::TableConstructor { fields, .. } => {
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

fn resolve_admission<E>(
    frontend: &BudgetedFrontend,
    shape: &ResolveShape,
) -> Result<(usize, usize), BudgetedCompileError<E>> {
    let tokens = frontend.lexed.tokens.len();
    let functions = shape.functions;
    let scopes = add(mul(shape.blocks, 2)?, 1)?;
    // 每個 Expr::Name 僅由 resolve_expr 查找一次，未找到時至多呼叫
    // 一次 declare_implicit_global；同名的兩種 readonly 狀態也需要
    // 各自獨立的 reference。Lua 5.4 只透過 root _ENV。其餘由實際 AST
    // declaration 計數，含 self、具名 vararg 與 generic-for 隱藏 close。
    let visible_bindings = add(shape.declarations, 1)?;
    let bindings = add(
        visible_bindings,
        if frontend.ast.profile == crate::LanguageProfile::Lua55 {
            shape.references
        } else {
            0
        },
    )?;
    let generated_names = mul(add(add(functions, shape.generic_fors)?, 1)?, 32)?;
    let names = add(shape.name_bytes, generated_names)?;
    let key_names = add(shape.key_bytes, mul(add(functions, 1)?, 8)?)?;
    // Parser 限制 reserve_node <=4*(tokens+1)；加實際 AST nodes
    // 覆蓋未經 reserve_node 的 field/Box 與 if-clause 容器元素。
    let node_slots = add(mul(add(tokens, 1)?, 4)?, frontend.ast_nodes)?;
    let node_size = [
        size_of::<ResolvedStmt>(),
        size_of::<ResolvedExpr>(),
        size_of::<ResolvedBlock>(),
        size_of::<ResolvedFunctionBody>(),
        size_of::<ResolvedTableField>(),
        size_of::<ResolvedLocalName>(),
        size_of::<ResolvedGlobalDeclaration>(),
        size_of::<crate::resolve::ResolvedIfClause>(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    let (scope_size, label_size, parent_size, access_size) = crate::resolve::budget_layout_sizes();
    let map_entry = add(
        16,
        [
            size_of::<(Vec<u8>, crate::BindingId)>(),
            add(size_of::<Vec<u8>>(), label_size)?,
            add(size_of::<Vec<u8>>(), parent_size)?,
            add(
                size_of::<Vec<u8>>(),
                mul(size_of::<Option<crate::BindingId>>(), 2)?,
            )?,
            add(size_of::<crate::BindingId>(), access_size)?,
            size_of::<(crate::BindingId, crate::UpvalueId)>(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0),
    )?;
    // Vec 的 retained buffer 加單次 grow 舊 buffer 至多四倍元素數。
    // rustc 1.98.1 所用 hashbrown 0.17.1：小表至少 4 buckets，大表
    // 容量為 buckets 的 7/8；成長目標是 max(所需數,舊容量+1)，
    // clone 保留 bucket 數。舊＋新表、bucket control/alignment 以五倍
    // entry bytes 加每表 128 bytes 支付；包含 scope bindings/labels、implicit globals、
    // upvalue ids、每層 child 的 parent-visible 與 parent-metadata clone。
    let map_entries = [
        visible_bindings,
        shape.labels,
        shape.references,
        // parent-visible、parent-metadata、upvalue-id 與 clone scratch
        // 的 key 數皆受每個 child 建立當下的祖先 binding prefix 限制。
        mul(shape.inherited_sum, 4)?,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    let output_nodes = mul(mul(node_slots, node_size)?, 3)?;
    let output_metadata = mul(mul(bindings, size_of::<crate::resolve::BindingMeta>())?, 4)?;
    // ScopeFrame 的 sizeof 僅包含 Vec handle；三個 backing buffer
    // 分別是 local bindings、close bindings、宣告 span snapshot。
    let scope_vectors = mul(
        mul(
            bindings,
            add(
                mul(size_of::<crate::BindingId>(), 2)?,
                size_of::<crate::Span>(),
            )?,
        )?,
        4,
    )?;
    let upvalue_metadata = mul(
        mul(
            shape.inherited_sum,
            add(
                size_of::<crate::resolve::UpvalueSource>(),
                size_of::<crate::BindingId>(),
            )?,
        )?,
        4,
    )?;
    // ancestor capture 另有獨立的 pending pair Vec；不借用 upvalue
    // output 的容量額度。
    let pending_captures = mul(
        mul(
            shape.inherited_sum,
            size_of::<(crate::BindingId, crate::UpvalueId)>(),
        )?,
        4,
    )?;
    let scope_metadata = mul(
        mul(
            scopes,
            add(scope_size, size_of::<crate::resolve::ScopeId>())?,
        )?,
        4,
    )?;
    let function_metadata = mul(
        mul(functions, size_of::<crate::resolve::ResolvedFunction>())?,
        4,
    )?;
    // close_path 只走當前 function 的 scope；child 的 binding 不會
    // 出現在 parent 的 close list。
    let close_binding_pairs = add(
        shape.close_binding_pairs,
        mul(shape.current_close_paths, shape.current_bindings)?,
    )?;
    let close_lists = mul(mul(close_binding_pairs, size_of::<crate::BindingId>())?, 8)?;
    let map_controls = add(add(mul(scopes, 2)?, mul(functions, 4)?)?, 1)?;
    let maps = add(
        mul(mul(map_entries, map_entry)?, 5)?,
        mul(map_controls, 128)?,
    )?;
    let payload = add(
        mul(
            add(
                add(mul(names, 4)?, shape.inherited_key_sum)?,
                mul(functions, generated_names)?,
            )?,
            8,
        )?,
        mul(shape.literal_bytes, 2)?,
    )?;
    let temporary = [
        output_nodes,
        output_metadata,
        scope_vectors,
        upvalue_metadata,
        pending_captures,
        scope_metadata,
        function_metadata,
        close_lists,
        maps,
        payload,
    ]
    .into_iter()
    .try_fold(0usize, add)?;

    // 每次名稱查找至多掃全部 scope，binding_kind/readonly 線性掃本
    // function bindings；child visible map 對每個 entry 也呼叫
    // binding_kind，祖先 capture 最多經 F 層轉接。goto 掃宣告快照，
    // close_path 掃所有離開的 scope 及其 local/close bindings。
    let lookup = mul(mul(shape.references, 4)?, add(scopes, bindings)?)?;
    // 每個 child 的 visible_bindings/visible_binding_access 只複製
    // prefix；binding_kind 最多線性掃該 prefix，兩段 walk 各以
    // prefix² 支付，包含空 parent map 與極端不均勻分布。
    let visible = mul(shape.inherited_square_sum, 2)?;
    let capture = mul(
        mul(shape.references, shape.max_depth)?,
        add(visible_bindings, bindings)?,
    )?;
    let goto = mul(add(shape.gotos, shape.labels)?, add(scopes, bindings)?)?;
    let close = mul(shape.close_paths, add(scopes, mul(bindings, 2)?)?)?;
    let structural = [lookup, visible, capture, goto, close]
        .into_iter()
        .try_fold(0usize, add)?;
    // 名稱 HashMap 在最壞碰撞下，每次 get/insert 可比對整張表的
    // key bytes；所有可見 key 來自 AST names（另含固定隱含名稱）。
    // 空 scope 的 get 不做 hash；非空 scope map 至多 visible_bindings
    // 張（每張至少一個顯式宣告，root _ENV 另計）。key_names 含全部
    // 參照名稱，故 4*visible_bindings*key_names 涵蓋跨 scope 重複 hash。
    // parent-visible clone 對至多 F*D entries 重做 hash/copy；字串
    // literal 不參與名稱 HashMap，僅在 resolved literal 複製一次。
    let name_ops = add(
        add(mul(shape.references, 4)?, mul(visible_bindings, 4)?)?,
        add(
            mul(shape.inherited_sum, 2)?,
            add(shape.gotos, shape.labels)?,
        )?,
    )?;
    let byte_work = add(mul(name_ops, key_names)?, mul(names, add(functions, 4)?)?)?;
    let byte_work = add(byte_work, mul(shape.literal_bytes, 2)?)?;
    let base = mul(
        add(
            add(add(tokens, frontend.ast_nodes)?, scopes)?,
            add(bindings, shape.close_paths)?,
        )?,
        128,
    )?;
    let work = add(add(base, mul(structural, 4)?)?, mul(byte_work, 2)?)?;
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
    // Parser 將 AST 節點數限於 4*(token 數)+4；此固定 scalar walk 每
    // node/field 不配置，只讀 enum、Vec length/capacity 並 checked 加總。
    // 先付 512 單位/token，才開始讀取實際宣告與 close-site shape。
    let shape_work = mul(add(frontend.lexed.tokens.len(), 1)?, 512)?;
    sink.spend_work(shape_work)
        .map_err(BudgetedCompileError::Budget)?;
    let mut shape = ResolveShape::root();
    shape.block(&frontend.ast.root)?;
    let (work, temporary) = resolve_admission(&frontend, &shape)?;
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

#[derive(Default)]
struct LowerShape {
    nodes: usize,
    small_emit_nodes: usize,
    simple_instructions: usize,
    simple_unsupported: bool,
    blocks: usize,
    labels: usize,
    gotos: usize,
    name_references: usize,
    name_bytes: usize,
    literal_bytes: usize,
    close_events: usize,
    close_bindings: usize,
    close_payload_pairs: usize,
    exited_bindings: usize,
    generic_for_name_exits: usize,
    native_list_writes: usize,
}

impl LowerShape {
    fn node<E>(&mut self) -> Result<(), BudgetedCompileError<E>> {
        bump(&mut self.nodes)
    }

    fn simple_emit<E>(&mut self, count: usize) -> Result<(), BudgetedCompileError<E>> {
        if !self.simple_unsupported {
            self.simple_instructions = add(self.simple_instructions, count)?;
        }
        Ok(())
    }

    fn name<E>(&mut self, name: &Vec<u8>) -> Result<(), BudgetedCompileError<E>> {
        self.name_bytes = add(self.name_bytes, name.capacity())?;
        Ok(())
    }

    fn local<E>(&mut self, local: &ResolvedLocalName) -> Result<(), BudgetedCompileError<E>> {
        self.node()?;
        self.name(&local.name)?;
        if let Some(attribute) = &local.attribute {
            self.name(&attribute.name)?;
        }
        Ok(())
    }

    fn locals<E>(&mut self, locals: &[ResolvedLocalName]) -> Result<(), BudgetedCompileError<E>> {
        for local in locals {
            self.local(local)?;
        }
        Ok(())
    }

    fn close<E>(&mut self, path: &ClosePath) -> Result<(), BudgetedCompileError<E>> {
        let len = path.bindings.len();
        if len != 0 {
            bump(&mut self.close_events)?;
            self.close_bindings = add(self.close_bindings, len)?;
            // registers 暫存、close_paths 成員及每筆 Close instruction
            // 都持有同長度的 Vec；故每條路徑的 payload 是二次量。
            self.close_payload_pairs = add(self.close_payload_pairs, mul(len, add(len, 3)?)?)?;
        }
        self.exited_bindings = add(self.exited_bindings, path.exited_bindings.len())?;
        Ok(())
    }

    fn expressions<E>(
        &mut self,
        expressions: &[ResolvedExpr],
    ) -> Result<(), BudgetedCompileError<E>> {
        for expression in expressions {
            self.expression(expression)?;
        }
        Ok(())
    }

    fn function<E>(
        &mut self,
        function: &ResolvedFunctionBody,
    ) -> Result<(), BudgetedCompileError<E>> {
        self.simple_unsupported = true;
        self.node()?;
        self.locals(&function.parameters)?;
        self.block(&function.body)
    }

    fn block<E>(&mut self, block: &ResolvedBlock) -> Result<(), BudgetedCompileError<E>> {
        self.node()?;
        bump(&mut self.small_emit_nodes)?;
        bump(&mut self.blocks)?;
        self.close(&block.normal_close_path)?;
        // 僅函式 root 的隱含返回可能消費 error path；全數納入上界。
        self.close(&block.error_close_path)?;
        for statement in &block.statements {
            self.statement(statement)?;
        }
        Ok(())
    }

    fn global<E>(
        &mut self,
        global: &ResolvedGlobalDeclaration,
    ) -> Result<(), BudgetedCompileError<E>> {
        match global {
            ResolvedGlobalDeclaration::Names { names, values, .. } => {
                self.locals(names)?;
                self.expressions(values)?;
            }
            ResolvedGlobalDeclaration::Star { .. } => {}
            ResolvedGlobalDeclaration::Function { name, body, .. } => {
                self.name(name)?;
                self.function(body)?;
            }
        }
        Ok(())
    }

    fn statement<E>(&mut self, statement: &ResolvedStmt) -> Result<(), BudgetedCompileError<E>> {
        self.node()?;
        if !self.simple_unsupported {
            match statement {
                ResolvedStmt::Empty { .. } => {}
                ResolvedStmt::Return { values, .. } => {
                    self.simple_emit(add(values.len(), 1)?)?;
                }
                ResolvedStmt::Assignment { targets, .. }
                    if targets
                        .iter()
                        .all(|target| matches!(target, ResolvedExpr::Name { .. })) =>
                {
                    self.simple_emit(mul(targets.len(), 2)?)?;
                }
                _ => self.simple_unsupported = true,
            }
        }
        match statement {
            ResolvedStmt::Empty { .. } => {}
            ResolvedStmt::Return {
                values, close_path, ..
            } => {
                bump(&mut self.small_emit_nodes)?;
                self.expressions(values)?;
                self.close(close_path)?;
            }
            ResolvedStmt::Assignment {
                targets, values, ..
            } => {
                self.expressions(targets)?;
                self.expressions(values)?;
            }
            ResolvedStmt::Call { call, .. } => self.expression(call)?,
            ResolvedStmt::Local { names, values, .. } => {
                self.locals(names)?;
                self.expressions(values)?;
            }
            ResolvedStmt::Global { declaration, .. } => self.global(declaration)?,
            ResolvedStmt::Break { close_path, .. } => self.close(close_path)?,
            ResolvedStmt::Goto {
                name, close_path, ..
            } => {
                bump(&mut self.gotos)?;
                self.name(name)?;
                self.close(close_path)?;
            }
            ResolvedStmt::Label { name, .. } => {
                bump(&mut self.labels)?;
                self.name(name)?;
            }
            ResolvedStmt::Do { body, .. } => self.block(body)?,
            ResolvedStmt::If {
                clauses,
                else_block,
                ..
            } => {
                for clause in clauses {
                    self.node()?;
                    self.expression(&clause.condition)?;
                    self.block(&clause.body)?;
                }
                if let Some(body) = else_block {
                    self.block(body)?;
                }
            }
            ResolvedStmt::While {
                condition, body, ..
            }
            | ResolvedStmt::Repeat {
                condition, body, ..
            } => {
                self.expression(condition)?;
                self.block(body)?;
            }
            ResolvedStmt::NumericFor {
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
            ResolvedStmt::GenericFor {
                names,
                values,
                body,
                close_path,
                ..
            } => {
                // 迴圈回邊逐一檢查可見 name 的捕獲，與 close_path 的
                // hidden closing binding 分屬兩條 lowering 路徑。
                self.generic_for_name_exits = add(self.generic_for_name_exits, names.len())?;
                self.locals(names)?;
                self.expressions(values)?;
                self.block(body)?;
                self.close(close_path)?;
            }
            ResolvedStmt::Function {
                name, method, body, ..
            } => {
                self.expression(name)?;
                if let Some(method) = method {
                    self.name(&method.name)?;
                }
                self.function(body)?;
            }
            ResolvedStmt::LocalFunction { name, body, .. } => {
                self.local(name)?;
                self.function(body)?;
            }
        }
        Ok(())
    }

    fn expression<E>(&mut self, expression: &ResolvedExpr) -> Result<(), BudgetedCompileError<E>> {
        self.node()?;
        match expression {
            ResolvedExpr::Literal { .. }
            | ResolvedExpr::Nil { .. }
            | ResolvedExpr::Bool { .. }
            | ResolvedExpr::Unary { .. } => self.simple_emit(1)?,
            ResolvedExpr::Name { .. } | ResolvedExpr::Binary { .. } => self.simple_emit(4)?,
            ResolvedExpr::Paren { .. } => {}
            _ => self.simple_unsupported = true,
        }
        match expression {
            ResolvedExpr::Literal { literal, .. } => {
                bump(&mut self.small_emit_nodes)?;
                self.literal_bytes = add(self.literal_bytes, literal_bytes(literal))?;
            }
            ResolvedExpr::Nil { .. } | ResolvedExpr::Bool { .. } | ResolvedExpr::Vararg { .. } => {}
            ResolvedExpr::Name {
                name, resolution, ..
            } => {
                bump(&mut self.name_references)?;
                self.name(name)?;
                if let ResolvedName::EnvField { name, .. } = resolution {
                    self.name(name)?;
                }
            }
            ResolvedExpr::Unary { expression, .. } | ResolvedExpr::Paren { expression, .. } => {
                self.expression(expression)?;
            }
            ResolvedExpr::Binary { left, right, .. }
            | ResolvedExpr::Index {
                base: left,
                index: right,
                ..
            } => {
                self.expression(left)?;
                self.expression(right)?;
            }
            ResolvedExpr::Field { base, name, .. } => {
                self.expression(base)?;
                self.name(name)?;
            }
            ResolvedExpr::Call {
                callee, arguments, ..
            } => {
                self.expression(callee)?;
                self.expressions(arguments)?;
            }
            ResolvedExpr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                self.expression(receiver)?;
                self.name(method)?;
                self.expressions(arguments)?;
            }
            ResolvedExpr::Function { body, .. } => self.function(body)?,
            ResolvedExpr::TableConstructor { fields, .. } => {
                if let Some(ResolvedTableField::Array { value, .. }) = fields.last() {
                    if matches!(
                        value,
                        ResolvedExpr::Call { .. }
                            | ResolvedExpr::MethodCall { .. }
                            | ResolvedExpr::Vararg { .. }
                    ) {
                        bump(&mut self.native_list_writes)?;
                    }
                }
                for field in fields {
                    self.node()?;
                    match field {
                        ResolvedTableField::Array { value, .. } => self.expression(value)?,
                        ResolvedTableField::Named { name, value, .. } => {
                            self.name(name)?;
                            self.expression(value)?;
                        }
                        ResolvedTableField::Indexed { key, value, .. } => {
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

fn lower_admission<E>(
    resolved: &BudgetedResolved,
    limits: &rivetlua_core::IrLimits,
    shape: &LowerShape,
) -> Result<(usize, usize, rivetlua_core::IrLimits), BudgetedCompileError<E>> {
    let functions = resolved.resolved.functions.len();
    let (bindings, upvalues, closeable_bindings, max_upvalues) =
        resolved.resolved.functions.iter().try_fold(
            (0usize, 0usize, 0usize, 0usize),
            |(all, captures, closeable, largest), function| {
                let marked = function
                    .bindings
                    .iter()
                    .filter(|binding| binding.close_marker.is_some())
                    .count();
                Ok((
                    add(all, function.bindings.len())?,
                    add(captures, function.upvalues.len())?,
                    add(closeable, marked)?,
                    largest.max(function.upvalues.len()),
                ))
            },
        )?;
    let structural_ceiling = if functions == 1
        && shape.blocks == 1
        && shape.close_events == 0
        && shape.exited_bindings == 0
        && !shape.simple_unsupported
    {
        // 唯一 root 中，Builder::new 不 emit；finish 至多補一筆 Return。
        // Return 的封閉值各至多一筆 Move，Assignment 的每個 target
        // 至多一筆 Move/LoadNil 加一筆 store。每個 Name 至多四筆
        // （EnvField target 的 key、upvalue 及兩筆 snapshot Move）；
        // `or` 在兩側 expression 之外至多四筆，其餘簡單節點更少。
        // close、open result、控制流、local 與 nested function 都退回原界。
        add(shape.simple_instructions, 1)?
    } else {
        // 複雜路徑保留原本逐節點、binding、function 與 close 的上界。
        let complex_nodes = shape
            .nodes
            .checked_sub(shape.small_emit_nodes)
            .ok_or(BudgetedCompileError::AdmissionOverflow)?;
        let residual_ast_nodes = resolved.ast_nodes.saturating_sub(shape.nodes);
        let complex_sites = add(
            add(add(complex_nodes, residual_ast_nodes)?, bindings)?,
            functions,
        )?;
        let closing = add(
            add(shape.close_bindings, shape.exited_bindings)?,
            shape.generic_for_name_exits,
        )?;
        add(
            add(
                add(mul(complex_sites, 32)?, mul(shape.small_emit_nodes, 8)?)?,
                mul(closing, 2)?,
            )?,
            mul(functions, 8)?,
        )?
    };
    let instruction_ceiling = structural_ceiling.min(mul(functions, limits.max_instructions)?);
    let mut local_limits = *limits;
    local_limits.max_instructions = structural_ceiling.min(limits.max_instructions);
    // 每個非空 Vec 最少可配置 4 個元素；倍增時最壞同時持有舊＋新
    // buffer。即使 IR cap=0，下一個 constant 也可能先於 emit 失敗
    // 而建構；open table-list 一次可先建兩個 constant。
    let instruction_slots = add(mul(instruction_ceiling, 3)?, mul(functions, 4)?)?;
    let constant_units = add(instruction_ceiling, mul(functions, 2)?)?;
    let constant_slots = add(mul(constant_units, 3)?, mul(functions, 4)?)?;
    let instruction_storage = mul(instruction_slots, size_of::<crate::ir::IrInstruction>())?;
    let debug_temporary_storage = mul(
        mul(instruction_ceiling, 3)?,
        size_of::<crate::ir::IrNativeTemporary>(),
    )?;
    let debug_initializer_storage = mul(
        mul(instruction_ceiling, 3)?,
        size_of::<crate::ir::IrNativeInitializerTemporary>(),
    )?;
    let debug_anchor_storage = mul(
        mul(instruction_ceiling, 3)?,
        size_of::<rivetlua_core::InstructionOffset>(),
    )?;
    // constant 是 append；每筆至少伴隨一筆 LoadConst，payload 按
    // 各個真正的 name/literal site 聚合，不以最大 literal 乘所有指令。
    let constant_storage = add(
        mul(constant_slots, size_of::<IrConstant>())?,
        mul(add(shape.name_bytes, shape.literal_bytes)?, 8)?,
    )?;
    let close_pair_size = add(
        size_of::<crate::BindingId>(),
        size_of::<rivetlua_core::Register>(),
    )?;
    let close_pairs = add(shape.close_payload_pairs, mul(closeable_bindings, 3)?)?;
    let close_storage = mul(
        4,
        add(
            add(
                mul(close_pairs, close_pair_size)?,
                mul(
                    add(shape.close_events, closeable_bindings)?,
                    size_of::<IrClosePath>(),
                )?,
            )?,
            mul(shape.exited_bindings, size_of::<crate::BindingId>())?,
        )?,
    )?;
    let prototypes = mul(
        functions.max(4),
        mul(
            4,
            add(
                size_of::<IrPrototype>(),
                add(
                    size_of::<(crate::FunctionId, rivetlua_core::ProtoId)>(),
                    size_of::<usize>(),
                )?,
            )?,
        )?,
    )?;
    let scratch_elements = [
        shape.nodes,
        bindings,
        upvalues,
        functions,
        shape.blocks,
        shape.labels,
        shape.gotos,
        shape.native_list_writes,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    // Builder 的 label/goto/loop/assignment/native debug 等各類 Vec
    // 至多按真實元素成長；instruction-index patch 暫存另按指令數。
    let scratch = add(
        mul(
            mul(scratch_elements, 4)?,
            crate::codegen::lower_scratch_unit_bytes(),
        )?,
        mul(mul(instruction_ceiling, 4)?, size_of::<usize>())?,
    )?;
    let metadata = mul(
        mul(add(upvalues, functions)?, 4)?,
        size_of::<crate::ir::IrUpvalue>(),
    )?;
    // lower 先複製 functions metadata；整個 ResolvedModule 的已測量
    // bytes 是該複本的保守上界，且與已產出的 IR、scratch 同時存活。
    let function_clone = resolved_allocation_bytes(&resolved.resolved)?;
    let temporary = add(
        add(
            add(instruction_storage, constant_storage)?,
            add(close_storage, prototypes)?,
        )?,
        add(
            add(add(scratch, metadata)?, function_clone)?,
            add(
                add(debug_temporary_storage, debug_initializer_storage)?,
                debug_anchor_storage,
            )?,
        )?,
    )?;
    // binding_register 線性掃當前 function；upvalue_origin 可經 F 層、
    // 每層線性找 parent。Builder::new 與 environment validation 各
    // 最多掃目前 function 的 upvalues 一次；每個 Name 觸發的
    // binding_value 至多再掃一次。兄弟 function 的 upvalues 不會在
    // 這些迴圈中出現，故使用單一 function 的最大長度，不用全模組總和。
    // CloseUpvalues 對每個 exited binding 掃 child/upvalues；label/goto
    // patch 與同 scope 重名檢查由 L+G 次掃描界住。open-result 的
    // Close chain 不重疊，驗證總走訪量按 instruction ceiling 支付。
    let traversal = mul(add(scratch_elements, instruction_ceiling)?, 64)?;
    let binding_work = mul(mul(instruction_ceiling, add(bindings, 1)?)?, 4)?;
    let ancestry = mul(add(functions, 1)?, add(functions, 1)?)?;
    let upvalue_work = mul(
        mul(
            mul(
                add(shape.name_references, mul(functions, 2)?)?,
                add(max_upvalues, 1)?,
            )?,
            ancestry,
        )?,
        8,
    )?;
    let exited_work = mul(
        mul(
            add(shape.exited_bindings, shape.generic_for_name_exits)?,
            add(add(functions, upvalues)?, add(bindings, 1)?)?,
        )?,
        8,
    )?;
    let control = add(shape.labels, shape.gotos)?;
    let control_work = mul(mul(control, add(add(shape.blocks, control)?, 1)?)?, 8)?;
    let structural_work = [
        traversal,
        binding_work,
        upvalue_work,
        exited_work,
        control_work,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    // Vec 倍增搬移按各類元素總數計；函式 metadata clone、名稱比較、
    // constant payload 與真實 close payload 二次複製皆按 bytes 支付。
    let copy_work = add(
        add(
            mul(function_clone, 2)?,
            mul(
                mul(constant_units, 2)?,
                add(
                    size_of::<crate::ir::IrInstruction>(),
                    size_of::<IrConstant>(),
                )?,
            )?,
        )?,
        add(
            mul(mul(close_pairs, close_pair_size)?, 4)?,
            mul(
                mul(scratch_elements, crate::codegen::lower_scratch_unit_bytes())?,
                2,
            )?,
        )?,
    )?;
    let name_work = mul(shape.name_bytes, mul(add(add(control, functions)?, 4)?, 4)?)?;
    let work = [
        structural_work,
        copy_work,
        name_work,
        mul(shape.literal_bytes, 4)?,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
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
    // 准入公式前只做 scalar 走訪：LowerShape 與
    // resolved_allocation_bytes 各走一次 tree，另掃一次 function/
    // binding metadata 的 close_marker。令 T=token 數：parser 的
    // reserve_node 至多 4T+4；function_name 未 reserve 的 Name/Field
    // 各由 function、dot/colon token 支付；local name、table field、
    // block、if clause、function body 各至多 T+1。兩次 tree walk
    // 合計少於 22(T+1) 個定長節點；顯式、implicit global、method
    // self、generic-for hidden binding 與 root _ENV 合計少於
    // 4(T+1) 個 metadata。新增簡單指令界僅於原本走訪中做定長 scalar
    // 計數，assignment target 的 Name 判斷只各多看一次（≤T+1）。
    // 每筆至多 36 個固定分支、長度與 checked scalar 操作；不走訪名稱
    // bytes、close 或 upvalue entries。故 (26*36+1)(T+1) <
    // 1024(T+1) 覆蓋兩次 walk、metadata 與新增 Name 判斷。
    let scan_work = mul(add(resolved.lexed.tokens.len(), 1)?, 1024)?;
    sink.spend_work(scan_work)
        .map_err(BudgetedCompileError::Budget)?;
    let mut shape = LowerShape::default();
    shape.block(&resolved.resolved.root)?;
    let (work, temporary, local_limits) = lower_admission(&resolved, limits, &shape)?;
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
            meter.vec(&debug.temporaries)?;
            meter.vec(&debug.initializer_temporaries)?;
            meter.vec(&debug.non_counted_pcs)?;
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

#[derive(Default)]
struct EmitShape {
    instructions: usize,
    bindings: usize,
    upvalues: usize,
    helper_calls: usize,
    debug: usize,
    scratch: usize,
    work: usize,
    name_lookup: usize,
}

fn emit_local_cfg_work<E>(
    i: usize,
    l: usize,
    h: usize,
    k: usize,
    functions: usize,
    all_upvalues: usize,
) -> Result<usize, BudgetedCompileError<E>> {
    let per_local = add(
        add(mul(i, 32)?, mul(mul(i, 8)?, 32)?)?,
        add(
            mul(mul(h, 2)?, add(functions, all_upvalues)?)?,
            mul(mul(k, 8)?, add(usize::BITS as usize, add(l, 2)?)?)?,
        )?,
    )?;
    mul(l, per_local)
}

fn emit_initializer_work<E>(
    instructions: usize,
    locals: usize,
    closures: usize,
    entries: usize,
    capture_work: usize,
) -> Result<usize, BudgetedCompileError<E>> {
    // Core 對每個 interval 先付 16I，再逐一檢查可到達 PC；只有
    // Closure 會在 capture_at 另付 F + child upvalues，故以 H(F+U)
    // 覆蓋，毋須把 F+U 乘上每個 PC。8L 涵蓋 binding/storage 查找、
    // active locals 與每組 future-slot 掃描；組數不超過 entries。
    // 每組 partition_point 至多 usize::BITS 次比較，其餘 preflight、
    // range、candidate 建構及定長檢查由額外 64 單位覆蓋。
    let per_entry = [
        mul(instructions, 16)?,
        mul(closures, capture_work)?,
        mul(locals, 8)?,
        add(usize::BITS as usize, 64)?,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    mul(entries, per_entry)
}

fn emit_temporary_cfg_work<E>(
    proto: &rivetlua_core::BytecodePrototype,
    debug: &crate::ir::IrNativeDebug,
) -> Result<usize, BudgetedCompileError<E>> {
    let instructions = proto.instructions.len();
    let temporaries = debug.temporaries.len();
    let mut total = 0usize;
    for temporary in &debug.temporaries {
        // Core 每項先收 2I+L；初始化 CFG 至多 2I 個狀態。
        // 消費 CFG 的每次走訪至多 3I 個 entry/exit，且每個以此
        // register 為 src 的 Move 至多觸發一次外層 Call relay 走訪。
        // 12I+4I*M 留有定長操作餘量；T 涵蓋同 PC 重複 register 掃描。
        let moves = proto
            .instructions
            .iter()
            .filter(|entry| {
                matches!(entry.instruction,
                    rivetlua_core::Instruction::Move { src, .. } if src == temporary.register)
            })
            .count();
        let per_instruction = add(12, mul(4, moves)?)?;
        let per_temporary = add(
            mul(instructions, per_instruction)?,
            add(add(debug.locals.len(), temporaries)?, 16)?,
        )?;
        total = add(total, per_temporary)?;
    }
    Ok(total)
}

fn emit_shape<E>(
    candidate: &BudgetedCandidate,
    chunk_name: &[u8],
) -> Result<EmitShape, BudgetedCompileError<E>> {
    let functions = candidate.ir.prototypes.len();
    let all_upvalues = candidate
        .ir
        .prototypes
        .iter()
        .try_fold(0usize, |sum, proto| add(sum, proto.upvalues.len()))?;
    let capture_work = add(functions, all_upvalues)?;
    let all_bindings = candidate
        .ir
        .prototypes
        .iter()
        .try_fold(0usize, |sum, proto| add(sum, proto.binding_registers.len()))?;
    let debug_header = add(
        size_of::<rivetlua_core::NativeDebug>(),
        add(
            mul(2, size_of::<usize>())?,
            core::mem::align_of::<rivetlua_core::NativeDebug>(),
        )?,
    )?;
    let mut shape = EmitShape {
        debug: add(
            debug_header,
            add(
                vec_upper(chunk_name.len(), size_of::<u8>())?,
                add(
                    vec_upper(functions, size_of::<rivetlua_core::NativePrototypeDebug>())?,
                    mul(
                        4,
                        vec_upper(
                            functions,
                            size_of::<
                                Vec<rivetlua_core::bytecode::native_debug::NativeStorageInterval>,
                            >(),
                        )?,
                    )?,
                )?,
            )?,
        )?,
        ..EmitShape::default()
    };
    for proto in &candidate.bytecode.prototypes {
        let i = proto.instructions.len();
        let b = proto.binding_registers.len();
        let u = proto.upvalues.len();
        let c = candidate
            .ir
            .prototypes
            .iter()
            .find(|entry| entry.id == proto.id)
            .map_or(0, |entry| entry.native_list_writes.len());
        let debug = candidate
            .ir
            .prototypes
            .iter()
            .find(|entry| entry.id == proto.id)
            .and_then(|entry| entry.native_debug.as_ref());
        let (l, e) = debug.map_or((0, 0), |debug| {
            (debug.locals.len(), debug.initializer_temporaries.len())
        });
        let child_upvalues = candidate
            .bytecode
            .prototypes
            .iter()
            .filter(|child| child.parent == Some(proto.id))
            .try_fold(0usize, |sum, child| add(sum, child.upvalues.len()))?;
        let mut h = 0usize;
        let mut k0 = 0usize;
        let mut k1 = 0usize;
        let mut prepares = 0usize;
        let mut nexts = 0usize;
        let mut markers = 0usize;
        let mut path_entries = 0usize;
        for path in &proto.close_paths {
            path_entries = add(
                path_entries,
                add(path.bindings.len(), path.registers.len())?,
            )?;
        }
        for entry in &proto.instructions {
            match entry.instruction {
                rivetlua_core::Instruction::Closure { .. } => h = add(h, 1)?,
                rivetlua_core::Instruction::Close { count: 0, .. } => k0 = add(k0, 1)?,
                rivetlua_core::Instruction::Close { count: 1, .. } => k1 = add(k1, 1)?,
                rivetlua_core::Instruction::NumericForPrepare { .. } => {
                    prepares = add(prepares, 1)?
                }
                rivetlua_core::Instruction::NumericForNext { .. } => nexts = add(nexts, 1)?,
                rivetlua_core::Instruction::Move { .. } if entry.close_path.is_some() => {
                    markers = add(markers, 1)?
                }
                _ => {}
            }
            if let Some(path) = &entry.close_path {
                path_entries = add(
                    path_entries,
                    add(path.bindings.len(), path.registers.len())?,
                )?;
            }
        }
        let k = add(k0, k1)?;
        shape.instructions = add(shape.instructions, i)?;
        shape.bindings = add(shape.bindings, b)?;
        shape.upvalues = add(shape.upvalues, u)?;
        shape.helper_calls = add(shape.helper_calls, c)?;
        // 每個 local 只形成一個 storage interval；每個 Close 至多一個
        // group operand。每個 group 的小 Vec 以四個元素計最低容量。
        let debug_parts = [
            vec_upper(i, size_of::<u32>())?,
            vec_upper(l, size_of::<rivetlua_core::NativeLocal>())?,
            vec_upper(u, size_of::<Option<Vec<u8>>>())?,
            vec_upper(
                l,
                size_of::<rivetlua_core::bytecode::native_debug::NativeStorageInterval>(),
            )?,
            vec_upper(
                k,
                size_of::<rivetlua_core::bytecode::native_debug::NativeCloseGroup>(),
            )?,
            mul(mul(k, 4)?, size_of::<(rivetlua_core::Register, u16)>())?,
        ];
        for part in debug_parts {
            shape.debug = add(shape.debug, part)?;
        }
        // NumericFor 的兩份 scratch 遵照 codec 的 768I 與 256I gate；
        // debug CFG 一次只處理一個 local，另計 events 與 close bitmap。
        let cfg = add(
            mul(i, 1024)?,
            mul(mul(l, 2)?, size_of::<(u32, bool, u8)>())?,
        )?;
        shape.scratch = add(
            shape.scratch,
            add(cfg, add(i, mul(l, size_of::<usize>())?)?)?,
        )?;

        let square = |n| mul::<E>(n, n);
        let codec = [
            square(b)?,
            square(u)?,
            mul(path_entries, b)?,
            mul(markers, add(markers, path_entries)?)?,
            mul(k1, path_entries)?,
            mul(k0, mul(b, add(functions, all_upvalues)?)?)?,
            mul(prepares, nexts)?,
            mul(h, functions)?,
            i,
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        // check_storage_cfg：每 local 固定 32I；兩次 capture 掃描；
        // 每 PC 至多八個 state，各 state 的固定分支/後繼成本以 32 計；
        // Close 才查二分 group，emit state 才走 group operands×storage。
        let debug_work = [
            emit_local_cfg_work(i, l, h, k, functions, all_upvalues)?,
            square(l)?,
            mul(mul(l, 2)?, usize::BITS as usize)?,
            add(add(functions, child_upvalues)?, mul(child_upvalues, l)?)?,
            mul(k0, add(b, l)?)?,
            mul(add(i, 2)?, usize::BITS as usize)?,
            mul(k1, path_entries)?,
            mul(i, 16)?,
        ]
        .into_iter()
        .try_fold(0usize, add)?;
        let helper_work = mul(c, add(add(functions, i)?, mul(all_upvalues, b)?)?)?;
        shape.work = add(
            shape.work,
            add(
                add(add(mul(codec, 8)?, debug_work)?, mul(helper_work, 8)?)?,
                add(
                    emit_initializer_work(i, l, h, e, capture_work)?,
                    debug.map_or(Ok(0), |debug| emit_temporary_cfg_work(proto, debug))?,
                )?,
            )?,
        )?;
        // name metadata 查找須在查找前另行預付；parent chain 深度至多 F，
        // 每層線性找 parent 至多 F，最後找 binding 至多全模組 B。
        let guest = u;
        shape.name_lookup = add(
            shape.name_lookup,
            add(
                add(functions, mul(l, all_bindings)?)?,
                mul(guest, add(mul(functions, functions)?, all_bindings)?)?,
            )?,
        )?;
    }
    // codec 的兩個 seen、function map、parent/environment 是五個 F²；
    // debug coverage 再一個。helper 的 candidate/verify needed 傳播
    // 各至多 F 個首次標記×F 搜尋，verify 的兩個 parent-map 查找
    // 各至多 F²；其餘固定掃描留在十六倍的餘量內。
    shape.work = add(shape.work, mul(mul(functions, functions)?, 16)?)?;
    Ok(shape)
}

fn emit_upvalue_name_len(
    function: &crate::resolve::ResolvedFunction,
    index: usize,
    functions: &[crate::resolve::ResolvedFunction],
) -> usize {
    let mut current = function;
    let mut upvalue = index;
    for _ in 0..functions.len() {
        let Some(parent) = current
            .parent
            .and_then(|id| functions.iter().find(|entry| entry.id == id))
        else {
            return 0;
        };
        match current.upvalues.get(upvalue) {
            Some(crate::UpvalueSource::ParentLocal(binding)) => {
                return parent
                    .bindings
                    .iter()
                    .find(|entry| entry.id == *binding)
                    .map_or(0, |entry| entry.name.len());
            }
            Some(crate::UpvalueSource::ParentUpvalue(id)) => {
                current = parent;
                upvalue = id.0 as usize;
            }
            None => return 0,
        }
    }
    0
}

fn emit_admission<S: CompileBudgetSink>(
    candidate: &BudgetedCandidate,
    source: &[u8],
    chunk_name: &[u8],
    sink: &mut S,
) -> Result<(usize, usize, usize, usize), BudgetedCompileError<S::Error>> {
    let wire = rivetlua_core::bytecode_wire_upper_bytes(&candidate.bytecode)
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    let base = rivetlua_core::bytecode_module_allocation_bytes(&candidate.bytecode)
        .map_err(|_| BudgetedCompileError::AdmissionOverflow)?;
    // candidate 已預付 wire 與容量遍歷；新增的純 scalar shape 遍歷先付
    // 四次 wire：Builder 使 debug local≤binding、helper call≤instruction；
    // 編碼上界含這些元素及 close payload，支付 scalar 計數。四次 F²
    // 另付兩次 IR 對照及一次 child 列舉；名稱查找依維度另行預付。
    let functions = candidate.ir.prototypes.len();
    // 下列 CFG 上界按每個 temporary 的 Move 來源掃描指令；併入
    // 原有首筆預付，維持既有的 emit admission 階段與拒絕順序。
    let mut temporary_scan_work = 0usize;
    for proto in &candidate.bytecode.prototypes {
        let temporaries = candidate
            .ir
            .prototypes
            .iter()
            .find(|entry| entry.id == proto.id)
            .and_then(|entry| entry.native_debug.as_ref())
            .map_or(0, |debug| debug.temporaries.len());
        temporary_scan_work = add(
            temporary_scan_work,
            mul(temporaries, proto.instructions.len())?,
        )?;
    }
    sink.spend_work(add(
        add(mul(wire, 4)?, mul(mul(functions, functions)?, 4)?)?,
        temporary_scan_work,
    )?)
    .map_err(BudgetedCompileError::Budget)?;
    let mut shape = emit_shape(candidate, chunk_name)?;
    sink.spend_work(shape.name_lookup)
        .map_err(BudgetedCompileError::Budget)?;
    let mut name_bytes = 0usize;
    for proto in &candidate.ir.prototypes {
        let Some(function) = candidate
            .resolved
            .functions
            .iter()
            .find(|entry| entry.id == proto.function)
        else {
            continue;
        };
        if let Some(debug) = &proto.native_debug {
            let t = debug.temporaries.len();
            let e = debug.initializer_temporaries.len();
            let a = debug.non_counted_pcs.len();
            shape.debug = add(
                shape.debug,
                mul(
                    2,
                    vec_upper(
                        e,
                        size_of::<rivetlua_core::bytecode::native_debug::NativeInitializerTemporary>(
                        ),
                    )?,
                )?,
            )?;
            shape.debug = add(
                shape.debug,
                mul(
                    2,
                    vec_upper(t, size_of::<rivetlua_core::NativeTemporary>())?,
                )?,
            )?;
            shape.debug = add(
                shape.debug,
                mul(
                    2,
                    vec_upper(
                        a,
                        size_of::<(rivetlua_core::ProtoId, rivetlua_core::InstructionOffset)>(),
                    )?,
                )?,
            )?;
            shape.scratch = add(shape.scratch, mul(proto.instructions.len(), 8)?)?;
            shape.work = add(shape.work, mul(a, add(functions, 4)?)?)?;
            for local in &debug.locals {
                if let Some(binding) = function
                    .bindings
                    .iter()
                    .find(|entry| entry.id == local.binding)
                {
                    let bytes = vec_upper(binding.name.len(), size_of::<u8>())?;
                    shape.debug = add(shape.debug, bytes)?;
                    name_bytes = add(name_bytes, binding.name.len())?;
                }
            }
        }
        for index in 0..proto.upvalues.len().min(function.upvalues.len()) {
            let len = emit_upvalue_name_len(function, index, &candidate.resolved.functions);
            if len != 0 {
                shape.debug = add(shape.debug, vec_upper(len, size_of::<u8>())?)?;
                name_bytes = add(name_bytes, len)?;
            }
        }
    }
    let functions = candidate.ir.prototypes.len();
    let plan = if shape.helper_calls == 0 {
        0
    } else {
        [
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
            vec_upper(
                shape.helper_calls,
                size_of::<rivetlua_core::OfficialPlanCall>(),
            )?,
            mul(
                shape.helper_calls,
                vec_upper(3, size_of::<rivetlua_core::Register>())?,
            )?,
        ]
        .into_iter()
        .try_fold(0usize, add)?
    };
    let arc_verified = add(
        mul(2, size_of::<usize>())?,
        core::mem::align_of::<rivetlua_core::VerifiedModule>(),
    )?;
    let verified_overhead = size_of::<rivetlua_core::VerifiedModule>()
        .checked_sub(size_of::<rivetlua_core::BytecodeModule>())
        .ok_or(BudgetedCompileError::AdmissionOverflow)?;
    let retained = add(
        add(add(base, verified_overhead)?, shape.debug)?,
        add(plan, arc_verified)?,
    )?;
    // module header、已完成的 prototype records、當前 record 前綴、
    // 當前 subsection 是 wire 的互不重疊區間；四層 writer 活長總和
    // 至多 wire，各容量至多兩倍，加上完成後的 encoded Vec 與小容量
    // 餘量取 6wire。debug/plan 候選及衍生資料、CFG/event/line 另計。
    let temporary = [
        mul(wire, 6)?,
        shape.scratch,
        mul(shape.debug, 2)?,
        mul(plan, 2)?,
        mul(add(source.len(), 1)?, size_of::<usize>())?,
        mul(shape.bindings, mul(8, size_of::<usize>())?)?,
        mul(shape.upvalues, mul(8, size_of::<usize>())?)?,
        mul(functions, mul(16, size_of::<usize>())?)?,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
    let work = [
        mul(wire, 12)?,
        shape.work,
        mul(shape.instructions, 128)?,
        mul(source.len(), 2)?,
        chunk_name.len(),
        mul(name_bytes, 4)?,
        shape.name_lookup,
        shape.helper_calls,
    ]
    .into_iter()
    .try_fold(0usize, add)?;
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
    let (work, temporary, retained, wire) = emit_admission(&candidate, source, chunk_name, sink)?;
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
    fn parse_admission_covers_ast_container_families_and_payloads() {
        let mut long_list = b"return ".to_vec();
        for index in 0..96 {
            if index != 0 {
                long_list.push(b',');
            }
            long_list.extend_from_slice(b"name");
        }
        let mut many_names = b"local ".to_vec();
        for index in 0..96 {
            if index != 0 {
                many_names.push(b',');
            }
            many_names.extend_from_slice(format!("n{index}").as_bytes());
        }
        let mut large_string = b"return [=[".to_vec();
        large_string.extend_from_slice(&vec![b'x'; 4096]);
        large_string.extend_from_slice(b"]=]");
        let mut nested = b"return ".to_vec();
        nested.extend_from_slice(&vec![b'('; 32]);
        nested.push(b'1');
        nested.extend_from_slice(&vec![b')'; 32]);
        let shared = [
            b"".to_vec(),
            b"local a<const>, b<close> = 1, 2; return a,b".to_vec(),
            b"return {1, a=2, [3]=4}".to_vec(),
            b"if a then b() elseif c then d() else e() end".to_vec(),
            b"function a.b.c:d(x) return x end".to_vec(),
            b"a,b=1,2; a:b('x')".to_vec(),
            long_list,
            many_names,
            large_string,
            nested,
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for source in &shared {
                let limits = CompileLimits::default();
                let lexed = crate::lex(source, profile, &limits).unwrap();
                let (work, temporary, local_limits) =
                    parse_admission::<()>(&lexed, &limits).unwrap();
                let (ast, nodes) =
                    crate::parser::parse_with_metrics(&lexed, profile, &local_limits).unwrap();
                assert!(nodes <= local_limits.max_ast_nodes);
                let actual = ast_allocation_bytes::<()>(&ast).unwrap();
                assert!(
                    actual <= temporary,
                    "{profile:?}, source_len={}, actual={actual}, declared={temporary}",
                    source.len()
                );
                assert!(work > 0 && temporary > 0);
                let mut sink = Probe::unlimited();
                assert!(lex_parse_with_budget(source, profile, &limits, &mut sink).is_ok());
            }
        }
        let source = b"global <const> x<a>, y = 1,2; global <const> *";
        let profile = LanguageProfile::Lua55;
        let limits = CompileLimits::default();
        let lexed = crate::lex(source, profile, &limits).unwrap();
        let (_, temporary, local_limits) = parse_admission::<()>(&lexed, &limits).unwrap();
        let (ast, _) = crate::parser::parse_with_metrics(&lexed, profile, &local_limits).unwrap();
        assert!(ast_allocation_bytes::<()>(&ast).unwrap() <= temporary);
    }

    #[test]
    fn parse_vec_bound_covers_minimum_capacity_and_old_plus_new_growth() {
        fn check<T>(mut create: impl FnMut() -> T) {
            let mut values = Vec::<T>::new();
            let width = size_of::<T>();
            assert!(width > 0 && width <= 1024);
            for elements in 1..=96 {
                let old_capacity = values.capacity();
                values.push(create());
                let (retained, scratch) = parse_vec_bytes::<()>(elements, 1, width).unwrap();
                assert!(values.capacity() * width <= retained);
                if values.capacity() != old_capacity {
                    assert!(
                        (values.capacity() + old_capacity) * width <= retained + scratch,
                        "width={width}, elements={elements}, old={old_capacity}, new={}, retained={retained}, scratch={scratch}",
                        values.capacity()
                    );
                }
            }
        }
        let span = crate::Span {
            start_byte: 0,
            end_byte: 0,
        };
        check(|| Stmt::Empty { span });
        check(|| Expr::Nil { span });
        check(|| LocalName {
            name: Vec::new(),
            attribute: None,
            span,
        });
        check(|| TableField::Array {
            value: Expr::Nil { span },
            separator: None,
            span,
        });
        check(|| {
            (
                Expr::Nil { span },
                Block {
                    statements: Vec::new(),
                    terminator: None,
                    span,
                },
            )
        });
    }

    #[test]
    fn parse_admission_preserves_typed_order_limits_and_checked_overflow() {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for (source, numeric_work) in [
                (b"return {x=1, [2]='v'}".as_slice(), 0),
                (b"return 1.25".as_slice(), 512 + 64 * 4),
            ] {
                let limits = CompileLimits::default();
                let lexed = crate::lex(source, profile, &limits).unwrap();
                let (lex_work, lex_temporary) = lex_admission::<()>(source.len(), &limits).unwrap();
                let (parse_work, parse_temporary, _) =
                    parse_admission::<()>(&lexed, &limits).unwrap();
                let exact_work = lex_work + numeric_work + parse_work;
                let exact_temporary = lex_temporary + parse_temporary;
                let mut exact = Probe::unlimited();
                exact.work_limit = exact_work;
                exact.temporary_limit = exact_temporary;
                assert!(lex_parse_with_budget(source, profile, &limits, &mut exact).is_ok());
                assert_eq!((exact.work, exact.temporary), (exact_work, exact_temporary));

                let mut short_work = Probe::unlimited();
                short_work.work_limit = exact_work - 1;
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut short_work),
                    Err(BudgetedCompileError::Budget(()))
                ));
                assert_eq!(short_work.work, exact_work);
                assert_eq!(short_work.temporary, lex_temporary);

                let mut short_temporary = Probe::unlimited();
                short_temporary.temporary_limit = exact_temporary - 1;
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut short_temporary),
                    Err(BudgetedCompileError::Budget(()))
                ));
                assert_eq!(short_temporary.work, exact_work);
                assert_eq!(short_temporary.temporary, exact_temporary);
            }

            let source = b"local =";
            let limits = CompileLimits::default();
            assert!(matches!(
                lex_parse_with_budget(source, profile, &limits, &mut Probe::unlimited()),
                Err(BudgetedCompileError::Frontend(Diagnostic {
                    code: crate::DiagnosticCode::Parse,
                    ..
                }))
            ));
            let mut node_limited = limits;
            node_limited.max_ast_nodes = 1;
            assert!(matches!(
                lex_parse_with_budget(b"return 1", profile, &node_limited, &mut Probe::unlimited()),
                Err(BudgetedCompileError::Frontend(Diagnostic {
                    code: crate::DiagnosticCode::CompileLimit,
                    ..
                }))
            ));
            let mut depth_limited = limits;
            depth_limited.max_parse_depth = 1;
            assert!(matches!(
                lex_parse_with_budget(
                    b"return ((1))",
                    profile,
                    &depth_limited,
                    &mut Probe::unlimited()
                ),
                Err(BudgetedCompileError::Frontend(Diagnostic {
                    code: crate::DiagnosticCode::CompileLimit,
                    ..
                }))
            ));
            let mut list_limited = limits;
            list_limited.max_list_entries = 1;
            assert!(matches!(
                lex_parse_with_budget(
                    b"return 1,2",
                    profile,
                    &list_limited,
                    &mut Probe::unlimited()
                ),
                Err(BudgetedCompileError::Frontend(Diagnostic {
                    code: crate::DiagnosticCode::CompileLimit,
                    ..
                }))
            ));
        }
        assert!(matches!(
            parse_vec_bytes::<()>(usize::MAX, 1, size_of::<Stmt>()),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        assert!(matches!(
            parse_vec_bytes::<()>(1, usize::MAX, size_of::<Expr>()),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        let mut value = usize::MAX;
        assert!(matches!(
            bump::<()>(&mut value),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum LexGateError {
        Denied,
        ParseReached,
    }

    struct LexGate {
        work_limit: usize,
        temporary_limit: usize,
        work_calls: usize,
        temporary_calls: usize,
        numeric_work: Option<usize>,
        parse_work: Option<usize>,
    }

    impl LexGate {
        fn new(work_limit: usize, temporary_limit: usize) -> Self {
            Self {
                work_limit,
                temporary_limit,
                work_calls: 0,
                temporary_calls: 0,
                numeric_work: None,
                parse_work: None,
            }
        }

        fn expecting(mut self, numeric_work: Option<usize>, parse_work: usize) -> Self {
            self.numeric_work = numeric_work;
            self.parse_work = Some(parse_work);
            self
        }
    }

    impl CompileBudgetSink for LexGate {
        type Error = LexGateError;

        fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
            self.work_calls += 1;
            if self.work_calls > 1 {
                if let Some(expected) = self.numeric_work.take() {
                    assert_eq!(units, expected, "預期 LEX numeric 轉換申報");
                    return Ok(());
                }
                assert_eq!(Some(units), self.parse_work, "預期下一階段 parse 申報");
                return Err(LexGateError::ParseReached);
            }
            (units <= self.work_limit)
                .then_some(())
                .ok_or(LexGateError::Denied)
        }

        fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
            self.temporary_calls += 1;
            assert_eq!(self.temporary_calls, 1);
            (bytes <= self.temporary_limit)
                .then_some(())
                .ok_or(LexGateError::Denied)
        }

        fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
            panic!("此 gate 應停在 parse admission")
        }
    }

    #[test]
    fn lex_admission_covers_linear_scan_families_and_exact_boundaries() {
        let mut numeral = b"return 0x".to_vec();
        numeral.extend_from_slice(&vec![b'0'; 2048]);
        numeral.extend_from_slice(b"1p+2");
        let mut long_string = b"return [=====[".to_vec();
        long_string.extend_from_slice(&b"]====x".repeat(256));
        long_string.extend_from_slice(b"]=====]");
        let mut long_comment = b"--[==[".to_vec();
        long_comment.extend_from_slice(&b"]=x".repeat(512));
        long_comment.extend_from_slice(b"]==]\r\nreturn 2");
        let sources = [
            (b"".to_vec(), None),
            (b"local name=1; return name".to_vec(), None),
            (
                b"return 'a\\z \t b\\x41', 12.5e+2".to_vec(),
                Some(512 + 64 * 7),
            ),
            (long_string, None),
            (long_comment, None),
            (numeral, Some(512)),
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for (source, numeric_work) in &sources {
                let limits = CompileLimits::default();
                let (work, temporary) =
                    lex_admission::<LexGateError>(source.len(), &limits).unwrap();
                let lexed = crate::lex(source, profile, &limits).unwrap();
                let (parse_work, _, _) = parse_admission::<LexGateError>(&lexed, &limits).unwrap();
                let mut exact = LexGate::new(work, temporary).expecting(*numeric_work, parse_work);
                assert!(
                    matches!(
                        lex_parse_with_budget(source, profile, &limits, &mut exact),
                        Err(BudgetedCompileError::Budget(LexGateError::ParseReached))
                    ),
                    "{profile:?}, source bytes={}",
                    source.len()
                );
                assert_eq!(
                    (exact.work_calls, exact.temporary_calls),
                    (2 + usize::from(numeric_work.is_some()), 1)
                );

                let mut short_work = LexGate::new(work - 1, temporary);
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut short_work),
                    Err(BudgetedCompileError::Budget(LexGateError::Denied))
                ));
                assert_eq!((short_work.work_calls, short_work.temporary_calls), (1, 0));

                let mut short_temporary = LexGate::new(work, temporary - 1);
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut short_temporary),
                    Err(BudgetedCompileError::Budget(LexGateError::Denied))
                ));
                assert_eq!(
                    (short_temporary.work_calls, short_temporary.temporary_calls),
                    (1, 1)
                );
            }
        }
    }

    #[test]
    fn lex_admission_preserves_errors_token_cap_and_checked_overflow() {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for source in [
                b"return [===x".as_slice(),
                b"--[==x".as_slice(),
                b"return [=[unterminated".as_slice(),
                b"return 1e+".as_slice(),
            ] {
                let limits = CompileLimits::default();
                let (work, temporary) =
                    lex_admission::<LexGateError>(source.len(), &limits).unwrap();
                let mut exact = LexGate::new(work, temporary);
                assert!(
                    matches!(
                        lex_parse_with_budget(source, profile, &limits, &mut exact),
                        Err(BudgetedCompileError::Frontend(Diagnostic {
                            code: crate::DiagnosticCode::Lex,
                            ..
                        }))
                    ),
                    "{profile:?}, source={source:?}"
                );
                let mut short = LexGate::new(work - 1, temporary);
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut short),
                    Err(BudgetedCompileError::Budget(LexGateError::Denied))
                ));
            }

            for (source, max_tokens) in [(b"return 1".as_slice(), 1), (b"".as_slice(), 0)] {
                let mut limits = CompileLimits::default();
                limits.max_tokens = max_tokens;
                let (work, temporary) =
                    lex_admission::<LexGateError>(source.len(), &limits).unwrap();
                let mut exact = LexGate::new(work, temporary);
                assert!(matches!(
                    lex_parse_with_budget(source, profile, &limits, &mut exact),
                    Err(BudgetedCompileError::Frontend(Diagnostic {
                        code: crate::DiagnosticCode::CompileLimit,
                        ..
                    }))
                ));
            }
        }
        assert!(matches!(
            lex_admission::<LexGateError>(usize::MAX, &CompileLimits::default()),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        assert!(matches!(
            lex_admission::<LexGateError>(usize::MAX / 288, &CompileLimits::default()),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
    }

    #[derive(Default)]
    struct NumericCapture {
        charges: Vec<NumericCharge>,
    }

    impl NumericBudget for NumericCapture {
        type Error = ();

        fn before_conversion(&mut self, charge: NumericCharge) -> Result<(), Self::Error> {
            self.charges.push(charge);
            Ok(())
        }
    }

    #[test]
    fn numeric_budgeted_lexer_preserves_public_tokens_and_classifies_conversions() {
        use rivetlua_core::Number;

        let cases: &[(&[u8], &[NumericCharge])] = &[
            (b"return 1.25", &[NumericCharge::DecimalFast(4)]),
            (b"return .5", &[NumericCharge::DecimalFast(2)]),
            (b"return 0", &[]),
            (b"return 1e22", &[NumericCharge::DecimalFast(4)]),
            (b"return 1e-22", &[NumericCharge::DecimalFast(5)]),
            (b"return 1e23", &[NumericCharge::DecimalConservative(4)]),
            (
                b"return 9007199254740992e0",
                &[NumericCharge::DecimalFast(18)],
            ),
            (
                b"return 9007199254740993e0",
                &[NumericCharge::DecimalConservative(18)],
            ),
            (
                b"return 0009007199254740992e0",
                &[NumericCharge::DecimalFast(21)],
            ),
            (
                b"return 00009007199254740992e0",
                &[NumericCharge::DecimalConservative(22)],
            ),
            (
                b"return 0.10000000000000001",
                &[NumericCharge::DecimalConservative(19)],
            ),
            (
                b"return 9223372036854775808",
                &[NumericCharge::DecimalConservative(19)],
            ),
            (b"return 0x1.8", &[NumericCharge::HexPowi]),
            (b"return 0x1p-2147483648", &[NumericCharge::HexPowi]),
            (b"return '1.25' -- 0x1p2", &[]),
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for &(source, expected) in cases {
                let limits = CompileLimits::default();
                let public = crate::lex(source, profile, &limits).unwrap();
                let mut capture = NumericCapture::default();
                let budgeted =
                    crate::lexer::lex_with_numeric_budget(source, profile, &limits, &mut capture)
                        .unwrap();
                assert_eq!(capture.charges, expected, "{profile:?}: {source:?}");
                assert_eq!(public, budgeted, "{profile:?}: {source:?}");
                for (plain, metered) in public.tokens.iter().zip(&budgeted.tokens) {
                    if let (
                        Some(Literal::Float(Number::Float(a))),
                        Some(Literal::Float(Number::Float(b))),
                    ) = (&plain.literal, &metered.literal)
                    {
                        assert_eq!(a.to_bits(), b.to_bits(), "{profile:?}: {source:?}");
                    }
                }
            }

            let mut long_decimal = b"return 0.".to_vec();
            long_decimal.extend_from_slice(&vec![b'0'; 2048]);
            long_decimal.push(b'1');
            let limits = CompileLimits::default();
            let plain = crate::lex(&long_decimal, profile, &limits).unwrap();
            let mut capture = NumericCapture::default();
            let metered = crate::lexer::lex_with_numeric_budget(
                &long_decimal,
                profile,
                &limits,
                &mut capture,
            )
            .unwrap();
            assert_eq!(plain, metered);
            assert_eq!(capture.charges, [NumericCharge::DecimalConservative(2051)]);
        }
    }

    #[test]
    fn numeric_work_exact_one_below_and_typed_errors_precede_conversion() {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for (source, extra) in [
                (b"return 1.25".as_slice(), 512 + 64 * 4),
                (
                    b"return 0.10000000000000001".as_slice(),
                    1_000_000 + 64 * 19,
                ),
                (
                    b"return 9223372036854775808".as_slice(),
                    1_000_000 + 64 * 19,
                ),
                (b"return 0x1.8".as_slice(), 512),
            ] {
                let limits = CompileLimits::default();
                let (base, temporary) = lex_admission::<()>(source.len(), &limits).unwrap();
                let mut exact = Probe::unlimited();
                exact.work_limit = base + extra;
                exact.temporary_limit = temporary;
                admit(&mut exact, base, temporary).unwrap();
                let admitted = crate::lexer::lex_with_numeric_budget(
                    source,
                    profile,
                    &limits,
                    &mut SinkNumericBudget(&mut exact),
                );
                assert!(admitted.is_ok(), "{profile:?}: {source:?}: {admitted:?}");
                assert_eq!(exact.work, base + extra);

                let mut below = Probe::unlimited();
                below.work_limit = base + extra - 1;
                below.temporary_limit = temporary;
                admit(&mut below, base, temporary).unwrap();
                assert!(matches!(
                    crate::lexer::lex_with_numeric_budget(
                        source,
                        profile,
                        &limits,
                        &mut SinkNumericBudget(&mut below)
                    ),
                    Err(ScanError::Budget(BudgetedCompileError::Budget(())))
                ));
            }

            for source in [
                b"return 1e+".as_slice(),
                b"return 1abc".as_slice(),
                b"return 0x1p+".as_slice(),
                b"return 0x1p2147483648".as_slice(),
            ] {
                let limits = CompileLimits::default();
                let public = crate::lex(source, profile, &limits).unwrap_err();
                let mut capture = NumericCapture::default();
                assert!(matches!(
                    crate::lexer::lex_with_numeric_budget(source, profile, &limits, &mut capture),
                    Err(ScanError::Diagnostic(ref diagnostic)) if *diagnostic == public
                ));
                assert!(capture.charges.is_empty());
            }

            let source = b"return 0x1p2147483647";
            let limits = CompileLimits::default();
            let mut capture = NumericCapture::default();
            assert!(matches!(
                crate::lexer::lex_with_numeric_budget(source, profile, &limits, &mut capture),
                Err(ScanError::Diagnostic(Diagnostic {
                    code: crate::DiagnosticCode::Lex,
                    ..
                }))
            ));
            assert_eq!(capture.charges, [NumericCharge::HexPowi]);

            let source = b"return 1e999999999999999999999999";
            let limits = CompileLimits::default();
            assert!(matches!(
                crate::lex(source, profile, &limits),
                Err(Diagnostic {
                    code: crate::DiagnosticCode::Lex,
                    ..
                })
            ));
            let mut denied = Probe::unlimited();
            let (base, temporary) = lex_admission::<()>(source.len(), &limits).unwrap();
            denied.work_limit = base;
            admit(&mut denied, base, temporary).unwrap();
            assert!(matches!(
                crate::lexer::lex_with_numeric_budget(
                    source,
                    profile,
                    &limits,
                    &mut SinkNumericBudget(&mut denied)
                ),
                Err(ScanError::Budget(BudgetedCompileError::Budget(())))
            ));
        }

        let mut sink = Probe::unlimited();
        assert!(matches!(
            SinkNumericBudget(&mut sink)
                .before_conversion(NumericCharge::DecimalConservative(usize::MAX)),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        assert_eq!(sink.work, 0);
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
    fn resolve_shape_covers_names_maps_captures_and_close_paths() {
        let mut payload = b"return '".to_vec();
        payload.extend_from_slice(&vec![b'a'; 4096]);
        payload.push(b'\'');
        let mut common = vec![
            b"".to_vec(),
            b"do end\n".repeat(128),
            payload,
            b"local x=1; local x=2; do local x=3; return x end".to_vec(),
            b"local x=1; local function f(a) return function(b) return x+a+b end end; return f(2)"
                .to_vec(),
            b"local t={}; function t:m(a) return self,a end".to_vec(),
            b"do local _ENV={x=1}; return x end".to_vec(),
            b"for k in iter, state, control, closing do local inner <close>; break end".to_vec(),
            b"do local a <close>; do local b <close>; return b end end".to_vec(),
            b"while true do local a <close>; break end; ::done:: goto done".to_vec(),
        ];
        let mut captures = String::new();
        for index in 0..40 {
            captures.push_str(&format!("local x{index}={index}; "));
        }
        captures.push_str("local function f() return ");
        for index in 0..40 {
            if index != 0 {
                captures.push(',');
            }
            captures.push_str(&format!("x{index}"));
        }
        captures.push_str(" end; return f()");
        common.push(captures.into_bytes());

        let mut labels = String::new();
        for index in 0..40 {
            labels.push_str(&format!("::L{index}:: goto L{index}; "));
        }
        common.push(labels.into_bytes());

        let mut closes = String::from("do ");
        for index in 0..40 {
            closes.push_str(&format!("local c{index} <close>; "));
        }
        closes.push_str("return c39 end");
        common.push(closes.into_bytes());
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for source in &common {
                let limits = CompileLimits::default();
                let mut ample = Probe::unlimited();
                let frontend = lex_parse_with_budget(source, profile, &limits, &mut ample).unwrap();
                let resolved = resolve_with_budget(frontend, profile, &limits, &mut ample).unwrap();
                assert!(!resolved.resolved.functions.is_empty());

                let mut exact = Probe::unlimited();
                exact.work_limit = ample.work;
                exact.temporary_limit = ample.temporary;
                let frontend = lex_parse_with_budget(source, profile, &limits, &mut exact).unwrap();
                assert!(resolve_with_budget(frontend, profile, &limits, &mut exact).is_ok());

                let mut short_work = Probe::unlimited();
                short_work.work_limit = ample.work - 1;
                let frontend =
                    lex_parse_with_budget(source, profile, &limits, &mut short_work).unwrap();
                assert!(matches!(
                    resolve_with_budget(frontend, profile, &limits, &mut short_work),
                    Err(BudgetedCompileError::Budget(()))
                ));

                let mut short_temporary = Probe::unlimited();
                short_temporary.temporary_limit = ample.temporary - 1;
                let frontend =
                    lex_parse_with_budget(source, profile, &limits, &mut short_temporary).unwrap();
                assert!(matches!(
                    resolve_with_budget(frontend, profile, &limits, &mut short_temporary),
                    Err(BudgetedCompileError::Budget(()))
                ));
            }
        }

        for source in [
            b"global<const>*; return free".as_slice(),
            b"global *; do local _ENV={x=1}; return x end",
            b"local function f(... args) return args end",
        ] {
            let mut sink = Probe::unlimited();
            let frontend = lex_parse_with_budget(
                source,
                LanguageProfile::Lua55,
                &CompileLimits::default(),
                &mut sink,
            )
            .unwrap();
            assert!(
                resolve_with_budget(
                    frontend,
                    LanguageProfile::Lua55,
                    &CompileLimits::default(),
                    &mut sink,
                )
                .is_ok()
            );
        }
    }

    #[test]
    fn resolve_shape_counts_root_environment_for_anonymous_siblings() {
        let source = b"return {function() end, function() end, function() end}";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut sink = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                    .unwrap();
            let mut shape = ResolveShape::root();
            shape.block::<()>(&frontend.ast.root).unwrap();
            assert_eq!(shape.functions, 4);
            assert_eq!(shape.inherited_sum, 3, "{profile:?}");
            assert_eq!(shape.inherited_square_sum, 3, "{profile:?}");
            assert_eq!(shape.inherited_key_sum, 24, "{profile:?}");
            assert_eq!(shape.max_depth, 2, "{profile:?}");
        }
    }

    #[test]
    fn resolve_shape_counts_method_self_key_in_descendant_prefix() {
        let source = b"function t:m() return function() end end";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut sink = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                    .unwrap();
            let Stmt::Function { body, .. } = &frontend.ast.root.statements[0] else {
                panic!("預期 method function")
            };
            let mut plain = ResolveShape::root();
            plain.function::<()>(body, false).unwrap();
            let mut method = ResolveShape::root();
            method.function::<()>(body, true).unwrap();
            assert_eq!(method.inherited_sum, plain.inherited_sum + 1, "{profile:?}");
            assert_eq!(
                method.inherited_key_sum,
                plain.inherited_key_sum + 8,
                "{profile:?}"
            );
        }
    }

    #[test]
    fn resolve_shape_preserves_frontend_limits_and_checked_overflow() {
        let cases = [
            (b"local x=1".as_slice(), "bindings"),
            (b"do end", "scope"),
            (b"local x=1; return function() return x end", "upvalues"),
            (b"::L::", "labels"),
            (b"::L:: goto L", "gotos"),
            (b"local x=1", "nodes"),
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for (source, limit_kind) in cases {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let mut limits = CompileLimits::default();
                match limit_kind {
                    "bindings" => limits.max_bindings_per_function = 0,
                    "scope" => limits.max_scope_depth = 0,
                    "upvalues" => limits.max_upvalues_per_function = 0,
                    "labels" => limits.max_labels = 0,
                    "gotos" => limits.max_gotos = 0,
                    "nodes" => limits.max_ast_nodes = 0,
                    _ => unreachable!(),
                }
                assert!(
                    matches!(
                        resolve_with_budget(frontend, profile, &limits, &mut sink),
                        Err(BudgetedCompileError::Frontend(Diagnostic {
                            code: crate::DiagnosticCode::CompileLimit,
                            ..
                        }))
                    ),
                    "{profile:?}: {limit_kind}"
                );
            }

            let source = b"goto missing";
            let mut ample = Probe::unlimited();
            let frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut ample)
                    .unwrap();
            let shape_work = mul::<()>(frontend.lexed.tokens.len() + 1, 512).unwrap();
            let mut denied = Probe::unlimited();
            denied.work_limit = ample.work + shape_work - 1;
            let denied_frontend =
                lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut denied)
                    .unwrap();
            assert!(matches!(
                resolve_with_budget(
                    denied_frontend,
                    profile,
                    &CompileLimits::default(),
                    &mut denied
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
            assert!(matches!(
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut ample),
                Err(BudgetedCompileError::Frontend(Diagnostic {
                    code: crate::DiagnosticCode::Resolve,
                    ..
                }))
            ));

            for source in [
                b"goto L; local x=1; ::L::".as_slice(),
                b"local x<const> = 1; x=2",
            ] {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                assert!(matches!(
                    resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut sink),
                    Err(BudgetedCompileError::Frontend(Diagnostic {
                        code: crate::DiagnosticCode::Resolve,
                        ..
                    }))
                ));
            }
        }
        let mut sink = Probe::unlimited();
        let source = b"global<const>*; free=1";
        let frontend = lex_parse_with_budget(
            source,
            LanguageProfile::Lua55,
            &CompileLimits::default(),
            &mut sink,
        )
        .unwrap();
        assert!(matches!(
            resolve_with_budget(
                frontend,
                LanguageProfile::Lua55,
                &CompileLimits::default(),
                &mut sink
            ),
            Err(BudgetedCompileError::Frontend(Diagnostic {
                code: crate::DiagnosticCode::Resolve,
                ..
            }))
        ));
        let mut sink = Probe::unlimited();
        let frontend = lex_parse_with_budget(
            b"",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
            &mut sink,
        )
        .unwrap();
        let shape = ResolveShape {
            references: usize::MAX,
            ..ResolveShape::default()
        };
        assert!(matches!(
            resolve_admission::<()>(&frontend, &shape),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        for shape in [
            ResolveShape {
                inherited_sum: usize::MAX,
                ..ResolveShape::default()
            },
            ResolveShape {
                inherited_square_sum: usize::MAX,
                ..ResolveShape::default()
            },
            ResolveShape {
                inherited_key_sum: usize::MAX,
                ..ResolveShape::default()
            },
            ResolveShape {
                close_binding_pairs: usize::MAX,
                ..ResolveShape::default()
            },
        ] {
            assert!(matches!(
                resolve_admission::<()>(&frontend, &shape),
                Err(BudgetedCompileError::AdmissionOverflow)
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
    fn lower_simple_instruction_ceiling_bounds_plain_ir_and_admission() {
        fn expr(expression: &ResolvedExpr) -> Option<usize> {
            match expression {
                ResolvedExpr::Literal { .. }
                | ResolvedExpr::Nil { .. }
                | ResolvedExpr::Bool { .. } => Some(1),
                ResolvedExpr::Name { .. } => Some(4),
                ResolvedExpr::Unary { expression, .. } => expr(expression)?.checked_add(1),
                ResolvedExpr::Binary { left, right, .. } => {
                    expr(left)?.checked_add(expr(right)?)?.checked_add(4)
                }
                ResolvedExpr::Paren { expression, .. } => expr(expression),
                _ => None,
            }
        }
        fn instructions(root: &ResolvedBlock) -> Option<usize> {
            if !root.normal_close_path.bindings.is_empty()
                || !root.normal_close_path.exited_bindings.is_empty()
                || !root.error_close_path.bindings.is_empty()
                || !root.error_close_path.exited_bindings.is_empty()
            {
                return None;
            }
            let mut total = 1usize; // finish 的隱含 Return。
            for statement in &root.statements {
                match statement {
                    ResolvedStmt::Empty { .. } => {}
                    ResolvedStmt::Return {
                        values, close_path, ..
                    } if close_path.bindings.is_empty()
                        && close_path.exited_bindings.is_empty() =>
                    {
                        total = total.checked_add(values.len())?.checked_add(1)?;
                        for value in values {
                            total = total.checked_add(expr(value)?)?;
                        }
                    }
                    ResolvedStmt::Assignment {
                        targets, values, ..
                    } if targets
                        .iter()
                        .all(|target| matches!(target, ResolvedExpr::Name { .. })) =>
                    {
                        total = total.checked_add(targets.len().checked_mul(2)?)?;
                        for target in targets {
                            total = total.checked_add(expr(target)?)?;
                        }
                        for value in values {
                            total = total.checked_add(expr(value)?)?;
                        }
                    }
                    _ => return None,
                }
            }
            Some(total)
        }

        let cases: &[(&str, &[u8])] = &[
            ("baseline", b"return 1"),
            ("explicit-env", b"return x"),
            ("loadfile", b"return 3, 4"),
            ("dofile-stdin", b"return 5, 6"),
            ("repository", b"return marker"),
            ("rvl", b"RVL=7; return RVL"),
            ("rvlu", b"RVLU=8; return RVLU"),
            ("rvlu-newline", b"RVLU\n=9; return RVLU"),
            ("rvlu-tab", b"RVLU\t=10; return RVLU"),
            ("sdk-load", b"return 40+2"),
            ("sdk-reader", b"return 31, 32"),
            ("empty", b""),
            ("nil-bool", b"return nil, true, false"),
            ("unary-paren", b"return (-1)"),
            ("short-circuit", b"return (0 and 1) or (2 and 3)"),
            ("nil-fill", b"a,b,c=1; return a,b,c"),
            ("extra-rhs", b"a=1,2,3; return a"),
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for &(name, source) in cases {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let resolved =
                    resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                assert_eq!(resolved.resolved.functions.len(), 1);
                let upper = instructions(&resolved.resolved.root).unwrap();
                let plain =
                    crate::lower(&resolved.resolved, &rivetlua_core::IrLimits::default()).unwrap();
                let actual = plain.prototypes[0].instructions.len();
                assert!(actual <= upper, "{profile:?} {name}: {actual}>{upper}");
                let mut shape = LowerShape::default();
                shape.block::<()>(&resolved.resolved.root).unwrap();
                assert!(!shape.simple_unsupported, "{profile:?} {name}");
                let (admitted_work, admitted_temp, admitted_limits) =
                    lower_admission::<()>(&resolved, &rivetlua_core::IrLimits::default(), &shape)
                        .unwrap();
                assert_eq!(admitted_limits.max_instructions, upper);
                assert!(ir_allocation_bytes::<()>(&plain).unwrap() <= admitted_temp);
                let previous_work = sink.work;
                let previous_temporary = sink.temporary;
                let token_count = resolved.lexed.tokens.len();
                let budgeted =
                    lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut sink)
                        .unwrap();
                assert_eq!(budgeted.ir, plain);
                assert_eq!(
                    sink.work - previous_work,
                    1024 * (token_count + 1) + admitted_work
                );
                assert_eq!(sink.temporary - previous_temporary, admitted_temp);
            }
        }
    }

    #[test]
    fn lower_simple_ceiling_excludes_unproved_paths() {
        let cases: &[(&str, &[u8])] = &[
            ("nested", b"return function() return 1 end"),
            ("if", b"if true then return 1 end"),
            ("loop", b"while false do end"),
            ("local", b"local x=1; return x"),
            ("call-open-return", b"return f()"),
            ("method", b"return t:m()"),
            ("vararg", b"return ..."),
            ("open-list", b"return {f()}"),
            ("field-index", b"return x.y, x[1]"),
            ("non-name-target", b"x.y=1"),
            ("goto", b"goto done; ::done:: return 1"),
            ("root-close", b"local f; local x <close> = f()"),
            ("return-close", b"local f; local x <close> = f(); return 1"),
            (
                "captured",
                b"local x=1; local function f() return x end; return f",
            ),
        ];
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for &(name, source) in cases {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let resolved =
                    resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let mut shape = LowerShape::default();
                shape.block::<()>(&resolved.resolved.root).unwrap();
                assert!(
                    shape.simple_unsupported
                        || resolved.resolved.functions.len() != 1
                        || shape.blocks != 1
                        || shape.close_events != 0
                        || shape.exited_bindings != 0,
                    "{profile:?} {name}"
                );
                if name == "root-close" || name == "return-close" {
                    assert!(shape.close_events > 0, "{profile:?} {name}");
                }
                let (_, _, local_limits) =
                    lower_admission::<()>(&resolved, &rivetlua_core::IrLimits::default(), &shape)
                        .unwrap();
                assert!(local_limits.max_instructions > shape.simple_instructions + 1);
            }
        }
    }

    #[test]
    fn lower_simple_exact_limits_ir_errors_and_overflow_are_typed() {
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let source = b"return 1,2";
            let frontend = || {
                let mut sink = Probe::unlimited();
                let parsed =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let resolved =
                    resolve_with_budget(parsed, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                (resolved, sink)
            };
            let (baseline_resolved, sink) = frontend();
            let mut shape = LowerShape::default();
            shape.block::<()>(&baseline_resolved.resolved.root).unwrap();
            let (work, temporary, limits) = lower_admission::<()>(
                &baseline_resolved,
                &rivetlua_core::IrLimits::default(),
                &shape,
            )
            .unwrap();
            assert!(limits.max_instructions >= 5);
            let scan_work = 1024 * (baseline_resolved.lexed.tokens.len() + 1);

            let (resolved, mut exact) = frontend();
            exact.work_limit = sink.work + scan_work + work;
            exact.temporary_limit = sink.temporary + temporary;
            assert!(
                lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut exact)
                    .is_ok()
            );
            let (resolved, mut short_work) = frontend();
            short_work.work_limit = sink.work + scan_work + work - 1;
            short_work.temporary_limit = sink.temporary + temporary;
            assert!(matches!(
                lower_with_budget(
                    resolved,
                    &rivetlua_core::IrLimits::default(),
                    &mut short_work
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
            let (resolved, mut short_temporary) = frontend();
            short_temporary.work_limit = sink.work + scan_work + work;
            short_temporary.temporary_limit = sink.temporary + temporary - 1;
            assert!(matches!(
                lower_with_budget(
                    resolved,
                    &rivetlua_core::IrLimits::default(),
                    &mut short_temporary
                ),
                Err(BudgetedCompileError::Budget(()))
            ));
            for max_instructions in [0, 1] {
                let (resolved, mut sink) = frontend();
                let mut limits = rivetlua_core::IrLimits::default();
                limits.max_instructions = max_instructions;
                assert!(matches!(
                    lower_with_budget(resolved, &limits, &mut sink),
                    Err(BudgetedCompileError::Ir(_))
                ));
            }
            shape.simple_instructions = usize::MAX;
            assert!(matches!(
                lower_admission::<()>(
                    &baseline_resolved,
                    &rivetlua_core::IrLimits::default(),
                    &shape
                ),
                Err(BudgetedCompileError::AdmissionOverflow)
            ));
        }
    }

    #[test]
    fn lower_shape_matches_real_ir_across_control_close_capture_and_open_paths() {
        let cases: &[(&[u8], bool, bool)] = &[
            (b"", false, false),
            (b"return 7", false, false),
            (b"local x=7; return x", false, false),
            (b"return 'a much longer literal payload'", false, false),
            (b"goto after; ::after:: return 1", false, false),
            (b"local x=true; while x do x=false end; return x", false, false),
            (
                b"local t={v=0}; function t:m(x) self.v=self.v+x; return self.v end; local n=0; repeat n=n+1 until n>1; if n>0 then for i=1,3 do t:m(i) end else t:m(0) end; return t.v",
                false,
                false,
            ),
            (b"local f; return 1,f()", false, false),
            (b"local f; return {1,f()}", false, true),
            (
                b"local function f(...) return {...} end; return f(1,2)",
                false,
                true,
            ),
            (
                b"local x=1; local function f(y) return function() return x+y end end; return f(2)",
                false,
                false,
            ),
            (b"local function f(...) return ... end; return f(1,2)", false, false),
            (
                b"local iter,state,control; for k,v in iter,state,control do end",
                true,
                false,
            ),
            (
                b"local iter,state,control; for k,v in iter,state,control do local function f() return k end end",
                true,
                false,
            ),
            (b"local f; do local a <close> = f(); local b <close> = f() end", true, false),
            (
                b"local f; do local a <close> = f(); goto done end ::done:: return 1",
                true,
                false,
            ),
        ];
        let mut large_payload = b"return '".to_vec();
        large_payload.extend_from_slice(&[b'a'; 4096]);
        large_payload.push(b'\'');
        let large_case = (large_payload.as_slice(), false, false);
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            for &(source, has_close, has_native_list) in cases.iter().chain([&large_case]) {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let resolved =
                    resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                let expected =
                    crate::lower(&resolved.resolved, &rivetlua_core::IrLimits::default())
                        .unwrap_or_else(|error| panic!("{profile:?} {source:?}: {error:?}"));
                let mut shape = LowerShape::default();
                shape.block::<()>(&resolved.resolved.root).unwrap();
                assert!(shape.nodes > 0 && shape.blocks > 0);
                if has_close {
                    assert!(shape.close_bindings > 0, "{profile:?} {source:?}");
                }
                if has_native_list {
                    assert_eq!(shape.native_list_writes, 1, "{profile:?} {source:?}");
                }
                let (_, temporary, _) =
                    lower_admission::<()>(&resolved, &rivetlua_core::IrLimits::default(), &shape)
                        .unwrap();
                let lowered =
                    lower_with_budget(resolved, &rivetlua_core::IrLimits::default(), &mut sink)
                        .unwrap_or_else(|error| panic!("{profile:?} {source:?}: {error:?}"));
                assert_eq!(lowered.ir, expected, "{profile:?} {source:?}");
                assert!(ir_allocation_bytes::<()>(&lowered.ir).unwrap() <= temporary);
            }
        }
    }

    #[test]
    fn lower_metadata_denial_exact_limits_and_overflow_are_typed() {
        struct DenyFirstWork {
            temporary_claims: usize,
        }

        impl CompileBudgetSink for DenyFirstWork {
            type Error = &'static str;

            fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
                Err("LOWER metadata work")
            }

            fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
                self.temporary_claims += 1;
                Ok(())
            }

            fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
                panic!("LOWER 不申報 module allocation")
            }
        }

        let source =
            b"local f; do local a <close> = f(); local b <close> = f() end; return {1,f()}";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let build = || {
                let mut sink = Probe::unlimited();
                let frontend =
                    lex_parse_with_budget(source, profile, &CompileLimits::default(), &mut sink)
                        .unwrap();
                resolve_with_budget(frontend, profile, &CompileLimits::default(), &mut sink)
                    .unwrap()
            };
            let ir_limits = rivetlua_core::IrLimits::default();
            let mut deny = DenyFirstWork {
                temporary_claims: 0,
            };
            assert!(matches!(
                lower_with_budget(build(), &ir_limits, &mut deny),
                Err(BudgetedCompileError::Budget("LOWER metadata work"))
            ));
            assert_eq!(deny.temporary_claims, 0);

            let mut ample = Probe::unlimited();
            let lowered = lower_with_budget(build(), &ir_limits, &mut ample).unwrap();
            assert!(
                lowered.ir.prototypes[0]
                    .close_paths
                    .iter()
                    .any(|path| path.bindings.len() == 2)
            );
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            assert!(lower_with_budget(build(), &ir_limits, &mut exact).is_ok());
            let mut short_work = Probe::unlimited();
            short_work.work_limit = ample.work - 1;
            assert!(matches!(
                lower_with_budget(build(), &ir_limits, &mut short_work),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temp = Probe::unlimited();
            short_temp.temporary_limit = ample.temporary - 1;
            assert!(matches!(
                lower_with_budget(build(), &ir_limits, &mut short_temp),
                Err(BudgetedCompileError::Budget(()))
            ));

            for limits in [
                rivetlua_core::IrLimits {
                    max_prototypes: 0,
                    ..ir_limits
                },
                rivetlua_core::IrLimits {
                    max_instructions: 0,
                    ..ir_limits
                },
                rivetlua_core::IrLimits {
                    max_instructions: 1,
                    ..ir_limits
                },
                rivetlua_core::IrLimits {
                    max_registers: 1,
                    ..ir_limits
                },
            ] {
                let mut sink = Probe::unlimited();
                assert!(matches!(
                    lower_with_budget(build(), &limits, &mut sink),
                    Err(BudgetedCompileError::Ir(_))
                ));
                assert!(sink.temporary > 0, "{profile:?} {limits:?}");
            }

            let capture_source = b"local x=1; local function f() return x end; return f()";
            let mut capture_sink = Probe::unlimited();
            let capture_frontend = lex_parse_with_budget(
                capture_source,
                profile,
                &CompileLimits::default(),
                &mut capture_sink,
            )
            .unwrap();
            let capture_resolved = resolve_with_budget(
                capture_frontend,
                profile,
                &CompileLimits::default(),
                &mut capture_sink,
            )
            .unwrap();
            assert!(matches!(
                lower_with_budget(
                    capture_resolved,
                    &rivetlua_core::IrLimits {
                        max_upvalues_per_prototype: 0,
                        ..ir_limits
                    },
                    &mut capture_sink,
                ),
                Err(BudgetedCompileError::Ir(_))
            ));

            let resolved = build();
            let shape = LowerShape {
                close_payload_pairs: usize::MAX,
                ..LowerShape::default()
            };
            assert!(matches!(
                lower_admission::<()>(&resolved, &ir_limits, &shape),
                Err(BudgetedCompileError::AdmissionOverflow)
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

    #[test]
    fn emit_private_vec_capacity_and_checked_cfg_envelope() {
        fn check<T>(count: usize) {
            let mut values: Vec<T> = Vec::new();
            values.try_reserve_exact(count).unwrap();
            let actual = values.capacity().checked_mul(size_of::<T>()).unwrap();
            assert!(actual <= vec_upper::<()>(count, size_of::<T>()).unwrap());
        }
        for count in [0, 1, 2, 3, 4, 5, 7, 8, 9, 16, 33, 128] {
            check::<rivetlua_core::NativePrototypeDebug>(count);
            check::<rivetlua_core::NativeLocal>(count);
            check::<rivetlua_core::bytecode::native_debug::NativeStorageInterval>(count);
            check::<rivetlua_core::bytecode::native_debug::NativeCloseGroup>(count);
            check::<Option<Vec<u8>>>(count);
            check::<(rivetlua_core::Register, u16)>(count);
            check::<u32>(count);
            check::<u8>(count);
        }
        assert!(matches!(
            emit_local_cfg_work::<()>(usize::MAX, 1, 0, 0, 1, 0),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        assert!(matches!(
            emit_local_cfg_work::<()>(1, usize::MAX, 0, 1, 1, 0),
            Err(BudgetedCompileError::AdmissionOverflow)
        ));
        assert_eq!(emit_initializer_work::<()>(1, 2, 3, 4, 5).unwrap(), 700);
        for shape in [
            (usize::MAX, 0, 0, 1, 0),
            (1, usize::MAX, 0, 1, 0),
            (1, 0, usize::MAX, 1, 2),
            (1, 0, 0, usize::MAX, 0),
        ] {
            assert!(matches!(
                emit_initializer_work::<()>(shape.0, shape.1, shape.2, shape.3, shape.4),
                Err(BudgetedCompileError::AdmissionOverflow)
            ));
        }
    }

    #[test]
    fn ir_allocation_measurement_includes_initializer_metadata() {
        let source = b"local x=1; return x";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let limits = CompileLimits::default();
            let tokens = crate::lex(source, profile, &limits).unwrap();
            let ast = crate::parse(&tokens, profile, &limits).unwrap();
            let resolved = crate::resolve(&ast, &tokens, profile, &limits).unwrap();
            let mut ir = crate::lower(&resolved, &rivetlua_core::IrLimits::default()).unwrap();
            let with = ir_allocation_bytes::<()>(&ir).unwrap();
            let debug = ir.prototypes[0].native_debug.as_mut().unwrap();
            let capacity = debug.initializer_temporaries.capacity();
            assert!(capacity > 0, "{profile:?}");
            debug.initializer_temporaries = Vec::new();
            let without = ir_allocation_bytes::<()>(&ir).unwrap();
            assert_eq!(
                with - without,
                capacity * size_of::<crate::ir::IrNativeInitializerTemporary>(),
                "{profile:?}"
            );
        }
    }

    #[test]
    fn sibling_functions_do_not_multiply_one_functions_bindings() {
        let mut source = b"local function heavy()\n".to_vec();
        for index in 0..180 {
            source.extend_from_slice(format!("local x{index}=0\n").as_bytes());
        }
        for _ in 0..180 {
            source.extend_from_slice(b"x0=x0+1\n");
        }
        source.extend_from_slice(b"return x0\nend\n");
        for index in 0..300 {
            source.extend_from_slice(format!("function empty{index}() end\n").as_bytes());
        }
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let mut sink = Probe::unlimited();
            sink.work_limit = 3 * 1024 * 1024 * 1024;
            sink.temporary_limit = 256 * 1024 * 1024;
            let compile = |budget: &mut Probe| {
                compile_with_budget(
                    &source,
                    b"@sibling.lua",
                    profile,
                    &CompileLimits::default(),
                    &rivetlua_core::IrLimits::default(),
                    &rivetlua_core::VerifyLimits::default(),
                    budget,
                )
            };
            let outcome = compile(&mut sink);
            assert!(
                outcome.is_ok(),
                "{profile:?} result={outcome:?} work={} temporary={}",
                sink.work,
                sink.temporary,
            );
            let mut exact = Probe::unlimited();
            exact.work_limit = sink.work;
            exact.temporary_limit = sink.temporary;
            assert!(compile(&mut exact).is_ok());
            let mut short_work = Probe::unlimited();
            short_work.work_limit = sink.work - 1;
            assert!(matches!(
                compile(&mut short_work),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temporary = Probe::unlimited();
            short_temporary.temporary_limit = sink.temporary - 1;
            assert!(matches!(
                compile(&mut short_temporary),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }

    #[test]
    #[ignore = "官方 Lua 測試來源的受控計費診斷"]
    fn db55_host_load_budget_admits_pending_call_debug() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/lua55/lua-5.5.1-tests/db.lua");
        let source = std::fs::read(path).unwrap();
        let mut sink = Probe::unlimited();
        sink.work_limit = 2 * 1024 * 1024 * 1024;
        sink.temporary_limit = 256 * 1024 * 1024;
        let result = compile_with_budget(
            &source,
            b"@db.lua",
            LanguageProfile::Lua55,
            &CompileLimits::default(),
            &rivetlua_core::IrLimits::default(),
            &rivetlua_core::VerifyLimits::default(),
            &mut sink,
        );
        assert!(
            result.is_ok(),
            "result={result:?} work={} temporary={}",
            sink.work,
            sink.temporary
        );
        let compile = |budget: &mut Probe| {
            compile_with_budget(
                &source,
                b"@db.lua",
                LanguageProfile::Lua55,
                &CompileLimits::default(),
                &rivetlua_core::IrLimits::default(),
                &rivetlua_core::VerifyLimits::default(),
                budget,
            )
        };
        let mut exact = Probe::unlimited();
        exact.work_limit = sink.work;
        exact.temporary_limit = sink.temporary;
        assert!(compile(&mut exact).is_ok());
        let mut short_work = Probe::unlimited();
        short_work.work_limit = sink.work - 1;
        assert!(matches!(
            compile(&mut short_work),
            Err(BudgetedCompileError::Budget(()))
        ));
        let mut short_temporary = Probe::unlimited();
        short_temporary.temporary_limit = sink.temporary - 1;
        assert!(matches!(
            compile(&mut short_temporary),
            Err(BudgetedCompileError::Budget(()))
        ));
    }

    #[test]
    fn nested_call_temporary_cfg_admission_keeps_exact_budget() {
        let source = b"local function f() return 19 end; local g={x=19}; return assert(g.x==f())";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let compile = |budget: &mut Probe| {
                compile_with_budget(
                    source,
                    b"@nested.lua",
                    profile,
                    &CompileLimits::default(),
                    &rivetlua_core::IrLimits::default(),
                    &rivetlua_core::VerifyLimits::default(),
                    budget,
                )
            };
            let mut ample = Probe::unlimited();
            assert!(compile(&mut ample).is_ok());
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            assert!(compile(&mut exact).is_ok());
            let mut short_work = Probe::unlimited();
            short_work.work_limit = ample.work - 1;
            assert!(matches!(
                compile(&mut short_work),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temporary = Probe::unlimited();
            short_temporary.temporary_limit = ample.temporary - 1;
            assert!(matches!(
                compile(&mut short_temporary),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }

    #[test]
    fn open_last_copied_local_pending_keeps_exact_budget() {
        let source = b"local function f(...) return ... end\nlocal function g() return 2,3 end\nreturn f(11,g())";
        for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
            let compile = |budget: &mut Probe| {
                compile_with_budget(
                    source,
                    b"@open-last-local.lua",
                    profile,
                    &CompileLimits::default(),
                    &rivetlua_core::IrLimits::default(),
                    &rivetlua_core::VerifyLimits::default(),
                    budget,
                )
            };
            let mut ample = Probe::unlimited();
            assert!(compile(&mut ample).is_ok());
            let mut exact = Probe::unlimited();
            exact.work_limit = ample.work;
            exact.temporary_limit = ample.temporary;
            assert!(compile(&mut exact).is_ok());
            let mut short_work = Probe::unlimited();
            short_work.work_limit = ample.work - 1;
            assert!(matches!(
                compile(&mut short_work),
                Err(BudgetedCompileError::Budget(()))
            ));
            let mut short_temporary = Probe::unlimited();
            short_temporary.temporary_limit = ample.temporary - 1;
            assert!(matches!(
                compile(&mut short_temporary),
                Err(BudgetedCompileError::Budget(()))
            ));
        }
    }
}
