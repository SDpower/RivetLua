//! P05 P04 resolved AST 到 typed IR 的 deterministic lowering；不產生 RVLU bytes 或 VM 行為。

use crate::ir::{IrClosePath, IrConstant, IrInstruction, IrModule, IrPrototype, IrUpvalue};
use crate::{
    BinaryOp, BindingId, BindingKind, ClosePath, FunctionId, LanguageProfile, Literal,
    ResolvedBlock, ResolvedExpr, ResolvedFunction, ResolvedFunctionBody, ResolvedGlobalDeclaration,
    ResolvedModule, ResolvedName, ResolvedStmt, ResolvedTableField, ScopeId, Span, UnaryOp,
    UpvalueSource,
};
use rivetlua_core::{
    BinaryOperation, ConstId, EnvironmentSource, FrameLayout, Instruction, InstructionOffset,
    IrLimits, LuaProfile, Number, ProtoId, Register, ResultMode, UnaryOperation, UpvalueId,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrError {
    pub span: Span,
    pub message: String,
}

impl core::fmt::Display for IrError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "{} at {}..{}",
            self.message, self.span.start_byte, self.span.end_byte
        )
    }
}

impl std::error::Error for IrError {}

pub fn lower(module: &ResolvedModule, limits: &IrLimits) -> Result<IrModule, IrError> {
    let profile = match module.profile {
        LanguageProfile::Lua55 => LuaProfile::Lua55,
        LanguageProfile::Lua54 => LuaProfile::Lua54,
    };
    let mut bodies = Vec::new();
    collect_block_bodies(&module.root, &mut bodies);
    let mut functions = module.functions.clone();
    functions.sort_by_key(|function| function.id.0);
    if functions.windows(2).any(|pair| pair[0].id == pair[1].id) {
        return Err(invalid(
            module.span,
            "P04 function metadata 有重複 FunctionId",
        ));
    }
    if !functions
        .iter()
        .any(|function| function.id == FunctionId(0))
    {
        return Err(invalid(module.span, "P04 metadata 缺少 root FunctionId"));
    }
    if functions.len() > limits.max_prototypes {
        return Err(limit(module.span, "prototype 數超過 IR 限制"));
    }
    let mut function_prototypes = Vec::new();
    for (index, function) in functions.iter().enumerate() {
        let id = ProtoId(
            u32::try_from(index).map_err(|_| limit(function.span, "prototype ID 超過 IR 限制"))?,
        );
        function_prototypes.push((function.id, id));
    }
    let mut prototypes = Vec::new();
    for function in &functions {
        let body = if function.id == FunctionId(0) {
            &module.root
        } else {
            bodies
                .iter()
                .find_map(|(id, body)| (*id == function.id).then_some(*body))
                .ok_or_else(|| invalid(function.span, "P04 function metadata 缺少 body"))?
        };
        if function.id != FunctionId(0)
            && bodies
                .iter()
                .filter(|(candidate, _)| *candidate == function.id)
                .count()
                != 1
        {
            return Err(invalid(function.span, "P04 function body map 不唯一"));
        }
        let id = proto_for(&function_prototypes, function.id, function.span)?;
        let parent = function
            .parent
            .map(|parent| proto_for(&function_prototypes, parent, function.span))
            .transpose()?;
        let mut builder = Builder::new(
            function,
            id,
            parent,
            body.span,
            limits,
            &function_prototypes,
            &functions,
        )?;
        builder.lower_block(body)?;
        prototypes.push(builder.finish()?);
    }
    Ok(IrModule {
        profile,
        span: module.span,
        function_prototypes,
        prototypes,
    })
}

fn collect_block_bodies<'a>(
    block: &'a ResolvedBlock,
    bodies: &mut Vec<(FunctionId, &'a ResolvedBlock)>,
) {
    for statement in &block.statements {
        collect_statement_bodies(statement, bodies);
    }
}

fn collect_body<'a>(
    body: &'a ResolvedFunctionBody,
    bodies: &mut Vec<(FunctionId, &'a ResolvedBlock)>,
) {
    bodies.push((body.function, &body.body));
    collect_block_bodies(&body.body, bodies);
}

fn collect_expr_bodies<'a>(
    expression: &'a ResolvedExpr,
    bodies: &mut Vec<(FunctionId, &'a ResolvedBlock)>,
) {
    match expression {
        ResolvedExpr::Unary { expression, .. } | ResolvedExpr::Paren { expression, .. } => {
            collect_expr_bodies(expression, bodies)
        }
        ResolvedExpr::Binary { left, right, .. } => {
            collect_expr_bodies(left, bodies);
            collect_expr_bodies(right, bodies);
        }
        ResolvedExpr::Index { base, index, .. } => {
            collect_expr_bodies(base, bodies);
            collect_expr_bodies(index, bodies);
        }
        ResolvedExpr::Field { base, .. } => collect_expr_bodies(base, bodies),
        ResolvedExpr::Call {
            callee, arguments, ..
        } => {
            collect_expr_bodies(callee, bodies);
            for argument in arguments {
                collect_expr_bodies(argument, bodies);
            }
        }
        ResolvedExpr::MethodCall {
            receiver,
            arguments,
            ..
        } => {
            collect_expr_bodies(receiver, bodies);
            for argument in arguments {
                collect_expr_bodies(argument, bodies);
            }
        }
        ResolvedExpr::Function { body, .. } => collect_body(body, bodies),
        ResolvedExpr::TableConstructor { fields, .. } => {
            for field in fields {
                match field {
                    ResolvedTableField::Array { value, .. }
                    | ResolvedTableField::Named { value, .. } => collect_expr_bodies(value, bodies),
                    ResolvedTableField::Indexed { key, value, .. } => {
                        collect_expr_bodies(key, bodies);
                        collect_expr_bodies(value, bodies);
                    }
                }
            }
        }
        ResolvedExpr::Literal { .. }
        | ResolvedExpr::Nil { .. }
        | ResolvedExpr::Bool { .. }
        | ResolvedExpr::Name { .. }
        | ResolvedExpr::Vararg { .. } => {}
    }
}

fn collect_statement_bodies<'a>(
    statement: &'a ResolvedStmt,
    bodies: &mut Vec<(FunctionId, &'a ResolvedBlock)>,
) {
    match statement {
        ResolvedStmt::Return { values, .. } | ResolvedStmt::Local { values, .. } => {
            for value in values {
                collect_expr_bodies(value, bodies);
            }
        }
        ResolvedStmt::Assignment {
            targets, values, ..
        } => {
            for target in targets {
                collect_expr_bodies(target, bodies);
            }
            for value in values {
                collect_expr_bodies(value, bodies);
            }
        }
        ResolvedStmt::Call { call, .. } => collect_expr_bodies(call, bodies),
        ResolvedStmt::Do { body, .. } => collect_block_bodies(body, bodies),
        ResolvedStmt::If {
            clauses,
            else_block,
            ..
        } => {
            for clause in clauses {
                collect_expr_bodies(&clause.condition, bodies);
                collect_block_bodies(&clause.body, bodies);
            }
            if let Some(body) = else_block {
                collect_block_bodies(body, bodies);
            }
        }
        ResolvedStmt::While {
            condition, body, ..
        } => {
            collect_expr_bodies(condition, bodies);
            collect_block_bodies(body, bodies);
        }
        ResolvedStmt::Repeat {
            body, condition, ..
        } => {
            collect_block_bodies(body, bodies);
            collect_expr_bodies(condition, bodies);
        }
        ResolvedStmt::NumericFor {
            initial,
            limit,
            step,
            body,
            ..
        } => {
            collect_expr_bodies(initial, bodies);
            collect_expr_bodies(limit, bodies);
            if let Some(step) = step {
                collect_expr_bodies(step, bodies);
            }
            collect_block_bodies(body, bodies);
        }
        ResolvedStmt::GenericFor { values, body, .. } => {
            for value in values {
                collect_expr_bodies(value, bodies);
            }
            collect_block_bodies(body, bodies);
        }
        ResolvedStmt::Function { name, body, .. } => {
            collect_expr_bodies(name, bodies);
            collect_body(body, bodies);
        }
        ResolvedStmt::LocalFunction { body, .. } => collect_body(body, bodies),
        ResolvedStmt::Global { declaration, .. } => match declaration {
            ResolvedGlobalDeclaration::Names { values, .. } => {
                for value in values {
                    collect_expr_bodies(value, bodies);
                }
            }
            ResolvedGlobalDeclaration::Function { body, .. } => collect_body(body, bodies),
            ResolvedGlobalDeclaration::Star { .. } => {}
        },
        ResolvedStmt::Empty { .. }
        | ResolvedStmt::Break { .. }
        | ResolvedStmt::Goto { .. }
        | ResolvedStmt::Label { .. } => {}
    }
}

struct Builder<'a> {
    function: &'a ResolvedFunction,
    id: ProtoId,
    parent: Option<ProtoId>,
    span: Span,
    limits: &'a IrLimits,
    prototypes: &'a [(FunctionId, ProtoId)],
    functions: &'a [ResolvedFunction],
    global_environment: Register,
    global_environment_binding: BindingId,
    environment_source: EnvironmentSource,
    initial_top: Register,
    dynamic_top: Register,
    next_register: u16,
    binding_registers: Vec<(BindingId, Register)>,
    constants: Vec<IrConstant>,
    instructions: Vec<IrInstruction>,
    close_paths: Vec<IrClosePath>,
    label_frames: Vec<LabelFrame>,
    pending_gotos: Vec<PendingGoto>,
    loops: Vec<LoopFrame>,
}

#[derive(Clone, Debug)]
struct LabelEntry {
    name: Vec<u8>,
    offset: Option<InstructionOffset>,
}

#[derive(Clone, Debug)]
struct LabelFrame {
    scope: ScopeId,
    labels: Vec<LabelEntry>,
}

#[derive(Clone, Debug)]
struct PendingGoto {
    instruction: usize,
    scope: ScopeId,
    name: Vec<u8>,
    span: Span,
}

#[derive(Clone, Debug, Default)]
struct LoopFrame {
    break_patches: Vec<usize>,
}

impl<'a> Builder<'a> {
    fn new(
        function: &'a ResolvedFunction,
        id: ProtoId,
        parent: Option<ProtoId>,
        span: Span,
        limits: &'a IrLimits,
        prototypes: &'a [(FunctionId, ProtoId)],
        functions: &'a [ResolvedFunction],
    ) -> Result<Self, IrError> {
        if function.upvalues.len() > limits.max_upvalues_per_prototype {
            return Err(limit(function.span, "upvalue 數超過 IR 限制"));
        }
        // R0 固定保留給 frame 的 return base；所有 P04 binding 從 R1 起配置。
        let mut binding_registers = Vec::new();
        for (index, binding) in function.bindings.iter().enumerate() {
            let register = u16::try_from(index + 1)
                .map_err(|_| limit(binding.span, "register 數超過 IR 限制"))?;
            if register >= limits.max_registers {
                return Err(limit(binding.span, "register 數超過 IR 限制"));
            }
            binding_registers.push((binding.id, Register(register)));
        }
        let global_environment_binding = functions
            .iter()
            .find(|candidate| candidate.id == FunctionId(0))
            .and_then(|root| {
                root.bindings
                    .iter()
                    .find(|binding| binding.kind == BindingKind::Environment)
            })
            .map(|binding| binding.id)
            .ok_or_else(|| invalid(span, "P04 metadata 缺少 root _ENV binding"))?;
        let global_environment = if function.id == FunctionId(0) {
            binding_registers
                .iter()
                .find_map(|(binding, register)| {
                    (*binding == global_environment_binding).then_some(*register)
                })
                .ok_or_else(|| invalid(span, "root _ENV binding 未配置 register"))?
        } else {
            Register(
                u16::try_from(binding_registers.len() + 1)
                    .map_err(|_| limit(span, "register 數超過 IR 限制"))?,
            )
        };
        let next_register = if function.id == FunctionId(0) {
            u16::try_from(binding_registers.len() + 1)
                .map_err(|_| limit(span, "register 數超過 IR 限制"))?
        } else {
            global_environment
                .0
                .checked_add(1)
                .ok_or_else(|| limit(span, "register 數超過 IR 限制"))?
        };
        if next_register > limits.max_registers {
            return Err(limit(span, "register 數超過 IR 限制"));
        }
        let environment_source = if function.id == FunctionId(0) {
            EnvironmentSource::RootExternal
        } else if let Some((index, source)) =
            function.upvalues.iter().enumerate().find(|(index, _)| {
                upvalue_origin(functions, function, *index) == Some(global_environment_binding)
            })
        {
            let upvalue = UpvalueId(
                u16::try_from(index).map_err(|_| limit(span, "upvalue ID 超過 IR 限制"))?,
            );
            match source {
                UpvalueSource::ParentLocal(_) => EnvironmentSource::ParentLocal { upvalue },
                UpvalueSource::ParentUpvalue(_) => EnvironmentSource::ParentUpvalue { upvalue },
            }
        } else {
            let parent_function = functions
                .iter()
                .find(|candidate| Some(candidate.id) == function.parent)
                .ok_or_else(|| invalid(span, "P04 function 缺少 parent environment source"))?;
            EnvironmentSource::ParentFrame {
                parent: proto_for(prototypes, parent_function.id, span)?,
                register: environment_slot(parent_function, global_environment_binding, span)?,
            }
        };
        Ok(Self {
            function,
            id,
            parent,
            span,
            limits,
            prototypes,
            functions,
            global_environment,
            global_environment_binding,
            environment_source,
            initial_top: Register(next_register),
            dynamic_top: Register(next_register),
            next_register,
            binding_registers,
            constants: Vec::new(),
            instructions: Vec::new(),
            close_paths: Vec::new(),
            label_frames: Vec::new(),
            pending_gotos: Vec::new(),
            loops: Vec::new(),
        })
    }

    fn finish(self) -> Result<IrPrototype, IrError> {
        if !self.label_frames.is_empty() || !self.pending_gotos.is_empty() || !self.loops.is_empty()
        {
            return Err(invalid(
                self.span,
                "CFG lowering 有未完成的 control-flow patch",
            ));
        }
        self.validate_environment_source()?;
        self.validate_open_results()?;
        let instruction_len = self.instructions.len();
        for instruction in &self.instructions {
            match instruction.instruction {
                Instruction::Jump { target } | Instruction::JumpIfFalse { target, .. }
                    if target.0 as usize >= instruction_len =>
                {
                    return Err(invalid(
                        instruction.span,
                        "CFG jump target 不在同一 prototype 指令範圍",
                    ));
                }
                _ => {}
            }
        }
        let register_count = self.next_register.max(1);
        if register_count > self.limits.max_registers {
            return Err(limit(self.span, "register 數超過 IR 限制"));
        }
        let upvalues = self
            .function
            .upvalues
            .iter()
            .enumerate()
            .map(|(index, source)| {
                Ok(IrUpvalue {
                    id: UpvalueId(
                        u16::try_from(index)
                            .map_err(|_| limit(self.span, "upvalue ID 超過 IR 限制"))?,
                    ),
                    source: source.clone(),
                })
            })
            .collect::<Result<Vec<_>, IrError>>()?;
        Ok(IrPrototype {
            id: self.id,
            function: self.function.id,
            parent: self.parent,
            span: self.span,
            register_count,
            frame: FrameLayout {
                register_limit: self.limits.max_registers,
                initial_top: self.initial_top,
                dynamic_top: self.dynamic_top,
                return_base: Register(0),
                environment: self.global_environment,
                environment_source: self.environment_source,
                registers_start_as_nil: true,
            },
            global_environment: self.global_environment,
            global_environment_binding: self.global_environment_binding,
            binding_registers: self.binding_registers,
            constants: self.constants,
            upvalues,
            instructions: self.instructions,
            close_paths: self.close_paths,
        })
    }

    fn validate_environment_source(&self) -> Result<(), IrError> {
        match self.environment_source {
            EnvironmentSource::RootExternal => {
                if self.function.id != FunctionId(0) || self.parent.is_some() {
                    return Err(invalid(
                        self.span,
                        "只有 root prototype 可以使用外部 environment source",
                    ));
                }
            }
            EnvironmentSource::ParentFrame { parent, register } => {
                let parent_function = self
                    .functions
                    .iter()
                    .find(|candidate| Some(candidate.id) == self.function.parent)
                    .ok_or_else(|| invalid(self.span, "environment source 缺少 parent function"))?;
                let expected_parent = proto_for(self.prototypes, parent_function.id, self.span)?;
                let expected_register =
                    environment_slot(parent_function, self.global_environment_binding, self.span)?;
                if parent != expected_parent || register != expected_register {
                    return Err(invalid(
                        self.span,
                        "ParentFrame environment source 與 P04 parent metadata 不符",
                    ));
                }
            }
            EnvironmentSource::ParentLocal { upvalue }
            | EnvironmentSource::ParentUpvalue { upvalue } => {
                let index = usize::from(upvalue.0);
                let Some(source) = self.function.upvalues.get(index) else {
                    return Err(invalid(self.span, "environment source 的 upvalue 不存在"));
                };
                let kind_matches = matches!(
                    (self.environment_source, source),
                    (
                        EnvironmentSource::ParentLocal { .. },
                        UpvalueSource::ParentLocal(_)
                    ) | (
                        EnvironmentSource::ParentUpvalue { .. },
                        UpvalueSource::ParentUpvalue(_)
                    )
                );
                if !kind_matches
                    || upvalue_origin(self.functions, self.function, index)
                        != Some(self.global_environment_binding)
                {
                    return Err(invalid(
                        self.span,
                        "environment source 與 P04 upvalue metadata 不符",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_open_results(&self) -> Result<(), IrError> {
        for (index, instruction) in self.instructions.iter().enumerate() {
            let is_open = matches!(
                instruction.instruction,
                Instruction::Call {
                    result_mode: ResultMode::All,
                    ..
                } | Instruction::Vararg {
                    result_mode: ResultMode::All,
                    ..
                }
            );
            if !is_open {
                continue;
            }
            let mut next = index + 1;
            while matches!(
                self.instructions.get(next).map(|entry| &entry.instruction),
                Some(Instruction::Close { .. })
            ) {
                next += 1;
            }
            if !matches!(
                self.instructions.get(next).map(|entry| &entry.instruction),
                Some(Instruction::Return {
                    result_mode: ResultMode::All,
                    ..
                })
            ) {
                return Err(invalid(
                    instruction.span,
                    "ResultMode::All 未立即流向 open return consumer",
                ));
            }
        }
        Ok(())
    }

    fn allocate(&mut self, span: Span) -> Result<Register, IrError> {
        if self.next_register >= self.limits.max_registers {
            return Err(limit(span, "register 數超過 IR 限制"));
        }
        let register = Register(self.next_register);
        self.next_register = self
            .next_register
            .checked_add(1)
            .ok_or_else(|| limit(span, "register 數超過 IR 限制"))?;
        Ok(register)
    }

    fn constant(&mut self, constant: IrConstant, span: Span) -> Result<ConstId, IrError> {
        let id = ConstId(
            u32::try_from(self.constants.len())
                .map_err(|_| limit(span, "constant ID 超過 IR 限制"))?,
        );
        self.constants.push(constant);
        Ok(id)
    }

    fn emit(
        &mut self,
        instruction: Instruction,
        span: Span,
        close_path: Option<IrClosePath>,
    ) -> Result<(), IrError> {
        if self.instructions.len() >= self.limits.max_instructions {
            return Err(limit(span, "instruction 數超過 IR 限制"));
        }
        self.instructions.push(IrInstruction {
            instruction,
            span,
            close_path,
        });
        Ok(())
    }

    fn current_offset(&self, span: Span) -> Result<InstructionOffset, IrError> {
        Ok(InstructionOffset(
            u32::try_from(self.instructions.len())
                .map_err(|_| limit(span, "instruction offset 超過 IR 限制"))?,
        ))
    }

    fn emit_jump_placeholder(&mut self, span: Span) -> Result<usize, IrError> {
        let index = self.instructions.len();
        self.emit(
            Instruction::Jump {
                target: InstructionOffset(u32::MAX),
            },
            span,
            None,
        )?;
        Ok(index)
    }

    fn emit_jump_if_false_placeholder(
        &mut self,
        condition: Register,
        span: Span,
    ) -> Result<usize, IrError> {
        let index = self.instructions.len();
        self.emit(
            Instruction::JumpIfFalse {
                condition,
                target: InstructionOffset(u32::MAX),
            },
            span,
            None,
        )?;
        Ok(index)
    }

    fn patch_jump(&mut self, index: usize, target: InstructionOffset) -> Result<(), IrError> {
        let instruction = self
            .instructions
            .get_mut(index)
            .ok_or_else(|| invalid(self.span, "CFG patch 指向不存在的 instruction"))?;
        match &mut instruction.instruction {
            Instruction::Jump {
                target: destination,
            }
            | Instruction::JumpIfFalse {
                target: destination,
                ..
            } => {
                *destination = target;
                Ok(())
            }
            _ => Err(invalid(
                instruction.span,
                "CFG patch 指向非 jump instruction",
            )),
        }
    }

    /// 固定 opcode 集沒有 Nop 或 Label；使用未被讀取的暫存器寫入作為 CFG join/label 的真實邊界。
    fn emit_cfg_anchor(&mut self, span: Span) -> Result<InstructionOffset, IrError> {
        let offset = self.current_offset(span)?;
        let dest = self.allocate(span)?;
        self.emit(
            Instruction::LoadNil {
                start: dest,
                count: 1,
            },
            span,
            None,
        )?;
        Ok(offset)
    }

    fn enter_label_frame(&mut self, block: &ResolvedBlock) -> Result<(), IrError> {
        let mut labels = Vec::new();
        for statement in &block.statements {
            if let ResolvedStmt::Label { name, span, .. } = statement {
                if labels.iter().any(|entry: &LabelEntry| entry.name == *name) {
                    return Err(invalid(*span, "P04 block 有重複 label"));
                }
                labels.push(LabelEntry {
                    name: name.clone(),
                    offset: None,
                });
            }
        }
        self.label_frames.push(LabelFrame {
            scope: block.scope,
            labels,
        });
        Ok(())
    }

    fn leave_label_frame(&mut self, block: &ResolvedBlock) -> Result<(), IrError> {
        if let Some(pending) = self
            .pending_gotos
            .iter()
            .find(|pending| pending.scope == block.scope)
        {
            return Err(invalid(pending.span, "P04 goto 缺少可 lower 的 label"));
        }
        let frame = self
            .label_frames
            .pop()
            .ok_or_else(|| invalid(block.span, "CFG label scope stack 不一致"))?;
        if frame.scope != block.scope {
            return Err(invalid(block.span, "CFG label scope stack 不一致"));
        }
        Ok(())
    }

    fn define_label(&mut self, name: &[u8], span: Span) -> Result<(), IrError> {
        let offset = self.emit_cfg_anchor(span)?;
        let frame = self
            .label_frames
            .last_mut()
            .ok_or_else(|| invalid(span, "label 不在 block scope"))?;
        let label = frame
            .labels
            .iter_mut()
            .find(|entry| entry.name == name)
            .ok_or_else(|| invalid(span, "P04 label 不在目前 scope"))?;
        if label.offset.replace(offset).is_some() {
            return Err(invalid(span, "P04 label 重複定義"));
        }
        let scope = frame.scope;
        let pending = core::mem::take(&mut self.pending_gotos);
        for pending_goto in pending {
            if pending_goto.scope == scope && pending_goto.name == name {
                self.patch_jump(pending_goto.instruction, offset)?;
            } else {
                self.pending_gotos.push(pending_goto);
            }
        }
        Ok(())
    }

    fn lower_goto(
        &mut self,
        name: &[u8],
        close_path: &ClosePath,
        span: Span,
    ) -> Result<(), IrError> {
        let target_scope = close_path
            .target_scope
            .ok_or_else(|| invalid(span, "P04 goto 缺少目標 scope"))?;
        let known = self
            .label_frames
            .iter()
            .rev()
            .find(|frame| frame.scope == target_scope)
            .and_then(|frame| {
                frame
                    .labels
                    .iter()
                    .find(|label| label.name == name)
                    .map(|label| label.offset)
            })
            .ok_or_else(|| invalid(span, "P04 goto 目標 label 不在 lexical scope"))?;
        self.emit_close(close_path)?;
        let jump = self.emit_jump_placeholder(span)?;
        if let Some(offset) = known {
            self.patch_jump(jump, offset)?;
        } else {
            self.pending_gotos.push(PendingGoto {
                instruction: jump,
                scope: target_scope,
                name: name.to_vec(),
                span,
            });
        }
        Ok(())
    }

    fn push_loop(&mut self) {
        self.loops.push(LoopFrame::default());
    }

    fn lower_break(&mut self, close_path: &ClosePath, span: Span) -> Result<(), IrError> {
        if self.loops.is_empty() {
            return Err(invalid(span, "P04 break 不在 loop 中"));
        }
        self.emit_close(close_path)?;
        let jump = self.emit_jump_placeholder(span)?;
        self.loops
            .last_mut()
            .expect("loop stack 已檢查")
            .break_patches
            .push(jump);
        Ok(())
    }

    fn finish_loop(&mut self, exit: InstructionOffset, span: Span) -> Result<(), IrError> {
        let frame = self
            .loops
            .pop()
            .ok_or_else(|| invalid(span, "CFG loop stack 不一致"))?;
        for jump in frame.break_patches {
            self.patch_jump(jump, exit)?;
        }
        Ok(())
    }

    fn lower_block_statements(&mut self, block: &ResolvedBlock) -> Result<(), IrError> {
        self.enter_label_frame(block)?;
        for statement in &block.statements {
            self.lower_statement(statement)?;
        }
        self.leave_label_frame(block)
    }

    fn lower_block(&mut self, block: &ResolvedBlock) -> Result<(), IrError> {
        self.lower_block_statements(block)?;
        self.emit_close(&block.normal_close_path)
    }

    fn emit_close(&mut self, path: &ClosePath) -> Result<(), IrError> {
        if path.bindings.is_empty() {
            return Ok(());
        }
        let mut registers = Vec::with_capacity(path.bindings.len());
        for binding in &path.bindings {
            registers.push(self.binding_register(*binding, path.span)?);
        }
        let ir_path = IrClosePath {
            kind: path.kind,
            span: path.span,
            from_scope: path.from_scope,
            target_scope: path.target_scope,
            bindings: path.bindings.clone(),
            registers: registers.clone(),
        };
        self.close_paths.push(ir_path.clone());
        // Close operand 僅能表示連續 register 範圍；每個 binding 各輸出一筆 Close，
        // 並逐指令保存同一條 P04 ClosePath 以供 codec/verifier 關聯。
        for register in registers {
            self.emit(
                Instruction::Close {
                    base: register,
                    count: 1,
                },
                path.span,
                Some(ir_path.clone()),
            )?;
        }
        Ok(())
    }

    fn lower_statement(&mut self, statement: &ResolvedStmt) -> Result<(), IrError> {
        match statement {
            ResolvedStmt::Empty { .. } => Ok(()),
            ResolvedStmt::Label { name, span, .. } => self.define_label(name, *span),
            ResolvedStmt::Return {
                values,
                close_path,
                span,
            } => self.lower_return(values, close_path, *span),
            ResolvedStmt::Local {
                bindings,
                values,
                span,
                ..
            } => {
                let base = self.lower_fixed_values(values, bindings.len(), *span)?;
                for (index, binding) in bindings.iter().enumerate() {
                    let dest = self.binding_register(*binding, *span)?;
                    let src = register_offset(base, index, *span)?;
                    self.emit(Instruction::Move { dest, src }, *span, None)?;
                }
                Ok(())
            }
            ResolvedStmt::Assignment {
                targets,
                values,
                span,
            } => {
                let base = self.lower_fixed_values(values, targets.len(), *span)?;
                for (index, target) in targets.iter().enumerate() {
                    self.store_target(target, register_offset(base, index, *span)?, *span)?;
                }
                Ok(())
            }
            ResolvedStmt::Call { call, span } => self.lower_statement_call(call, *span),
            ResolvedStmt::Break { close_path, span } => self.lower_break(close_path, *span),
            ResolvedStmt::Goto {
                name,
                close_path,
                span,
                ..
            } => self.lower_goto(name, close_path, *span),
            ResolvedStmt::Do { body, .. } => self.lower_block(body),
            ResolvedStmt::If {
                clauses,
                else_block,
                span,
            } => {
                let mut end_patches = Vec::new();
                let mut false_to_join = Vec::new();
                for (index, clause) in clauses.iter().enumerate() {
                    let condition = self.lower_expr(&clause.condition)?;
                    let false_jump = self
                        .emit_jump_if_false_placeholder(condition, expr_span(&clause.condition))?;
                    self.lower_block(&clause.body)?;
                    end_patches.push(self.emit_jump_placeholder(*span)?);
                    if index + 1 < clauses.len() {
                        let next_clause = self.current_offset(*span)?;
                        self.patch_jump(false_jump, next_clause)?;
                    } else if let Some(body) = else_block {
                        let else_entry = self.emit_cfg_anchor(body.span)?;
                        self.patch_jump(false_jump, else_entry)?;
                        self.lower_block(body)?;
                    } else {
                        false_to_join.push(false_jump);
                    }
                }
                let join = self.emit_cfg_anchor(*span)?;
                for jump in end_patches.into_iter().chain(false_to_join) {
                    self.patch_jump(jump, join)?;
                }
                Ok(())
            }
            ResolvedStmt::While {
                condition,
                body,
                span,
                ..
            } => {
                let loop_start = self.current_offset(*span)?;
                let condition_register = self.lower_expr(condition)?;
                let exit_jump =
                    self.emit_jump_if_false_placeholder(condition_register, expr_span(condition))?;
                self.push_loop();
                self.lower_block(body)?;
                self.emit(Instruction::Jump { target: loop_start }, *span, None)?;
                let exit = self.emit_cfg_anchor(*span)?;
                self.patch_jump(exit_jump, exit)?;
                self.finish_loop(exit, *span)
            }
            ResolvedStmt::Repeat {
                body,
                condition,
                span,
                ..
            } => {
                // `until` condition 仍在 repeat body scope；只有判斷後才離開該 scope。
                let loop_start = self.emit_cfg_anchor(*span)?;
                self.push_loop();
                self.lower_block_statements(body)?;
                let condition_register = self.lower_expr(condition)?;
                self.emit_close(&body.normal_close_path)?;
                self.emit(
                    Instruction::JumpIfFalse {
                        condition: condition_register,
                        target: loop_start,
                    },
                    expr_span(condition),
                    None,
                )?;
                let exit = self.emit_cfg_anchor(*span)?;
                self.finish_loop(exit, *span)
            }
            ResolvedStmt::NumericFor {
                name,
                initial,
                limit: end,
                step,
                body,
                span,
            } => {
                // initial/limit/step 一律在進入 loop 前各求值一次並保存至暫存器。
                let control = self.binding_register(name.binding, *span)?;
                let initial_value = self.lower_expr(initial)?;
                self.emit(
                    Instruction::Move {
                        dest: control,
                        src: initial_value,
                    },
                    *span,
                    None,
                )?;
                let end_value = self.lower_expr(end)?;
                let end_register = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: end_register,
                        src: end_value,
                    },
                    *span,
                    None,
                )?;
                let step_value = match step {
                    Some(step) => self.lower_expr(step)?,
                    None => {
                        let register = self.allocate(*span)?;
                        let constant = self.constant(
                            IrConstant::Literal(Literal::Integer(Number::Integer(1))),
                            *span,
                        )?;
                        self.emit(
                            Instruction::LoadConst {
                                dest: register,
                                constant,
                            },
                            *span,
                            None,
                        )?;
                        register
                    }
                };
                let step_register = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: step_register,
                        src: step_value,
                    },
                    *span,
                    None,
                )?;
                let zero_register = self.allocate(*span)?;
                let zero_constant = self.constant(
                    IrConstant::Literal(Literal::Integer(Number::Integer(0))),
                    *span,
                )?;
                self.emit(
                    Instruction::LoadConst {
                        dest: zero_register,
                        constant: zero_constant,
                    },
                    *span,
                    None,
                )?;

                let loop_start = self.current_offset(*span)?;
                let negative = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest: negative,
                        op: BinaryOperation::Less,
                        left: step_register,
                        right: zero_register,
                    },
                    *span,
                    None,
                )?;
                let positive_branch = self.emit_jump_if_false_placeholder(negative, *span)?;

                let negative_comparison = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest: negative_comparison,
                        op: BinaryOperation::GreaterEqual,
                        left: control,
                        right: end_register,
                    },
                    *span,
                    None,
                )?;
                let negative_exit =
                    self.emit_jump_if_false_placeholder(negative_comparison, *span)?;
                let negative_to_body = self.emit_jump_placeholder(*span)?;

                let positive_start = self.current_offset(*span)?;
                self.patch_jump(positive_branch, positive_start)?;
                let positive_comparison = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest: positive_comparison,
                        op: BinaryOperation::LessEqual,
                        left: control,
                        right: end_register,
                    },
                    *span,
                    None,
                )?;
                let positive_exit =
                    self.emit_jump_if_false_placeholder(positive_comparison, *span)?;
                let body_start = self.current_offset(*span)?;
                self.patch_jump(negative_to_body, body_start)?;

                self.push_loop();
                self.lower_block(body)?;
                let next = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest: next,
                        op: BinaryOperation::Add,
                        left: control,
                        right: step_register,
                    },
                    *span,
                    None,
                )?;
                self.emit(
                    Instruction::Move {
                        dest: control,
                        src: next,
                    },
                    *span,
                    None,
                )?;
                self.emit(Instruction::Jump { target: loop_start }, *span, None)?;
                let exit = self.emit_cfg_anchor(*span)?;
                self.patch_jump(negative_exit, exit)?;
                self.patch_jump(positive_exit, exit)?;
                self.finish_loop(exit, *span)
            }
            ResolvedStmt::GenericFor {
                names,
                values,
                body,
                span,
            } => {
                // 所有 initial expressions 均按原順序求值；僅前 3 個形成 iterator triple。
                let mut initial_values = Vec::with_capacity(values.len());
                for value in values {
                    initial_values.push(self.lower_expr(value)?);
                }
                let iterator_source = *initial_values
                    .first()
                    .ok_or_else(|| invalid(*span, "P04 generic for 缺少 iterator"))?;
                let iterator = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: iterator,
                        src: iterator_source,
                    },
                    *span,
                    None,
                )?;
                let state_source = match initial_values.get(1) {
                    Some(value) => *value,
                    None => self.nil_register(*span)?,
                };
                let state = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: state,
                        src: state_source,
                    },
                    *span,
                    None,
                )?;
                let control_source = match initial_values.get(2) {
                    Some(value) => *value,
                    None => self.nil_register(*span)?,
                };
                let control = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: control,
                        src: control_source,
                    },
                    *span,
                    None,
                )?;

                let loop_start = self.current_offset(*span)?;
                let call_base = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: call_base,
                        src: iterator,
                    },
                    *span,
                    None,
                )?;
                let call_state = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: call_state,
                        src: state,
                    },
                    *span,
                    None,
                )?;
                let call_control = self.allocate(*span)?;
                self.emit(
                    Instruction::Move {
                        dest: call_control,
                        src: control,
                    },
                    *span,
                    None,
                )?;
                let result_count = u16::try_from(names.len())
                    .map_err(|_| limit(*span, "generic for result 數超過 IR 限制"))?;
                if result_count == 0 {
                    return Err(invalid(*span, "P04 generic for 缺少 control name"));
                }
                for _ in 3..usize::from(result_count) {
                    self.allocate(*span)?;
                }
                self.emit(
                    Instruction::Call {
                        base: call_base,
                        arg_count: 2,
                        result_mode: ResultMode::Fixed(result_count),
                    },
                    *span,
                    None,
                )?;
                // Lua generic-for 僅在第一個 iterator result 是 nil 時終止；false 仍可作 control。
                let nil = self.nil_register(*span)?;
                let non_nil = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest: non_nil,
                        op: BinaryOperation::NotEqual,
                        left: call_base,
                        right: nil,
                    },
                    *span,
                    None,
                )?;
                let exit_jump = self.emit_jump_if_false_placeholder(non_nil, *span)?;
                self.emit(
                    Instruction::Move {
                        dest: control,
                        src: call_base,
                    },
                    *span,
                    None,
                )?;
                for (index, name) in names.iter().enumerate() {
                    let source =
                        Register(
                            call_base
                                .0
                                .checked_add(u16::try_from(index).map_err(|_| {
                                    limit(*span, "generic for result 數超過 IR 限制")
                                })?)
                                .ok_or_else(|| limit(*span, "generic for register 超過 IR 限制"))?,
                        );
                    let destination = self.binding_register(name.binding, name.span)?;
                    self.emit(
                        Instruction::Move {
                            dest: destination,
                            src: source,
                        },
                        name.span,
                        None,
                    )?;
                }
                self.push_loop();
                self.lower_block(body)?;
                self.emit(Instruction::Jump { target: loop_start }, *span, None)?;
                let exit = self.emit_cfg_anchor(*span)?;
                self.patch_jump(exit_jump, exit)?;
                self.finish_loop(exit, *span)
            }
            ResolvedStmt::Function {
                name, body, span, ..
            } => {
                let closure = self.lower_function(body)?;
                self.store_target(name, closure, *span)
            }
            ResolvedStmt::LocalFunction { name, body, span } => {
                let closure = self.lower_function(body)?;
                let dest = self.binding_register(name.binding, *span)?;
                self.emit(Instruction::Move { dest, src: closure }, *span, None)
            }
            ResolvedStmt::Global { declaration, span } => self.lower_global(declaration, *span),
        }
    }

    fn lower_global(
        &mut self,
        declaration: &ResolvedGlobalDeclaration,
        span: Span,
    ) -> Result<(), IrError> {
        let table = self.global_table_register(span)?;
        match declaration {
            ResolvedGlobalDeclaration::Names { names, values, .. } => {
                for (index, name) in names.iter().enumerate() {
                    let value = match values.get(index) {
                        Some(value) => self.lower_expr(value)?,
                        None => {
                            let register = self.allocate(span)?;
                            self.emit(
                                Instruction::LoadNil {
                                    start: register,
                                    count: 1,
                                },
                                span,
                                None,
                            )?;
                            register
                        }
                    };
                    let key = self.name_constant(&name.name, name.span)?;
                    self.emit(Instruction::SetTable { table, key, value }, span, None)?;
                }
                Ok(())
            }
            ResolvedGlobalDeclaration::Star { .. } => Ok(()),
            ResolvedGlobalDeclaration::Function { name, body, .. } => {
                let value = self.lower_function(body)?;
                let key = self.name_constant(name, span)?;
                self.emit(Instruction::SetTable { table, key, value }, span, None)
            }
        }
    }

    fn nil_register(&mut self, span: Span) -> Result<Register, IrError> {
        let register = self.allocate(span)?;
        self.emit(
            Instruction::LoadNil {
                start: register,
                count: 1,
            },
            span,
            None,
        )?;
        Ok(register)
    }

    fn mark_dynamic_top(&mut self, base: Register) {
        self.dynamic_top = base;
    }

    fn reserve_registers(&mut self, count: usize, span: Span) -> Result<Register, IrError> {
        let base = Register(self.next_register);
        for _ in 0..count {
            self.allocate(span)?;
        }
        Ok(base)
    }

    fn lower_fixed_values(
        &mut self,
        values: &[ResolvedExpr],
        count: usize,
        span: Span,
    ) -> Result<Register, IrError> {
        let mut sources = Vec::with_capacity(values.len());
        for value in values {
            sources.push(self.lower_expr(value)?);
        }
        let base = self.reserve_registers(count, span)?;
        for index in 0..count {
            let dest = register_offset(base, index, span)?;
            match sources.get(index) {
                Some(source) => self.emit(Instruction::Move { dest, src: *source }, span, None)?,
                None => self.emit(
                    Instruction::LoadNil {
                        start: dest,
                        count: 1,
                    },
                    span,
                    None,
                )?,
            }
        }
        Ok(base)
    }

    fn lower_return(
        &mut self,
        values: &[ResolvedExpr],
        close_path: &ClosePath,
        span: Span,
    ) -> Result<(), IrError> {
        if let [value] = values {
            if matches!(
                value,
                ResolvedExpr::Call { .. } | ResolvedExpr::MethodCall { .. }
            ) {
                return self.lower_tail_return(value, close_path, span);
            }
        }
        let (base, result_mode) = self.lower_return_values(values, span)?;
        self.emit_close(close_path)?;
        self.emit(Instruction::Return { base, result_mode }, span, None)
    }

    fn lower_return_values(
        &mut self,
        values: &[ResolvedExpr],
        span: Span,
    ) -> Result<(Register, ResultMode), IrError> {
        if values.is_empty() {
            return Ok((Register(0), ResultMode::Fixed(0)));
        }
        let last = values.last().expect("non-empty 已檢查");
        if self.is_open_expression(last) {
            let mut prefix = Vec::with_capacity(values.len() - 1);
            for value in &values[..values.len() - 1] {
                prefix.push(self.lower_expr(value)?);
            }
            let call_base_offset = prefix.len();
            let slots = call_base_offset
                .checked_add(self.open_slots(last, span)?)
                .ok_or_else(|| limit(span, "return register 數超過 IR 限制"))?;
            let base = self.reserve_registers(slots, span)?;
            for (index, source) in prefix.into_iter().enumerate() {
                self.emit(
                    Instruction::Move {
                        dest: register_offset(base, index, span)?,
                        src: source,
                    },
                    span,
                    None,
                )?;
            }
            self.lower_open_expression_at(
                last,
                register_offset(base, call_base_offset, span)?,
                span,
            )?;
            Ok((base, ResultMode::All))
        } else {
            let base = self.lower_fixed_values(values, values.len(), span)?;
            Ok((
                base,
                ResultMode::Fixed(
                    u16::try_from(values.len())
                        .map_err(|_| limit(span, "return result 數超過 IR 限制"))?,
                ),
            ))
        }
    }

    fn is_open_expression(&self, expression: &ResolvedExpr) -> bool {
        matches!(
            expression,
            ResolvedExpr::Call { .. }
                | ResolvedExpr::MethodCall { .. }
                | ResolvedExpr::Vararg { .. }
        )
    }

    fn open_slots(&self, expression: &ResolvedExpr, span: Span) -> Result<usize, IrError> {
        match expression {
            ResolvedExpr::Call { arguments, .. } => Ok(arguments.len().saturating_add(1)),
            ResolvedExpr::MethodCall { arguments, .. } => Ok(arguments.len().saturating_add(2)),
            ResolvedExpr::Vararg { .. } => Ok(1),
            _ => Err(invalid(span, "只有 Call 或 Vararg 可使用 ResultMode::All")),
        }
    }

    fn lower_tail_return(
        &mut self,
        expression: &ResolvedExpr,
        close_path: &ClosePath,
        span: Span,
    ) -> Result<(), IrError> {
        let (base, arg_count) = self.prepare_open_call(expression, span)?;
        self.emit_close(close_path)?;
        self.mark_dynamic_top(base);
        self.emit(
            Instruction::TailCall {
                base,
                arg_count,
                result_mode: ResultMode::All,
            },
            span,
            None,
        )
    }

    fn lower_statement_call(
        &mut self,
        expression: &ResolvedExpr,
        span: Span,
    ) -> Result<(), IrError> {
        let (base, arg_count) = self.prepare_open_call(expression, span)?;
        self.emit(
            Instruction::Call {
                base,
                arg_count,
                result_mode: ResultMode::Fixed(0),
            },
            span,
            None,
        )
    }

    fn prepare_open_call(
        &mut self,
        expression: &ResolvedExpr,
        span: Span,
    ) -> Result<(Register, u16), IrError> {
        match expression {
            ResolvedExpr::Call {
                callee, arguments, ..
            } => {
                let callee = self.lower_expr(callee)?;
                let arguments = self.lower_argument_registers(arguments)?;
                self.prepare_call_registers(callee, &arguments, span)
            }
            ResolvedExpr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                let receiver = self.lower_expr(receiver)?;
                let key = self.name_constant(method, span)?;
                let callee = self.allocate(span)?;
                self.emit(
                    Instruction::GetTable {
                        dest: callee,
                        table: receiver,
                        key,
                    },
                    span,
                    None,
                )?;
                let mut values = Vec::with_capacity(arguments.len() + 1);
                values.push(receiver);
                values.extend(self.lower_argument_registers(arguments)?);
                self.prepare_call_registers(callee, &values, span)
            }
            _ => Err(invalid(span, "只有 Call 可作 call statement 或 tail call")),
        }
    }

    fn lower_argument_registers(
        &mut self,
        arguments: &[ResolvedExpr],
    ) -> Result<Vec<Register>, IrError> {
        let mut values = Vec::with_capacity(arguments.len());
        for argument in arguments {
            values.push(self.lower_expr(argument)?);
        }
        Ok(values)
    }

    fn prepare_call_registers(
        &mut self,
        callee: Register,
        arguments: &[Register],
        span: Span,
    ) -> Result<(Register, u16), IrError> {
        let arg_count =
            u16::try_from(arguments.len()).map_err(|_| limit(span, "call arg 數超過 IR 限制"))?;
        let base = self.reserve_registers(arguments.len().saturating_add(1), span)?;
        self.emit(
            Instruction::Move {
                dest: base,
                src: callee,
            },
            span,
            None,
        )?;
        for (index, source) in arguments.iter().enumerate() {
            self.emit(
                Instruction::Move {
                    dest: register_offset(base, index + 1, span)?,
                    src: *source,
                },
                span,
                None,
            )?;
        }
        Ok((base, arg_count))
    }

    fn lower_open_expression_at(
        &mut self,
        expression: &ResolvedExpr,
        base: Register,
        span: Span,
    ) -> Result<(), IrError> {
        match expression {
            ResolvedExpr::Call {
                callee, arguments, ..
            } => {
                let callee = self.lower_expr(callee)?;
                let arguments = self.lower_argument_registers(arguments)?;
                let arg_count = self.move_call_inputs_at(base, callee, &arguments, span)?;
                self.mark_dynamic_top(base);
                self.emit(
                    Instruction::Call {
                        base,
                        arg_count,
                        result_mode: ResultMode::All,
                    },
                    span,
                    None,
                )
            }
            ResolvedExpr::MethodCall {
                receiver,
                method,
                arguments,
                ..
            } => {
                let receiver = self.lower_expr(receiver)?;
                let key = self.name_constant(method, span)?;
                let callee = self.allocate(span)?;
                self.emit(
                    Instruction::GetTable {
                        dest: callee,
                        table: receiver,
                        key,
                    },
                    span,
                    None,
                )?;
                let mut values = Vec::with_capacity(arguments.len() + 1);
                values.push(receiver);
                values.extend(self.lower_argument_registers(arguments)?);
                let arg_count = self.move_call_inputs_at(base, callee, &values, span)?;
                self.mark_dynamic_top(base);
                self.emit(
                    Instruction::Call {
                        base,
                        arg_count,
                        result_mode: ResultMode::All,
                    },
                    span,
                    None,
                )
            }
            ResolvedExpr::Vararg { .. } => {
                self.mark_dynamic_top(base);
                self.emit(
                    Instruction::Vararg {
                        base,
                        result_mode: ResultMode::All,
                    },
                    span,
                    None,
                )
            }
            _ => Err(invalid(span, "只有 Call 或 Vararg 可使用 ResultMode::All")),
        }
    }

    fn move_call_inputs_at(
        &mut self,
        base: Register,
        callee: Register,
        arguments: &[Register],
        span: Span,
    ) -> Result<u16, IrError> {
        let arg_count =
            u16::try_from(arguments.len()).map_err(|_| limit(span, "call arg 數超過 IR 限制"))?;
        self.emit(
            Instruction::Move {
                dest: base,
                src: callee,
            },
            span,
            None,
        )?;
        for (index, source) in arguments.iter().enumerate() {
            self.emit(
                Instruction::Move {
                    dest: register_offset(base, index + 1, span)?,
                    src: *source,
                },
                span,
                None,
            )?;
        }
        Ok(arg_count)
    }

    fn lower_expr(&mut self, expression: &ResolvedExpr) -> Result<Register, IrError> {
        self.lower_expr_mode(expression, ResultMode::Fixed(1))
    }

    fn lower_expr_mode(
        &mut self,
        expression: &ResolvedExpr,
        result_mode: ResultMode,
    ) -> Result<Register, IrError> {
        if matches!(result_mode, ResultMode::All) && !self.is_open_expression(expression) {
            return Err(invalid(
                expr_span(expression),
                "ResultMode::All 只可流向 Call、Vararg 或 Return",
            ));
        }
        match expression {
            ResolvedExpr::Literal { literal, span } => {
                let dest = self.allocate(*span)?;
                let constant = self.constant(IrConstant::Literal(literal.clone()), *span)?;
                self.emit(Instruction::LoadConst { dest, constant }, *span, None)?;
                Ok(dest)
            }
            ResolvedExpr::Nil { span } => self.nil_register(*span),
            ResolvedExpr::Bool { value, span } => {
                let dest = self.allocate(*span)?;
                let constant = self.constant(IrConstant::Boolean(*value), *span)?;
                self.emit(Instruction::LoadConst { dest, constant }, *span, None)?;
                Ok(dest)
            }
            ResolvedExpr::Name {
                name,
                resolution,
                span,
            } => self.lower_name(name, resolution, *span),
            ResolvedExpr::Vararg { span, .. } => {
                let base = self.reserve_registers(
                    match result_mode {
                        ResultMode::Fixed(count) => usize::from(count.max(1)),
                        ResultMode::All => 1,
                    },
                    *span,
                )?;
                self.emit(Instruction::Vararg { base, result_mode }, *span, None)?;
                Ok(base)
            }
            ResolvedExpr::Unary {
                op,
                expression,
                span,
            } => {
                let src = self.lower_expr(expression)?;
                let dest = self.allocate(*span)?;
                self.emit(
                    Instruction::UnaryOp {
                        dest,
                        op: map_unary(*op),
                        src,
                    },
                    *span,
                    None,
                )?;
                Ok(dest)
            }
            ResolvedExpr::Binary {
                op,
                left,
                right,
                span,
            } => {
                let left = self.lower_expr(left)?;
                let right = self.lower_expr(right)?;
                let dest = self.allocate(*span)?;
                self.emit(
                    Instruction::BinaryOp {
                        dest,
                        op: map_binary(*op),
                        left,
                        right,
                    },
                    *span,
                    None,
                )?;
                Ok(dest)
            }
            ResolvedExpr::Paren { expression, .. } => self.lower_expr(expression),
            ResolvedExpr::Index { base, index, span } => {
                let table = self.lower_expr(base)?;
                let key = self.lower_expr(index)?;
                let dest = self.allocate(*span)?;
                self.emit(Instruction::GetTable { dest, table, key }, *span, None)?;
                Ok(dest)
            }
            ResolvedExpr::Field { base, name, span } => {
                let table = self.lower_expr(base)?;
                let key = self.name_constant(name, *span)?;
                let dest = self.allocate(*span)?;
                self.emit(Instruction::GetTable { dest, table, key }, *span, None)?;
                Ok(dest)
            }
            ResolvedExpr::Call { span, .. } => {
                let (base, arg_count) = self.prepare_open_call(expression, *span)?;
                self.emit(
                    Instruction::Call {
                        base,
                        arg_count,
                        result_mode,
                    },
                    *span,
                    None,
                )?;
                Ok(base)
            }
            ResolvedExpr::MethodCall { span, .. } => {
                let (base, arg_count) = self.prepare_open_call(expression, *span)?;
                self.emit(
                    Instruction::Call {
                        base,
                        arg_count,
                        result_mode,
                    },
                    *span,
                    None,
                )?;
                Ok(base)
            }
            ResolvedExpr::Function { body, .. } => self.lower_function(body),
            ResolvedExpr::TableConstructor { fields, span } => {
                let table = self.allocate(*span)?;
                self.emit(Instruction::NewTable { dest: table }, *span, None)?;
                for field in fields {
                    match field {
                        ResolvedTableField::Array { value, span, .. } => {
                            let key = self.constant_register(
                                IrConstant::Name(span.start_byte.to_le_bytes().to_vec()),
                                *span,
                            )?;
                            let value = self.lower_expr(value)?;
                            self.emit(Instruction::SetTable { table, key, value }, *span, None)?;
                        }
                        ResolvedTableField::Named {
                            name, value, span, ..
                        } => {
                            let key = self.name_constant(name, *span)?;
                            let value = self.lower_expr(value)?;
                            self.emit(Instruction::SetTable { table, key, value }, *span, None)?;
                        }
                        ResolvedTableField::Indexed {
                            key, value, span, ..
                        } => {
                            let key = self.lower_expr(key)?;
                            let value = self.lower_expr(value)?;
                            self.emit(Instruction::SetTable { table, key, value }, *span, None)?;
                        }
                    }
                }
                Ok(table)
            }
        }
    }

    fn lower_function(&mut self, body: &ResolvedFunctionBody) -> Result<Register, IrError> {
        let dest = self.allocate(body.span)?;
        let proto = proto_for(self.prototypes, body.function, body.span)?;
        self.emit(Instruction::Closure { dest, proto }, body.span, None)?;
        Ok(dest)
    }

    fn lower_name(
        &mut self,
        name: &[u8],
        resolution: &ResolvedName,
        span: Span,
    ) -> Result<Register, IrError> {
        match resolution {
            ResolvedName::Local(binding) => self.binding_register(*binding, span),
            ResolvedName::Upvalue(upvalue) => self.load_upvalue(*upvalue, span),
            ResolvedName::EnvField { env, .. } => {
                let key = self.name_constant(name, span)?;
                let table = self.binding_value(*env, span)?;
                let dest = self.allocate(span)?;
                self.emit(Instruction::GetTable { dest, table, key }, span, None)?;
                Ok(dest)
            }
            ResolvedName::Global(_) => {
                let key = self.name_constant(name, span)?;
                let table = self.global_table_register(span)?;
                let dest = self.allocate(span)?;
                self.emit(Instruction::GetTable { dest, table, key }, span, None)?;
                Ok(dest)
            }
        }
    }

    fn load_upvalue(
        &mut self,
        upvalue: crate::resolve::UpvalueId,
        span: Span,
    ) -> Result<Register, IrError> {
        let dest = self.allocate(span)?;
        self.emit(
            Instruction::GetUpvalue {
                dest,
                upvalue: UpvalueId(
                    u16::try_from(upvalue.0).map_err(|_| limit(span, "upvalue ID 超過 IR 限制"))?,
                ),
            },
            span,
            None,
        )?;
        Ok(dest)
    }

    fn binding_value(&mut self, binding: BindingId, span: Span) -> Result<Register, IrError> {
        if binding.function == self.function.id {
            return self.binding_register(binding, span);
        }
        let upvalue = self
            .function
            .upvalues
            .iter()
            .enumerate()
            .find_map(|(index, _)| {
                (upvalue_origin(self.functions, self.function, index) == Some(binding))
                    .then_some(index)
            })
            .ok_or_else(|| invalid(span, "P04 binding 未以目前 function upvalue 提供"))?;
        self.load_upvalue(
            crate::resolve::UpvalueId(
                u32::try_from(upvalue).map_err(|_| limit(span, "upvalue ID 超過 IR 限制"))?,
            ),
            span,
        )
    }

    fn global_table_register(&mut self, _span: Span) -> Result<Register, IrError> {
        Ok(self.global_environment)
    }

    fn store_target(
        &mut self,
        target: &ResolvedExpr,
        value: Register,
        span: Span,
    ) -> Result<(), IrError> {
        match target {
            ResolvedExpr::Name {
                resolution: ResolvedName::Local(binding),
                ..
            } => {
                let dest = self.binding_register(*binding, span)?;
                self.emit(Instruction::Move { dest, src: value }, span, None)
            }
            ResolvedExpr::Name {
                resolution: ResolvedName::Upvalue(upvalue),
                ..
            } => self.emit(
                Instruction::SetUpvalue {
                    upvalue: UpvalueId(
                        u16::try_from(upvalue.0)
                            .map_err(|_| limit(span, "upvalue ID 超過 IR 限制"))?,
                    ),
                    src: value,
                },
                span,
                None,
            ),
            ResolvedExpr::Index { base, index, .. } => {
                let table = self.lower_expr(base)?;
                let key = self.lower_expr(index)?;
                self.emit(Instruction::SetTable { table, key, value }, span, None)
            }
            ResolvedExpr::Field { base, name, .. } => {
                let table = self.lower_expr(base)?;
                let key = self.name_constant(name, span)?;
                self.emit(Instruction::SetTable { table, key, value }, span, None)
            }
            ResolvedExpr::Name {
                name,
                resolution: ResolvedName::EnvField { env, .. },
                ..
            } => {
                let key = self.name_constant(name, span)?;
                let table = self.binding_value(*env, span)?;
                self.emit(Instruction::SetTable { table, key, value }, span, None)
            }
            ResolvedExpr::Name {
                name,
                resolution: ResolvedName::Global(_),
                ..
            } => {
                let key = self.name_constant(name, span)?;
                let table = self.global_table_register(span)?;
                self.emit(Instruction::SetTable { table, key, value }, span, None)
            }
            _ => Err(invalid(span, "P04 assignment target 不可 lower")),
        }
    }

    fn binding_register(&self, binding: BindingId, span: Span) -> Result<Register, IrError> {
        self.binding_registers
            .iter()
            .find_map(|(candidate, register)| (*candidate == binding).then_some(*register))
            .ok_or_else(|| invalid(span, "P04 binding 不屬於目前 prototype"))
    }

    fn name_constant(&mut self, name: &[u8], span: Span) -> Result<Register, IrError> {
        self.constant_register(IrConstant::Name(name.to_vec()), span)
    }
    fn constant_register(&mut self, constant: IrConstant, span: Span) -> Result<Register, IrError> {
        let dest = self.allocate(span)?;
        let constant = self.constant(constant, span)?;
        self.emit(Instruction::LoadConst { dest, constant }, span, None)?;
        Ok(dest)
    }
}

fn environment_slot(
    function: &ResolvedFunction,
    root_environment: BindingId,
    span: Span,
) -> Result<Register, IrError> {
    if function.id == FunctionId(0) {
        function
            .bindings
            .iter()
            .position(|binding| binding.id == root_environment)
            .map(|index| {
                Register(
                    u16::try_from(index + 1).expect("function binding index 已受 P04 limit 限制"),
                )
            })
            .ok_or_else(|| invalid(span, "root _ENV binding 未配置 register"))
    } else {
        Ok(Register(
            u16::try_from(function.bindings.len() + 1)
                .map_err(|_| limit(span, "register 數超過 IR 限制"))?,
        ))
    }
}

fn upvalue_origin(
    functions: &[ResolvedFunction],
    function: &ResolvedFunction,
    index: usize,
) -> Option<BindingId> {
    match function.upvalues.get(index)? {
        UpvalueSource::ParentLocal(binding) => Some(*binding),
        UpvalueSource::ParentUpvalue(parent_index) => {
            let parent = functions
                .iter()
                .find(|candidate| Some(candidate.id) == function.parent)?;
            upvalue_origin(functions, parent, parent_index.0 as usize)
        }
    }
}

fn register_offset(base: Register, offset: usize, span: Span) -> Result<Register, IrError> {
    let offset = u16::try_from(offset).map_err(|_| limit(span, "register offset 超過 IR 限制"))?;
    Ok(Register(base.0.checked_add(offset).ok_or_else(|| {
        limit(span, "register offset 超過 IR 限制")
    })?))
}

fn proto_for(
    prototypes: &[(FunctionId, ProtoId)],
    function: FunctionId,
    span: Span,
) -> Result<ProtoId, IrError> {
    prototypes
        .iter()
        .find_map(|(candidate, proto)| (*candidate == function).then_some(*proto))
        .ok_or_else(|| invalid(span, "P04 FunctionId 無 prototype map"))
}
fn invalid(span: Span, message: &str) -> IrError {
    IrError {
        span,
        message: message.into(),
    }
}
fn expr_span(expression: &ResolvedExpr) -> Span {
    match expression {
        ResolvedExpr::Literal { span, .. }
        | ResolvedExpr::Nil { span }
        | ResolvedExpr::Bool { span, .. }
        | ResolvedExpr::Name { span, .. }
        | ResolvedExpr::Vararg { span, .. }
        | ResolvedExpr::Unary { span, .. }
        | ResolvedExpr::Binary { span, .. }
        | ResolvedExpr::Paren { span, .. }
        | ResolvedExpr::Index { span, .. }
        | ResolvedExpr::Field { span, .. }
        | ResolvedExpr::Call { span, .. }
        | ResolvedExpr::MethodCall { span, .. }
        | ResolvedExpr::Function { span, .. }
        | ResolvedExpr::TableConstructor { span, .. } => *span,
    }
}
fn limit(span: Span, message: &str) -> IrError {
    IrError {
        span,
        message: message.into(),
    }
}
fn map_unary(op: UnaryOp) -> UnaryOperation {
    match op {
        UnaryOp::Negate => UnaryOperation::Negate,
        UnaryOp::Not => UnaryOperation::Not,
        UnaryOp::Length => UnaryOperation::Length,
        UnaryOp::BitNot => UnaryOperation::BitNot,
    }
}
fn map_binary(op: BinaryOp) -> BinaryOperation {
    match op {
        BinaryOp::Or => BinaryOperation::Or,
        BinaryOp::And => BinaryOperation::And,
        BinaryOp::Equal => BinaryOperation::Equal,
        BinaryOp::NotEqual => BinaryOperation::NotEqual,
        BinaryOp::Less => BinaryOperation::Less,
        BinaryOp::LessEqual => BinaryOperation::LessEqual,
        BinaryOp::Greater => BinaryOperation::Greater,
        BinaryOp::GreaterEqual => BinaryOperation::GreaterEqual,
        BinaryOp::Pipe => BinaryOperation::Pipe,
        BinaryOp::BitXor => BinaryOperation::BitXor,
        BinaryOp::Ampersand => BinaryOperation::Ampersand,
        BinaryOp::ShiftLeft => BinaryOperation::ShiftLeft,
        BinaryOp::ShiftRight => BinaryOperation::ShiftRight,
        BinaryOp::Concat => BinaryOperation::Concat,
        BinaryOp::Add => BinaryOperation::Add,
        BinaryOp::Subtract => BinaryOperation::Subtract,
        BinaryOp::Multiply => BinaryOperation::Multiply,
        BinaryOp::Divide => BinaryOperation::Divide,
        BinaryOp::FloorDivide => BinaryOperation::FloorDivide,
        BinaryOp::Modulo => BinaryOperation::Modulo,
        BinaryOp::Power => BinaryOperation::Power,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompileLimits, lex, parse, resolve};

    #[test]
    fn ir_rejects_open_result_without_immediate_return_consumer() {
        let limits = CompileLimits::default();
        let chunk = lex(b"", LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&module, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let function = &resolved.functions[0];
        let mappings = vec![(FunctionId(0), ProtoId(0))];
        let ir_limits = IrLimits::default();
        let mut builder = Builder::new(
            function,
            ProtoId(0),
            None,
            resolved.span,
            &ir_limits,
            &mappings,
            &resolved.functions,
        )
        .unwrap();
        builder
            .emit(
                Instruction::Call {
                    base: Register(0),
                    arg_count: 0,
                    result_mode: ResultMode::All,
                },
                resolved.span,
                None,
            )
            .unwrap();
        assert!(builder.finish().is_err());
    }

    #[test]
    fn ir_lowers_a_binary_return_without_source_rescan() {
        let limits = CompileLimits::default();
        let chunk = lex(b"return 1+2", LanguageProfile::Lua55, &limits).unwrap();
        let module = parse(&chunk, LanguageProfile::Lua55, &limits).unwrap();
        let resolved = resolve(&module, &chunk, LanguageProfile::Lua55, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        assert!(
            ir.prototypes[0]
                .instructions
                .iter()
                .any(|instruction| matches!(
                    instruction.instruction,
                    Instruction::BinaryOp {
                        op: BinaryOperation::Add,
                        ..
                    }
                ))
        );
    }
}

/// 將已完成 P05 lowering 的 owned IR 轉成 RVLU candidate，並交給 core 共用 validator/codec。
pub fn emit(
    module: &IrModule,
    limits: &rivetlua_core::VerifyLimits,
) -> Result<rivetlua_core::EncodedModule, rivetlua_core::BytecodeError> {
    rivetlua_core::encode_module(bytecode_module(module)?, module.profile, limits)
}

fn bytecode_module(
    module: &IrModule,
) -> Result<rivetlua_core::BytecodeModule, rivetlua_core::BytecodeError> {
    Ok(rivetlua_core::BytecodeModule {
        profile: module.profile,
        numeric_config: rivetlua_core::RVLU_NUMERIC_I64_F64,
        span: bytecode_span(module.span),
        function_prototypes: module
            .function_prototypes
            .iter()
            .map(|(function, prototype)| (function.0, *prototype))
            .collect(),
        prototypes: module
            .prototypes
            .iter()
            .map(bytecode_prototype)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn bytecode_prototype(
    prototype: &IrPrototype,
) -> Result<rivetlua_core::BytecodePrototype, rivetlua_core::BytecodeError> {
    Ok(rivetlua_core::BytecodePrototype {
        id: prototype.id,
        function: prototype.function.0,
        parent: prototype.parent,
        span: bytecode_span(prototype.span),
        register_count: prototype.register_count,
        frame: prototype.frame,
        global_environment: prototype.global_environment,
        global_environment_binding: bytecode_binding(prototype.global_environment_binding),
        binding_registers: prototype
            .binding_registers
            .iter()
            .map(|(binding, register)| (bytecode_binding(*binding), *register))
            .collect(),
        constants: prototype.constants.iter().map(bytecode_constant).collect(),
        upvalues: prototype
            .upvalues
            .iter()
            .map(bytecode_upvalue)
            .collect::<Result<Vec<_>, _>>()?,
        instructions: prototype
            .instructions
            .iter()
            .map(|instruction| rivetlua_core::BytecodeInstruction {
                instruction: instruction.instruction.clone(),
                span: bytecode_span(instruction.span),
                close_path: instruction.close_path.as_ref().map(bytecode_close_path),
            })
            .collect(),
        close_paths: prototype
            .close_paths
            .iter()
            .map(bytecode_close_path)
            .collect(),
    })
}

fn bytecode_constant(constant: &IrConstant) -> rivetlua_core::BytecodeConstant {
    match constant {
        IrConstant::Literal(Literal::Name(value)) | IrConstant::Name(value) => {
            rivetlua_core::BytecodeConstant::Name(value.clone())
        }
        IrConstant::Literal(Literal::String(value)) => {
            rivetlua_core::BytecodeConstant::String(value.clone())
        }
        IrConstant::Literal(Literal::Integer(Number::Integer(value)))
        | IrConstant::Literal(Literal::Float(Number::Integer(value))) => {
            rivetlua_core::BytecodeConstant::Integer(*value)
        }
        IrConstant::Literal(Literal::Integer(Number::Float(value)))
        | IrConstant::Literal(Literal::Float(Number::Float(value))) => {
            rivetlua_core::BytecodeConstant::FloatBits(value.to_bits())
        }
        IrConstant::Boolean(value) => rivetlua_core::BytecodeConstant::Boolean(*value),
    }
}

fn bytecode_upvalue(
    upvalue: &IrUpvalue,
) -> Result<rivetlua_core::BytecodeUpvalue, rivetlua_core::BytecodeError> {
    let source = match upvalue.source {
        UpvalueSource::ParentLocal(binding) => {
            rivetlua_core::BytecodeUpvalueSource::ParentLocal(bytecode_binding(binding))
        }
        UpvalueSource::ParentUpvalue(parent) => {
            rivetlua_core::BytecodeUpvalueSource::ParentUpvalue(UpvalueId(
                u16::try_from(parent.0).map_err(|_| rivetlua_core::BytecodeError {
                    code: rivetlua_core::BytecodeErrorCode::CompileLimit,
                    offset: 0,
                    message: "P04 upvalue ID 超過 RVLU 限制".into(),
                })?,
            ))
        }
    };
    Ok(rivetlua_core::BytecodeUpvalue {
        id: upvalue.id,
        source,
    })
}

fn bytecode_close_path(close: &IrClosePath) -> rivetlua_core::BytecodeClosePath {
    rivetlua_core::BytecodeClosePath {
        kind: match close.kind {
            crate::ExitKind::Normal => rivetlua_core::BytecodeExitKind::Normal,
            crate::ExitKind::Return => rivetlua_core::BytecodeExitKind::Return,
            crate::ExitKind::Break => rivetlua_core::BytecodeExitKind::Break,
            crate::ExitKind::Goto => rivetlua_core::BytecodeExitKind::Goto,
            crate::ExitKind::Error => rivetlua_core::BytecodeExitKind::Error,
        },
        span: bytecode_span(close.span),
        from_scope: close.from_scope.0,
        target_scope: close.target_scope.map(|scope| scope.0),
        bindings: close
            .bindings
            .iter()
            .map(|binding| bytecode_binding(*binding))
            .collect(),
        registers: close.registers.clone(),
    }
}

fn bytecode_binding(binding: BindingId) -> rivetlua_core::BytecodeBindingId {
    rivetlua_core::BytecodeBindingId {
        function: binding.function.0,
        ordinal: binding.ordinal,
    }
}

fn bytecode_span(span: Span) -> rivetlua_core::BytecodeSpan {
    rivetlua_core::BytecodeSpan {
        start_byte: span.start_byte as u64,
        end_byte: span.end_byte as u64,
    }
}
