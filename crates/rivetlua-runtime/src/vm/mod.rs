//! 已驗證模組的最小暫存器執行器。

mod numeric_for;
mod ops;

use rivetlua_core::{
    BinaryOperation, BytecodeConstant, BytecodePrototype, CoreError, CoreErrorKind, Instruction,
    LuaProfile, Opcode, RVLU_V2, Register, ResultMode, UnaryOperation, Value, VerifiedModule, VmId,
};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, checked_bytes, reserve_vec};
use crate::{RootId, RootKind, Vm, VmError};

/// VM 內部錯誤；不建立 Lua 字串，P08／P11 可用診斷 ID 映射可見錯誤值。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeErrorKind {
    UnsupportedFormat,
    MissingEntryPoint,
    UnsupportedInstruction(Opcode),
    UnsupportedUnaryOperation(UnaryOperation),
    UnsupportedBinaryOperation(BinaryOperation),
    UnsupportedConstant,
    UnsupportedResultMode,
    NumericForZeroStep,
    InvalidNumericForState,
    RegisterOutOfBounds,
    ProgramCounterOutOfBounds,
    TerminalExecution,
    Heap(VmError),
    Core(CoreError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeError {
    pub kind: RuntimeErrorKind,
    pub diagnostic_id: &'static str,
}

impl RuntimeError {
    pub const fn new(kind: RuntimeErrorKind) -> Self {
        let diagnostic_id = match kind {
            RuntimeErrorKind::UnsupportedFormat => "E_VM_FORMAT",
            RuntimeErrorKind::MissingEntryPoint => "E_VM_ENTRY",
            RuntimeErrorKind::UnsupportedInstruction(_) => "E_VM_OPCODE_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedUnaryOperation(_) => "E_VM_UNARY_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedBinaryOperation(_) => "E_VM_BINARY_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedConstant => "E_VM_CONSTANT_UNSUPPORTED",
            RuntimeErrorKind::UnsupportedResultMode => "E_VM_RESULT_UNSUPPORTED",
            RuntimeErrorKind::NumericForZeroStep => "E_NUMERIC_FOR_ZERO_STEP",
            RuntimeErrorKind::InvalidNumericForState => "E_VM_NUMERIC_FOR_STATE",
            RuntimeErrorKind::RegisterOutOfBounds => "E_VM_REGISTER_BOUNDS",
            RuntimeErrorKind::ProgramCounterOutOfBounds => "E_VM_PC_BOUNDS",
            RuntimeErrorKind::TerminalExecution => "E_VM_TERMINAL",
            RuntimeErrorKind::Heap(error) => error.code(),
            RuntimeErrorKind::Core(error) => match error.kind {
                CoreErrorKind::IntegerDivideByZero => "E_INTEGER_DIVIDE_BY_ZERO",
                CoreErrorKind::IntegerModuloByZero => "E_INTEGER_MODULO_BY_ZERO",
                CoreErrorKind::NotInteger => "E_NOT_INTEGER",
                CoreErrorKind::NotNumeric => "E_NOT_NUMERIC",
            },
        };
        Self {
            kind,
            diagnostic_id,
        }
    }
}

impl From<VmError> for RuntimeError {
    fn from(error: VmError) -> Self {
        Self::new(RuntimeErrorKind::Heap(error))
    }
}

impl From<CoreError> for RuntimeError {
    fn from(error: CoreError) -> Self {
        Self::new(RuntimeErrorKind::Core(error))
    }
}

/// 每次取指前消耗一個 fuel；耗盡後不可續跑原 execution。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortReason {
    FuelExhausted,
}

#[derive(Clone, Debug, PartialEq)]
pub enum RunOutcome {
    Returned(Vec<Value>),
    LuaError(RuntimeError),
    Aborted(AbortReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionState {
    Ready,
    Returned,
    LuaError,
    Failed,
    Aborted,
}

enum DispatchResult {
    Continue,
    Returned(Vec<Value>, Option<Reservation>),
}

struct Frame {
    pc: usize,
    registers: Vec<Value>,
    roots: Vec<Option<RootId>>,
    dynamic_top: usize,
    register_limit: usize,
    ledger: AllocationLedger,
    charge: usize,
}

impl Frame {
    fn new(prototype: &BytecodePrototype, ledger: &AllocationLedger) -> Result<Self, RuntimeError> {
        let limit = usize::from(prototype.register_count);
        if limit > usize::from(prototype.frame.register_limit)
            || !prototype.frame.registers_start_as_nil
        {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let register_bytes = checked_bytes(limit, core::mem::size_of::<Value>())?;
        let root_bytes = checked_bytes(limit, core::mem::size_of::<Option<RootId>>())?;
        let charge = register_bytes
            .checked_add(root_bytes)
            .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let mut registers = Vec::new();
        let register_ticket = reserve_vec(
            ledger,
            &mut registers,
            limit,
            FailPoint::FrameRegistersReserve,
        )?;
        registers.resize(limit, Value::Nil);
        let mut roots = Vec::new();
        let root_ticket = reserve_vec(ledger, &mut roots, limit, FailPoint::FrameRootsReserve)?;
        roots.resize(limit, None);
        let dynamic_top = usize::from(prototype.frame.initial_top.0);
        if dynamic_top > limit || usize::from(prototype.frame.dynamic_top.0) > limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        register_ticket.commit()?;
        if let Err(error) = root_ticket.commit() {
            ledger.refund_on_drop(register_bytes);
            return Err(error.into());
        }
        Ok(Self {
            pc: 0,
            registers,
            roots,
            dynamic_top,
            register_limit: limit,
            ledger: ledger.clone(),
            charge,
        })
    }

    fn index(&self, register: Register) -> Result<usize, RuntimeError> {
        let index = usize::from(register.0);
        if index >= self.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        Ok(index)
    }

    fn read(&self, register: Register) -> Result<Value, RuntimeError> {
        self.registers
            .get(self.index(register)?)
            .copied()
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
    }

    fn write(&mut self, vm: &mut Vm, register: Register, value: Value) -> Result<(), RuntimeError> {
        let index = self.index(register)?;
        let new_root = if let Value::Object(object) = value {
            Some(vm.add_root(RootKind::Stack, object)?)
        } else {
            None
        };
        if let Some(old_root) = self.roots[index] {
            if let Err(error) = vm.remove_root(old_root) {
                if let Some(root) = new_root {
                    let _ = vm.remove_root(root);
                }
                return Err(error.into());
            }
        }
        self.registers[index] = value;
        self.roots[index] = new_root;
        Ok(())
    }

    fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        for root in &mut self.roots {
            if let Some(id) = *root {
                vm.remove_root(id)?;
                *root = None;
            }
        }
        Ok(())
    }

    fn release_storage(&mut self) {
        self.registers = Vec::new();
        self.roots = Vec::new();
        self.register_limit = 0;
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
            self.charge = 0;
        }
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.release_storage();
    }
}

/// 擁有 frame 並借用原 VM；丟棄未執行的 execution 也會清理 stack roots。
pub struct Execution<'vm> {
    vm: &'vm mut Vm,
    vm_id: VmId,
    module: VerifiedModule,
    entry_index: usize,
    frame: Frame,
    fuel: u64,
    state: ExecutionState,
}

impl Vm {
    /// 唯一公開載入入口，只能接受 P05 已驗證模組。
    ///
    /// ```compile_fail
    /// use rivetlua_runtime::Vm;
    /// use rivetlua_core::BytecodeModule;
    /// let mut vm = Vm::new().unwrap();
    /// let candidate: BytecodeModule = todo!();
    /// let _execution = vm.load(candidate);
    /// ```
    pub fn load(&mut self, module: VerifiedModule) -> Result<Execution<'_>, RuntimeError> {
        if module.format_version() != RVLU_V2 {
            return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedFormat));
        }
        let data = module.module();
        if !matches!(module.profile(), LuaProfile::Lua54 | LuaProfile::Lua55) {
            return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedFormat));
        }
        let Some((_, entry_id)) = data
            .function_prototypes
            .iter()
            .find(|(function, _)| *function == 0)
        else {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        };
        let entry_index = data
            .prototypes
            .iter()
            .position(|candidate| candidate.id == *entry_id)
            .ok_or(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint))?;
        if data.prototypes[entry_index].parent.is_some() {
            return Err(RuntimeError::new(RuntimeErrorKind::MissingEntryPoint));
        }
        for prototype in &data.prototypes {
            for constant in &prototype.constants {
                if !matches!(
                    constant,
                    BytecodeConstant::Integer(_)
                        | BytecodeConstant::FloatBits(_)
                        | BytecodeConstant::Boolean(_)
                ) {
                    return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedConstant));
                }
            }
            for instruction in &prototype.instructions {
                match instruction.instruction {
                    Instruction::LoadConst { .. }
                    | Instruction::LoadNil { .. }
                    | Instruction::Move { .. }
                    | Instruction::Jump { .. }
                    | Instruction::JumpIfFalse { .. }
                    | Instruction::NumericForPrepare { .. }
                    | Instruction::NumericForNext { .. }
                    | Instruction::UnaryOp {
                        op: UnaryOperation::Negate | UnaryOperation::Not | UnaryOperation::BitNot,
                        ..
                    }
                    | Instruction::BinaryOp {
                        op:
                            BinaryOperation::Equal
                            | BinaryOperation::NotEqual
                            | BinaryOperation::Less
                            | BinaryOperation::LessEqual
                            | BinaryOperation::Greater
                            | BinaryOperation::GreaterEqual
                            | BinaryOperation::Pipe
                            | BinaryOperation::BitXor
                            | BinaryOperation::Ampersand
                            | BinaryOperation::ShiftLeft
                            | BinaryOperation::ShiftRight
                            | BinaryOperation::Add
                            | BinaryOperation::Subtract
                            | BinaryOperation::Multiply
                            | BinaryOperation::Divide
                            | BinaryOperation::FloorDivide
                            | BinaryOperation::Modulo
                            | BinaryOperation::Power,
                        ..
                    }
                    | Instruction::Return {
                        result_mode: ResultMode::Fixed(_),
                        ..
                    } => {}
                    Instruction::Return {
                        result_mode: ResultMode::All,
                        ..
                    } => {
                        return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedResultMode));
                    }
                    Instruction::UnaryOp { op, .. } => {
                        return Err(RuntimeError::new(
                            RuntimeErrorKind::UnsupportedUnaryOperation(op),
                        ));
                    }
                    Instruction::BinaryOp { op, .. } => {
                        return Err(RuntimeError::new(
                            RuntimeErrorKind::UnsupportedBinaryOperation(op),
                        ));
                    }
                    ref other => {
                        return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedInstruction(
                            other.opcode(),
                        )));
                    }
                }
            }
        }
        let frame = Frame::new(&data.prototypes[entry_index], self.allocation_ledger())?;
        Ok(Execution {
            vm_id: self.id(),
            vm: self,
            module,
            entry_index,
            frame,
            fuel: 1_000_000,
            state: ExecutionState::Ready,
        })
    }
}

impl Execution<'_> {
    pub fn vm_id(&self) -> VmId {
        self.vm_id
    }

    pub fn pc(&self) -> usize {
        self.frame.pc
    }

    pub fn dynamic_top(&self) -> usize {
        self.frame.dynamic_top
    }

    pub fn fuel_remaining(&self) -> u64 {
        self.fuel
    }

    pub fn set_fuel(&mut self, fuel: u64) -> Result<(), RuntimeError> {
        if self.state != ExecutionState::Ready {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        self.fuel = fuel;
        Ok(())
    }

    fn prototype(&self) -> &BytecodePrototype {
        &self.module.module().prototypes[self.entry_index]
    }

    fn next_pc(&self) -> Result<usize, RuntimeError> {
        self.frame
            .pc
            .checked_add(1)
            .filter(|index| *index < self.prototype().instructions.len())
            .ok_or(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ))
    }

    fn jump_target(&self, target: rivetlua_core::InstructionOffset) -> Result<usize, RuntimeError> {
        let index = usize::try_from(target.0)
            .map_err(|_| RuntimeError::new(RuntimeErrorKind::ProgramCounterOutOfBounds))?;
        if index >= self.prototype().instructions.len() {
            return Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds,
            ));
        }
        Ok(index)
    }

    /// 執行直到 Return、受控錯誤或 fuel 中止。終結後不能再一般 run。
    pub fn run(&mut self) -> Result<RunOutcome, RuntimeError> {
        if self.state != ExecutionState::Ready {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        loop {
            if self.frame.pc >= self.prototype().instructions.len() {
                self.state = ExecutionState::Failed;
                self.finish()?;
                return Err(RuntimeError::new(
                    RuntimeErrorKind::ProgramCounterOutOfBounds,
                ));
            }
            if self.fuel == 0 {
                self.state = ExecutionState::Aborted;
                self.finish()?;
                return Ok(RunOutcome::Aborted(AbortReason::FuelExhausted));
            }
            self.fuel -= 1;
            match self.dispatch_one() {
                Ok(DispatchResult::Returned(values, ticket)) => {
                    self.state = ExecutionState::Returned;
                    self.finish()?;
                    // 結果 Vec 在此移交宿主持有；VM 僅檢查並暫留配置額度。
                    drop(ticket);
                    return Ok(RunOutcome::Returned(values));
                }
                Ok(DispatchResult::Continue) => {}
                Err(error) => {
                    let lua_error = matches!(
                        error.kind,
                        RuntimeErrorKind::Core(_) | RuntimeErrorKind::NumericForZeroStep
                    );
                    self.state = if lua_error {
                        ExecutionState::LuaError
                    } else {
                        ExecutionState::Failed
                    };
                    self.finish()?;
                    return if lua_error {
                        Ok(RunOutcome::LuaError(error))
                    } else {
                        Err(error)
                    };
                }
            }
        }
    }

    fn finish(&mut self) -> Result<(), RuntimeError> {
        self.frame.clear_roots(self.vm)?;
        self.frame.release_storage();
        Ok(())
    }

    fn dispatch_one(&mut self) -> Result<DispatchResult, RuntimeError> {
        let instruction = self.prototype().instructions[self.frame.pc]
            .instruction
            .clone();
        match instruction {
            Instruction::LoadConst { dest, constant } => {
                let value = match self.prototype().constants.get(constant.0 as usize) {
                    Some(BytecodeConstant::Integer(value)) => Value::Integer(*value),
                    Some(BytecodeConstant::FloatBits(bits)) => Value::Float(f64::from_bits(*bits)),
                    Some(BytecodeConstant::Boolean(value)) => Value::Boolean(*value),
                    _ => return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedConstant)),
                };
                let next = self.next_pc()?;
                self.frame.write(self.vm, dest, value)?;
                self.frame.pc = next;
            }
            Instruction::LoadNil { start, count } => {
                let first = self.frame.index(start)?;
                let end = first
                    .checked_add(usize::from(count))
                    .filter(|end| *end <= self.frame.register_limit)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                let next = self.next_pc()?;
                for index in first..end {
                    self.frame
                        .write(self.vm, Register(index as u16), Value::Nil)?;
                }
                self.frame.pc = next;
            }
            Instruction::Move { dest, src } => {
                let value = self.frame.read(src)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                self.frame.write(self.vm, dest, value)?;
                self.frame.pc = next;
            }
            Instruction::UnaryOp { dest, op, src } => {
                let value = self.frame.read(src)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let result = ops::unary(op, value)?;
                self.frame.write(self.vm, dest, result)?;
                self.frame.pc = next;
            }
            Instruction::BinaryOp {
                dest,
                op,
                left,
                right,
            } => {
                let left = self.frame.read(left)?;
                let right = self.frame.read(right)?;
                self.frame.index(dest)?;
                let next = self.next_pc()?;
                let result = ops::binary(op, left, right)?;
                self.frame.write(self.vm, dest, result)?;
                self.frame.pc = next;
            }
            Instruction::Jump { target } => {
                self.frame.pc = self.jump_target(target)?;
            }
            Instruction::JumpIfFalse { condition, target } => {
                let value = self.frame.read(condition)?;
                self.frame.pc = if value.is_truthy() {
                    self.next_pc()?
                } else {
                    self.jump_target(target)?
                };
            }
            Instruction::NumericForPrepare {
                control,
                limit,
                step,
                visible,
                exit,
            } => {
                let initial = self.frame.read(control)?;
                let limit_value = self.frame.read(limit)?;
                let step_value = self.frame.read(step)?;
                self.frame.index(visible)?;
                let body = self.next_pc()?;
                let exit = self.jump_target(exit)?;
                match numeric_for::prepare(initial, limit_value, step_value)? {
                    numeric_for::Prepared::Skip => self.frame.pc = exit,
                    numeric_for::Prepared::Enter {
                        control: prepared_control,
                        limit: prepared_limit,
                        step: prepared_step,
                        visible: prepared_visible,
                    } => {
                        self.frame.write(self.vm, control, prepared_control)?;
                        self.frame.write(self.vm, limit, prepared_limit)?;
                        self.frame.write(self.vm, step, prepared_step)?;
                        self.frame.write(self.vm, visible, prepared_visible)?;
                        self.frame.pc = body;
                    }
                }
            }
            Instruction::NumericForNext {
                control,
                limit,
                step,
                visible,
                target,
                exit,
            } => {
                let control_value = self.frame.read(control)?;
                let limit_value = self.frame.read(limit)?;
                let step_value = self.frame.read(step)?;
                self.frame.index(visible)?;
                let body = self.jump_target(target)?;
                let exit = self.jump_target(exit)?;
                match numeric_for::next(control_value, limit_value, step_value)? {
                    numeric_for::Advanced::Exit => self.frame.pc = exit,
                    numeric_for::Advanced::Enter {
                        control: next_control,
                        visible: next_visible,
                    } => {
                        self.frame.write(self.vm, control, next_control)?;
                        self.frame.write(self.vm, visible, next_visible)?;
                        self.frame.pc = body;
                    }
                }
            }
            Instruction::Return {
                base,
                result_mode: ResultMode::Fixed(count),
            } => {
                let first = self.frame.index(base)?;
                let end = first
                    .checked_add(usize::from(count))
                    .filter(|end| *end <= self.frame.register_limit)
                    .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
                let mut result = Vec::new();
                let ticket = if count == 0 {
                    None
                } else {
                    Some(reserve_vec(
                        self.vm.allocation_ledger(),
                        &mut result,
                        usize::from(count),
                        FailPoint::ReturnReserve,
                    )?)
                };
                result.extend_from_slice(&self.frame.registers[first..end]);
                return Ok(DispatchResult::Returned(result, ticket));
            }
            other => {
                return Err(RuntimeError::new(RuntimeErrorKind::UnsupportedInstruction(
                    other.opcode(),
                )));
            }
        }
        Ok(DispatchResult::Continue)
    }
}

impl Drop for Execution<'_> {
    fn drop(&mut self) {
        // RootId 由本 frame 唯一持有；P06 remove_root 不配置也不觸發 GC。
        let cleanup = self.frame.clear_roots(self.vm);
        debug_assert!(cleanup.is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RootKind, Vm};
    use rivetlua_core::{
        BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule,
        BytecodePrototype, BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction,
        InstructionOffset, LuaProfile, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V2, Register,
        ResultMode, Value, VerifyLimits, verify_module,
    };

    fn module(
        instructions: Vec<Instruction>,
        constants: Vec<BytecodeConstant>,
    ) -> rivetlua_core::VerifiedModule {
        let span = BytecodeSpan {
            start_byte: 0,
            end_byte: 10,
        };
        let candidate = BytecodeModule {
            format_version: RVLU_V2,
            profile: LuaProfile::Lua55,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 3,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 4096,
                    initial_top: Register(3),
                    dynamic_top: Register(3),
                    return_base: Register(0),
                    environment: Register(2),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(2),
                global_environment_binding: BytecodeBindingId {
                    function: 0,
                    ordinal: 0,
                },
                binding_registers: vec![(
                    BytecodeBindingId {
                        function: 0,
                        ordinal: 0,
                    },
                    Register(2),
                )],
                constants,
                upvalues: vec![],
                instructions: instructions
                    .into_iter()
                    .map(|instruction| BytecodeInstruction {
                        instruction,
                        span,
                        close_path: None,
                    })
                    .collect(),
                close_paths: vec![],
            }],
        };
        verify_module(candidate, LuaProfile::Lua55, &VerifyLimits::default()).unwrap()
    }

    fn numeric_for_candidate(
        instructions: Vec<Instruction>,
        constants: Vec<BytecodeConstant>,
    ) -> BytecodeModule {
        let mut candidate = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        )
        .module()
        .clone();
        let span = candidate.span;
        let root = &mut candidate.prototypes[0];
        root.register_count = 6;
        root.frame.initial_top = Register(6);
        root.frame.dynamic_top = Register(6);
        root.frame.environment = Register(5);
        root.global_environment = Register(5);
        root.binding_registers[0].1 = Register(5);
        root.constants = constants;
        root.instructions = instructions
            .into_iter()
            .map(|instruction| BytecodeInstruction {
                instruction,
                span,
                close_path: None,
            })
            .collect();
        candidate
    }

    fn numeric_for_module(
        initial: BytecodeConstant,
        limit: BytecodeConstant,
        step: BytecodeConstant,
    ) -> rivetlua_core::VerifiedModule {
        let instructions = vec![
            Instruction::LoadConst {
                dest: Register(0),
                constant: ConstId(0),
            },
            Instruction::LoadConst {
                dest: Register(1),
                constant: ConstId(1),
            },
            Instruction::LoadConst {
                dest: Register(2),
                constant: ConstId(2),
            },
            Instruction::NumericForPrepare {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                exit: InstructionOffset(6),
            },
            Instruction::Move {
                dest: Register(4),
                src: Register(3),
            },
            Instruction::NumericForNext {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                target: InstructionOffset(4),
                exit: InstructionOffset(6),
            },
            Instruction::Return {
                base: Register(4),
                result_mode: ResultMode::Fixed(1),
            },
        ];
        verify_module(
            numeric_for_candidate(instructions, vec![initial, limit, step]),
            LuaProfile::Lua55,
            &VerifyLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn vm_frame_starts_nil_and_checks_register_bounds() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(execution.frame.registers, vec![Value::Nil; 3]);
        assert_eq!(execution.dynamic_top(), 3);
        assert_eq!(
            execution.frame.read(Register(3)),
            Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
        );
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![Value::Nil])));
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_dispatch_checks_pc_and_jump_target() {
        let verified = module(
            vec![
                Instruction::Jump {
                    target: InstructionOffset(2),
                },
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(99)],
        );
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![Value::Nil])));
        assert_eq!(execution.pc(), 2);
        drop(execution);

        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.jump_target(InstructionOffset(u32::MAX)),
            Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds
            ))
        );
        execution.frame.pc = usize::MAX;
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(
                RuntimeErrorKind::ProgramCounterOutOfBounds
            ))
        );
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_stack_roots_protect_objects_and_are_released_on_drop() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        {
            let mut execution = vm.load(verified).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
            assert_eq!(execution.vm.collect().unwrap(), 0);
        }
        assert_eq!(vm.roots().count(RootKind::Stack), 0);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn vm_stack_roots_are_released_after_return_and_internal_error() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(9)).unwrap();
        {
            let mut execution = vm.load(verified.clone()).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
            assert_eq!(
                execution.run(),
                Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
            );
        }
        {
            let mut execution = vm.load(verified).unwrap();
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(object))
                .unwrap();
            execution.frame.pc = usize::MAX;
            assert_eq!(
                execution.run(),
                Err(RuntimeError::new(
                    RuntimeErrorKind::ProgramCounterOutOfBounds
                ))
            );
            assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        }
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn vm_rejected_object_write_preserves_existing_register_and_root() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(1)).unwrap();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        let foreign = rivetlua_core::ObjectRef::new_opaque().unwrap();
        assert!(
            execution
                .frame
                .write(execution.vm, Register(0), Value::Object(foreign))
                .is_err()
        );
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Object(object)));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
    }

    #[test]
    fn vm_move_keeps_both_object_registers_rooted_until_return() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(12)).unwrap();
        let object_only = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.frame.read(Register(1)), Ok(Value::Object(object)));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 2);
        assert_eq!(execution.vm.collect().unwrap(), 0);
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        assert_eq!(execution.vm.ledger_snapshot(), object_only);
    }

    #[test]
    fn vm_frame_charge_is_live_until_drop_and_refunded_after_return() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        {
            let mut execution = vm.load(verified.clone()).unwrap();
            assert!(execution.vm.ledger_snapshot().committed > before.committed);
            assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }
        {
            let execution = vm.load(verified).unwrap();
            assert!(execution.vm.ledger_snapshot().committed > before.committed);
            drop(execution);
        }
        assert_eq!(vm.ledger_snapshot(), before);
    }

    #[test]
    fn vm_return_result_respects_remaining_quota_and_releases_frame() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let frame_bytes = execution.vm.ledger_snapshot().committed;
        execution.vm.set_allocation_limit(frame_bytes);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::Heap(
                crate::VmError::AllocationFailed
            )))
        );
        assert_eq!(execution.vm.ledger_snapshot().committed, baseline.committed);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        assert_eq!(execution.vm.roots().total_count(), 0);
    }

    #[test]
    fn vm_return_reserve_failure_is_terminal_and_refunds_frame() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.vm.inject_failure_once(FailPoint::ReturnReserve);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::InjectedFailure(FailPoint::ReturnReserve)
            )))
        );
        assert_eq!(execution.vm.ledger_snapshot(), baseline);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_returned_values_transfer_to_host_without_vm_charge() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let outcome = execution.run().unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Nil]));
        assert_eq!(execution.vm.ledger_snapshot(), baseline);
        drop(execution);
        assert_eq!(vm.ledger_snapshot(), baseline);
        drop(outcome);
        assert_eq!(vm.ledger_snapshot(), baseline);
    }

    #[test]
    fn vm_empty_return_does_not_allocate_a_result_buffer() {
        let verified = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let frame_bytes = execution.vm.ledger_snapshot().committed;
        execution.vm.set_allocation_limit(frame_bytes);
        execution.vm.inject_failure_once(FailPoint::ReturnReserve);
        assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
        assert_eq!(execution.vm.ledger_snapshot().committed, baseline.committed);
        assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn vm_p01_integer_wrap_and_power_float_path() {
        for (constants, op, expected) in [
            (
                vec![
                    BytecodeConstant::Integer(i64::MAX),
                    BytecodeConstant::Integer(1),
                ],
                rivetlua_core::BinaryOperation::Add,
                Value::Integer(i64::MIN),
            ),
            (
                vec![BytecodeConstant::Integer(2), BytecodeConstant::Integer(3)],
                rivetlua_core::BinaryOperation::Power,
                Value::Float(8.0),
            ),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                constants,
            );
            let mut vm = Vm::new().unwrap();
            let baseline = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), baseline);
        }
    }

    #[test]
    fn vm_p01_exact_integer_float_comparison_and_truthy_zero() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Greater,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![
                BytecodeConstant::Integer(9_007_199_254_740_993),
                BytecodeConstant::FloatBits(9_007_199_254_740_992.0_f64.to_bits()),
            ],
        );
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.load(verified).unwrap().run(),
            Ok(RunOutcome::Returned(vec![Value::Boolean(true)]))
        );

        for constant in [
            BytecodeConstant::Integer(0),
            BytecodeConstant::FloatBits(0.0_f64.to_bits()),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::UnaryOp {
                        dest: Register(0),
                        op: rivetlua_core::UnaryOperation::Not,
                        src: Register(0),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![constant],
            );
            assert_eq!(
                vm.load(verified).unwrap().run(),
                Ok(RunOutcome::Returned(vec![Value::Boolean(false)]))
            );
        }
    }

    #[test]
    fn vm_p01_lua_error_is_structured_and_terminal() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
        );
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("整數除以零須為 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert!(
            matches!(error.kind, RuntimeErrorKind::Core(core) if core.operation == rivetlua_core::Operation::FloorDivide && core.operand == rivetlua_core::ValueKind::Integer && core.kind == rivetlua_core::CoreErrorKind::IntegerDivideByZero)
        );
        assert_eq!(execution.fuel_remaining(), 999_997);
        assert_eq!(execution.pc(), 2);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), baseline);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn vm_numeric_opcodes_route_to_p01_helpers() {
        use rivetlua_core::BinaryOperation as B;
        for (left, right, op, expected) in [
            (6, 3, B::Subtract, Value::Integer(3)),
            (6, 3, B::Multiply, Value::Integer(18)),
            (6, 3, B::Divide, Value::Float(2.0)),
            (6, 3, B::FloorDivide, Value::Integer(2)),
            (6, 4, B::Modulo, Value::Integer(2)),
            (6, 3, B::Pipe, Value::Integer(7)),
            (6, 3, B::BitXor, Value::Integer(5)),
            (6, 3, B::Ampersand, Value::Integer(2)),
            (1, 2, B::ShiftLeft, Value::Integer(4)),
            (8, 2, B::ShiftRight, Value::Integer(2)),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![
                    BytecodeConstant::Integer(left),
                    BytecodeConstant::Integer(right),
                ],
            );
            let mut vm = Vm::new().unwrap();
            assert_eq!(
                vm.load(verified).unwrap().run(),
                Ok(RunOutcome::Returned(vec![expected]))
            );
        }
    }

    #[test]
    fn vm_p01_type_and_integer_errors_become_lua_errors() {
        for (left, right, op, diagnostic) in [
            (
                BytecodeConstant::Boolean(true),
                BytecodeConstant::Integer(1),
                rivetlua_core::BinaryOperation::Add,
                "E_NOT_NUMERIC",
            ),
            (
                BytecodeConstant::Integer(1),
                BytecodeConstant::Integer(0),
                rivetlua_core::BinaryOperation::Modulo,
                "E_INTEGER_MODULO_BY_ZERO",
            ),
            (
                BytecodeConstant::FloatBits(1.5_f64.to_bits()),
                BytecodeConstant::Integer(1),
                rivetlua_core::BinaryOperation::Ampersand,
                "E_NOT_INTEGER",
            ),
        ] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::BinaryOp {
                        dest: Register(0),
                        op,
                        left: Register(0),
                        right: Register(1),
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![left, right],
            );
            let mut vm = Vm::new().unwrap();
            let mut execution = vm.load(verified).unwrap();
            let Ok(RunOutcome::LuaError(error)) = execution.run() else {
                panic!("P01 錯誤須變成 LuaError")
            };
            assert_eq!(error.diagnostic_id, diagnostic);
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn vm_unavailable_length_and_concat_are_rejected_at_load() {
        let unary = module(
            vec![
                Instruction::UnaryOp {
                    dest: Register(0),
                    op: rivetlua_core::UnaryOperation::Length,
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![],
        );
        let binary = module(
            vec![
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Concat,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.load(unary).err().unwrap().kind,
            RuntimeErrorKind::UnsupportedUnaryOperation(rivetlua_core::UnaryOperation::Length)
        );
        assert_eq!(
            vm.load(binary).err().unwrap().kind,
            RuntimeErrorKind::UnsupportedBinaryOperation(rivetlua_core::BinaryOperation::Concat)
        );
    }

    #[test]
    fn vm_condition_branches_and_return_consume_fuel() {
        for (condition, expected, fuel_used) in
            [(false, Value::Nil, 3), (true, Value::Integer(9), 4)]
        {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::JumpIfFalse {
                        condition: Register(0),
                        target: InstructionOffset(3),
                    },
                    Instruction::LoadConst {
                        dest: Register(1),
                        constant: ConstId(1),
                    },
                    Instruction::Return {
                        base: Register(1),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![
                    BytecodeConstant::Boolean(condition),
                    BytecodeConstant::Integer(9),
                ],
            );
            let mut vm = Vm::new().unwrap();
            let baseline = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(fuel_used).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 3);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), baseline);
        }
    }

    #[test]
    fn assignment_overlap_and_repeated_source_follow_move_order() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                Instruction::Move {
                    dest: Register(0),
                    src: Register(1),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(2),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(2)],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(2),
                Value::Integer(1)
            ]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Move {
                    dest: Register(2),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(1),
                    result_mode: ResultMode::Fixed(2),
                },
            ],
            vec![BytecodeConstant::Integer(7)],
        );
        assert_eq!(
            vm.load(verified).unwrap().run(),
            Ok(RunOutcome::Returned(vec![
                Value::Integer(7),
                Value::Integer(7)
            ]))
        );
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
    }

    #[test]
    fn assignment_prior_write_survives_later_lua_error_without_partial_destination_write() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::Move {
                    dest: Register(0),
                    src: Register(1),
                },
                Instruction::LoadConst {
                    dest: Register(2),
                    constant: ConstId(2),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![
                BytecodeConstant::Integer(10),
                BytecodeConstant::Integer(20),
                BytecodeConstant::Integer(0),
            ],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..4 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pc(), 4);
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(20)));
        let error = execution.dispatch_one().err().unwrap();
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(20)));
        assert_eq!(execution.pc(), 4);
        assert_eq!(execution.run(), Ok(RunOutcome::LuaError(error)));
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        assert_eq!(
            execution.run(),
            Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution))
        );
    }

    #[test]
    fn assignment_move_root_failure_keeps_destination_and_cleans_existing_root() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(5)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        execution
            .frame
            .write(execution.vm, Register(1), Value::Integer(9))
            .unwrap();
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.dispatch_one().err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve))
        );
        assert_eq!(execution.frame.read(Register(1)), Ok(Value::Integer(9)));
        assert_eq!(execution.pc(), 0);
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn numeric_for_prepare_and_next_update_control_visible_and_targets() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(1),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Nil));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.pc(), 4);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Integer(1)));
        for expected in [2, 3] {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            assert_eq!(execution.pc(), 5);
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
            assert_eq!(execution.pc(), 4);
            assert_eq!(
                execution.frame.read(Register(0)),
                Ok(Value::Integer(expected))
            );
            assert_eq!(
                execution.frame.read(Register(3)),
                Ok(Value::Integer(expected))
            );
            assert_eq!(execution.frame.read(Register(1)), Ok(Value::Integer(3)));
            assert_eq!(execution.frame.read(Register(2)), Ok(Value::Integer(1)));
        }
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert!(matches!(
            execution.dispatch_one(),
            Ok(DispatchResult::Continue)
        ));
        assert_eq!(execution.pc(), 6);
        assert_eq!(execution.frame.read(Register(0)), Ok(Value::Integer(3)));
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Integer(3)));
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(3)]))
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn numeric_for_zero_step_fails_before_visible_write_and_cleans_frame() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(0),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        for _ in 0..3 {
            assert!(matches!(
                execution.dispatch_one(),
                Ok(DispatchResult::Continue)
            ));
        }
        let error = execution.dispatch_one().err().unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::NumericForZeroStep);
        assert_eq!(error.diagnostic_id, "E_NUMERIC_FOR_ZERO_STEP");
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.frame.read(Register(3)), Ok(Value::Nil));
        assert_eq!(execution.run(), Ok(RunOutcome::LuaError(error)));
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn numeric_for_integer_edge_and_fuel_stop_before_next_side_effect() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(i64::MAX - 1),
            BytecodeConstant::Integer(i64::MAX),
            BytecodeConstant::Integer(1),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified.clone()).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Integer(i64::MAX)]))
        );
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(5).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn numeric_for_verifier_rejects_alias_and_unpaired_next() {
        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(3),
            BytecodeConstant::Integer(1),
        );
        let mut alias = verified.module().clone();
        alias.prototypes[0].instructions[3].instruction = Instruction::NumericForPrepare {
            control: Register(0),
            limit: Register(0),
            step: Register(2),
            visible: Register(3),
            exit: InstructionOffset(6),
        };
        assert!(verify_module(alias, LuaProfile::Lua55, &VerifyLimits::default()).is_err());

        let mut unmatched = verified.module().clone();
        unmatched.prototypes[0].instructions[5].instruction = Instruction::NumericForNext {
            control: Register(0),
            limit: Register(1),
            step: Register(4),
            visible: Register(3),
            target: InstructionOffset(4),
            exit: InstructionOffset(6),
        };
        assert!(verify_module(unmatched, LuaProfile::Lua55, &VerifyLimits::default()).is_err());
    }

    #[test]
    fn numeric_for_next_rejects_unprepared_mixed_mode() {
        let error = numeric_for::next(Value::Integer(1), Value::Float(2.0), Value::Integer(1))
            .err()
            .unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNumericForState);
        assert_eq!(error.diagnostic_id, "E_VM_NUMERIC_FOR_STATE");
        let error = numeric_for::next(Value::Integer(1), Value::Integer(2), Value::Integer(0))
            .err()
            .unwrap();
        assert_eq!(error.kind, RuntimeErrorKind::InvalidNumericForState);
    }

    #[test]
    fn fuel_linear_dispatch_and_return_each_cost_one() {
        let verified = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::LoadNil {
                    start: Register(2),
                    count: 1,
                },
                Instruction::UnaryOp {
                    dest: Register(2),
                    op: rivetlua_core::UnaryOperation::Not,
                    src: Register(2),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::Equal,
                    left: Register(1),
                    right: Register(2),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1)],
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified.clone()).unwrap();
        execution.set_fuel(6).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Returned(vec![Value::Boolean(false)]))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);

        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(5).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 5);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn fuel_jump_and_both_conditional_edges_each_cost_one() {
        for (condition, expected) in [(false, Value::Nil), (true, Value::Boolean(true))] {
            let verified = module(
                vec![
                    Instruction::LoadConst {
                        dest: Register(0),
                        constant: ConstId(0),
                    },
                    Instruction::JumpIfFalse {
                        condition: Register(0),
                        target: InstructionOffset(3),
                    },
                    Instruction::Jump {
                        target: InstructionOffset(4),
                    },
                    Instruction::LoadNil {
                        start: Register(0),
                        count: 1,
                    },
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![BytecodeConstant::Boolean(condition)],
            );
            let mut vm = Vm::new().unwrap();
            let before = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(4).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 4);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }
    }

    #[test]
    fn fuel_numeric_for_enter_next_skip_and_return_each_cost_one() {
        for (initial, limit, budget, expected) in
            [(1, 2, 9, Value::Integer(2)), (3, 1, 5, Value::Nil)]
        {
            let verified = numeric_for_module(
                BytecodeConstant::Integer(initial),
                BytecodeConstant::Integer(limit),
                BytecodeConstant::Integer(1),
            );
            let mut vm = Vm::new().unwrap();
            let before = vm.ledger_snapshot();
            let mut execution = vm.load(verified).unwrap();
            execution.set_fuel(budget).unwrap();
            assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![expected])));
            assert_eq!(execution.pc(), 6);
            assert_eq!(execution.fuel_remaining(), 0);
            assert_eq!(execution.vm.roots().total_count(), 0);
            assert_eq!(execution.vm.ledger_snapshot(), before);
        }

        let verified = numeric_for_module(
            BytecodeConstant::Integer(1),
            BytecodeConstant::Integer(2),
            BytecodeConstant::Integer(0),
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(4).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("零 step 預備指令須形成 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::NumericForZeroStep);
        assert_eq!(execution.pc(), 3);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
    }

    #[test]
    fn fuel_zero_prevents_move_root_side_effect_and_releases_frame() {
        let verified = module(
            vec![
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
            ],
            vec![],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(4)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 1);
        execution.set_fuel(0).unwrap();
        execution.vm.inject_failure_once(FailPoint::RootReserve);
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(AbortReason::FuelExhausted))
        );
        assert_eq!(execution.pc(), 0);
        assert_eq!(execution.fuel_remaining(), 0);
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().count(RootKind::Stack), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);
        assert_eq!(
            vm.add_root(RootKind::Temporary, object).err().unwrap(),
            VmError::InjectedFailure(FailPoint::RootReserve)
        );
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn fuel_lua_error_and_early_internal_error_clear_roots_and_terminalize() {
        let lua_error_module = module(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::LoadConst {
                    dest: Register(1),
                    constant: ConstId(1),
                },
                Instruction::BinaryOp {
                    dest: Register(0),
                    op: rivetlua_core::BinaryOperation::FloorDivide,
                    left: Register(0),
                    right: Register(1),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::Integer(1), BytecodeConstant::Integer(0)],
        );
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate(Value::Integer(8)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(lua_error_module).unwrap();
        execution
            .frame
            .write(execution.vm, Register(2), Value::Object(object))
            .unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("整數除零必須形成 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert_eq!(execution.pc(), 2);
        assert_eq!(execution.fuel_remaining(), 999_997);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);
        assert_eq!(vm.collect().unwrap(), 1);

        let internal_module = module(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        );
        let object = vm.allocate(Value::Integer(9)).unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(internal_module).unwrap();
        execution
            .frame
            .write(execution.vm, Register(0), Value::Object(object))
            .unwrap();
        execution.frame.pc = usize::MAX;
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::ProgramCounterOutOfBounds
        );
        assert_eq!(execution.fuel_remaining(), 1_000_000);
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.vm.roots().total_count(), 0);
        assert_eq!(execution.vm.ledger_snapshot(), before);
        drop(execution);
        assert_eq!(vm.collect().unwrap(), 1);
    }
}
