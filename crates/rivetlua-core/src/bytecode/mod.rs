//! P05 自有 typed IR 的共用 bytecode 契約；不含 VM。

pub mod codec;
pub use codec::*;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Register(pub u16);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConstId(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UpvalueId(pub u16);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtoId(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InstructionOffset(pub u32);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BytecodeVersion(pub u16);

pub const RVLU_V1: BytecodeVersion = BytecodeVersion(1);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum LuaProfile {
    Lua55,
    Lua54,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileRequirement {
    Any,
    Only(LuaProfile),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultMode {
    Fixed(u16),
    All,
}

/// P05 frame 的靜態配置；dynamic_top 只描述開放結果的起點，不代表執行期狀態。
/// P05 frame environment slot 的可驗證初始化來源。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnvironmentSource {
    RootExternal,
    ParentFrame { parent: ProtoId, register: Register },
    ParentLocal { upvalue: UpvalueId },
    ParentUpvalue { upvalue: UpvalueId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameLayout {
    pub register_limit: u16,
    pub initial_top: Register,
    pub dynamic_top: Register,
    pub return_base: Register,
    /// 由 P04 root `_ENV` 來源指定的外部環境 slot；不是硬編碼 table operand。
    pub environment: Register,
    pub environment_source: EnvironmentSource,
    pub registers_start_as_nil: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnaryOperation {
    Negate,
    Not,
    Length,
    BitNot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BinaryOperation {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Pipe,
    BitXor,
    Ampersand,
    ShiftLeft,
    ShiftRight,
    Concat,
    Add,
    Subtract,
    Multiply,
    Divide,
    FloorDivide,
    Modulo,
    Power,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Opcode {
    LoadConst,
    LoadNil,
    Move,
    GetUpvalue,
    SetUpvalue,
    NewTable,
    GetTable,
    SetTable,
    UnaryOp,
    BinaryOp,
    Jump,
    JumpIfFalse,
    Closure,
    Call,
    TailCall,
    Vararg,
    Return,
    Close,
}

impl Opcode {
    pub const ALL: [Self; 18] = [
        Self::LoadConst,
        Self::LoadNil,
        Self::Move,
        Self::GetUpvalue,
        Self::SetUpvalue,
        Self::NewTable,
        Self::GetTable,
        Self::SetTable,
        Self::UnaryOp,
        Self::BinaryOp,
        Self::Jump,
        Self::JumpIfFalse,
        Self::Closure,
        Self::Call,
        Self::TailCall,
        Self::Vararg,
        Self::Return,
        Self::Close,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlFlow {
    Linear,
    Jump,
    ConditionalJump,
    Terminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisterEffects {
    pub reads: Vec<Register>,
    pub writes: Vec<Register>,
    pub control_flow: ControlFlow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Instruction {
    LoadConst {
        dest: Register,
        constant: ConstId,
    },
    LoadNil {
        start: Register,
        count: u16,
    },
    Move {
        dest: Register,
        src: Register,
    },
    GetUpvalue {
        dest: Register,
        upvalue: UpvalueId,
    },
    SetUpvalue {
        upvalue: UpvalueId,
        src: Register,
    },
    NewTable {
        dest: Register,
    },
    GetTable {
        dest: Register,
        table: Register,
        key: Register,
    },
    SetTable {
        table: Register,
        key: Register,
        value: Register,
    },
    UnaryOp {
        dest: Register,
        op: UnaryOperation,
        src: Register,
    },
    BinaryOp {
        dest: Register,
        op: BinaryOperation,
        left: Register,
        right: Register,
    },
    Jump {
        target: InstructionOffset,
    },
    JumpIfFalse {
        condition: Register,
        target: InstructionOffset,
    },
    Closure {
        dest: Register,
        proto: ProtoId,
    },
    Call {
        base: Register,
        arg_count: u16,
        result_mode: ResultMode,
    },
    TailCall {
        base: Register,
        arg_count: u16,
        result_mode: ResultMode,
    },
    Vararg {
        base: Register,
        result_mode: ResultMode,
    },
    Return {
        base: Register,
        result_mode: ResultMode,
    },
    Close {
        base: Register,
        count: u16,
    },
}

impl Instruction {
    pub const fn opcode(&self) -> Opcode {
        match self {
            Self::LoadConst { .. } => Opcode::LoadConst,
            Self::LoadNil { .. } => Opcode::LoadNil,
            Self::Move { .. } => Opcode::Move,
            Self::GetUpvalue { .. } => Opcode::GetUpvalue,
            Self::SetUpvalue { .. } => Opcode::SetUpvalue,
            Self::NewTable { .. } => Opcode::NewTable,
            Self::GetTable { .. } => Opcode::GetTable,
            Self::SetTable { .. } => Opcode::SetTable,
            Self::UnaryOp { .. } => Opcode::UnaryOp,
            Self::BinaryOp { .. } => Opcode::BinaryOp,
            Self::Jump { .. } => Opcode::Jump,
            Self::JumpIfFalse { .. } => Opcode::JumpIfFalse,
            Self::Closure { .. } => Opcode::Closure,
            Self::Call { .. } => Opcode::Call,
            Self::TailCall { .. } => Opcode::TailCall,
            Self::Vararg { .. } => Opcode::Vararg,
            Self::Return { .. } => Opcode::Return,
            Self::Close { .. } => Opcode::Close,
        }
    }

    pub const fn profile_requirement(&self) -> ProfileRequirement {
        ProfileRequirement::Any
    }

    pub fn effects(&self) -> RegisterEffects {
        let (reads, writes, control_flow) = match self {
            Self::LoadConst { dest, .. } => (vec![], vec![*dest], ControlFlow::Linear),
            Self::LoadNil { start, count } => (
                vec![],
                (0..*count)
                    .map(|offset| Register(start.0.saturating_add(offset)))
                    .collect(),
                ControlFlow::Linear,
            ),
            Self::Move { dest, src } => (vec![*src], vec![*dest], ControlFlow::Linear),
            Self::GetUpvalue { dest, .. } => (vec![], vec![*dest], ControlFlow::Linear),
            Self::SetUpvalue { src, .. } => (vec![*src], vec![], ControlFlow::Linear),
            Self::NewTable { dest } => (vec![], vec![*dest], ControlFlow::Linear),
            Self::GetTable { dest, table, key } => {
                (vec![*table, *key], vec![*dest], ControlFlow::Linear)
            }
            Self::SetTable { table, key, value } => {
                (vec![*table, *key, *value], vec![], ControlFlow::Linear)
            }
            Self::UnaryOp { dest, src, .. } => (vec![*src], vec![*dest], ControlFlow::Linear),
            Self::BinaryOp {
                dest, left, right, ..
            } => (vec![*left, *right], vec![*dest], ControlFlow::Linear),
            Self::Jump { .. } => (vec![], vec![], ControlFlow::Jump),
            Self::JumpIfFalse { condition, .. } => {
                (vec![*condition], vec![], ControlFlow::ConditionalJump)
            }
            Self::Closure { dest, .. } => (vec![], vec![*dest], ControlFlow::Linear),
            Self::Call {
                base,
                arg_count,
                result_mode,
            }
            | Self::TailCall {
                base,
                arg_count,
                result_mode,
            } => {
                let reads = (0..=(*arg_count))
                    .map(|offset| Register(base.0.saturating_add(offset)))
                    .collect();
                let writes = match result_mode {
                    ResultMode::Fixed(count) => (0..*count)
                        .map(|offset| Register(base.0.saturating_add(offset)))
                        .collect(),
                    ResultMode::All => vec![*base],
                };
                let control = if matches!(self, Self::TailCall { .. }) {
                    ControlFlow::Terminal
                } else {
                    ControlFlow::Linear
                };
                (reads, writes, control)
            }
            Self::Vararg { base, result_mode } => (
                vec![],
                match result_mode {
                    ResultMode::Fixed(count) => (0..*count)
                        .map(|offset| Register(base.0.saturating_add(offset)))
                        .collect(),
                    ResultMode::All => vec![*base],
                },
                ControlFlow::Linear,
            ),
            Self::Return { base, result_mode } => (
                match result_mode {
                    ResultMode::Fixed(count) => (0..*count)
                        .map(|offset| Register(base.0.saturating_add(offset)))
                        .collect(),
                    ResultMode::All => vec![*base],
                },
                vec![],
                ControlFlow::Terminal,
            ),
            Self::Close { base, count } => (
                (0..*count)
                    .map(|offset| Register(base.0.saturating_add(offset)))
                    .collect(),
                vec![],
                ControlFlow::Linear,
            ),
        };
        RegisterEffects {
            reads,
            writes,
            control_flow,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrLimits {
    pub max_prototypes: usize,
    pub max_instructions: usize,
    pub max_registers: u16,
    pub max_upvalues_per_prototype: usize,
}

impl Default for IrLimits {
    fn default() -> Self {
        Self {
            max_prototypes: 4096,
            max_instructions: 100_000,
            max_registers: 4096,
            max_upvalues_per_prototype: 255,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_opcode_set_and_effects_are_typed() {
        assert_eq!(Opcode::ALL.len(), 18);
        assert!(Opcode::ALL.contains(&Opcode::Call));
        assert!(Opcode::ALL.contains(&Opcode::Close));
        let instruction = Instruction::BinaryOp {
            dest: Register(3),
            op: BinaryOperation::Add,
            left: Register(1),
            right: Register(2),
        };
        assert_eq!(instruction.opcode(), Opcode::BinaryOp);
        assert_eq!(instruction.profile_requirement(), ProfileRequirement::Any);
        assert_eq!(instruction.effects().reads, vec![Register(1), Register(2)]);
        assert_eq!(instruction.effects().writes, vec![Register(3)]);
        assert_eq!(
            Instruction::Close {
                base: Register(2),
                count: 1
            }
            .effects()
            .control_flow,
            ControlFlow::Linear
        );
        let frame = FrameLayout {
            register_limit: 8,
            initial_top: Register(3),
            dynamic_top: Register(3),
            return_base: Register(0),
            environment: Register(1),
            environment_source: EnvironmentSource::RootExternal,
            registers_start_as_nil: true,
        };
        assert!(frame.registers_start_as_nil);
        assert_eq!(frame.environment, Register(1));
    }
}
