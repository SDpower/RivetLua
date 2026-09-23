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
/// 唯一可編碼與驗證的 RVLU 語言 bytecode 格式。
pub const RVLU_V2: BytecodeVersion = BytecodeVersion(2);

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
    NumericForPrepare,
    NumericForNext,
}

impl Opcode {
    pub const ALL: [Self; 20] = [
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
        Self::NumericForPrepare,
        Self::NumericForNext,
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
pub struct InstructionEffects {
    pub reads: Vec<Register>,
    pub writes: Vec<Register>,
    pub control_flow: ControlFlow,
    pub allocates: bool,
    pub writes_heap: bool,
    pub may_call: bool,
    pub may_yield: bool,
    pub may_error: bool,
    pub safe_point: bool,
}

/// RVLU v1 時期的名稱保留為 source 相容 alias；v2 唯一的公開 effect
/// 契約是 `InstructionEffects`，不是 GC heap-edge graph。
pub type RegisterEffects = InstructionEffects;

impl InstructionEffects {
    pub const ALLOCATES: u8 = 1 << 0;
    pub const WRITES_HEAP: u8 = 1 << 1;
    pub const MAY_CALL: u8 = 1 << 2;
    pub const MAY_YIELD: u8 = 1 << 3;
    pub const MAY_ERROR: u8 = 1 << 4;
    pub const SAFE_POINT: u8 = 1 << 5;
    pub const KNOWN_FLAGS: u8 = Self::ALLOCATES
        | Self::WRITES_HEAP
        | Self::MAY_CALL
        | Self::MAY_YIELD
        | Self::MAY_ERROR
        | Self::SAFE_POINT;

    pub const fn encoded_flags(&self) -> u8 {
        (if self.allocates { Self::ALLOCATES } else { 0 })
            | (if self.writes_heap {
                Self::WRITES_HEAP
            } else {
                0
            })
            | (if self.may_call { Self::MAY_CALL } else { 0 })
            | (if self.may_yield { Self::MAY_YIELD } else { 0 })
            | (if self.may_error { Self::MAY_ERROR } else { 0 })
            | (if self.safe_point { Self::SAFE_POINT } else { 0 })
    }
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
    /// 將已求值的 numeric-for 三個控制值轉為 numeric mode，並在初始值不符
    /// 終止條件時跳至 `exit`。四個 register 必須彼此不同。
    NumericForPrepare {
        control: Register,
        limit: Register,
        step: Register,
        visible: Register,
        exit: InstructionOffset,
    },
    /// 依 numeric-for mode 做不溢位前進與終止判定；成功回到 `target`，否則至
    /// `exit`。這是唯一可表達 numeric-for 回邊的 RVLU v2 instruction。
    NumericForNext {
        control: Register,
        limit: Register,
        step: Register,
        visible: Register,
        target: InstructionOffset,
        exit: InstructionOffset,
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
            Self::NumericForPrepare { .. } => Opcode::NumericForPrepare,
            Self::NumericForNext { .. } => Opcode::NumericForNext,
        }
    }

    pub const fn profile_requirement(&self) -> ProfileRequirement {
        ProfileRequirement::Any
    }

    /// 以固定 opcode 語意計算 canonical effect flags，不依 operand 數量配置暫存器集合。
    pub(crate) const fn canonical_effect_flags(&self) -> u8 {
        match self {
            Self::NewTable { .. } | Self::Closure { .. } => {
                InstructionEffects::ALLOCATES
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::GetTable { .. } => {
                InstructionEffects::MAY_CALL
                    | InstructionEffects::MAY_YIELD
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::SetTable { .. } => {
                InstructionEffects::WRITES_HEAP
                    | InstructionEffects::MAY_CALL
                    | InstructionEffects::MAY_YIELD
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::BinaryOp {
                op: BinaryOperation::Concat,
                ..
            } => {
                InstructionEffects::ALLOCATES
                    | InstructionEffects::MAY_CALL
                    | InstructionEffects::MAY_YIELD
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::UnaryOp { .. } | Self::BinaryOp { .. } => {
                InstructionEffects::MAY_CALL
                    | InstructionEffects::MAY_YIELD
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::SetUpvalue { .. } => {
                InstructionEffects::WRITES_HEAP | InstructionEffects::SAFE_POINT
            }
            Self::Call { .. } | Self::TailCall { .. } | Self::Close { .. } => {
                InstructionEffects::MAY_CALL
                    | InstructionEffects::MAY_YIELD
                    | InstructionEffects::MAY_ERROR
                    | InstructionEffects::SAFE_POINT
            }
            Self::NumericForPrepare { .. } | Self::NumericForNext { .. } => {
                InstructionEffects::MAY_ERROR | InstructionEffects::SAFE_POINT
            }
            _ => 0,
        }
    }

    pub fn effects(&self) -> InstructionEffects {
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
            Self::NumericForPrepare {
                control,
                limit,
                step,
                visible,
                ..
            }
            | Self::NumericForNext {
                control,
                limit,
                step,
                visible,
                ..
            } => (
                vec![*control, *limit, *step],
                vec![*control, *visible],
                ControlFlow::ConditionalJump,
            ),
        };
        // P10 的 metamethod 路徑可將 table/operator access 轉為 runtime call；此處
        // 與 SetUpvalue 的 heap write 標記都由同一 canonical flags 路徑提供。
        let flags = self.canonical_effect_flags();
        InstructionEffects {
            reads,
            writes,
            control_flow,
            allocates: flags & InstructionEffects::ALLOCATES != 0,
            writes_heap: flags & InstructionEffects::WRITES_HEAP != 0,
            may_call: flags & InstructionEffects::MAY_CALL != 0,
            may_yield: flags & InstructionEffects::MAY_YIELD != 0,
            may_error: flags & InstructionEffects::MAY_ERROR != 0,
            safe_point: flags & InstructionEffects::SAFE_POINT != 0,
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
        assert_eq!(Opcode::ALL.len(), 20);
        assert!(Opcode::ALL.contains(&Opcode::Call));
        assert!(Opcode::ALL.contains(&Opcode::Close));
        assert!(Opcode::ALL.contains(&Opcode::NumericForPrepare));
        assert!(Opcode::ALL.contains(&Opcode::NumericForNext));
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
        assert!(instruction.effects().may_call);
        assert!(instruction.effects().may_yield);
        assert!(instruction.effects().safe_point);
        assert!(!instruction.effects().allocates);
        let concat = Instruction::BinaryOp {
            dest: Register(3),
            op: BinaryOperation::Concat,
            left: Register(1),
            right: Register(2),
        }
        .effects();
        assert!(concat.allocates);
        assert_ne!(concat.encoded_flags() & InstructionEffects::ALLOCATES, 0);
        let get = Instruction::GetTable {
            dest: Register(3),
            table: Register(1),
            key: Register(2),
        }
        .effects();
        assert!(get.may_call && get.may_yield && get.safe_point);
        let upvalue_write = Instruction::SetUpvalue {
            upvalue: UpvalueId(0),
            src: Register(1),
        }
        .effects();
        assert!(upvalue_write.writes_heap && upvalue_write.safe_point);
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

    #[test]
    fn canonical_effect_flags_match_instruction_effects_for_every_opcode() {
        let instructions = [
            Instruction::LoadConst {
                dest: Register(0),
                constant: ConstId(0),
            },
            Instruction::LoadNil {
                start: Register(0),
                count: u16::MAX,
            },
            Instruction::Move {
                dest: Register(0),
                src: Register(1),
            },
            Instruction::GetUpvalue {
                dest: Register(0),
                upvalue: UpvalueId(0),
            },
            Instruction::SetUpvalue {
                upvalue: UpvalueId(0),
                src: Register(1),
            },
            Instruction::NewTable { dest: Register(0) },
            Instruction::GetTable {
                dest: Register(0),
                table: Register(1),
                key: Register(2),
            },
            Instruction::SetTable {
                table: Register(0),
                key: Register(1),
                value: Register(2),
            },
            Instruction::UnaryOp {
                dest: Register(0),
                op: UnaryOperation::Negate,
                src: Register(1),
            },
            Instruction::BinaryOp {
                dest: Register(0),
                op: BinaryOperation::Concat,
                left: Register(1),
                right: Register(2),
            },
            Instruction::Jump {
                target: InstructionOffset(0),
            },
            Instruction::JumpIfFalse {
                condition: Register(0),
                target: InstructionOffset(0),
            },
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(0),
            },
            Instruction::Call {
                base: Register(0),
                arg_count: u16::MAX,
                result_mode: ResultMode::Fixed(u16::MAX),
            },
            Instruction::TailCall {
                base: Register(0),
                arg_count: u16::MAX,
                result_mode: ResultMode::All,
            },
            Instruction::Vararg {
                base: Register(0),
                result_mode: ResultMode::Fixed(u16::MAX),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::All,
            },
            Instruction::Close {
                base: Register(0),
                count: u16::MAX,
            },
            Instruction::NumericForPrepare {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                exit: InstructionOffset(0),
            },
            Instruction::NumericForNext {
                control: Register(0),
                limit: Register(1),
                step: Register(2),
                visible: Register(3),
                target: InstructionOffset(0),
                exit: InstructionOffset(1),
            },
        ];

        for instruction in instructions {
            let flags = instruction.canonical_effect_flags();
            let effects = instruction.effects();
            assert_eq!(effects.encoded_flags(), flags);
            assert_eq!(
                effects.allocates,
                flags & InstructionEffects::ALLOCATES != 0
            );
            assert_eq!(
                effects.writes_heap,
                flags & InstructionEffects::WRITES_HEAP != 0
            );
            assert_eq!(effects.may_call, flags & InstructionEffects::MAY_CALL != 0);
            assert_eq!(
                effects.may_yield,
                flags & InstructionEffects::MAY_YIELD != 0
            );
            assert_eq!(
                effects.may_error,
                flags & InstructionEffects::MAY_ERROR != 0
            );
            assert_eq!(
                effects.safe_point,
                flags & InstructionEffects::SAFE_POINT != 0
            );
        }
    }
}
