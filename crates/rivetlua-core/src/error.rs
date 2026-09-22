//! P01 可檢查的數值核心錯誤。

use crate::value::ValueKind;

/// 產生錯誤的數值操作。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    FloorDivide,
    Modulo,
    BitAnd,
    BitOr,
    BitXor,
    BitNot,
    ShiftLeft,
    ShiftRight,
    ConvertToInteger,
    ConvertToNumber,
}

/// 可由呼叫端檢查的錯誤原因。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreErrorKind {
    IntegerDivideByZero,
    IntegerModuloByZero,
    NotInteger,
    NotNumeric,
}

/// P01 核心錯誤資料，不含宿主位址或未初始化資料。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreError {
    pub operation: Operation,
    pub operand: ValueKind,
    pub kind: CoreErrorKind,
}

impl CoreError {
    pub const fn new(operation: Operation, operand: ValueKind, kind: CoreErrorKind) -> Self {
        Self {
            operation,
            operand,
            kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CoreError, CoreErrorKind, Operation};
    use crate::ValueKind;

    #[test]
    fn errors_keep_operation_operand_and_reason() {
        let error = CoreError::new(
            Operation::FloorDivide,
            ValueKind::Integer,
            CoreErrorKind::IntegerDivideByZero,
        );
        assert_eq!(error.operation, Operation::FloorDivide);
        assert_eq!(error.operand, ValueKind::Integer);
        assert_eq!(error.kind, CoreErrorKind::IntegerDivideByZero);
    }
}
