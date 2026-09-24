//! P07 數值與比較運算只透過 P01 集中 helper。

use core::cmp::Ordering;

use rivetlua_core::{
    self as lua_core, BinaryOperation, Number, UnaryOperation, Value, number_from_value,
};

use super::{RuntimeError, RuntimeErrorKind};

fn number(value: Value) -> Result<Number, RuntimeError> {
    number_from_value(value).map_err(RuntimeError::from)
}

fn value(number: Number) -> Value {
    match number {
        Number::Integer(number) => Value::Integer(number),
        Number::Float(number) => Value::Float(number),
    }
}

fn number_if(value: Value) -> Option<Number> {
    match value {
        Value::Integer(number) => Some(Number::Integer(number)),
        Value::Float(number) => Some(Number::Float(number)),
        _ => None,
    }
}

pub(super) fn unary(op: UnaryOperation, operand: Value) -> Result<Value, RuntimeError> {
    match op {
        UnaryOperation::Negate => Ok(value(lua_core::negate(number(operand)?))),
        UnaryOperation::Not => Ok(Value::Boolean(!operand.is_truthy())),
        UnaryOperation::BitNot => Ok(value(lua_core::bit_not(number(operand)?)?)),
        UnaryOperation::Length => Err(RuntimeError::new(
            RuntimeErrorKind::UnsupportedUnaryOperation(op),
        )),
    }
}

fn equal(left: Value, right: Value) -> bool {
    match (number_if(left), number_if(right)) {
        (Some(left), Some(right)) => lua_core::equal(left, right),
        _ => left == right,
    }
}

pub(super) fn binary(
    op: BinaryOperation,
    left: Value,
    right: Value,
) -> Result<Value, RuntimeError> {
    use BinaryOperation as B;

    match op {
        B::Equal => Ok(Value::Boolean(equal(left, right))),
        B::NotEqual => Ok(Value::Boolean(!equal(left, right))),
        B::Less | B::LessEqual | B::Greater | B::GreaterEqual => {
            let ordering = lua_core::compare(number(left)?, number(right)?);
            let result = match op {
                B::Less => ordering == Some(Ordering::Less),
                B::LessEqual => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
                B::Greater => ordering == Some(Ordering::Greater),
                B::GreaterEqual => matches!(ordering, Some(Ordering::Greater | Ordering::Equal)),
                _ => {
                    return Err(RuntimeError::new(
                        RuntimeErrorKind::UnsupportedBinaryOperation(op),
                    ));
                }
            };
            Ok(Value::Boolean(result))
        }
        B::Or | B::And | B::Concat => Err(RuntimeError::new(
            RuntimeErrorKind::UnsupportedBinaryOperation(op),
        )),
        _ => {
            let left = number(left)?;
            let right = number(right)?;
            let result = match op {
                B::Pipe => lua_core::bit_or(left, right)?,
                B::BitXor => lua_core::bit_xor(left, right)?,
                B::Ampersand => lua_core::bit_and(left, right)?,
                B::ShiftLeft => lua_core::shift_left(left, right)?,
                B::ShiftRight => lua_core::shift_right(left, right)?,
                B::Add => lua_core::add(left, right),
                B::Subtract => lua_core::subtract(left, right),
                B::Multiply => lua_core::multiply(left, right),
                B::Divide => lua_core::divide(left, right),
                B::FloorDivide => lua_core::floor_divide(left, right)?,
                B::Modulo => lua_core::modulo(left, right)?,
                B::Power => lua_core::power(left, right),
                _ => {
                    return Err(RuntimeError::new(
                        RuntimeErrorKind::UnsupportedBinaryOperation(op),
                    ));
                }
            };
            Ok(value(result))
        }
    }
}
