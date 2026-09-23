//! P01 唯一的數值運算入口。

use core::cmp::Ordering;

use crate::error::{CoreError, CoreErrorKind, Operation};
use crate::value::{Value, ValueKind};

/// 保留 Integer 與 Float 子型別的數值。
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Number {
    Integer(i64),
    Float(f64),
}

impl Number {
    pub const fn kind(self) -> ValueKind {
        match self {
            Self::Integer(_) => ValueKind::Integer,
            Self::Float(_) => ValueKind::Float,
        }
    }

    fn as_float(self) -> f64 {
        match self {
            Self::Integer(value) => value as f64,
            Self::Float(value) => value,
        }
    }
}

/// 將值轉成數值，非數值以可檢查錯誤回傳。
pub fn number_from_value(value: Value) -> Result<Number, CoreError> {
    match value {
        Value::Integer(number) => Ok(Number::Integer(number)),
        Value::Float(number) => Ok(Number::Float(number)),
        other => Err(CoreError::new(
            Operation::ConvertToNumber,
            other.kind(),
            CoreErrorKind::NotNumeric,
        )),
    }
}

pub fn add(left: Number, right: Number) -> Number {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => {
            Number::Integer(left.wrapping_add(right))
        }
        _ => Number::Float(left.as_float() + right.as_float()),
    }
}

pub fn subtract(left: Number, right: Number) -> Number {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => {
            Number::Integer(left.wrapping_sub(right))
        }
        _ => Number::Float(left.as_float() - right.as_float()),
    }
}

pub fn multiply(left: Number, right: Number) -> Number {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => {
            Number::Integer(left.wrapping_mul(right))
        }
        _ => Number::Float(left.as_float() * right.as_float()),
    }
}

pub fn negate(value: Number) -> Number {
    match value {
        Number::Integer(value) => Number::Integer(value.wrapping_neg()),
        Number::Float(value) => Number::Float(-value),
    }
}

/// Lua `/` 規則：一律產生 Float。
pub fn divide(left: Number, right: Number) -> Number {
    Number::Float(left.as_float() / right.as_float())
}

/// Lua `^` 規則：兩個 operand 都走 `f64`，結果一律產生 Float。
pub fn power(left: Number, right: Number) -> Number {
    Number::Float(left.as_float().powf(right.as_float()))
}

/// Lua 向負無限的整數或浮點整除。
pub fn floor_divide(left: Number, right: Number) -> Result<Number, CoreError> {
    match (left, right) {
        (Number::Integer(_), Number::Integer(0)) => Err(CoreError::new(
            Operation::FloorDivide,
            ValueKind::Integer,
            CoreErrorKind::IntegerDivideByZero,
        )),
        (Number::Integer(i64::MIN), Number::Integer(-1)) => Ok(Number::Integer(i64::MIN)),
        (Number::Integer(left), Number::Integer(right)) => {
            let quotient = left / right;
            let remainder = left % right;
            let quotient = if remainder != 0 && (remainder > 0) != (right > 0) {
                quotient.wrapping_sub(1)
            } else {
                quotient
            };
            Ok(Number::Integer(quotient))
        }
        _ => Ok(Number::Float((left.as_float() / right.as_float()).floor())),
    }
}

/// Lua 餘數規則，與向下整除一致。
pub fn modulo(left: Number, right: Number) -> Result<Number, CoreError> {
    match (left, right) {
        (Number::Integer(_), Number::Integer(0)) => Err(CoreError::new(
            Operation::Modulo,
            ValueKind::Integer,
            CoreErrorKind::IntegerModuloByZero,
        )),
        (Number::Integer(i64::MIN), Number::Integer(-1)) => Ok(Number::Integer(0)),
        (Number::Integer(left), Number::Integer(right)) => {
            let remainder = left % right;
            let remainder = if remainder != 0 && (remainder > 0) != (right > 0) {
                remainder.wrapping_add(right)
            } else {
                remainder
            };
            Ok(Number::Integer(remainder))
        }
        _ => {
            let quotient = (left.as_float() / right.as_float()).floor();
            Ok(Number::Float(left.as_float() - quotient * right.as_float()))
        }
    }
}

/// 不將 Integer 降為 Float 的數值比較；NaN 沒有順序。
pub fn compare(left: Number, right: Number) -> Option<Ordering> {
    match (left, right) {
        (Number::Integer(left), Number::Integer(right)) => Some(left.cmp(&right)),
        (Number::Float(left), Number::Float(right)) => left.partial_cmp(&right),
        (Number::Integer(integer), Number::Float(float)) => compare_integer_float(integer, float),
        (Number::Float(float), Number::Integer(integer)) => {
            compare_integer_float(integer, float).map(Ordering::reverse)
        }
    }
}

pub fn equal(left: Number, right: Number) -> bool {
    compare(left, right) == Some(Ordering::Equal)
}

fn compare_integer_float(integer: i64, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float == f64::INFINITY {
        return Some(Ordering::Less);
    }
    if float == f64::NEG_INFINITY {
        return Some(Ordering::Greater);
    }
    let minimum = i64::MIN as f64;
    let exclusive_maximum = 9_223_372_036_854_775_808.0_f64;
    if float < minimum {
        return Some(Ordering::Greater);
    }
    if float >= exclusive_maximum {
        return Some(Ordering::Less);
    }
    let truncated = float.trunc();
    let converted = truncated as i64;
    match integer.cmp(&converted) {
        Ordering::Equal if float > truncated => Some(Ordering::Less),
        Ordering::Equal if float < truncated => Some(Ordering::Greater),
        ordering => Some(ordering),
    }
}

pub fn bit_and(left: Number, right: Number) -> Result<Number, CoreError> {
    Ok(Number::Integer(
        to_integer(left, Operation::BitAnd)? & to_integer(right, Operation::BitAnd)?,
    ))
}

pub fn bit_or(left: Number, right: Number) -> Result<Number, CoreError> {
    Ok(Number::Integer(
        to_integer(left, Operation::BitOr)? | to_integer(right, Operation::BitOr)?,
    ))
}

pub fn bit_xor(left: Number, right: Number) -> Result<Number, CoreError> {
    Ok(Number::Integer(
        to_integer(left, Operation::BitXor)? ^ to_integer(right, Operation::BitXor)?,
    ))
}

pub fn bit_not(value: Number) -> Result<Number, CoreError> {
    Ok(Number::Integer(!to_integer(value, Operation::BitNot)?))
}

pub fn shift_left(value: Number, amount: Number) -> Result<Number, CoreError> {
    shift(value, amount, Operation::ShiftLeft, true)
}

pub fn shift_right(value: Number, amount: Number) -> Result<Number, CoreError> {
    shift(value, amount, Operation::ShiftRight, false)
}

fn shift(
    value: Number,
    shift: Number,
    operation: Operation,
    left: bool,
) -> Result<Number, CoreError> {
    let value = to_integer(value, operation)?;
    let shift = to_integer(shift, operation)?;
    let magnitude = shift.unsigned_abs();
    if magnitude >= 64 {
        return Ok(Number::Integer(0));
    }
    let magnitude = magnitude as u32;
    let result = if (shift >= 0) == left {
        value.wrapping_shl(magnitude)
    } else {
        ((value as u64) >> magnitude) as i64
    };
    Ok(Number::Integer(result))
}

fn to_integer(value: Number, operation: Operation) -> Result<i64, CoreError> {
    match value {
        Number::Integer(value) => Ok(value),
        Number::Float(value)
            if value.is_finite()
                && value.fract() == 0.0
                && value >= i64::MIN as f64
                && value < 9_223_372_036_854_775_808.0_f64 =>
        {
            Ok(value as i64)
        }
        Number::Float(_) => Err(CoreError::new(
            operation,
            ValueKind::Float,
            CoreErrorKind::NotInteger,
        )),
    }
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use super::{
        Number, add, bit_and, bit_not, compare, divide, equal, floor_divide, modulo, multiply,
        negate, number_from_value, power, shift_left, subtract,
    };
    use crate::{CoreErrorKind, Value};

    #[test]
    fn arithmetic_keeps_integer_and_float_paths_distinct() {
        assert_eq!(
            add(Number::Integer(i64::MAX), Number::Integer(1)),
            Number::Integer(i64::MIN)
        );
        assert_eq!(
            subtract(Number::Integer(1), Number::Integer(2)),
            Number::Integer(-1)
        );
        assert_eq!(
            multiply(Number::Integer(3), Number::Integer(4)),
            Number::Integer(12)
        );
        assert_eq!(negate(Number::Integer(i64::MIN)), Number::Integer(i64::MIN));
        assert_eq!(
            divide(Number::Integer(3), Number::Integer(2)),
            Number::Float(1.5)
        );
        assert_eq!(
            add(Number::Integer(1), Number::Float(0.5)),
            Number::Float(1.5)
        );
    }

    #[test]
    fn power_always_uses_float_and_preserves_ieee_boundaries() {
        assert_eq!(
            power(Number::Integer(2), Number::Integer(3)),
            Number::Float(8.0)
        );
        assert_eq!(
            power(Number::Float(9.0), Number::Float(0.5)),
            Number::Float(3.0)
        );
        let Number::Float(nan) = power(Number::Float(f64::NAN), Number::Integer(1)) else {
            unreachable!();
        };
        assert!(nan.is_nan());
        let Number::Float(positive_infinity) =
            power(Number::Float(f64::INFINITY), Number::Integer(2))
        else {
            unreachable!();
        };
        assert!(positive_infinity.is_infinite() && positive_infinity.is_sign_positive());
        let Number::Float(negative_infinity) =
            power(Number::Float(f64::NEG_INFINITY), Number::Integer(3))
        else {
            unreachable!();
        };
        assert!(negative_infinity.is_infinite() && negative_infinity.is_sign_negative());
        assert_eq!(
            power(Number::Integer(-2), Number::Integer(3)),
            Number::Float(-8.0)
        );
        let Number::Float(non_integer_exponent) = power(Number::Integer(-2), Number::Float(0.5))
        else {
            unreachable!();
        };
        assert!(non_integer_exponent.is_nan());
        let Number::Float(negative_zero_odd) = power(Number::Float(-0.0), Number::Integer(3))
        else {
            unreachable!();
        };
        assert_eq!(negative_zero_odd, 0.0);
        assert!(negative_zero_odd.is_sign_negative());
        let Number::Float(negative_zero_even) = power(Number::Float(-0.0), Number::Integer(2))
        else {
            unreachable!();
        };
        assert_eq!(negative_zero_even, 0.0);
        assert!(negative_zero_even.is_sign_positive());
        let Number::Float(negative_infinite_reciprocal) =
            power(Number::Float(-0.0), Number::Integer(-3))
        else {
            unreachable!();
        };
        assert!(
            negative_infinite_reciprocal.is_infinite()
                && negative_infinite_reciprocal.is_sign_negative()
        );
        let Number::Float(positive_infinite_reciprocal) =
            power(Number::Float(-0.0), Number::Integer(-2))
        else {
            unreachable!();
        };
        assert!(
            positive_infinite_reciprocal.is_infinite()
                && positive_infinite_reciprocal.is_sign_positive()
        );
    }

    #[test]
    fn floor_division_and_modulo_follow_lua_rules() {
        assert_eq!(
            floor_divide(Number::Integer(-3), Number::Integer(2)),
            Ok(Number::Integer(-2))
        );
        assert_eq!(
            modulo(Number::Integer(-3), Number::Integer(2)),
            Ok(Number::Integer(1))
        );
        assert_eq!(
            modulo(Number::Integer(3), Number::Integer(-2)),
            Ok(Number::Integer(-1))
        );
    }

    #[test]
    fn integer_float_comparison_keeps_large_integer_precision() {
        assert!(!equal(
            Number::Integer(9_007_199_254_740_993),
            Number::Float(9_007_199_254_740_992.0)
        ));
        assert_eq!(
            compare(
                Number::Integer(9_007_199_254_740_993),
                Number::Float(9_007_199_254_740_992.0)
            ),
            Some(Ordering::Greater)
        );
        assert_eq!(compare(Number::Float(f64::NAN), Number::Integer(0)), None);
    }

    #[test]
    fn integer_float_comparison_covers_special_values_and_boundaries() {
        assert_eq!(
            compare(Number::Integer(i64::MAX), Number::Float(2_f64.powi(63))),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare(Number::Integer(i64::MIN), Number::Float(-2_f64.powi(63))),
            Some(Ordering::Equal)
        );
        assert_eq!(
            compare(Number::Integer(-1), Number::Float(-1.5)),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare(Number::Integer(0), Number::Float(f64::INFINITY)),
            Some(Ordering::Less)
        );
        assert_eq!(
            compare(Number::Integer(0), Number::Float(f64::NEG_INFINITY)),
            Some(Ordering::Greater)
        );
        assert!(equal(Number::Float(-0.0), Number::Float(0.0)));
        let Number::Float(value) = Number::Float(-0.0) else {
            unreachable!();
        };
        assert!(value.is_sign_negative());
    }

    #[test]
    fn bit_operations_handle_exact_conversion_and_shift_direction() {
        assert_eq!(
            bit_and(Number::Float(6.0), Number::Integer(3)),
            Ok(Number::Integer(2))
        );
        assert_eq!(
            shift_left(Number::Integer(1), Number::Integer(-1)),
            Ok(Number::Integer(0))
        );
        assert_eq!(
            shift_left(Number::Integer(1), Number::Integer(64)),
            Ok(Number::Integer(0))
        );
    }

    #[test]
    fn boundary_operations_wrap_or_return_checkable_errors() {
        assert_eq!(
            floor_divide(Number::Integer(i64::MIN), Number::Integer(-1)),
            Ok(Number::Integer(i64::MIN))
        );
        assert_eq!(
            modulo(Number::Integer(i64::MIN), Number::Integer(-1)),
            Ok(Number::Integer(0))
        );
        assert_eq!(
            floor_divide(Number::Integer(1), Number::Integer(0))
                .unwrap_err()
                .kind,
            CoreErrorKind::IntegerDivideByZero
        );
        assert_eq!(
            modulo(Number::Integer(1), Number::Integer(0))
                .unwrap_err()
                .kind,
            CoreErrorKind::IntegerModuloByZero
        );
        assert_eq!(
            bit_and(Number::Float(f64::NAN), Number::Integer(1))
                .unwrap_err()
                .kind,
            CoreErrorKind::NotInteger
        );
        assert_eq!(
            bit_not(Number::Float(f64::INFINITY)).unwrap_err().kind,
            CoreErrorKind::NotInteger
        );
        assert_eq!(
            bit_and(Number::Float(f64::NEG_INFINITY), Number::Integer(1))
                .unwrap_err()
                .kind,
            CoreErrorKind::NotInteger
        );
        assert_eq!(
            number_from_value(Value::Nil).unwrap_err().kind,
            CoreErrorKind::NotNumeric
        );
    }
}
