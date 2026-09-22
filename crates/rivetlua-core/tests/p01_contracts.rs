use std::cmp::Ordering;
use std::env;

use rivetlua_core::{
    CoreErrorKind, Number, ObjectRef, Value, add, bit_and, bit_not, bit_or, bit_xor, compare,
    equal, floor_divide, modulo, number_from_value, select_and, select_or, shift_left,
};

macro_rules! check_case {
    ($id:expr, $operands:expr, $actual:expr, $expected:expr) => {{
        let actual = $actual;
        let expected = $expected;
        println!(
            "P01_CASE\t{}\t{:?}\t{:?}\t{:?}",
            $id, $operands, expected, actual
        );
        assert_eq!(actual, expected);
    }};
}

fn require_profile() -> &'static str {
    match env::var("RIVETLUA_P01_PROFILE")
        .as_deref()
        .unwrap_or("lua55-i64f64")
    {
        "lua55-i64f64" => "lua55",
        "lua54-i64f64" => "lua54",
        _ => panic!("P01 case 必須接收完整 profile"),
    }
}

#[test]
fn profile_mapping_is_explicit() {
    assert!(matches!(require_profile(), "lua55" | "lua54"));
}

#[test]
fn num_001_floor_division() {
    require_profile();
    let expected = env::var("RIVETLUA_P01_NUM001_EXPECTED")
        .ok()
        .map(|value| value.parse::<i64>().expect("fixture 必須是 i64"))
        .unwrap_or(-2);
    check_case!(
        "NUM-001",
        "Integer(-3)//Integer(2)",
        floor_divide(Number::Integer(-3), Number::Integer(2)),
        Ok(Number::Integer(expected))
    );
}

#[test]
fn num_002_negative_modulo() {
    require_profile();
    check_case!(
        "NUM-002",
        "Integer(-3)%Integer(2)",
        modulo(Number::Integer(-3), Number::Integer(2)),
        Ok(Number::Integer(1))
    );
}

#[test]
fn num_003_negative_divisor_modulo() {
    require_profile();
    check_case!(
        "NUM-003",
        "Integer(3)%Integer(-2)",
        modulo(Number::Integer(3), Number::Integer(-2)),
        Ok(Number::Integer(-1))
    );
}

#[test]
fn num_004_integer_addition_wraps() {
    require_profile();
    check_case!(
        "NUM-004",
        "Integer(MAX)+Integer(1)",
        add(Number::Integer(i64::MAX), Number::Integer(1)),
        Number::Integer(i64::MIN)
    );
}

#[test]
fn num_005_large_integer_float_comparison_is_exact() {
    require_profile();
    check_case!(
        "NUM-005",
        "Integer(9007199254740993)==Float(9007199254740992)",
        equal(
            Number::Integer(9_007_199_254_740_993),
            Number::Float(9_007_199_254_740_992.0)
        ),
        false
    );
    check_case!(
        "NUM-005",
        "Integer(MAX)<Float(2^63)",
        compare(Number::Integer(i64::MAX), Number::Float(2_f64.powi(63))),
        Some(Ordering::Less)
    );
    check_case!(
        "NUM-005",
        "Integer(MIN)==Float(-2^63)",
        compare(Number::Integer(i64::MIN), Number::Float(-2_f64.powi(63))),
        Some(Ordering::Equal)
    );
    check_case!(
        "NUM-005",
        "Integer(-1)>Float(-1.5)",
        compare(Number::Integer(-1), Number::Float(-1.5)),
        Some(Ordering::Greater)
    );
    check_case!(
        "NUM-005",
        "Integer(0)<Float(+Infinity)",
        compare(Number::Integer(0), Number::Float(f64::INFINITY)),
        Some(Ordering::Less)
    );
    check_case!(
        "NUM-005",
        "Integer(0)>Float(-Infinity)",
        compare(Number::Integer(0), Number::Float(f64::NEG_INFINITY)),
        Some(Ordering::Greater)
    );
    check_case!(
        "NUM-005",
        "Float(-0)==Float(+0)",
        equal(Number::Float(-0.0), Number::Float(0.0)),
        true
    );
}

#[test]
fn num_006_minimum_integer_boundaries_do_not_panic() {
    require_profile();
    check_case!(
        "NUM-006",
        "Integer(MIN)//Integer(-1)",
        floor_divide(Number::Integer(i64::MIN), Number::Integer(-1)),
        Ok(Number::Integer(i64::MIN))
    );
    check_case!(
        "NUM-006",
        "Integer(MIN)%Integer(-1)",
        modulo(Number::Integer(i64::MIN), Number::Integer(-1)),
        Ok(Number::Integer(0))
    );
}

#[test]
fn num_007_bit_conversion_and_shift_boundaries() {
    require_profile();
    check_case!(
        "NUM-007",
        "Float(6)&Integer(3)",
        bit_and(Number::Float(6.0), Number::Integer(3)),
        Ok(Number::Integer(2))
    );
    check_case!(
        "NUM-007",
        "Integer(4)|Integer(3)",
        bit_or(Number::Integer(4), Number::Integer(3)),
        Ok(Number::Integer(7))
    );
    check_case!(
        "NUM-007",
        "Integer(6)^Integer(3)",
        bit_xor(Number::Integer(6), Number::Integer(3)),
        Ok(Number::Integer(5))
    );
    check_case!(
        "NUM-007",
        "~Integer(0)",
        bit_not(Number::Integer(0)),
        Ok(Number::Integer(-1))
    );
    check_case!(
        "NUM-007",
        "Integer(1)<<Integer(-1)",
        shift_left(Number::Integer(1), Number::Integer(-1)),
        Ok(Number::Integer(0))
    );
    check_case!(
        "NUM-007",
        "Integer(1)<<Integer(64)",
        shift_left(Number::Integer(1), Number::Integer(64)),
        Ok(Number::Integer(0))
    );
}

#[test]
fn val_001_and_keeps_selected_operand() {
    require_profile();
    check_case!(
        "VAL-001",
        "Integer(0) and Integer(7)",
        select_and(Value::Integer(0), Value::Integer(7)),
        Value::Integer(7)
    );
}

#[test]
fn val_002_or_keeps_truthy_object_operand() {
    require_profile();
    let object = Value::Object(ObjectRef::new_opaque().unwrap());
    check_case!(
        "VAL-002",
        "Object or Integer(8)",
        select_or(object, Value::Integer(8)),
        object
    );
}

#[test]
fn val_003_only_nil_and_false_are_falsey() {
    require_profile();
    let object = Value::Object(ObjectRef::new_opaque().unwrap());
    check_case!("VAL-003", "Nil truthiness", Value::Nil.is_truthy(), false);
    check_case!(
        "VAL-003",
        "false truthiness",
        Value::Boolean(false).is_truthy(),
        false
    );
    check_case!(
        "VAL-003",
        "true truthiness",
        Value::Boolean(true).is_truthy(),
        true
    );
    check_case!(
        "VAL-003",
        "Integer(0) truthiness",
        Value::Integer(0).is_truthy(),
        true
    );
    check_case!(
        "VAL-003",
        "Float(-0) truthiness",
        Value::Float(-0.0).is_truthy(),
        true
    );
    check_case!(
        "VAL-003",
        "Float(-0) preserves sign",
        match Value::Float(-0.0) {
            Value::Float(value) => value.is_sign_negative(),
            _ => false,
        },
        true
    );
    check_case!("VAL-003", "Object truthiness", object.is_truthy(), true);
}

#[test]
fn err_001_integer_division_by_zero_is_checkable() {
    require_profile();
    check_case!(
        "ERR-001",
        "Integer(1)//Integer(0)",
        floor_divide(Number::Integer(1), Number::Integer(0))
            .unwrap_err()
            .kind,
        CoreErrorKind::IntegerDivideByZero
    );
}

#[test]
fn err_002_integer_modulo_by_zero_is_checkable() {
    require_profile();
    check_case!(
        "ERR-002",
        "Integer(1)%Integer(0)",
        modulo(Number::Integer(1), Number::Integer(0))
            .unwrap_err()
            .kind,
        CoreErrorKind::IntegerModuloByZero
    );
}

#[test]
fn err_003_inexact_or_nonfinite_float_is_not_integer() {
    require_profile();
    check_case!(
        "ERR-003",
        "Float(1.5)&Integer(1)",
        bit_and(Number::Float(1.5), Number::Integer(1))
            .unwrap_err()
            .kind,
        CoreErrorKind::NotInteger
    );
    check_case!(
        "ERR-003",
        "Float(NaN)&Integer(1)",
        bit_and(Number::Float(f64::NAN), Number::Integer(1))
            .unwrap_err()
            .kind,
        CoreErrorKind::NotInteger
    );
    check_case!(
        "ERR-003",
        "Float(+Infinity)&Integer(1)",
        bit_and(Number::Float(f64::INFINITY), Number::Integer(1))
            .unwrap_err()
            .kind,
        CoreErrorKind::NotInteger
    );
    check_case!(
        "ERR-003",
        "Float(-Infinity)&Integer(1)",
        bit_and(Number::Float(f64::NEG_INFINITY), Number::Integer(1))
            .unwrap_err()
            .kind,
        CoreErrorKind::NotInteger
    );
}

#[test]
fn err_004_non_numeric_value_is_checkable() {
    require_profile();
    check_case!(
        "ERR-004",
        "number(Nil)",
        number_from_value(Value::Nil).unwrap_err().kind,
        CoreErrorKind::NotNumeric
    );
}
