use rivetlua_core::Value;
use rivetlua_core::{
    CoreErrorKind, Number, add, bit_and, bit_not, compare, equal, floor_divide, modulo,
    number_from_value, shift_left,
};
use std::cmp::Ordering;

#[test]
fn public_number_api_preserves_p01_numeric_contracts() {
    assert_eq!(
        floor_divide(Number::Integer(-3), Number::Integer(2)),
        Ok(Number::Integer(-2))
    );
    assert_eq!(
        modulo(Number::Integer(-3), Number::Integer(2)),
        Ok(Number::Integer(1))
    );
    assert_eq!(
        add(Number::Integer(i64::MAX), Number::Integer(1)),
        Number::Integer(i64::MIN)
    );
    assert!(!equal(
        Number::Integer(9_007_199_254_740_993),
        Number::Float(9_007_199_254_740_992.0)
    ));
    assert_eq!(
        bit_and(Number::Float(6.0), Number::Integer(3)),
        Ok(Number::Integer(2))
    );
    assert_eq!(
        shift_left(Number::Integer(1), Number::Integer(64)),
        Ok(Number::Integer(0))
    );
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
    let Number::Float(signed_zero) = Number::Float(-0.0) else {
        unreachable!();
    };
    assert!(signed_zero.is_sign_negative());
    assert!(Value::Float(-0.0).is_truthy());
}

#[test]
fn public_number_api_returns_checkable_errors() {
    assert_eq!(
        floor_divide(Number::Integer(1), Number::Integer(0))
            .unwrap_err()
            .kind,
        CoreErrorKind::IntegerDivideByZero
    );
    assert_eq!(
        number_from_value(Value::Nil).unwrap_err().kind,
        CoreErrorKind::NotNumeric
    );
    assert_eq!(
        modulo(Number::Integer(1), Number::Integer(0))
            .unwrap_err()
            .kind,
        CoreErrorKind::IntegerModuloByZero
    );
    assert_eq!(
        bit_and(Number::Float(1.5), Number::Integer(1))
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
        floor_divide(Number::Integer(i64::MIN), Number::Integer(-1)),
        Ok(Number::Integer(i64::MIN))
    );
}
