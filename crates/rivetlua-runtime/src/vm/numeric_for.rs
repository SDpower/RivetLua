//! RVLU_V2 numeric-for 專用指令的數值狀態轉換。

use core::cmp::Ordering;

use rivetlua_core::{Number, Value, add, compare, number_from_value};

use super::{RuntimeError, RuntimeErrorKind};

pub(super) enum Prepared {
    Skip,
    Enter {
        control: Value,
        limit: Value,
        step: Value,
        visible: Value,
    },
}

pub(super) enum Advanced {
    Exit,
    Enter { control: Value, visible: Value },
}

fn float(number: Number) -> Result<f64, RuntimeError> {
    match number {
        Number::Float(value) => Ok(value),
        Number::Integer(_) => match add(Number::Float(0.0), number) {
            Number::Float(value) => Ok(value),
            Number::Integer(_) => Err(RuntimeError::new(RuntimeErrorKind::InvalidNumericForState)),
        },
    }
}

fn integer_limit(limit: Number, positive: bool) -> Option<i64> {
    match limit {
        Number::Integer(value) => Some(value),
        Number::Float(value) => {
            if value.is_nan() {
                return (!positive).then_some(i64::MIN);
            }
            let rounded = if positive {
                value.floor()
            } else {
                value.ceil()
            };
            const EXCLUSIVE_MAX: f64 = 9_223_372_036_854_775_808.0;
            if rounded >= EXCLUSIVE_MAX {
                return positive.then_some(i64::MAX);
            }
            if rounded < i64::MIN as f64 {
                return (!positive).then_some(i64::MIN);
            }
            Some(rounded as i64)
        }
    }
}

pub(super) fn prepare(initial: Value, limit: Value, step: Value) -> Result<Prepared, RuntimeError> {
    let initial = number_from_value(initial)?;
    let step = number_from_value(step)?;
    if matches!(step, Number::Integer(0) | Number::Float(0.0)) {
        return Err(RuntimeError::new(RuntimeErrorKind::NumericForZeroStep));
    }
    let limit = number_from_value(limit)?;
    if let (Number::Integer(initial), Number::Integer(step)) = (initial, step) {
        let positive =
            compare(Number::Integer(step), Number::Integer(0)) == Some(Ordering::Greater);
        let Some(limit) = integer_limit(limit, positive) else {
            return Ok(Prepared::Skip);
        };
        let ordering = compare(Number::Integer(initial), Number::Integer(limit));
        let out_of_range = if positive {
            ordering == Some(Ordering::Greater)
        } else {
            ordering == Some(Ordering::Less)
        };
        if out_of_range {
            return Ok(Prepared::Skip);
        }
        return Ok(Prepared::Enter {
            control: Value::Integer(initial),
            limit: Value::Integer(limit),
            step: Value::Integer(step),
            visible: Value::Integer(initial),
        });
    }

    let initial = float(initial)?;
    let limit = float(limit)?;
    let step = float(step)?;
    let positive = compare(Number::Float(step), Number::Float(0.0)) == Some(Ordering::Greater);
    let initial_limit = compare(Number::Float(initial), Number::Float(limit));
    let out_of_range = if positive {
        initial_limit == Some(Ordering::Greater)
    } else {
        initial_limit == Some(Ordering::Less)
    };
    if out_of_range {
        return Ok(Prepared::Skip);
    }
    Ok(Prepared::Enter {
        control: Value::Float(initial),
        limit: Value::Float(limit),
        step: Value::Float(step),
        visible: Value::Float(initial),
    })
}

pub(super) fn next(control: Value, limit: Value, step: Value) -> Result<Advanced, RuntimeError> {
    match (control, limit, step) {
        (Value::Integer(control), Value::Integer(limit), Value::Integer(step)) => {
            if step == 0 {
                return Err(RuntimeError::new(RuntimeErrorKind::InvalidNumericForState));
            }
            let Some(next) = control.checked_add(step) else {
                return Ok(Advanced::Exit);
            };
            let positive =
                compare(Number::Integer(step), Number::Integer(0)) == Some(Ordering::Greater);
            let ordering = compare(Number::Integer(next), Number::Integer(limit));
            let in_range = if positive {
                matches!(ordering, Some(Ordering::Less | Ordering::Equal))
            } else {
                matches!(ordering, Some(Ordering::Greater | Ordering::Equal))
            };
            if in_range {
                Ok(Advanced::Enter {
                    control: Value::Integer(next),
                    visible: Value::Integer(next),
                })
            } else {
                Ok(Advanced::Exit)
            }
        }
        (Value::Float(control), Value::Float(limit), Value::Float(step)) => {
            if step == 0.0 {
                return Err(RuntimeError::new(RuntimeErrorKind::InvalidNumericForState));
            }
            let Number::Float(next) = add(Number::Float(control), Number::Float(step)) else {
                return Err(RuntimeError::new(RuntimeErrorKind::InvalidNumericForState));
            };
            let positive =
                compare(Number::Float(step), Number::Float(0.0)) == Some(Ordering::Greater);
            let comparison = compare(Number::Float(next), Number::Float(limit));
            let in_range = if positive {
                matches!(comparison, Some(Ordering::Less | Ordering::Equal))
            } else {
                matches!(comparison, Some(Ordering::Greater | Ordering::Equal))
            };
            if in_range {
                Ok(Advanced::Enter {
                    control: Value::Float(next),
                    visible: Value::Float(next),
                })
            } else {
                Ok(Advanced::Exit)
            }
        }
        _ => Err(RuntimeError::new(RuntimeErrorKind::InvalidNumericForState)),
    }
}
