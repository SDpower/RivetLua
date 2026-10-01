//! Lua 5.4／5.5 的數值函式；random 狀態與比較續行由 VM 管理。

use rivetlua_core::{LuaProfile, Value};

use crate::alloc::{FailPoint, Reservation, reserve_vec};
use crate::pending_op::PrintArguments;
use crate::stdlib::basic;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MathBuiltin {
    Abs,
    Acos,
    Asin,
    Atan,
    Ceil,
    Cos,
    Deg,
    Exp,
    Floor,
    Fmod,
    Frexp,
    Ldexp,
    Log,
    Max,
    Min,
    Modf,
    Rad,
    Sin,
    Sqrt,
    Tan,
    ToInteger,
    Type,
    Ult,
    Random,
    RandomSeed,
}

pub(crate) fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::MathArgument)
}

pub(crate) fn values(
    vm: &Vm,
    values: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let mut output = Vec::new();
    let ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut output,
        values.len(),
        FailPoint::ReturnReserve,
    )?;
    output.extend_from_slice(values);
    Ok((output, Some(ticket)))
}

fn arg(args: &[Value], index: usize) -> Result<Value, RuntimeError> {
    args.get(index).copied().ok_or_else(argument)
}

pub(crate) fn number(vm: &Vm, value: Value) -> Result<Value, RuntimeError> {
    match basic::number(vm, value, None)? {
        number @ (Value::Integer(_) | Value::Float(_)) => Ok(number),
        _ => Err(argument()),
    }
}

pub(crate) fn integer(vm: &Vm, value: Value) -> Result<i64, RuntimeError> {
    basic::lua_integer(number(vm, value)?).ok_or_else(argument)
}

fn float(vm: &Vm, args: &[Value], index: usize) -> Result<f64, RuntimeError> {
    Ok(match number(vm, arg(args, index)?)? {
        Value::Integer(number) => number as f64,
        Value::Float(number) => number,
        _ => return Err(argument()),
    })
}

fn number_or_integer(value: f64) -> Value {
    basic::lua_integer(Value::Float(value))
        .map(Value::Integer)
        .unwrap_or(Value::Float(value))
}

pub(crate) fn numeric_parse_units(
    vm: &Vm,
    kind: MathBuiltin,
    args: &[Value],
) -> Result<usize, RuntimeError> {
    let count = match kind {
        MathBuiltin::Max | MathBuiltin::Min | MathBuiltin::Type => 0,
        MathBuiltin::Fmod | MathBuiltin::Ult | MathBuiltin::Ldexp => 2,
        MathBuiltin::Atan | MathBuiltin::Log => 2,
        MathBuiltin::Random | MathBuiltin::RandomSeed => args.len().min(2),
        _ => 1,
    };
    let mut units = 0_usize;
    for value in args.iter().take(count) {
        if let Value::Object(object) = value {
            if vm.object_kind(*object)? == ObjectKind::ByteString {
                let length = vm.with_byte_string(*object, |string| string.len())?;
                units = units
                    .checked_add(length)
                    .ok_or(VmError::ArithmeticOverflow)?;
            }
        }
    }
    Ok(units)
}

pub(crate) fn execute(
    vm: &mut Vm,
    kind: MathBuiltin,
    args: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    use MathBuiltin as M;
    let result = match kind {
        M::Abs => match arg(args, 0)? {
            Value::Integer(value) => Value::Integer(value.wrapping_abs()),
            _ => Value::Float(float(vm, args, 0)?.abs()),
        },
        M::Acos => Value::Float(float(vm, args, 0)?.acos()),
        M::Asin => Value::Float(float(vm, args, 0)?.asin()),
        M::Atan => {
            let y = float(vm, args, 0)?;
            let x = if args.get(1).is_none_or(|value| *value == Value::Nil) {
                1.0
            } else {
                float(vm, args, 1)?
            };
            Value::Float(y.atan2(x))
        }
        M::Ceil => match arg(args, 0)? {
            value @ Value::Integer(_) => value,
            _ => number_or_integer(float(vm, args, 0)?.ceil()),
        },
        M::Cos => Value::Float(float(vm, args, 0)?.cos()),
        M::Deg => Value::Float(float(vm, args, 0)? * (180.0 / core::f64::consts::PI)),
        M::Exp => Value::Float(float(vm, args, 0)?.exp()),
        M::Floor => match arg(args, 0)? {
            value @ Value::Integer(_) => value,
            _ => number_or_integer(float(vm, args, 0)?.floor()),
        },
        M::Fmod => {
            let left = arg(args, 0)?;
            let right = arg(args, 1)?;
            match (left, right) {
                (Value::Integer(_), Value::Integer(0)) => return Err(argument()),
                (Value::Integer(_), Value::Integer(-1)) => Value::Integer(0),
                (Value::Integer(a), Value::Integer(b)) => Value::Integer(a % b),
                _ => Value::Float(float(vm, args, 0)? % float(vm, args, 1)?),
            }
        }
        M::Frexp => {
            if vm.language_profile() != LuaProfile::Lua55 {
                return Err(argument());
            }
            let (fraction, exponent) = frexp(float(vm, args, 0)?);
            return values(vm, &[Value::Float(fraction), Value::Integer(exponent)]);
        }
        M::Ldexp => {
            if vm.language_profile() != LuaProfile::Lua55 {
                return Err(argument());
            }
            let x = float(vm, args, 0)?;
            let exponent = integer(vm, arg(args, 1)?)? as i32;
            Value::Float(ldexp(x, exponent))
        }
        M::Log => {
            let x = float(vm, args, 0)?;
            let result = if args.get(1).is_none_or(|value| *value == Value::Nil) {
                x.ln()
            } else {
                let base = float(vm, args, 1)?;
                if base == 2.0 {
                    x.log2()
                } else if base == 10.0 {
                    x.log10()
                } else {
                    x.ln() / base.ln()
                }
            };
            Value::Float(result)
        }
        M::Modf => match arg(args, 0)? {
            value @ Value::Integer(_) => {
                return values(vm, &[value, Value::Float(0.0)]);
            }
            _ => {
                let number = float(vm, args, 0)?;
                let integer = number.trunc();
                let fraction = if number == integer {
                    0.0
                } else {
                    number - integer
                };
                return values(vm, &[number_or_integer(integer), Value::Float(fraction)]);
            }
        },
        M::Rad => Value::Float(float(vm, args, 0)? * (core::f64::consts::PI / 180.0)),
        M::Sin => Value::Float(float(vm, args, 0)?.sin()),
        M::Sqrt => Value::Float(float(vm, args, 0)?.sqrt()),
        M::Tan => Value::Float(float(vm, args, 0)?.tan()),
        M::ToInteger => {
            let value = arg(args, 0)?;
            let converted = basic::number(vm, value, None)?;
            basic::lua_integer(converted)
                .map(Value::Integer)
                .unwrap_or(Value::Nil)
        }
        M::Type => {
            let value = arg(args, 0)?;
            let label = match value {
                Value::Integer(_) => b"integer".as_slice(),
                Value::Float(_) => b"float".as_slice(),
                _ => return values(vm, &[Value::Nil]),
            };
            Value::Object(vm.allocate_byte_string(label)?)
        }
        M::Ult => {
            let left = integer(vm, arg(args, 0)?)?;
            let right = integer(vm, arg(args, 1)?)?;
            Value::Boolean((left as u64) < (right as u64))
        }
        M::Max | M::Min | M::Random | M::RandomSeed => return Err(argument()),
    };
    values(vm, &[result])
}

pub(crate) struct MinMaxState {
    pub arguments: PrintArguments,
    pub minimum: bool,
    pub best: usize,
    pub next: usize,
}

pub(crate) fn next_random(state: &mut [u64; 4]) -> u64 {
    let first = state[0];
    let second = state[1];
    let third = state[2] ^ first;
    let fourth = state[3] ^ second;
    let result = second.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
    state[0] = first ^ fourth;
    state[1] = second ^ third;
    state[2] = third ^ (second << 17);
    state[3] = fourth.rotate_left(45);
    result
}

pub(crate) fn initial_random_state(first: u64, second: u64) -> [u64; 4] {
    [first, 0xff, second, 0]
}

pub(crate) fn random_float(bits: u64) -> f64 {
    ((bits >> 11) as f64) * (1.0 / ((1_u64 << 53) as f64))
}

pub(crate) fn projection_mask(mut width: u64) -> u64 {
    width |= width >> 1;
    width |= width >> 2;
    width |= width >> 4;
    width |= width >> 8;
    width |= width >> 16;
    width |= width >> 32;
    width
}

impl MinMaxState {
    pub(crate) fn new(vm: &mut Vm, args: &[Value], minimum: bool) -> Result<Self, RuntimeError> {
        if args.is_empty() {
            return Err(argument());
        }
        Ok(Self {
            arguments: PrintArguments::new(vm, args)?,
            minimum,
            best: 0,
            next: 1,
        })
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.clear_roots(vm)
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.restore_roots(vm)
    }

    pub(crate) fn trace_children(
        &self,
        visit: impl FnMut(rivetlua_core::ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.arguments.trace_children(visit)
    }

    pub(crate) fn operands(&self) -> (Value, Value) {
        let values = self.arguments.values();
        if self.minimum {
            (values[self.next], values[self.best])
        } else {
            (values[self.best], values[self.next])
        }
    }

    pub(crate) fn accept(&mut self, less: bool) {
        if less {
            self.best = self.next;
        }
        self.next += 1;
    }

    pub(crate) fn best(&self) -> Value {
        self.arguments.values()[self.best]
    }

    pub(crate) fn done(&self) -> bool {
        self.next >= self.arguments.values().len()
    }
}

fn frexp(value: f64) -> (f64, i64) {
    let bits = value.to_bits();
    let sign = bits & (1_u64 << 63);
    let exponent = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent == 0x7ff || (exponent == 0 && fraction == 0) {
        return (value, 0);
    }
    if exponent != 0 {
        let result = f64::from_bits(sign | (1022_u64 << 52) | fraction);
        return (result, exponent - 1022);
    }
    let highest = 63 - i64::from(fraction.leading_zeros());
    let normalized = fraction << (52 - highest);
    let result = f64::from_bits(sign | (1022_u64 << 52) | (normalized & ((1_u64 << 52) - 1)));
    (result, highest - 1073)
}

fn ldexp(value: f64, exponent: i32) -> f64 {
    let bits = value.to_bits();
    let sign = bits & (1_u64 << 63);
    let old_exponent = ((bits >> 52) & 0x7ff) as i64;
    let fraction = bits & ((1_u64 << 52) - 1);
    if old_exponent == 0x7ff || (old_exponent == 0 && fraction == 0) {
        return value;
    }
    let (significand, unbiased) = if old_exponent == 0 {
        let highest = 63 - i64::from(fraction.leading_zeros());
        let shift = 52 - highest;
        (fraction << shift, highest - 1074)
    } else {
        ((1_u64 << 52) | fraction, old_exponent - 1023)
    };
    let unbiased = unbiased + i64::from(exponent);
    if unbiased > 1023 {
        return f64::from_bits(sign | (0x7ff_u64 << 52));
    }
    if unbiased >= -1022 {
        let new_exponent = (unbiased + 1023) as u64;
        return f64::from_bits(sign | (new_exponent << 52) | (significand & ((1_u64 << 52) - 1)));
    }
    let shift = -1022 - unbiased;
    if shift > 53 {
        return f64::from_bits(sign);
    }
    let shift = shift as u32;
    let mut rounded = significand >> shift;
    let remainder = significand & ((1_u64 << shift) - 1);
    let halfway = 1_u64 << (shift - 1);
    if remainder > halfway || (remainder == halfway && rounded & 1 != 0) {
        rounded += 1;
    }
    f64::from_bits(sign | rounded)
}

#[cfg(test)]
mod tests {
    use super::{frexp, ldexp};

    #[test]
    fn p13_d_frexp_ldexp_cover_binary64_edges() {
        let smallest = f64::from_bits(1);
        assert_eq!(frexp(smallest), (0.5, -1073));
        assert_eq!(frexp(-smallest), (-0.5, -1073));
        assert_eq!(frexp(-0.0).0.to_bits(), (-0.0_f64).to_bits());
        assert_eq!(frexp(-0.0).1, 0);
        assert_eq!(frexp(f64::INFINITY), (f64::INFINITY, 0));
        assert!(frexp(f64::NAN).0.is_nan());
        assert_eq!(ldexp(smallest, 1074), 1.0);
        assert_eq!(ldexp(1.0, -1074), smallest);
        assert_eq!(ldexp(1.0, -1075), 0.0);
        assert_eq!(ldexp(1.5, -1075), smallest);
        assert_eq!(ldexp(-1.0, -1075).to_bits(), (-0.0_f64).to_bits());
        assert_eq!(ldexp(1.0, 1024), f64::INFINITY);
        assert_eq!(ldexp(-0.0, 2048).to_bits(), (-0.0_f64).to_bits());
        assert!(ldexp(f64::NAN, 2048).is_nan());
    }
}
