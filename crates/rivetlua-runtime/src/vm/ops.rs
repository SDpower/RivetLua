//! P07 數值與比較運算沿用 P01 helper；P08 加入 raw 長度路徑。

use core::cmp::Ordering;
use core::fmt::Write;

use rivetlua_core::{
    self as lua_core, BinaryOperation, LuaProfile, Number, UnaryOperation, Value, number_from_value,
};

use super::{RuntimeError, RuntimeErrorKind};
use crate::alloc::{FailPoint, reserve_vec};
use crate::{ObjectKind, Vm, VmError};

struct NumberBytes {
    bytes: [u8; 128],
    len: usize,
}

impl NumberBytes {
    fn new() -> Self {
        Self {
            bytes: [0; 128],
            len: 0,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), VmError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        let slice = self
            .bytes
            .get_mut(self.len..end)
            .ok_or(VmError::ArithmeticOverflow)?;
        slice.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl core::fmt::Write for NumberBytes {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        self.append(text.as_bytes()).map_err(|_| core::fmt::Error)
    }
}

fn format_lua_float(
    number: &mut NumberBytes,
    value: f64,
    profile: LuaProfile,
) -> Result<(), RuntimeError> {
    if value.is_nan() {
        number.append(b"nan")?;
        return Ok(());
    }
    if value == f64::INFINITY {
        number.append(b"inf")?;
        return Ok(());
    }
    if value == f64::NEG_INFINITY {
        number.append(b"-inf")?;
        return Ok(());
    }

    // Lua 5.4 使用 %.14g；Lua 5.5 先試 %.15g，回讀不等時改用 %.17g。
    let mut precision = match profile {
        LuaProfile::Lua54 => 14,
        LuaProfile::Lua55 => 15,
    };
    let scientific = loop {
        let mut candidate = NumberBytes::new();
        write!(candidate, "{:.*e}", precision - 1, value)
            .map_err(|_| VmError::ArithmeticOverflow)?;
        let text = core::str::from_utf8(&candidate.bytes[..candidate.len])
            .map_err(|_| VmError::ArithmeticOverflow)?;
        let parsed = text
            .parse::<f64>()
            .map_err(|_| VmError::ArithmeticOverflow)?;
        if profile == LuaProfile::Lua54 || parsed == value || precision == 17 {
            break candidate;
        }
        precision = 17;
    };
    let text = core::str::from_utf8(&scientific.bytes[..scientific.len])
        .map_err(|_| VmError::ArithmeticOverflow)?;
    let (mantissa, exponent_text) = text.split_once('e').ok_or(VmError::ArithmeticOverflow)?;
    let exponent = exponent_text
        .parse::<i32>()
        .map_err(|_| VmError::ArithmeticOverflow)?;
    let mut digits = [0u8; 17];
    let mut digit_count = 0;
    for byte in mantissa.bytes() {
        if byte.is_ascii_digit() {
            let slot = digits
                .get_mut(digit_count)
                .ok_or(VmError::ArithmeticOverflow)?;
            *slot = byte;
            digit_count += 1;
        } else if byte != b'.' && byte != b'-' {
            return Err(VmError::ArithmeticOverflow.into());
        }
    }
    if digit_count == 0 {
        return Err(VmError::ArithmeticOverflow.into());
    }
    while digit_count > 1 && digits[digit_count - 1] == b'0' {
        digit_count -= 1;
    }
    if value.is_sign_negative() {
        number.append(b"-")?;
    }
    if exponent < -4
        || exponent >= i32::try_from(precision).map_err(|_| VmError::ArithmeticOverflow)?
    {
        number.append(&digits[..1])?;
        if digit_count > 1 {
            number.append(b".")?;
            number.append(&digits[1..digit_count])?;
        }
        write!(number, "e{exponent:+03}").map_err(|_| VmError::ArithmeticOverflow)?;
    } else {
        let decimal = exponent + 1;
        if decimal <= 0 {
            number.append(b"0.")?;
            for _ in 0..-decimal {
                number.append(b"0")?;
            }
            number.append(&digits[..digit_count])?;
        } else {
            let decimal = usize::try_from(decimal).map_err(|_| VmError::ArithmeticOverflow)?;
            if decimal >= digit_count {
                number.append(&digits[..digit_count])?;
                for _ in digit_count..decimal {
                    number.append(b"0")?;
                }
                number.append(b".0")?;
            } else {
                number.append(&digits[..decimal])?;
                number.append(b".")?;
                number.append(&digits[decimal..digit_count])?;
            }
        }
    }
    Ok(())
}

pub(super) fn basic_number_bytes(
    value: Value,
    profile: LuaProfile,
) -> Result<([u8; 128], usize), RuntimeError> {
    let mut number = NumberBytes::new();
    match value {
        Value::Integer(value) => {
            write!(number, "{value}").map_err(|_| VmError::ArithmeticOverflow)?;
        }
        Value::Float(value) => format_lua_float(&mut number, value, profile)?,
        _ => return Err(RuntimeError::new(RuntimeErrorKind::BasicArgument)),
    }
    Ok((number.bytes, number.len))
}

fn concat_piece_len(
    vm: &Vm,
    profile: LuaProfile,
    value: Value,
    number: &mut NumberBytes,
) -> Result<Option<usize>, RuntimeError> {
    match value {
        Value::Integer(value) => {
            write!(number, "{value}").map_err(|_| VmError::ArithmeticOverflow)?;
            Ok(Some(number.len))
        }
        Value::Float(value) => {
            format_lua_float(number, value, profile)?;
            Ok(Some(number.len))
        }
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            Ok(Some(vm.with_byte_string(object, |string| string.len())?))
        }
        _ => Ok(None),
    }
}

fn append_concat_piece(
    vm: &Vm,
    value: Value,
    number: &NumberBytes,
    output: &mut Vec<u8>,
) -> Result<(), RuntimeError> {
    if let Value::Object(object) = value {
        vm.with_byte_string(object, |string| output.extend_from_slice(string.as_bytes()))?;
    } else {
        output.extend_from_slice(&number.bytes[..number.len]);
    }
    Ok(())
}

pub(super) fn raw_concat(
    vm: &mut Vm,
    profile: LuaProfile,
    left: Value,
    right: Value,
) -> Result<Option<Value>, RuntimeError> {
    let mut a = NumberBytes::new();
    let mut b = NumberBytes::new();
    let Some(a_len) = concat_piece_len(vm, profile, left, &mut a)? else {
        return Ok(None);
    };
    let Some(b_len) = concat_piece_len(vm, profile, right, &mut b)? else {
        return Ok(None);
    };
    let total = a_len
        .checked_add(b_len)
        .ok_or(VmError::ArithmeticOverflow)?;
    let mut bytes = Vec::new();
    let ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut bytes,
        total,
        FailPoint::StringBytesReserve,
    )?;
    append_concat_piece(vm, left, &a, &mut bytes)?;
    append_concat_piece(vm, right, &b, &mut bytes)?;
    let object = vm.allocate_byte_string(&bytes)?;
    drop(ticket);
    Ok(Some(Value::Object(object)))
}

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

pub(super) fn length(vm: &Vm, operand: Value) -> Result<Value, RuntimeError> {
    let Value::Object(object) = operand else {
        return Err(RuntimeError::new(
            RuntimeErrorKind::UnsupportedUnaryOperation(UnaryOperation::Length),
        ));
    };
    let length = match vm.object_kind(object)? {
        ObjectKind::ByteString => {
            let bytes = vm.with_byte_string(object, |string| string.len())?;
            i64::try_from(bytes).map_err(|_| VmError::ArithmeticOverflow)?
        }
        ObjectKind::Table => vm.with_table(object, |table| table.border_len())?,
        ObjectKind::Value
        | ObjectKind::Closure
        | ObjectKind::Builtin
        | ObjectKind::Coroutine
        | ObjectKind::Upvalue
        | ObjectKind::Module => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::UnsupportedUnaryOperation(UnaryOperation::Length),
            ));
        }
        ObjectKind::File => {
            return Err(RuntimeError::new(
                RuntimeErrorKind::UnsupportedUnaryOperation(UnaryOperation::Length),
            ));
        }
    };
    Ok(Value::Integer(length))
}

fn equal(left: Value, right: Value) -> bool {
    match (number_if(left), number_if(right)) {
        (Some(left), Some(right)) => lua_core::equal(left, right),
        _ => left == right,
    }
}

pub(super) fn raw_equal(vm: &Vm, left: Value, right: Value) -> Result<bool, RuntimeError> {
    if let (Value::Object(a), Value::Object(b)) = (left, right) {
        if vm.object_kind(a)? == ObjectKind::ByteString
            && vm.object_kind(b)? == ObjectKind::ByteString
        {
            return Ok(vm.with_byte_string(a, |a| {
                vm.with_byte_string(b, |b| a.as_bytes() == b.as_bytes())
            })??);
        }
    }
    Ok(equal(left, right))
}

pub(super) fn raw_order(
    vm: &Vm,
    op: BinaryOperation,
    left: Value,
    right: Value,
) -> Result<Option<Value>, RuntimeError> {
    let ordering = if let (Some(left), Some(right)) = (number_if(left), number_if(right)) {
        lua_core::compare(left, right)
    } else if let (Value::Object(a), Value::Object(b)) = (left, right) {
        if vm.object_kind(a)? == ObjectKind::ByteString
            && vm.object_kind(b)? == ObjectKind::ByteString
        {
            Some(vm.with_byte_string(a, |a| {
                vm.with_byte_string(b, |b| a.as_bytes().cmp(b.as_bytes()))
            })??)
        } else {
            return Ok(None);
        }
    } else {
        return Ok(None);
    };
    let result = match op {
        BinaryOperation::Less => ordering == Some(Ordering::Less),
        BinaryOperation::LessEqual => matches!(ordering, Some(Ordering::Less | Ordering::Equal)),
        BinaryOperation::Greater => ordering == Some(Ordering::Greater),
        BinaryOperation::GreaterEqual => {
            matches!(ordering, Some(Ordering::Greater | Ordering::Equal))
        }
        _ => return Ok(None),
    };
    Ok(Some(Value::Boolean(result)))
}

pub(super) fn raw_arithmetic(
    op: BinaryOperation,
    left: Value,
    right: Value,
) -> Result<Option<Value>, RuntimeError> {
    if op == BinaryOperation::Concat {
        return Ok(None);
    }
    if number_if(left).is_none() || number_if(right).is_none() {
        return Ok(None);
    }
    match binary(op, left, right) {
        Ok(value) => Ok(Some(value)),
        Err(RuntimeError {
            kind: RuntimeErrorKind::Core(error),
            ..
        }) if matches!(
            error.kind,
            lua_core::CoreErrorKind::NotNumeric | lua_core::CoreErrorKind::NotInteger
        ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
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
