#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BasicBuiltin {
    Assert,
    Select,
    Type,
    ToString,
    ToNumber,
    Next,
    Pairs,
    IPairs,
    IPairsAux,
    GetMetatable,
    SetMetatable,
    RawGet,
    RawSet,
    RawEqual,
    RawLen,
    Print,
}

struct Text {
    bytes: [u8; 128],
    len: usize,
}

impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 128],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Write for Text {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(core::fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(core::fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}

fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::BasicArgument)
}

fn arg(args: &[Value], index: usize) -> Result<Value, RuntimeError> {
    args.get(index).copied().ok_or_else(argument)
}

pub(crate) fn lua_integer(value: Value) -> Option<i64> {
    match value {
        Value::Integer(value) => Some(value),
        Value::Float(value)
            if value.is_finite()
                && value.fract() == 0.0
                && value >= i64::MIN as f64
                && value < 9_223_372_036_854_775_808.0 =>
        {
            Some(value as i64)
        }
        _ => None,
    }
}

fn table_arg(vm: &Vm, args: &[Value], index: usize) -> Result<ObjectRef, RuntimeError> {
    let Value::Object(table) = arg(args, index)? else {
        return Err(argument());
    };
    if vm.object_kind(table)? != ObjectKind::Table {
        return Err(argument());
    }
    Ok(table)
}

fn result(vm: &Vm, values: &[Value]) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
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

fn text_for(vm: &Vm, value: Value) -> Result<Option<Text>, RuntimeError> {
    let mut text = Text::new();
    match value {
        Value::Nil => text
            .write_str("nil")
            .map_err(|_| VmError::ArithmeticOverflow)?,
        Value::Boolean(value) => text
            .write_str(if value { "true" } else { "false" })
            .map_err(|_| VmError::ArithmeticOverflow)?,
        Value::Integer(_) | Value::Float(_) => {
            let (bytes, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            text.bytes[..len].copy_from_slice(&bytes[..len]);
            text.len = len;
        }
        Value::Object(object) => {
            let kind = vm.object_kind(object)?;
            if kind == ObjectKind::ByteString {
                return Ok(None);
            }
            let name = match kind {
                ObjectKind::Table => "table",
                ObjectKind::Closure | ObjectKind::Builtin => "function",
                ObjectKind::Coroutine => "thread",
                ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => "userdata",
                ObjectKind::ByteString => unreachable!(),
                ObjectKind::File => {
                    if vm.with_file(object, |file| file.lease.is_some())? {
                        "file"
                    } else {
                        "closed file"
                    }
                }
            };
            if kind == ObjectKind::File {
                write!(text, "{name}").map_err(|_| VmError::ArithmeticOverflow)?;
                return Ok(Some(text));
            }
            write!(text, "{name}: {:?}", object.identity())
                .map_err(|_| VmError::ArithmeticOverflow)?;
        }
    }
    Ok(Some(text))
}

pub(crate) struct PrintBuffer {
    bytes: Vec<u8>,
    ledger: AllocationLedger,
    charge: usize,
}

impl PrintBuffer {
    pub(crate) fn new(vm: &Vm) -> Self {
        Self {
            bytes: Vec::new(),
            ledger: vm.allocation_ledger().clone(),
            charge: 0,
        }
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let next = self
            .charge
            .checked_add(bytes.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        let ticket = reserve_vec(
            &self.ledger,
            &mut self.bytes,
            bytes.len(),
            FailPoint::WorkReserve,
        )?;
        ticket.commit()?;
        self.bytes.extend_from_slice(bytes);
        self.charge = next;
        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for PrintBuffer {
    fn drop(&mut self) {
        self.ledger.refund_on_drop(self.charge);
    }
}

pub(crate) fn is_string(vm: &Vm, value: Value) -> Result<bool, RuntimeError> {
    match value {
        Value::Integer(_) | Value::Float(_) => Ok(true),
        Value::Object(object) => Ok(vm.object_kind(object)? == ObjectKind::ByteString),
        _ => Ok(false),
    }
}

pub(crate) fn print_value_len(
    vm: &Vm,
    value: Value,
    separator: bool,
) -> Result<usize, RuntimeError> {
    let len = match text_for(vm, value)? {
        Some(text) => text.as_bytes().len(),
        None => {
            let Value::Object(object) = value else {
                unreachable!()
            };
            vm.with_byte_string(object, |string| string.len())?
        }
    };
    len.checked_add(usize::from(separator))
        .ok_or(VmError::ArithmeticOverflow.into())
}

pub(crate) fn append_print_value(
    vm: &Vm,
    buffer: &mut PrintBuffer,
    value: Value,
    separator: bool,
) -> Result<(), RuntimeError> {
    if separator {
        buffer.append(b"\t")?;
    }
    match text_for(vm, value)? {
        Some(text) => buffer.append(text.as_bytes()),
        None => {
            let Value::Object(object) = value else {
                unreachable!()
            };
            vm.with_byte_string(object, |string| buffer.append(string.as_bytes()))??;
            Ok(())
        }
    }
}

fn value_to_string(vm: &mut Vm, value: Value) -> Result<Value, RuntimeError> {
    if let Value::Object(object) = value {
        if vm.object_kind(object)? == ObjectKind::ByteString {
            return Ok(value);
        }
    }
    let text = text_for(vm, value)?.ok_or_else(argument)?;
    Ok(Value::Object(vm.allocate_byte_string(text.as_bytes())?))
}

fn type_name(vm: &Vm, value: Value) -> Result<&'static [u8], RuntimeError> {
    Ok(match value {
        Value::Nil => b"nil",
        Value::Boolean(_) => b"boolean",
        Value::Integer(_) | Value::Float(_) => b"number",
        Value::Object(object) => match vm.object_kind(object)? {
            ObjectKind::ByteString => b"string",
            ObjectKind::Table => b"table",
            ObjectKind::Closure | ObjectKind::Builtin => b"function",
            ObjectKind::Coroutine => b"thread",
            ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => b"userdata",
            ObjectKind::File => b"userdata",
        },
    })
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn lua_hex_number(text: &str) -> Option<Value> {
    let mut bytes = text.as_bytes();
    let negative = bytes.first() == Some(&b'-');
    if matches!(bytes.first(), Some(b'-' | b'+')) {
        bytes = &bytes[1..];
    }
    if !bytes.starts_with(b"0x") && !bytes.starts_with(b"0X") {
        return None;
    }
    bytes = &bytes[2..];
    let mut integer = 0_u64;
    let mut number = 0_f64;
    let mut digits = 0_usize;
    let mut fraction = 1_f64;
    let mut dot = false;
    while let Some((&byte, rest)) = bytes.split_first() {
        if byte == b'.' && !dot {
            dot = true;
            bytes = rest;
            continue;
        }
        let Some(digit) = hex_digit(byte) else {
            break;
        };
        digits += 1;
        integer = integer.wrapping_mul(16).wrapping_add(u64::from(digit));
        if dot {
            fraction /= 16.0;
            number += f64::from(digit) * fraction;
        } else {
            number = number * 16.0 + f64::from(digit);
        }
        bytes = rest;
    }
    if digits == 0 {
        return None;
    }
    if !dot && bytes.is_empty() && digits <= 16 {
        return Some(Value::Integer(if negative {
            (0_u64.wrapping_sub(integer)) as i64
        } else {
            integer as i64
        }));
    }
    if matches!(bytes.first(), Some(b'p' | b'P')) {
        let exponent = core::str::from_utf8(&bytes[1..])
            .ok()?
            .parse::<i32>()
            .ok()?;
        number *= 2_f64.powi(exponent);
    } else if !bytes.is_empty() {
        return None;
    }
    Some(Value::Float(if negative { -number } else { number }))
}

pub(crate) fn number(vm: &Vm, value: Value, base: Option<Value>) -> Result<Value, RuntimeError> {
    if base.is_none() || base == Some(Value::Nil) {
        if matches!(value, Value::Integer(_) | Value::Float(_)) {
            return Ok(value);
        }
    }
    let Value::Object(object) = value else {
        return if base.is_none() || base == Some(Value::Nil) {
            Ok(Value::Nil)
        } else {
            Err(argument())
        };
    };
    if vm.object_kind(object)? != ObjectKind::ByteString {
        return if base.is_none() || base == Some(Value::Nil) {
            Ok(Value::Nil)
        } else {
            Err(argument())
        };
    }
    vm.with_byte_string(object, |string| {
        let bytes = string.as_bytes();
        if let Some(base) = base.filter(|base| *base != Value::Nil) {
            let Some(base) = lua_integer(base) else {
                return Err(argument());
            };
            if !(2..=36).contains(&base) {
                return Err(argument());
            }
            let mut input = bytes;
            while input.first().is_some_and(u8::is_ascii_whitespace) {
                input = &input[1..];
            }
            let negative = matches!(input.first(), Some(b'-'));
            if matches!(input.first(), Some(b'-' | b'+')) {
                input = &input[1..];
            }
            let mut n = 0_u64;
            let mut digits = 0;
            while let Some((&first, rest)) = input.split_first() {
                let digit = if first.is_ascii_digit() {
                    first - b'0'
                } else if first.is_ascii_alphabetic() {
                    first.to_ascii_uppercase() - b'A' + 10
                } else {
                    break;
                };
                if u64::from(digit) >= base as u64 {
                    return Ok(Value::Nil);
                }
                n = n.wrapping_mul(base as u64).wrapping_add(u64::from(digit));
                digits += 1;
                input = rest;
            }
            if digits == 0 || !input.iter().all(u8::is_ascii_whitespace) {
                return Ok(Value::Nil);
            }
            return Ok(Value::Integer(if negative {
                (0_u64.wrapping_sub(n)) as i64
            } else {
                n as i64
            }));
        }
        let Ok(text) = core::str::from_utf8(bytes) else {
            return Ok(Value::Nil);
        };
        let text = text.trim_matches(|ch: char| ch.is_ascii_whitespace());
        if text
            .as_bytes()
            .get(..2)
            .is_some_and(|prefix| prefix == b"0x" || prefix == b"0X")
            || text
                .as_bytes()
                .get(1..3)
                .is_some_and(|prefix| prefix == b"0x" || prefix == b"0X")
        {
            return Ok(lua_hex_number(text).unwrap_or(Value::Nil));
        }
        if let Ok(value) = text.parse::<i64>() {
            return Ok(Value::Integer(value));
        }
        let word = text.trim_start_matches(['-', '+']);
        if word.eq_ignore_ascii_case("nan")
            || word.eq_ignore_ascii_case("inf")
            || word.eq_ignore_ascii_case("infinity")
        {
            return Ok(Value::Nil);
        }
        if let Ok(value) = text.parse::<f64>() {
            return Ok(Value::Float(value));
        }
        Ok(Value::Nil)
    })?
}

fn next_pair(
    vm: &Vm,
    table: ObjectRef,
    previous: Value,
) -> Result<Option<(Value, Value)>, RuntimeError> {
    let previous_key = if previous == Value::Nil {
        None
    } else {
        vm.canonical_key(previous)?
    };
    if previous != Value::Nil && previous_key.is_none() {
        return Err(RuntimeError::new(RuntimeErrorKind::InvalidNextKey));
    }
    let mut seen = previous_key.is_none();
    let mut found = false;
    let mut pair = None;
    vm.with_table(table, |stored| {
        stored.for_each_raw(|key, value| {
            if pair.is_some() {
                return Ok(());
            }
            if seen {
                pair = Some((key, value));
                return Ok(());
            }
            if vm.canonical_key(key)? == previous_key {
                seen = true;
                found = true;
            }
            Ok(())
        })
    })??;
    if previous_key.is_some() && !found {
        return Err(RuntimeError::new(RuntimeErrorKind::InvalidNextKey));
    }
    Ok(pair)
}

fn protected_metatable(vm: &mut Vm, table: ObjectRef) -> Result<Option<Value>, RuntimeError> {
    let Some(metatable) = vm.get_metatable(table)? else {
        return Ok(None);
    };
    protected_metatable_value(vm, metatable).map(Some)
}

fn protected_metatable_value(vm: &mut Vm, metatable: ObjectRef) -> Result<Value, RuntimeError> {
    let value = metatable_field(vm, metatable)?;
    Ok(if value == Value::Nil {
        Value::Object(metatable)
    } else {
        value
    })
}

fn metatable_field(vm: &mut Vm, metatable: ObjectRef) -> Result<Value, RuntimeError> {
    let key = vm.allocate_byte_string(b"__metatable")?;
    let value = vm.raw_get(metatable, Value::Object(key));
    vm.reclaim(key)?;
    Ok(value?)
}

pub(crate) fn print(vm: &mut Vm, args: &[Value]) -> Result<(), RuntimeError> {
    if !vm.host_output_allowed() {
        return Err(RuntimeError::new(RuntimeErrorKind::HostPolicyOutput));
    }
    let mut buffer = PrintBuffer::new(vm);
    for (index, value) in args.iter().enumerate() {
        append_print_value(vm, &mut buffer, *value, index != 0)?;
    }
    buffer.append(b"\n")?;
    match vm.write_host_output(buffer.as_bytes()) {
        Ok(()) => Ok(()),
        Err(HostServiceError::PolicyDenied) => {
            Err(RuntimeError::new(RuntimeErrorKind::HostPolicyOutput))
        }
        Err(HostServiceError::OutputFailed) => {
            Err(RuntimeError::new(RuntimeErrorKind::HostOutputFailed))
        }
    }
}

pub(crate) fn execute(
    vm: &mut Vm,
    builtin: BasicBuiltin,
    args: &[Value],
    pc: usize,
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    match builtin {
        BasicBuiltin::Assert => {
            let condition = arg(args, 0)?;
            if !condition.is_truthy() {
                let message = match args.get(1).copied() {
                    Some(value) if value != Value::Nil => value,
                    _ => Value::Object(vm.allocate_byte_string(b"assertion failed!")?),
                };
                return Err(explicit_error(message, pc));
            }
            result(vm, args)
        }
        BasicBuiltin::Select => {
            let index = arg(args, 0)?;
            if let Value::Object(object) = index {
                if vm.object_kind(object)? == ObjectKind::ByteString
                    && vm.with_byte_string(object, |s| s.as_bytes().first() == Some(&b'#'))?
                {
                    return result(
                        vm,
                        &[Value::Integer(
                            i64::try_from(args.len() - 1)
                                .map_err(|_| VmError::ArithmeticOverflow)?,
                        )],
                    );
                }
            }
            let Some(mut index) = lua_integer(index) else {
                return Err(argument());
            };
            let total = i64::try_from(args.len()).map_err(|_| VmError::ArithmeticOverflow)?;
            if index < 0 {
                index = total
                    .checked_add(index)
                    .ok_or(VmError::ArithmeticOverflow)?;
            } else if index > total {
                index = total;
            }
            if index < 1 {
                return Err(argument());
            }
            result(
                vm,
                &args[usize::try_from(index).map_err(|_| VmError::ArithmeticOverflow)?..],
            )
        }
        BasicBuiltin::Type => {
            let value = arg(args, 0)?;
            let name = type_name(vm, value)?;
            let string = vm.allocate_byte_string(name)?;
            result(vm, &[Value::Object(string)])
        }
        BasicBuiltin::ToString => {
            let value = arg(args, 0)?;
            let string = value_to_string(vm, value)?;
            result(vm, &[string])
        }
        BasicBuiltin::ToNumber => result(vm, &[number(vm, arg(args, 0)?, args.get(1).copied())?]),
        BasicBuiltin::Next => {
            let table = table_arg(vm, args, 0)?;
            match next_pair(vm, table, args.get(1).copied().unwrap_or(Value::Nil))? {
                Some((key, value)) => result(vm, &[key, value]),
                None => result(vm, &[Value::Nil]),
            }
        }
        BasicBuiltin::Pairs => {
            let table = table_arg(vm, args, 0)?;
            let iterator = vm.allocate_basic_builtin(BasicBuiltin::Next)?;
            if vm.language_profile() == rivetlua_core::LuaProfile::Lua54 {
                result(
                    vm,
                    &[Value::Object(iterator), Value::Object(table), Value::Nil],
                )
            } else {
                result(
                    vm,
                    &[
                        Value::Object(iterator),
                        Value::Object(table),
                        Value::Nil,
                        Value::Nil,
                    ],
                )
            }
        }
        BasicBuiltin::IPairs => {
            let state = arg(args, 0)?;
            let iterator = vm.allocate_basic_builtin(BasicBuiltin::IPairsAux)?;
            result(vm, &[Value::Object(iterator), state, Value::Integer(0)])
        }
        BasicBuiltin::IPairsAux => {
            let table = table_arg(vm, args, 0)?;
            let Some(index) = lua_integer(arg(args, 1)?) else {
                return Err(argument());
            };
            let next = index.wrapping_add(1);
            let value = vm.raw_get(table, Value::Integer(next))?;
            if value == Value::Nil {
                result(vm, &[Value::Nil])
            } else {
                result(vm, &[Value::Integer(next), value])
            }
        }
        BasicBuiltin::GetMetatable => {
            let value = arg(args, 0)?;
            let Value::Object(object) = value else {
                return result(vm, &[Value::Nil]);
            };
            let value = match vm.object_kind(object)? {
                ObjectKind::Table => protected_metatable(vm, object)?.unwrap_or(Value::Nil),
                ObjectKind::ByteString => match vm.string_metatable() {
                    Some(metatable) => protected_metatable_value(vm, metatable)?,
                    None => Value::Nil,
                },
                _ => Value::Nil,
            };
            result(vm, &[value])
        }
        BasicBuiltin::SetMetatable => {
            let table = table_arg(vm, args, 0)?;
            let metatable = match arg(args, 1)? {
                Value::Nil => None,
                Value::Object(object) if vm.object_kind(object)? == ObjectKind::Table => {
                    Some(object)
                }
                _ => return Err(argument()),
            };
            if let Some(existing) = vm.get_metatable(table)? {
                if metatable_field(vm, existing)? != Value::Nil {
                    return Err(argument());
                }
            }
            vm.set_metatable(table, metatable)?;
            result(vm, &[Value::Object(table)])
        }
        BasicBuiltin::RawGet => {
            let table = table_arg(vm, args, 0)?;
            let value = vm.raw_get(table, arg(args, 1)?)?;
            result(vm, &[value])
        }
        BasicBuiltin::RawSet => {
            let table = table_arg(vm, args, 0)?;
            vm.raw_set(table, arg(args, 1)?, arg(args, 2)?)?;
            result(vm, &[Value::Object(table)])
        }
        BasicBuiltin::RawEqual => {
            let equal = crate::vm::basic_raw_equal(vm, arg(args, 0)?, arg(args, 1)?)?;
            result(vm, &[Value::Boolean(equal)])
        }
        BasicBuiltin::RawLen => {
            let Value::Object(object) = arg(args, 0)? else {
                return Err(argument());
            };
            let length = match vm.object_kind(object)? {
                ObjectKind::ByteString => {
                    i64::try_from(vm.with_byte_string(object, |string| string.len())?)
                        .map_err(|_| VmError::ArithmeticOverflow)?
                }
                ObjectKind::Table => vm.with_table(object, |table| table.border_len())?,
                _ => return Err(argument()),
            };
            result(vm, &[Value::Integer(length)])
        }
        BasicBuiltin::Print => {
            print(vm, args)?;
            result(vm, &[])
        }
    }
}
use core::fmt::Write;

use rivetlua_core::{ObjectRef, Value};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, reserve_vec};
use crate::errors::explicit_error;
use crate::host::HostServiceError;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, Vm, VmError};

#[cfg(test)]
mod p13_a_tests {
    use super::*;

    #[test]
    fn p13_a_print_buffer_failure_rolls_back_host_ledger_and_retries() {
        let mut vm = Vm::new().unwrap();
        let baseline = vm.ledger_snapshot().host_allocation_bytes;
        let mut buffer = PrintBuffer::new(&vm);
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(matches!(
            buffer.append(b"hello"),
            Err(RuntimeError {
                kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::WorkReserve)),
                ..
            })
        ));
        assert!(buffer.as_bytes().is_empty());
        assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline);
        buffer.append(b"hello").unwrap();
        assert_eq!(buffer.as_bytes(), b"hello");
        drop(buffer);
        assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
