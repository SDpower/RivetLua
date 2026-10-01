//! UTF-8 函式庫以原始 bytes 和 Lua byte position 運作。

use rivetlua_core::{LuaProfile, ObjectRef, Value};

use crate::alloc::{FailPoint, Reservation, reserve_vec};
use crate::stdlib::{basic, string};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, Vm, VmError};

pub(crate) const CHAR_PATTERN: &[u8] = b"[\0-\x7f\xc2-\xfd][\x80-\xbf]*";
const MAX_UTF: u32 = 0x7fff_ffff;
const MAX_UNICODE: u32 = 0x10ffff;
const LIMITS: [u32; 6] = [u32::MAX, 0x80, 0x800, 0x10000, 0x200000, 0x4000000];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Utf8Builtin {
    Len,
    Codepoint,
    Char,
    Codes { strict: ObjectRef, lax: ObjectRef },
    Offset,
    Iterator { strict: bool },
}

pub(crate) enum Prepared {
    Values(Vec<Value>, Option<Reservation>),
    Bytes(string::Buffer),
    Codes { iterator: ObjectRef, source: Value },
}

enum Stop {
    Aborted,
    Error(RuntimeError),
}

impl From<RuntimeError> for Stop {
    fn from(error: RuntimeError) -> Self {
        Self::Error(error)
    }
}

impl From<VmError> for Stop {
    fn from(error: VmError) -> Self {
        Self::Error(error.into())
    }
}

fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::Utf8Argument)
}

fn sequence() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::Utf8Sequence)
}

fn arg(args: &[Value], index: usize) -> Result<Value, Stop> {
    args.get(index)
        .copied()
        .ok_or_else(|| Stop::Error(argument()))
}

fn charge(
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
    units: usize,
) -> Result<(), Stop> {
    if work(units)? {
        Ok(())
    } else {
        Err(Stop::Aborted)
    }
}

fn integer(
    vm: &Vm,
    value: Value,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<i64, Stop> {
    if let Value::Object(object) = value {
        if vm.object_kind(object)? == ObjectKind::ByteString {
            let length = vm.with_byte_string(object, |bytes| bytes.len())?;
            charge(work, length)?;
        }
    }
    let number = basic::number(vm, value, None).map_err(|error| {
        if error.kind == RuntimeErrorKind::BasicArgument {
            argument()
        } else {
            error
        }
    })?;
    basic::lua_integer(number).ok_or_else(|| Stop::Error(argument()))
}

fn optional_integer(
    vm: &Vm,
    value: Option<Value>,
    default: i64,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<i64, Stop> {
    match value {
        None | Some(Value::Nil) => Ok(default),
        Some(value) => integer(vm, value, work),
    }
}

fn with_bytes<R>(
    vm: &Vm,
    value: Value,
    f: impl FnOnce(&[u8]) -> Result<R, Stop>,
) -> Result<R, Stop> {
    match value {
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            vm.with_byte_string(object, |bytes| f(bytes.as_bytes()))?
        }
        number @ (Value::Integer(_) | Value::Float(_)) => {
            let (bytes, length) = crate::vm::basic_number_bytes(number, vm.language_profile())?;
            f(&bytes[..length])
        }
        _ => Err(Stop::Error(argument())),
    }
}

fn relative(position: i64, length: usize) -> i128 {
    if position >= 0 {
        position as i128
    } else if position.unsigned_abs() as u128 > length as u128 {
        0
    } else {
        length as i128 + position as i128 + 1
    }
}

fn byte_at(
    bytes: &[u8],
    index: usize,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<u8, Stop> {
    charge(work, 1)?;
    Ok(bytes.get(index).copied().unwrap_or(0))
}

fn is_cont(byte: u8) -> bool {
    byte & 0xc0 == 0x80
}

fn decode(
    bytes: &[u8],
    index: usize,
    strict: bool,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Option<(usize, u32)>, Stop> {
    let lead = byte_at(bytes, index, work)?;
    let (continuations, mut code) = if lead < 0x80 {
        (0, lead as u32)
    } else if lead >= 0xfe {
        return Ok(None);
    } else {
        let count = lead.leading_ones() as usize;
        if !(2..=6).contains(&count) {
            return Ok(None);
        }
        let continuation_count = count - 1;
        let first_bits = 7 - count;
        (
            continuation_count,
            (lead & ((1_u8 << first_bits) - 1)) as u32,
        )
    };
    for offset in 1..=continuations {
        let Some(next) = index
            .checked_add(offset)
            .and_then(|index| bytes.get(index).copied())
        else {
            return Ok(None);
        };
        charge(work, 1)?;
        if !is_cont(next) {
            return Ok(None);
        }
        code = (code << 6) | (next & 0x3f) as u32;
    }
    if (continuations != 0 && code < LIMITS[continuations])
        || code > MAX_UTF
        || (strict && (code > MAX_UNICODE || (0xd800..=0xdfff).contains(&code)))
    {
        return Ok(None);
    }
    Ok(index.checked_add(continuations + 1).map(|end| (end, code)))
}

fn output(
    vm: &Vm,
    values: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    charge(work, values.len())?;
    let (values, ticket) = string::values(vm, values)?;
    Ok(Prepared::Values(values, ticket))
}

fn len(
    vm: &Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = arg(args, 0)?;
    with_bytes(vm, source, |bytes| {
        let first = relative(
            optional_integer(vm, args.get(1).copied(), 1, work)?,
            bytes.len(),
        );
        let last = relative(
            optional_integer(vm, args.get(2).copied(), -1, work)?,
            bytes.len(),
        );
        let lax = args.get(3).is_some_and(|value| value.is_truthy());
        if first < 1 || first > bytes.len() as i128 + 1 || last > bytes.len() as i128 {
            return Err(argument().into());
        }
        let mut position = (first - 1) as usize;
        let mut count = 0_i64;
        while position as i128 <= last - 1 {
            match decode(bytes, position, !lax, work)? {
                Some((next, _)) => {
                    position = next;
                    count = count.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
                }
                None => {
                    return output(vm, &[Value::Nil, Value::Integer(position as i64 + 1)], work);
                }
            }
        }
        output(vm, &[Value::Integer(count)], work)
    })
}

fn codepoint(
    vm: &Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = arg(args, 0)?;
    with_bytes(vm, source, |bytes| {
        let first = relative(
            optional_integer(vm, args.get(1).copied(), 1, work)?,
            bytes.len(),
        );
        let last = match args.get(2).copied() {
            None | Some(Value::Nil) => first,
            Some(value) => relative(integer(vm, value, work)?, bytes.len()),
        };
        let lax = args.get(3).is_some_and(|value| value.is_truthy());
        if first < 1 || last > bytes.len() as i128 {
            return Err(argument().into());
        }
        if first > last {
            return Ok(Prepared::Values(Vec::new(), None));
        }
        let upper = last - first + 1;
        if upper > i32::MAX as i128 {
            return Err(argument().into());
        }
        let upper = usize::try_from(upper).map_err(|_| VmError::ArithmeticOverflow)?;
        charge(work, upper)?;
        let mut values = Vec::new();
        let ticket = reserve_vec(
            vm.allocation_ledger(),
            &mut values,
            upper,
            FailPoint::ReturnReserve,
        )?;
        let mut position = (first - 1) as usize;
        while position < last as usize {
            let Some((next, code)) = decode(bytes, position, !lax, work)? else {
                return Err(sequence().into());
            };
            values.push(Value::Integer(code as i64));
            position = next;
        }
        Ok(Prepared::Values(values, Some(ticket)))
    })
}

fn encode(code: u32, bytes: &mut [u8; 6]) -> usize {
    let length = match code {
        0..=0x7f => 1,
        0x80..=0x7ff => 2,
        0x800..=0xffff => 3,
        0x10000..=0x1fffff => 4,
        0x200000..=0x3ffffff => 5,
        _ => 6,
    };
    let mut value = code;
    for index in (1..length).rev() {
        bytes[index] = 0x80 | (value as u8 & 0x3f);
        value >>= 6;
    }
    bytes[0] = if length == 1 {
        value as u8
    } else {
        ((!0_u8) << (8 - length)) | value as u8
    };
    length
}

fn char_bytes(
    vm: &Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let maximum = args
        .len()
        .checked_mul(6)
        .ok_or(VmError::ArithmeticOverflow)?;
    if maximum > string::max_size(vm.language_profile()) {
        return Err(argument().into());
    }
    let mut buffer = string::Buffer::empty(vm);
    for value in args {
        let code = integer(vm, *value, work)?;
        if !(0..=MAX_UTF as i64).contains(&code) {
            return Err(argument().into());
        }
        let mut bytes = [0_u8; 6];
        let length = encode(code as u32, &mut bytes);
        charge(work, length)?;
        buffer.append(&bytes[..length])?;
    }
    charge(work, 1)?;
    Ok(Prepared::Bytes(buffer))
}

fn offset(
    vm: &Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = arg(args, 0)?;
    with_bytes(vm, source, |bytes| {
        let mut n = integer(vm, arg(args, 1)?, work)?;
        let first = match args.get(2).copied() {
            None | Some(Value::Nil) => {
                if n >= 0 {
                    1
                } else {
                    bytes.len() as i128 + 1
                }
            }
            Some(value) => relative(integer(vm, value, work)?, bytes.len()),
        };
        if first < 1 || first > bytes.len() as i128 + 1 {
            return Err(argument().into());
        }
        let mut position = (first - 1) as usize;
        if n == 0 {
            while position > 0 && is_cont(byte_at(bytes, position, work)?) {
                position -= 1;
            }
        } else {
            if is_cont(byte_at(bytes, position, work)?) {
                return Err(sequence().into());
            }
            if n < 0 {
                while n < 0 && position > 0 {
                    position -= 1;
                    while position > 0 && is_cont(byte_at(bytes, position, work)?) {
                        position -= 1;
                    }
                    n += 1;
                }
            } else {
                n -= 1;
                while n > 0 && position < bytes.len() {
                    position += 1;
                    while is_cont(byte_at(bytes, position, work)?) {
                        position += 1;
                    }
                    n -= 1;
                }
            }
        }
        if n != 0 {
            return output(vm, &[Value::Nil], work);
        }
        let start = Value::Integer(position as i64 + 1);
        if vm.language_profile() == LuaProfile::Lua54 {
            return output(vm, &[start], work);
        }
        let mut end = position;
        let current = byte_at(bytes, position, work)?;
        if current & 0x80 != 0 {
            if is_cont(current) {
                return Err(sequence().into());
            }
            while is_cont(byte_at(bytes, end + 1, work)?) {
                end += 1;
            }
        }
        output(vm, &[start, Value::Integer(end as i64 + 1)], work)
    })
}

fn codes(
    vm: &Vm,
    args: &[Value],
    strict: ObjectRef,
    lax: ObjectRef,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = arg(args, 0)?;
    with_bytes(vm, source, |bytes| {
        if !bytes.is_empty() && is_cont(byte_at(bytes, 0, work)?) {
            return Err(sequence().into());
        }
        if matches!(source, Value::Integer(_) | Value::Float(_)) {
            charge(work, bytes.len())?;
        }
        charge(work, 3)?;
        Ok(Prepared::Codes {
            iterator: if args.get(1).is_some_and(|value| value.is_truthy()) {
                lax
            } else {
                strict
            },
            source,
        })
    })
}

fn iterator(
    vm: &Vm,
    args: &[Value],
    strict: bool,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = arg(args, 0)?;
    with_bytes(vm, source, |bytes| {
        let control = match args.get(1).copied() {
            None => 0,
            Some(value) => {
                if let Value::Object(object) = value {
                    if vm.object_kind(object)? == ObjectKind::ByteString {
                        charge(work, vm.with_byte_string(object, |bytes| bytes.len())?)?;
                    }
                }
                match basic::number(vm, value, None) {
                    Ok(number) => basic::lua_integer(number).unwrap_or(0),
                    Err(error) if error.kind == RuntimeErrorKind::BasicArgument => 0,
                    Err(error) => return Err(error.into()),
                }
            }
        } as u64;
        let mut position = control;
        if position < bytes.len() as u64 {
            while is_cont(byte_at(bytes, position as usize, work)?) {
                position += 1;
            }
        }
        if position >= bytes.len() as u64 {
            return Ok(Prepared::Values(Vec::new(), None));
        }
        let Some((next, code)) = decode(bytes, position as usize, strict, work)? else {
            return Err(sequence().into());
        };
        if next < bytes.len() && is_cont(byte_at(bytes, next, work)?) {
            return Err(sequence().into());
        }
        output(
            vm,
            &[
                Value::Integer(position as i64 + 1),
                Value::Integer(code as i64),
            ],
            work,
        )
    })
}

pub(crate) fn execute(
    vm: &Vm,
    kind: Utf8Builtin,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Option<Prepared>, RuntimeError> {
    let result = match kind {
        Utf8Builtin::Len => len(vm, args, work),
        Utf8Builtin::Codepoint => codepoint(vm, args, work),
        Utf8Builtin::Char => char_bytes(vm, args, work),
        Utf8Builtin::Codes { strict, lax } => codes(vm, args, strict, lax, work),
        Utf8Builtin::Offset => offset(vm, args, work),
        Utf8Builtin::Iterator { strict } => iterator(vm, args, strict, work),
    };
    match result {
        Ok(prepared) => Ok(Some(prepared)),
        Err(Stop::Aborted) => Ok(None),
        Err(Stop::Error(error)) => Err(error),
    }
}
