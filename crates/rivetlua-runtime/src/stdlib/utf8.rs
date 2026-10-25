//! UTF-8 函式庫以原始 bytes 和 Lua byte position 運作。

use core::fmt::{self, Write};

use rivetlua_core::{LuaProfile, ObjectRef, Value};

use crate::stdlib::{basic, string};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, OwnedValues, Vm, VmError};

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
    Scalars([Value; 2], usize),
    Values(OwnedValues),
    Bytes(string::Buffer),
    Codes { iterator: ObjectRef, source: Value },
}

enum ErrorMessage {
    Text(&'static str),
    Argument {
        function: &'static str,
        index: usize,
        reason: &'static str,
    },
    TypeArgument {
        function: &'static str,
        index: usize,
        expected: &'static str,
        actual: Option<Value>,
    },
}

enum Stop {
    Aborted,
    Error(RuntimeError),
    Message(RuntimeError, ErrorMessage),
}

struct ErrorText {
    bytes: [u8; 128],
    len: usize,
}

impl ErrorText {
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

impl Write for ErrorText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
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

fn argument_message(function: &'static str, index: usize, reason: &'static str) -> Stop {
    argument_message_for(argument(), function, index, reason)
}

fn argument_message_for(
    error: RuntimeError,
    function: &'static str,
    index: usize,
    reason: &'static str,
) -> Stop {
    Stop::Message(
        error,
        ErrorMessage::Argument {
            function,
            index,
            reason,
        },
    )
}

fn type_argument_message(
    function: &'static str,
    index: usize,
    expected: &'static str,
    actual: Option<Value>,
) -> Stop {
    Stop::Message(
        argument(),
        ErrorMessage::TypeArgument {
            function,
            index,
            expected,
            actual,
        },
    )
}

fn sequence_message(message: &'static str) -> Stop {
    Stop::Message(sequence(), ErrorMessage::Text(message))
}

fn required_argument(
    args: &[Value],
    index: usize,
    function: &'static str,
    expected: &'static str,
) -> Result<Value, Stop> {
    args.get(index)
        .copied()
        .ok_or_else(|| type_argument_message(function, index + 1, expected, None))
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
    function: &'static str,
    index: usize,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<i64, Stop> {
    if let Value::Object(object) = value {
        if vm.object_kind(object)? == ObjectKind::ByteString {
            let length = vm.with_byte_string(object, |bytes| bytes.len())?;
            charge(work, length)?;
        }
    }
    let number = match basic::number(vm, value, None) {
        Ok(number) => number,
        Err(error) if error.kind == RuntimeErrorKind::BasicArgument => {
            return Err(type_argument_message(function, index, "number", Some(value)));
        }
        Err(error) => return Err(error.into()),
    };
    if number == Value::Nil {
        return Err(type_argument_message(function, index, "number", Some(value)));
    }
    basic::lua_integer(number).ok_or_else(|| {
        argument_message(function, index, "number has no integer representation")
    })
}

fn optional_integer(
    vm: &Vm,
    value: Option<Value>,
    default: i64,
    function: &'static str,
    index: usize,
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<i64, Stop> {
    match value {
        None | Some(Value::Nil) => Ok(default),
        Some(value) => integer(vm, value, function, index, work),
    }
}

fn with_bytes<R>(
    vm: &Vm,
    value: Value,
    function: &'static str,
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
        _ => Err(type_argument_message(function, 1, "string", Some(value))),
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
    let mut scalars = [Value::Nil; 2];
    if values.len() > scalars.len() {
        return Err(VmError::LedgerInvariant.into());
    }
    scalars[..values.len()].copy_from_slice(values);
    Ok(Prepared::Scalars(scalars, values.len()))
}

fn len(
    vm: &Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = required_argument(args, 0, "len", "string")?;
    with_bytes(vm, source, "len", |bytes| {
        let first = relative(
            optional_integer(vm, args.get(1).copied(), 1, "len", 2, work)?,
            bytes.len(),
        );
        let last = relative(
            optional_integer(vm, args.get(2).copied(), -1, "len", 3, work)?,
            bytes.len(),
        );
        let lax = args.get(3).is_some_and(|value| value.is_truthy());
        if first < 1 || first > bytes.len() as i128 + 1 {
            return Err(argument_message(
                "len",
                2,
                "initial position out of bounds",
            ));
        }
        if last > bytes.len() as i128 {
            return Err(argument_message("len", 3, "final position out of bounds"));
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
    vm: &mut Vm,
    args: &[Value],
    work: &mut impl FnMut(usize) -> Result<bool, RuntimeError>,
) -> Result<Prepared, Stop> {
    let source = required_argument(args, 0, "codepoint", "string")?;
    let (first, last, lax, upper) = with_bytes(vm, source, "codepoint", |bytes| {
        let first = relative(
            optional_integer(vm, args.get(1).copied(), 1, "codepoint", 2, work)?,
            bytes.len(),
        );
        let last = match args.get(2).copied() {
            None | Some(Value::Nil) => first,
            Some(value) => relative(integer(vm, value, "codepoint", 3, work)?, bytes.len()),
        };
        let lax = args.get(3).is_some_and(|value| value.is_truthy());
        if first < 1 {
            return Err(argument_message("codepoint", 2, "out of bounds"));
        }
        if last > bytes.len() as i128 {
            return Err(argument_message("codepoint", 3, "out of bounds"));
        }
        if first > last {
            return Ok((first, last, lax, 0));
        }
        let upper = last - first + 1;
        if upper > i32::MAX as i128 {
            return Err(Stop::Message(
                argument(),
                ErrorMessage::Text("string slice too long"),
            ));
        }
        let upper = usize::try_from(upper).map_err(|_| VmError::ArithmeticOverflow)?;
        charge(work, upper)?;
        Ok((first, last, lax, upper))
    })?;
    if upper == 0 {
        return Ok(Prepared::Values(OwnedValues::try_copy_from(vm, &[])?));
    }
    let mut values = OwnedValues::try_with_capacity_borrowed(vm, upper, args)?;
    with_bytes(vm, source, "codepoint", |bytes| {
        let mut position = (first - 1) as usize;
        while position < last as usize {
            let Some((next, code)) = decode(bytes, position, !lax, work)? else {
                return Err(sequence_message("invalid UTF-8 code"));
            };
            values.push_scalar(Value::Integer(code as i64))?;
            position = next;
        }
        Ok(())
    })?;
    Ok(Prepared::Values(values))
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
    for (index, value) in args.iter().enumerate() {
        let code = integer(vm, *value, "char", index + 1, work)?;
        if !(0..=MAX_UTF as i64).contains(&code) {
            return Err(argument_message("char", index + 1, "value out of range"));
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
    let source = required_argument(args, 0, "offset", "string")?;
    with_bytes(vm, source, "offset", |bytes| {
        let mut n = integer(
            vm,
            required_argument(args, 1, "offset", "number")?,
            "offset",
            2,
            work,
        )?;
        let first = match args.get(2).copied() {
            None | Some(Value::Nil) => {
                if n >= 0 {
                    1
                } else {
                    bytes.len() as i128 + 1
                }
            }
            Some(value) => relative(integer(vm, value, "offset", 3, work)?, bytes.len()),
        };
        if first < 1 || first > bytes.len() as i128 + 1 {
            return Err(argument_message("offset", 3, "position out of bounds"));
        }
        let mut position = (first - 1) as usize;
        if n == 0 {
            while position > 0 && is_cont(byte_at(bytes, position, work)?) {
                position -= 1;
            }
        } else {
            if is_cont(byte_at(bytes, position, work)?) {
                return Err(sequence_message(
                    "initial position is a continuation byte",
                ));
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
                return Err(sequence_message(
                    "initial position is a continuation byte",
                ));
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
    let source = required_argument(args, 0, "codes", "string")?;
    with_bytes(vm, source, "codes", |bytes| {
        if !bytes.is_empty() && is_cont(byte_at(bytes, 0, work)?) {
            return Err(argument_message_for(
                sequence(),
                "codes",
                1,
                "invalid UTF-8 code",
            ));
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
    let source = required_argument(args, 0, "for iterator", "string")?;
    with_bytes(vm, source, "for iterator", |bytes| {
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
            return output(vm, &[], work);
        }
        let Some((next, code)) = decode(bytes, position as usize, strict, work)? else {
            return Err(sequence_message("invalid UTF-8 code"));
        };
        if next < bytes.len() && is_cont(byte_at(bytes, next, work)?) {
            return Err(sequence_message("invalid UTF-8 code"));
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
    vm: &mut Vm,
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
        Err(Stop::Message(mut error, message)) => {
            error.value = match message {
                ErrorMessage::Text(message) => {
                    let mut text = ErrorText::new();
                    text.write_str(message)
                        .map_err(|_| VmError::ArithmeticOverflow)?;
                    Value::Object(vm.allocate_byte_string(text.as_bytes())?)
                }
                ErrorMessage::Argument {
                    function,
                    index,
                    reason,
                } => basic::argument_error(vm, function, index, reason)?.value,
                ErrorMessage::TypeArgument {
                    function,
                    index,
                    expected,
                    actual,
                } => basic::type_argument_error(vm, function, index, expected, actual)?.value,
            };
            Err(error)
        }
    }
}


