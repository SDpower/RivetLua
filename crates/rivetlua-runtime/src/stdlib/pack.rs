//! Lua string pack 格式、大小前置檢查與 endian 編解碼。

use crate::rust_alloc::vec::Vec;

use core::mem::size_of;
use rivetlua_core::{LuaProfile, Value};

use crate::stdlib::basic;
use crate::stdlib::string::{self, Buffer, StringBuiltin};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, OwnedValues, Vm, VmError};

fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringArgument)
}

#[derive(Clone, Copy)]
enum Stop {
    Runtime(RuntimeError),
    Argument {
        index: usize,
        reason: &'static str,
    },
    Type {
        index: usize,
        expected: &'static str,
        actual: Option<Value>,
    },
    Direct(&'static [u8]),
    InvalidOption(u8),
    SizeLimit(usize),
    IntegerFit(usize),
}

impl From<RuntimeError> for Stop {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

impl From<VmError> for Stop {
    fn from(error: VmError) -> Self {
        Self::Runtime(error.into())
    }
}

fn error_text(vm: &mut Vm, text: &[u8]) -> Result<RuntimeError, RuntimeError> {
    let mut error = argument();
    error.value = Value::Object(vm.allocate_byte_string(text)?);
    Ok(error)
}

fn append_usize(buffer: &mut basic::PrintBuffer, mut value: usize) -> Result<(), RuntimeError> {
    let mut digits = [0_u8; 40];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buffer.append(&digits[start..])
}

fn materialize(
    vm: &mut Vm,
    function: &'static str,
    stop: Stop,
) -> Result<RuntimeError, RuntimeError> {
    let error = match stop {
        Stop::Runtime(error) => return Ok(error),
        Stop::Argument { index, reason } => basic::argument_error(vm, function, index, reason)?,
        Stop::Type { index, expected, actual } => {
            basic::type_argument_error(vm, function, index, expected, actual)?
        }
        Stop::Direct(text) => return error_text(vm, text),
        Stop::InvalidOption(code) => {
            let mut text = basic::PrintBuffer::new(vm);
            text.append(b"invalid format option '")?;
            text.append(&[code])?;
            text.append(b"'")?;
            return error_text(vm, text.as_bytes());
        }
        Stop::SizeLimit(size) => {
            let mut text = basic::PrintBuffer::new(vm);
            text.append(b"integral size (")?;
            append_usize(&mut text, size)?;
            text.append(b") out of limits [1,16]")?;
            return error_text(vm, text.as_bytes());
        }
        Stop::IntegerFit(size) => {
            let mut text = basic::PrintBuffer::new(vm);
            append_usize(&mut text, size)?;
            text.append(b"-byte integer does not fit into Lua Integer")?;
            return error_text(vm, text.as_bytes());
        }
    };
    Ok(RuntimeError {
        kind: RuntimeErrorKind::StringArgument,
        diagnostic_id: "E_STRING_ARGUMENT",
        ..error
    })
}

fn with_bytes<R>(
    vm: &Vm,
    value: Value,
    f: impl FnOnce(&[u8]) -> Result<R, Stop>,
) -> Result<R, Stop> {
    match value {
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            vm.with_byte_string(object, |stored| f(stored.as_bytes()))?
        }
        Value::Integer(_) | Value::Float(_) => {
            let (bytes, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            f(&bytes[..len])
        }
        _ => Err(Stop::Runtime(argument())),
    }
}

fn checked_string(vm: &Vm, args: &[Value], index: usize) -> Result<Value, Stop> {
    let actual = args.get(index).copied();
    match actual {
        Some(value) if basic::is_string(vm, value)? => Ok(value),
        _ => Err(Stop::Type {
            index: index + 1,
            expected: "string",
            actual,
        }),
    }
}

fn checked_number(vm: &Vm, args: &[Value], index: usize) -> Result<f64, Stop> {
    let actual = args.get(index).copied();
    let Some(value) = actual else {
        return Err(Stop::Type {
            index: index + 1,
            expected: "number",
            actual,
        });
    };
    match basic::number(vm, value, None)? {
        Value::Integer(value) => Ok(value as f64),
        Value::Float(value) => Ok(value),
        _ => Err(Stop::Type {
            index: index + 1,
            expected: "number",
            actual,
        }),
    }
}

fn checked_integer(vm: &Vm, args: &[Value], index: usize) -> Result<i64, Stop> {
    let actual = args.get(index).copied();
    let Some(value) = actual else {
        return Err(Stop::Type {
            index: index + 1,
            expected: "number",
            actual,
        });
    };
    let number = basic::number(vm, value, None)?;
    match basic::lua_integer(number) {
        Some(integer) => Ok(integer),
        None if number == Value::Nil => {
            Err(Stop::Type {
                index: index + 1,
                expected: "number",
                actual,
            })
        }
        None => Err(Stop::Argument {
            index: index + 1,
            reason: "number has no integer representation",
        }),
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Int(bool),
    Float,
    Char,
    String,
    Zero,
    Pad,
    Align,
    Noop,
}

#[derive(Clone, Copy)]
struct Spec {
    kind: Kind,
    size: usize,
    pad: usize,
    little: bool,
}

struct Parser<'a> {
    bytes: &'a [u8],
    offset: usize,
    profile: LuaProfile,
    little: bool,
    maxalign: usize,
    native_align: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], profile: LuaProfile) -> Self {
        Self {
            bytes,
            offset: 0,
            profile,
            little: cfg!(target_endian = "little"),
            maxalign: 1,
            native_align: native_max_align(profile),
        }
    }

    fn number(&mut self, default: usize) -> usize {
        if !self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            return default;
        }
        let mut number = 0_usize;
        let limit = (string::max_size(self.profile) - 9) / 10;
        // 前一位未超過 limit，故再乘十加一位仍不溢位；停止位置與官方 getnum 相同。
        while let Some(digit) = self
            .bytes
            .get(self.offset)
            .copied()
            .filter(u8::is_ascii_digit)
        {
            number = number * 10 + usize::from(digit - b'0');
            self.offset += 1;
            if number > limit {
                break;
            }
        }
        number
    }

    fn limited(&mut self, default: usize) -> Result<usize, Stop> {
        let size = self.number(default);
        if !(1..=16).contains(&size) {
            return Err(Stop::SizeLimit(size));
        }
        Ok(size)
    }

    fn option(&mut self) -> Result<Option<(Kind, usize)>, Stop> {
        let Some(&code) = self.bytes.get(self.offset) else {
            return Ok(None);
        };
        if code == 0 {
            return Ok(None);
        }
        self.offset += 1;
        let (kind, size) = match code {
            b'b' => (Kind::Int(true), 1),
            b'B' => (Kind::Int(false), 1),
            b'h' => (Kind::Int(true), size_of::<core::ffi::c_short>()),
            b'H' => (Kind::Int(false), size_of::<core::ffi::c_short>()),
            b'l' => (Kind::Int(true), size_of::<core::ffi::c_long>()),
            b'L' => (Kind::Int(false), size_of::<core::ffi::c_long>()),
            b'j' => (Kind::Int(true), size_of::<i64>()),
            b'J' => (Kind::Int(false), size_of::<i64>()),
            b'T' => (Kind::Int(false), size_of::<usize>()),
            b'i' => (
                Kind::Int(true),
                self.limited(size_of::<core::ffi::c_int>())?,
            ),
            b'I' => (
                Kind::Int(false),
                self.limited(size_of::<core::ffi::c_int>())?,
            ),
            b'f' => (Kind::Float, 4),
            b'd' | b'n' => (Kind::Float, 8),
            b'c' => (Kind::Char, self.number(usize::MAX)),
            b's' => (Kind::String, self.limited(size_of::<usize>())?),
            b'z' => (Kind::Zero, 0),
            b'x' => (Kind::Pad, 1),
            b'X' => (Kind::Align, 0),
            b' ' => (Kind::Noop, 0),
            b'<' => {
                self.little = true;
                (Kind::Noop, 0)
            }
            b'>' => {
                self.little = false;
                (Kind::Noop, 0)
            }
            b'=' => {
                self.little = cfg!(target_endian = "little");
                (Kind::Noop, 0)
            }
            b'!' => {
                self.maxalign = self.limited(self.native_align)?;
                (Kind::Noop, 0)
            }
            _ => return Err(Stop::InvalidOption(code)),
        };
        if matches!(kind, Kind::Char) && size == usize::MAX {
            return Err(Stop::Direct(b"missing size for format option 'c'"));
        }
        Ok(Some((kind, size)))
    }

    fn next(&mut self, total: usize) -> Result<Option<Spec>, Stop> {
        let Some((kind, size)) = self.option()? else {
            return Ok(None);
        };
        let align = if matches!(kind, Kind::Align) {
            let Some((next, size)) = self.option()? else {
                return Err(Stop::Argument { index: 1, reason: "invalid next option for option 'X'" });
            };
            if matches!(next, Kind::Char) || size == 0 {
                return Err(Stop::Argument { index: 1, reason: "invalid next option for option 'X'" });
            }
            size
        } else if matches!(kind, Kind::Char) {
            1
        } else {
            size
        };
        let align = align.min(self.maxalign);
        if align > 1 && !align.is_power_of_two() {
            return Err(Stop::Argument { index: 1, reason: "format asks for alignment not power of 2" });
        }
        let pad = if align > 1 {
            (align - (total & (align - 1))) & (align - 1)
        } else {
            0
        };
        Ok(Some(Spec {
            kind,
            size,
            pad,
            little: self.little,
        }))
    }
}

fn native_max_align(profile: LuaProfile) -> usize {
    if profile == LuaProfile::Lua54 {
        return 8;
    }
    #[cfg(any(
        target_os = "windows",
        all(target_arch = "aarch64", target_vendor = "apple")
    ))]
    {
        8
    }
    #[cfg(not(any(
        target_os = "windows",
        all(target_arch = "aarch64", target_vendor = "apple")
    )))]
    {
        core::mem::align_of::<u128>().max(core::mem::align_of::<f64>())
    }
}

fn checked_size(current: usize, extra: usize, max: usize, stop: Stop) -> Result<usize, Stop> {
    let size = current
        .checked_add(extra)
        .filter(|size| *size <= max);
    size.ok_or(stop)
}

fn pack_max_size(profile: LuaProfile) -> usize {
    if profile == LuaProfile::Lua54 {
        usize::MAX
    } else {
        string::max_size(profile)
    }
}

fn validate_integer(value: i64, size: usize, signed: bool, index: usize) -> Result<(), Stop> {
    if size < 8 {
        let value = i128::from(value);
        if signed {
            let limit = 1_i128 << (size * 8 - 1);
            if value < -limit || value >= limit {
                return Err(Stop::Argument { index, reason: "integer overflow" });
            }
        } else if value < 0 || value >= (1_i128 << (size * 8)) {
            return Err(Stop::Argument { index, reason: "unsigned overflow" });
        }
    }
    Ok(())
}

fn string_len(vm: &Vm, value: Value) -> Result<usize, Stop> {
    with_bytes(vm, value, |bytes| Ok(bytes.len()))
}

fn pack_size_inner(vm: &Vm, args: &[Value]) -> Result<usize, Stop> {
    let format = checked_string(vm, args, 0)?;
    with_bytes(vm, format, |bytes| {
        let profile = vm.language_profile();
        let mut parser = Parser::new(bytes, profile);
        let max_size = pack_max_size(profile);
        let mut total = 0_usize;
        let mut argument_index = 1;
        while let Some(spec) = parser.next(total)? {
            let too_long = if profile == LuaProfile::Lua55 {
                Stop::Argument {
                    index: argument_index,
                    reason: "result too long",
                }
            } else {
                Stop::Direct(b"buffer too large")
            };
            let fixed = spec.pad.checked_add(spec.size).ok_or(too_long)?;
            total = checked_size(total, fixed, max_size, too_long)?;
            match spec.kind {
                Kind::Int(signed) => {
                    let value = checked_integer(vm, args, argument_index)?;
                    validate_integer(value, spec.size, signed, argument_index + 1)?;
                    argument_index += 1;
                }
                Kind::Float => {
                    checked_number(vm, args, argument_index)?;
                    argument_index += 1;
                }
                Kind::Char | Kind::String | Kind::Zero => {
                    let value = checked_string(vm, args, argument_index)?;
                    let length = string_len(vm, value)?;
                    match spec.kind {
                        Kind::Char if length > spec.size => {
                            return Err(Stop::Argument {
                                index: argument_index + 1,
                                reason: "string longer than given size",
                            });
                        }
                        Kind::String
                            if spec.size < 8 && (length as u128) >= (1_u128 << (spec.size * 8)) =>
                        {
                            return Err(Stop::Argument {
                                index: argument_index + 1,
                                reason: "string length does not fit in given size",
                            });
                        }
                        Kind::Zero => {
                            with_bytes(vm, value, |bytes| {
                                if bytes.contains(&0) {
                                    Err(Stop::Argument {
                                        index: argument_index + 1,
                                        reason: "string contains zeros",
                                    })
                                } else {
                                    Ok(())
                                }
                            })?;
                        }
                        _ => {}
                    }
                    let buffer_too_large = if profile == LuaProfile::Lua54 {
                        Stop::Direct(b"buffer too large")
                    } else {
                        Stop::Direct(b"resulting string too large")
                    };
                    total = checked_size(
                        total,
                        if matches!(spec.kind, Kind::Zero) {
                            length
                                .checked_add(1)
                                .ok_or(buffer_too_large)?
                        } else if matches!(spec.kind, Kind::String) {
                            length
                        } else {
                            0
                        },
                        max_size,
                        buffer_too_large,
                    )?;
                    argument_index += 1;
                }
                Kind::Pad | Kind::Align | Kind::Noop => {}
            }
        }
        Ok(total)
    })
}

pub(crate) fn pack_size(vm: &mut Vm, args: &[Value]) -> Result<usize, RuntimeError> {
    match pack_size_inner(vm, args) {
        Ok(size) => Ok(size),
        Err(stop) => Err(materialize(vm, "pack", stop)?),
    }
}

pub(crate) fn format_length(vm: &mut Vm, kind: StringBuiltin, args: &[Value]) -> Result<usize, RuntimeError> {
    let function = match kind {
        StringBuiltin::Pack => "pack",
        StringBuiltin::Unpack => "unpack",
        StringBuiltin::PackSize => "packsize",
        _ => return Err(argument()),
    };
    let result = (|| {
        let format = checked_string(vm, args, 0)?;
        with_bytes(vm, format, |bytes| Ok(bytes.len()))
    })();
    match result {
        Ok(length) => Ok(length),
        Err(stop) => Err(materialize(vm, function, stop)?),
    }
}

fn write_integer(output: &mut Vec<u8>, number: u64, size: usize, little: bool, negative: bool) {
    for index in 0..size {
        let part = if index >= 8 {
            if negative { 255 } else { 0 }
        } else {
            (number >> (index * 8)) as u8
        };
        if little {
            output.push(part);
        } else {
            output.insert(output.len() - index, part);
        }
    }
}

fn next_spec(
    vm: &mut Vm,
    function: &'static str,
    parser: &mut Parser<'_>,
    total: usize,
) -> Result<Option<Spec>, RuntimeError> {
    match parser.next(total) {
        Ok(spec) => Ok(spec),
        Err(stop) => Err(materialize(vm, function, stop)?),
    }
}

fn pack(vm: &mut Vm, args: &[Value]) -> Result<OwnedValues, RuntimeError> {
    let size = pack_size(vm, args)?;
    let format = string::owned_bytes(vm, string::arg(args, 0)?)?;
    let mut output = Buffer::new(vm, size)?;
    let mut parser = Parser::new(&format.bytes, vm.language_profile());
    let mut index = 1;
    while let Some(spec) = next_spec(vm, "pack", &mut parser, output.bytes.len())? {
        output.bytes.extend(core::iter::repeat_n(0, spec.pad));
        match spec.kind {
            Kind::Int(signed) => {
                let n = match checked_integer(vm, args, index) {
                    Ok(value) => value,
                    Err(stop) => return Err(materialize(vm, "pack", stop)?),
                };
                write_integer(
                    &mut output.bytes,
                    n as u64,
                    spec.size,
                    spec.little,
                    signed && n < 0,
                );
                index += 1;
            }
            Kind::Float => {
                let value = match checked_number(vm, args, index) {
                    Ok(value) => value,
                    Err(stop) => return Err(materialize(vm, "pack", stop)?),
                };
                if spec.size == 4 {
                    let bytes = (value as f32).to_bits().to_le_bytes();
                    if spec.little {
                        output.bytes.extend_from_slice(&bytes);
                    } else {
                        output.bytes.extend(bytes.into_iter().rev());
                    }
                } else {
                    let bytes = value.to_bits().to_le_bytes();
                    if spec.little {
                        output.bytes.extend_from_slice(&bytes);
                    } else {
                        output.bytes.extend(bytes.into_iter().rev());
                    }
                }
                index += 1;
            }
            Kind::Char | Kind::String | Kind::Zero => {
                let value = string::arg(args, index)?;
                string::with_bytes(vm, value, |bytes| {
                    if matches!(spec.kind, Kind::String) {
                        write_integer(
                            &mut output.bytes,
                            bytes.len() as u64,
                            spec.size,
                            spec.little,
                            false,
                        );
                    }
                    output.bytes.extend_from_slice(bytes);
                    if matches!(spec.kind, Kind::Char) {
                        output
                            .bytes
                            .extend(core::iter::repeat_n(0, spec.size - bytes.len()));
                    }
                    if matches!(spec.kind, Kind::Zero) {
                        output.bytes.push(0);
                    }
                    Ok(())
                })?;
                index += 1;
            }
            Kind::Pad => output.bytes.push(0),
            Kind::Align | Kind::Noop => {}
        }
    }
    string::string_result(vm, &output)
}

fn read_integer(bytes: &[u8], little: bool, signed: bool) -> Result<i64, Stop> {
    let size = bytes.len();
    let mut result = 0_u64;
    for index in (0..size.min(8)).rev() {
        result = (result << 8) | u64::from(bytes[if little { index } else { size - 1 - index }]);
    }
    if size < 8 && signed {
        let shift = 64 - size * 8;
        result = (((result << shift) as i64) >> shift) as u64;
    }
    if size > 8 {
        let extension = if signed && (result as i64) < 0 {
            255
        } else {
            0
        };
        for index in 8..size {
            if bytes[if little { index } else { size - 1 - index }] != extension {
                return Err(Stop::IntegerFit(size));
            }
        }
    }
    Ok(result as i64)
}

fn unpack_pass(vm: &Vm, format: &[u8], data: &[u8], initial: usize) -> Result<usize, Stop> {
    let mut parser = Parser::new(format, vm.language_profile());
    let mut position = initial;
    let mut count = 0_usize;
    while let Some(spec) = parser.next(position)? {
        let advance = spec.pad.checked_add(spec.size).ok_or(Stop::Argument { index: 2, reason: "data string too short" })?;
        if advance > data.len().saturating_sub(position) {
            return Err(Stop::Argument { index: 2, reason: "data string too short" });
        }
        position += spec.pad;
        match spec.kind {
            Kind::Int(signed) => {
                read_integer(&data[position..position + spec.size], spec.little, signed)?;
                count = count.checked_add(1).ok_or(Stop::Direct(b"too many results"))?;
            }
            Kind::Float | Kind::Char => {
                count = count.checked_add(1).ok_or(Stop::Direct(b"too many results"))?;
            }
            Kind::String => {
                let length =
                    read_integer(&data[position..position + spec.size], spec.little, false)? as u64;
                let length = usize::try_from(length).map_err(|_| Stop::Argument { index: 2, reason: "data string too short" })?;
                if length > data.len() - position - spec.size {
                    return Err(Stop::Argument { index: 2, reason: "data string too short" });
                }
                position += length;
                count = count.checked_add(1).ok_or(Stop::Direct(b"too many results"))?;
            }
            Kind::Zero => {
                let length = data[position..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or(Stop::Argument { index: 2, reason: "unfinished string for format 'z'" })?;
                position = position.checked_add(length + 1).ok_or(Stop::Argument { index: 2, reason: "data string too short" })?;
                count = count.checked_add(1).ok_or(Stop::Direct(b"too many results"))?;
            }
            Kind::Pad | Kind::Align | Kind::Noop => {}
        }
        position = checked_size(position, spec.size, usize::MAX, Stop::Argument { index: 2, reason: "data string too short" })?;
    }
    Ok(count)
}

pub(crate) struct PreparedUnpack {
    format: Buffer,
    data: Buffer,
    initial: usize,
    output_count: usize,
}

impl PreparedUnpack {
    pub(crate) fn output_count(&self) -> usize {
        self.output_count
    }
}

fn prepare_unpack_inner(vm: &Vm, args: &[Value]) -> Result<PreparedUnpack, Stop> {
    let format = string::owned_bytes(vm, checked_string(vm, args, 0)?)?;
    let data = string::owned_bytes(vm, checked_string(vm, args, 1)?)?;
    let initial = match args.get(2) {
        None | Some(Value::Nil) => 1,
        Some(_) => checked_integer(vm, args, 2)?,
    };
    let initial = string::start_position(initial, data.bytes.len()).saturating_sub(1);
    if initial > data.bytes.len() {
        return Err(Stop::Argument { index: 3, reason: "initial position out of string" });
    }
    let count = unpack_pass(vm, &format.bytes, &data.bytes, initial)?;
    let output_count = count.checked_add(1).ok_or(Stop::Direct(b"too many results"))?;
    vm.check_builtin_result_count(output_count)?;
    Ok(PreparedUnpack { format, data, initial, output_count })
}

pub(crate) fn prepare_unpack(vm: &mut Vm, args: &[Value]) -> Result<PreparedUnpack, RuntimeError> {
    match prepare_unpack_inner(vm, args) {
        Ok(prepared) => Ok(prepared),
        Err(stop) => Err(materialize(vm, "unpack", stop)?),
    }
}

fn unpack(
    vm: &mut Vm,
    args: &[Value],
    prepared: Option<PreparedUnpack>,
) -> Result<OwnedValues, RuntimeError> {
    let PreparedUnpack { format, data, initial, output_count } =
        match prepared {
            Some(prepared) => prepared,
            None => prepare_unpack(vm, args)?,
        };
    let mut output = OwnedValues::try_with_capacity_borrowed(vm, output_count, args)?;
    {
        let mut parser = Parser::new(&format.bytes, vm.language_profile());
        let mut position = initial;
        while let Some(spec) = next_spec(vm, "unpack", &mut parser, position)? {
            position += spec.pad;
            match spec.kind {
                Kind::Int(signed) => {
                    let value = match read_integer(
                        &data.bytes[position..position + spec.size], spec.little, signed,
                    ) {
                        Ok(value) => value,
                        Err(stop) => return Err(materialize(vm, "unpack", stop)?),
                    };
                    output.push_scalar(Value::Integer(value))?;
                }
                Kind::Float => {
                    let bytes = &data.bytes[position..position + spec.size];
                    let value = if spec.size == 4 {
                        let mut bits = [0_u8; 4];
                        if spec.little {
                            bits.copy_from_slice(bytes);
                        } else {
                            for (dst, src) in bits.iter_mut().zip(bytes.iter().rev()) {
                                *dst = *src;
                            }
                        }
                        f32::from_bits(u32::from_le_bytes(bits)) as f64
                    } else {
                        let mut bits = [0_u8; 8];
                        if spec.little {
                            bits.copy_from_slice(bytes);
                        } else {
                            for (dst, src) in bits.iter_mut().zip(bytes.iter().rev()) {
                                *dst = *src;
                            }
                        }
                        f64::from_bits(u64::from_le_bytes(bits))
                    };
                    output.push_scalar(Value::Float(value))?;
                }
                Kind::Char | Kind::String | Kind::Zero => {
                    let (first, last) = match spec.kind {
                        Kind::Char => (position, position + spec.size),
                        Kind::String => {
                            let length = match read_integer(
                                &data.bytes[position..position + spec.size],
                                spec.little,
                                false,
                            ) {
                                Ok(length) => length as u64,
                                Err(stop) => return Err(materialize(vm, "unpack", stop)?),
                            };
                            let length = usize::try_from(length).map_err(|_| argument())?;
                            position += length;
                            (position - length + spec.size, position + spec.size)
                        }
                        Kind::Zero => {
                            let length = data.bytes[position..]
                                .iter()
                                .position(|byte| *byte == 0)
                                .ok_or_else(argument)?;
                            position += length + 1;
                            (position - length - 1, position - 1)
                        }
                        _ => return Err(argument()),
                    };
                    let object = vm.allocate_byte_string(&data.bytes[first..last])?;
                    output.try_push(vm, Value::Object(object))?;
                }
                Kind::Pad | Kind::Align | Kind::Noop => {}
            }
            position += spec.size;
        }
        output.push_scalar(Value::Integer(
            i64::try_from(position + 1).map_err(|_| VmError::ArithmeticOverflow)?,
        ))?;
    }
    Ok(output)
}

fn packsize_inner(vm: &Vm, args: &[Value]) -> Result<usize, Stop> {
    let format = checked_string(vm, args, 0)?;
    with_bytes(vm, format, |bytes| {
        let mut parser = Parser::new(bytes, vm.language_profile());
        let mut total = 0_usize;
        while let Some(spec) = parser.next(total)? {
            if matches!(spec.kind, Kind::String | Kind::Zero) {
                return Err(Stop::Argument { index: 1, reason: "variable-length format" });
            }
            let extra = spec.pad.checked_add(spec.size).ok_or(Stop::Argument { index: 1, reason: "format result too large" })?;
            total = checked_size(total, extra, string::max_size(vm.language_profile()), Stop::Argument { index: 1, reason: "format result too large" })?;
        }
        Ok(total)
    })
}

pub(crate) fn execute(
    vm: &mut Vm,
    kind: StringBuiltin,
    args: &[Value],
    prepared_unpack: Option<PreparedUnpack>,
) -> Result<OwnedValues, RuntimeError> {
    match kind {
        StringBuiltin::Pack => pack(vm, args),
        StringBuiltin::Unpack => unpack(vm, args, prepared_unpack),
        StringBuiltin::PackSize => {
            let size = match packsize_inner(vm, args) {
                Ok(size) => size,
                Err(stop) => return Err(materialize(vm, "packsize", stop)?),
            };
            string::values(vm, &[Value::Integer(size as i64)])
        }
        _ => Err(argument()),
    }
}


