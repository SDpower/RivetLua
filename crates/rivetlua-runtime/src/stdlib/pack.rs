//! Lua string pack 格式、大小前置檢查與 endian 編解碼。

use core::mem::size_of;
use rivetlua_core::{LuaProfile, Value};

use crate::alloc::{FailPoint, Reservation, reserve_vec};
use crate::roots::{RootId, RootKind};
use crate::stdlib::basic;
use crate::stdlib::string::{self, Buffer, StringBuiltin};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{Vm, VmError};

fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringArgument)
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
    little: bool,
    maxalign: usize,
    native_align: usize,
}

impl<'a> Parser<'a> {
    fn new(bytes: &'a [u8], profile: LuaProfile) -> Self {
        Self {
            bytes,
            offset: 0,
            little: cfg!(target_endian = "little"),
            maxalign: 1,
            native_align: native_max_align(profile),
        }
    }

    fn number(&mut self, default: usize) -> Result<usize, RuntimeError> {
        if !self.bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
            return Ok(default);
        }
        let mut number = 0_usize;
        while let Some(digit) = self
            .bytes
            .get(self.offset)
            .copied()
            .filter(u8::is_ascii_digit)
        {
            number = number
                .checked_mul(10)
                .and_then(|n| n.checked_add(usize::from(digit - b'0')))
                .ok_or_else(argument)?;
            self.offset += 1;
        }
        Ok(number)
    }

    fn limited(&mut self, default: usize) -> Result<usize, RuntimeError> {
        let size = self.number(default)?;
        if !(1..=16).contains(&size) {
            return Err(argument());
        }
        Ok(size)
    }

    fn option(&mut self) -> Result<Option<(Kind, usize)>, RuntimeError> {
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
            b'c' => (Kind::Char, self.number(usize::MAX)?),
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
            _ => return Err(argument()),
        };
        if matches!(kind, Kind::Char) && size == usize::MAX {
            return Err(argument());
        }
        Ok(Some((kind, size)))
    }

    fn next(&mut self, total: usize) -> Result<Option<Spec>, RuntimeError> {
        let Some((kind, size)) = self.option()? else {
            return Ok(None);
        };
        let align = if matches!(kind, Kind::Align) {
            let Some((next, size)) = self.option()? else {
                return Err(argument());
            };
            if matches!(next, Kind::Char) || size == 0 {
                return Err(argument());
            }
            size
        } else if matches!(kind, Kind::Char) {
            1
        } else {
            size
        };
        let align = align.min(self.maxalign);
        if align > 1 && !align.is_power_of_two() {
            return Err(argument());
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

fn checked_size(vm: &Vm, current: usize, extra: usize) -> Result<usize, RuntimeError> {
    let size = current.checked_add(extra).ok_or_else(argument)?;
    if size > string::max_size(vm.language_profile()) {
        return Err(argument());
    }
    Ok(size)
}

fn number(vm: &Vm, value: Value) -> Result<f64, RuntimeError> {
    match basic::number(vm, value, None)? {
        Value::Integer(value) => Ok(value as f64),
        Value::Float(value) => Ok(value),
        _ => Err(argument()),
    }
}

fn validate_integer(value: i64, size: usize, signed: bool) -> Result<(), RuntimeError> {
    if size < 8 {
        let value = i128::from(value);
        if signed {
            let limit = 1_i128 << (size * 8 - 1);
            if value < -limit || value >= limit {
                return Err(argument());
            }
        } else if value < 0 || value >= (1_i128 << (size * 8)) {
            return Err(argument());
        }
    }
    Ok(())
}

fn string_len(vm: &Vm, value: Value) -> Result<usize, RuntimeError> {
    string::with_bytes(vm, value, |bytes| Ok(bytes.len()))
}

pub(crate) fn pack_size(vm: &Vm, args: &[Value]) -> Result<usize, RuntimeError> {
    let format = string::arg(args, 0)?;
    string::with_bytes(vm, format, |bytes| {
        let mut parser = Parser::new(bytes, vm.language_profile());
        let mut total = 0_usize;
        let mut argument_index = 1;
        while let Some(spec) = parser.next(total)? {
            total = checked_size(vm, total, spec.pad)?;
            total = checked_size(vm, total, spec.size)?;
            match spec.kind {
                Kind::Int(signed) => {
                    let value = string::integer(vm, string::arg(args, argument_index)?)?;
                    validate_integer(value, spec.size, signed)?;
                    argument_index += 1;
                }
                Kind::Float => {
                    number(vm, string::arg(args, argument_index)?)?;
                    argument_index += 1;
                }
                Kind::Char | Kind::String | Kind::Zero => {
                    let value = string::arg(args, argument_index)?;
                    let length = string_len(vm, value)?;
                    match spec.kind {
                        Kind::Char if length > spec.size => return Err(argument()),
                        Kind::String
                            if spec.size < 8 && (length as u128) >= (1_u128 << (spec.size * 8)) =>
                        {
                            return Err(argument());
                        }
                        Kind::Zero => {
                            string::with_bytes(vm, value, |bytes| {
                                if bytes.contains(&0) {
                                    Err(argument())
                                } else {
                                    Ok(())
                                }
                            })?;
                        }
                        _ => {}
                    }
                    total = checked_size(
                        vm,
                        total,
                        if matches!(spec.kind, Kind::Zero) {
                            length.checked_add(1).ok_or_else(argument)?
                        } else if matches!(spec.kind, Kind::String) {
                            length
                        } else {
                            0
                        },
                    )?;
                    argument_index += 1;
                }
                Kind::Pad | Kind::Align | Kind::Noop => {}
            }
        }
        Ok(total)
    })
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

fn pack(vm: &mut Vm, args: &[Value]) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let size = pack_size(vm, args)?;
    let format = string::owned_bytes(vm, string::arg(args, 0)?)?;
    let mut output = Buffer::new(vm, size)?;
    let mut parser = Parser::new(&format.bytes, vm.language_profile());
    let mut index = 1;
    while let Some(spec) = parser.next(output.bytes.len())? {
        output.bytes.extend(core::iter::repeat_n(0, spec.pad));
        match spec.kind {
            Kind::Int(signed) => {
                let n = string::integer(vm, string::arg(args, index)?)?;
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
                let value = number(vm, string::arg(args, index)?)?;
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

fn read_integer(bytes: &[u8], little: bool, signed: bool) -> Result<i64, RuntimeError> {
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
                return Err(argument());
            }
        }
    }
    Ok(result as i64)
}

fn unpack_pass(vm: &Vm, format: &[u8], data: &[u8], initial: usize) -> Result<usize, RuntimeError> {
    let mut parser = Parser::new(format, vm.language_profile());
    let mut position = initial;
    let mut count = 0_usize;
    while let Some(spec) = parser.next(position)? {
        let advance = spec.pad.checked_add(spec.size).ok_or_else(argument)?;
        if advance > data.len().saturating_sub(position) {
            return Err(argument());
        }
        position += spec.pad;
        match spec.kind {
            Kind::Int(signed) => {
                read_integer(&data[position..position + spec.size], spec.little, signed)?;
                count += 1;
            }
            Kind::Float | Kind::Char => {
                count += 1;
            }
            Kind::String => {
                let length =
                    read_integer(&data[position..position + spec.size], spec.little, false)? as u64;
                let length = usize::try_from(length).map_err(|_| argument())?;
                if length > data.len() - position - spec.size {
                    return Err(argument());
                }
                position += length;
                count += 1;
            }
            Kind::Zero => {
                let length = data[position..]
                    .iter()
                    .position(|byte| *byte == 0)
                    .ok_or_else(argument)?;
                position = position.checked_add(length + 1).ok_or_else(argument)?;
                count += 1;
            }
            Kind::Pad | Kind::Align | Kind::Noop => {}
        }
        position = checked_size(vm, position, spec.size)?;
        if count >= usize::from(u16::MAX) {
            return Err(argument());
        }
    }
    Ok(count)
}

fn unpack(vm: &mut Vm, args: &[Value]) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let format = string::owned_bytes(vm, string::arg(args, 0)?)?;
    let data = string::owned_bytes(vm, string::arg(args, 1)?)?;
    let initial = string::optional_integer(vm, args.get(2).copied(), 1)?;
    let initial = string::start_position(initial, data.bytes.len()).saturating_sub(1);
    if initial > data.bytes.len() {
        return Err(argument());
    }
    let count = unpack_pass(vm, &format.bytes, &data.bytes, initial)?;
    let mut output = Vec::new();
    let output_ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut output,
        count + 1,
        FailPoint::ReturnReserve,
    )?;
    let mut roots: Vec<RootId> = Vec::new();
    let roots_ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut roots,
        count,
        FailPoint::WorkReserve,
    )?;
    let roots_owner = roots_ticket.commit_charge()?;
    let produced = (|| {
        let mut parser = Parser::new(&format.bytes, vm.language_profile());
        let mut position = initial;
        while let Some(spec) = parser.next(position)? {
            position += spec.pad;
            match spec.kind {
                Kind::Int(signed) => output.push(Value::Integer(read_integer(
                    &data.bytes[position..position + spec.size],
                    spec.little,
                    signed,
                )?)),
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
                    output.push(Value::Float(value));
                }
                Kind::Char | Kind::String | Kind::Zero => {
                    let (first, last) = match spec.kind {
                        Kind::Char => (position, position + spec.size),
                        Kind::String => {
                            let length = read_integer(
                                &data.bytes[position..position + spec.size],
                                spec.little,
                                false,
                            )? as u64;
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
                    roots.push(vm.add_root(RootKind::Temporary, object)?);
                    output.push(Value::Object(object));
                }
                Kind::Pad | Kind::Align | Kind::Noop => {}
            }
            position += spec.size;
        }
        output.push(Value::Integer(
            i64::try_from(position + 1).map_err(|_| VmError::ArithmeticOverflow)?,
        ));
        Ok::<(), RuntimeError>(())
    })();
    for root in roots {
        vm.remove_root(root)?;
    }
    drop(roots_owner);
    produced?;
    Ok((output, Some(output_ticket)))
}

pub(crate) fn execute(
    vm: &mut Vm,
    kind: StringBuiltin,
    args: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    match kind {
        StringBuiltin::Pack => pack(vm, args),
        StringBuiltin::Unpack => unpack(vm, args),
        StringBuiltin::PackSize => {
            let format = string::arg(args, 0)?;
            let size = string::with_bytes(vm, format, |bytes| {
                let mut parser = Parser::new(bytes, vm.language_profile());
                let mut total = 0_usize;
                while let Some(spec) = parser.next(total)? {
                    if matches!(spec.kind, Kind::String | Kind::Zero) {
                        return Err(argument());
                    }
                    total = checked_size(
                        vm,
                        total,
                        spec.pad.checked_add(spec.size).ok_or_else(argument)?,
                    )?;
                }
                Ok(total)
            })?;
            string::values(
                vm,
                &[Value::Integer(i64::try_from(size).map_err(|_| argument())?)],
            )
        }
        _ => Err(argument()),
    }
}
