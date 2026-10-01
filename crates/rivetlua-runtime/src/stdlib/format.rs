//! `string.format` 的 VM 暫存狀態、格式解析與 bytes 輸出。

use core::fmt::{self, Write};

use rivetlua_core::{ObjectRef, Value};

use crate::pending_op::PrintArguments;
use crate::stdlib::basic;
use crate::stdlib::string::{self, Buffer};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, Vm, VmError};

fn format_error() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringFormat)
}

#[derive(Clone, Copy)]
pub(crate) struct Spec {
    pub kind: u8,
    pub left: bool,
    pub plus: bool,
    pub space: bool,
    pub alternative: bool,
    pub zero: bool,
    pub width: usize,
    pub precision: Option<usize>,
    pub modified: bool,
}

pub(crate) enum Token {
    Literal { first: usize, end: usize },
    Percent,
    Spec(Spec, Value),
    Done,
}

pub(crate) struct FormatState {
    pub arguments: PrintArguments,
    pub buffer: Buffer,
    offset: usize,
    argument: usize,
    awaiting: Option<Spec>,
}

impl FormatState {
    pub(crate) fn new(vm: &mut Vm, args: &[Value]) -> Result<Self, RuntimeError> {
        let first = args.first().copied().ok_or_else(format_error)?;
        string::with_bytes(vm, first, |_| Ok(()))?;
        Ok(Self {
            arguments: PrintArguments::new(vm, args)?,
            buffer: Buffer::empty(vm),
            offset: 0,
            argument: 1,
            awaiting: None,
        })
    }

    pub(crate) fn await_string(&mut self, spec: Spec) {
        self.awaiting = Some(spec);
    }

    pub(crate) fn take_awaiting(&mut self) -> Result<Spec, RuntimeError> {
        self.awaiting.take().ok_or_else(format_error)
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.clear_roots(vm)
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.restore_roots(vm)
    }

    pub(crate) fn trace_children(
        &self,
        visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.arguments.trace_children(visit)
    }

    pub(crate) fn next(&mut self, vm: &Vm) -> Result<Token, RuntimeError> {
        let source = self.arguments.values()[0];
        let (token, offset, argument) = string::with_bytes(vm, source, |bytes| {
            if self.offset >= bytes.len() {
                return Ok((Token::Done, self.offset, self.argument));
            }
            if bytes[self.offset] != b'%' {
                let end = bytes[self.offset..]
                    .iter()
                    .position(|byte| *byte == b'%')
                    .map_or(bytes.len(), |index| self.offset + index);
                return Ok((
                    Token::Literal {
                        first: self.offset,
                        end,
                    },
                    end,
                    self.argument,
                ));
            }
            let mut cursor = self.offset + 1;
            if bytes.get(cursor) == Some(&b'%') {
                return Ok((Token::Percent, cursor + 1, self.argument));
            }
            let flags_start = cursor;
            let mut spec = Spec {
                kind: 0,
                left: false,
                plus: false,
                space: false,
                alternative: false,
                zero: false,
                width: 0,
                precision: None,
                modified: false,
            };
            while let Some(flag) = bytes.get(cursor).copied() {
                match flag {
                    b'-' => spec.left = true,
                    b'+' => spec.plus = true,
                    b' ' => spec.space = true,
                    b'#' => spec.alternative = true,
                    b'0' => spec.zero = true,
                    _ => break,
                }
                cursor += 1;
            }
            let flags_end = cursor;
            let width_start = cursor;
            while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                if cursor - width_start >= 2 {
                    return Err(format_error());
                }
                spec.width = spec.width * 10 + usize::from(bytes[cursor] - b'0');
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'.') {
                cursor += 1;
                spec.precision = Some(0);
                let precision_start = cursor;
                while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
                    if cursor - precision_start >= 2 {
                        return Err(format_error());
                    }
                    spec.precision =
                        Some(spec.precision.unwrap_or(0) * 10 + usize::from(bytes[cursor] - b'0'));
                    cursor += 1;
                }
            }
            spec.kind = *bytes.get(cursor).ok_or_else(format_error)?;
            spec.modified = cursor > flags_start;
            if cursor - self.offset >= 22 || !valid_spec(spec, &bytes[flags_start..flags_end]) {
                return Err(format_error());
            }
            let argument = self
                .arguments
                .values()
                .get(self.argument)
                .copied()
                .ok_or_else(format_error)?;
            Ok((Token::Spec(spec, argument), cursor + 1, self.argument + 1))
        })?;
        self.offset = offset;
        self.argument = argument;
        Ok(token)
    }

    pub(crate) fn append_literal(
        &mut self,
        vm: &Vm,
        first: usize,
        end: usize,
    ) -> Result<(), RuntimeError> {
        let source = self.arguments.values()[0];
        string::with_bytes(vm, source, |bytes| {
            self.check_size(vm, end - first)?;
            self.buffer.append(&bytes[first..end])
        })
    }

    pub(crate) fn append_bytes(&mut self, vm: &Vm, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.check_size(vm, bytes.len())?;
        self.buffer.append(bytes)
    }

    fn check_size(&self, vm: &Vm, additional: usize) -> Result<(), RuntimeError> {
        let next = self
            .buffer
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(VmError::ArithmeticOverflow)?;
        if next > string::max_size(vm.language_profile()) {
            return Err(format_error());
        }
        Ok(())
    }

    pub(crate) fn append_string(
        &mut self,
        vm: &Vm,
        spec: Spec,
        value: Value,
    ) -> Result<usize, RuntimeError> {
        string::with_bytes(vm, value, |bytes| {
            let raw = !spec.modified;
            if !raw && bytes.contains(&0) {
                return Err(format_error());
            }
            let selected = if raw || (spec.precision.is_none() && bytes.len() >= 100) {
                bytes
            } else {
                &bytes[..bytes.len().min(spec.precision.unwrap_or(usize::MAX))]
            };
            let padding = if raw || (spec.precision.is_none() && bytes.len() >= 100) {
                0
            } else {
                spec.width.saturating_sub(selected.len())
            };
            let total = selected
                .len()
                .checked_add(padding)
                .ok_or(VmError::ArithmeticOverflow)?;
            self.check_size(vm, total)?;
            self.buffer.reserve_extra(total)?;
            if !spec.left {
                self.buffer
                    .bytes
                    .extend(core::iter::repeat_n(b' ', padding));
            }
            self.buffer.bytes.extend_from_slice(selected);
            if spec.left {
                self.buffer
                    .bytes
                    .extend(core::iter::repeat_n(b' ', padding));
            }
            Ok(total)
        })
    }

    pub(crate) fn string_cost(
        &self,
        vm: &Vm,
        spec: Spec,
        value: Value,
    ) -> Result<usize, RuntimeError> {
        string::with_bytes(vm, value, |bytes| {
            let selected = if !spec.modified || (spec.precision.is_none() && bytes.len() >= 100) {
                bytes.len()
            } else {
                bytes.len().min(spec.precision.unwrap_or(usize::MAX))
            };
            let output = selected.max(spec.width);
            if spec.modified {
                bytes
                    .len()
                    .checked_add(output)
                    .ok_or(VmError::ArithmeticOverflow.into())
            } else {
                Ok(output)
            }
        })
    }
}

fn valid_spec(spec: Spec, flags: &[u8]) -> bool {
    let allowed: &[u8] = match spec.kind {
        b'c' | b'p' | b's' => b"-",
        b'd' | b'i' => b"-+0 ",
        b'u' => b"-0",
        b'o' | b'x' | b'X' => b"-#0",
        b'a' | b'A' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => b"-+#0 ",
        b'q' => return !spec.modified,
        _ => return false,
    };
    flags.iter().all(|flag| allowed.contains(flag))
        && (spec.precision.is_none() || !matches!(spec.kind, b'c' | b'p'))
}

#[derive(Clone, Copy)]
pub(crate) struct Text {
    bytes: [u8; 512],
    len: usize,
}

impl Text {
    fn new() -> Self {
        Self {
            bytes: [0; 512],
            len: 0,
        }
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn push(&mut self, byte: u8) -> Result<(), RuntimeError> {
        let place = self.bytes.get_mut(self.len).ok_or_else(format_error)?;
        *place = byte;
        self.len += 1;
        Ok(())
    }

    fn extend(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        let end = self
            .len
            .checked_add(bytes.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        let place = self.bytes.get_mut(self.len..end).ok_or_else(format_error)?;
        place.copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }
}

impl fmt::Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.extend(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

pub(crate) enum Piece {
    Small(Text),
    Quoted(Value, usize),
}

impl Piece {
    pub(crate) fn cost(&self) -> usize {
        match self {
            Self::Small(text) => text.len,
            Self::Quoted(_, length) => *length,
        }
    }
}

fn integer(vm: &Vm, value: Value) -> Result<i64, RuntimeError> {
    let number = basic::number(vm, value, None)?;
    basic::lua_integer(number).ok_or_else(format_error)
}

fn number(vm: &Vm, value: Value) -> Result<f64, RuntimeError> {
    match basic::number(vm, value, None)? {
        Value::Integer(value) => Ok(value as f64),
        Value::Float(value) => Ok(value),
        _ => Err(format_error()),
    }
}

fn apply_width(spec: Spec, raw: &[u8], numeric: bool) -> Result<Text, RuntimeError> {
    let mut output = Text::new();
    let padding = spec.width.saturating_sub(raw.len());
    let integer = matches!(spec.kind, b'd' | b'i' | b'u' | b'o' | b'x' | b'X');
    let special = raw
        .windows(3)
        .any(|bytes| bytes.eq_ignore_ascii_case(b"inf") || bytes.eq_ignore_ascii_case(b"nan"));
    let zero =
        numeric && spec.zero && !spec.left && (!integer || spec.precision.is_none()) && !special;
    if !spec.left && !zero {
        for _ in 0..padding {
            output.push(b' ')?;
        }
    }
    if zero {
        let mut prefix = usize::from(matches!(raw.first(), Some(b'+' | b'-' | b' ')));
        if raw
            .get(prefix..)
            .is_some_and(|bytes| bytes.starts_with(b"0x") || bytes.starts_with(b"0X"))
        {
            prefix += 2;
        }
        output.extend(&raw[..prefix])?;
        for _ in 0..padding {
            output.push(b'0')?;
        }
        output.extend(&raw[prefix..])?;
    } else {
        output.extend(raw)?;
    }
    if spec.left {
        for _ in 0..padding {
            output.push(b' ')?;
        }
    }
    Ok(output)
}

fn integer_piece(vm: &Vm, spec: Spec, value: Value) -> Result<Text, RuntimeError> {
    let number = integer(vm, value)?;
    let unsigned = number as u64;
    let signed = matches!(spec.kind, b'd' | b'i');
    let mut digits = Text::new();
    if spec.precision != Some(0) || unsigned != 0 {
        match spec.kind {
            b'd' | b'i' => write!(digits, "{}", number.unsigned_abs()),
            b'u' => write!(digits, "{unsigned}"),
            b'o' => write!(digits, "{unsigned:o}"),
            b'x' => write!(digits, "{unsigned:x}"),
            b'X' => write!(digits, "{unsigned:X}"),
            _ => return Err(format_error()),
        }
        .map_err(|_| format_error())?;
    }
    let mut prefix = Text::new();
    if signed {
        if number < 0 {
            prefix.push(b'-')?;
        } else if spec.plus {
            prefix.push(b'+')?;
        } else if spec.space {
            prefix.push(b' ')?;
        }
    }
    if spec.alternative && unsigned != 0 && matches!(spec.kind, b'x' | b'X') {
        prefix.extend(if spec.kind == b'x' { b"0x" } else { b"0X" })?;
    }
    let mut precision = spec.precision.unwrap_or(0);
    if spec.alternative && spec.kind == b'o' {
        if digits.len == 0 {
            digits.push(b'0')?;
        } else if digits.as_bytes().first() != Some(&b'0') {
            precision = precision.max(digits.len + 1);
        }
    }
    let mut raw = Text::new();
    raw.extend(prefix.as_bytes())?;
    for _ in 0..precision.saturating_sub(digits.len) {
        raw.push(b'0')?;
    }
    raw.extend(digits.as_bytes())?;
    apply_width(spec, raw.as_bytes(), true)
}

fn normalized_exponent(output: &mut Text, exponent: i32, marker: u8) -> Result<(), RuntimeError> {
    output.push(marker)?;
    output.push(if exponent < 0 { b'-' } else { b'+' })?;
    let magnitude = exponent.unsigned_abs();
    if magnitude < 10 {
        output.push(b'0')?;
    }
    write!(output, "{magnitude}").map_err(|_| format_error())
}

fn scientific(number: f64, precision: usize, uppercase: bool) -> Result<(Text, i32), RuntimeError> {
    let mut raw = Text::new();
    write!(raw, "{number:.precision$e}").map_err(|_| format_error())?;
    let marker = raw
        .as_bytes()
        .iter()
        .position(|byte| *byte == b'e')
        .ok_or_else(format_error)?;
    let exponent = core::str::from_utf8(&raw.as_bytes()[marker + 1..])
        .map_err(|_| format_error())?
        .parse::<i32>()
        .map_err(|_| format_error())?;
    let mut output = Text::new();
    output.extend(&raw.as_bytes()[..marker])?;
    normalized_exponent(&mut output, exponent, if uppercase { b'E' } else { b'e' })?;
    Ok((output, exponent))
}

fn trim_decimal(raw: &Text, exponent: bool) -> Result<Text, RuntimeError> {
    let marker = if exponent {
        raw.as_bytes()
            .iter()
            .position(|byte| matches!(byte, b'e' | b'E'))
            .ok_or_else(format_error)?
    } else {
        raw.len
    };
    let mut end = marker;
    if raw.as_bytes()[..marker].contains(&b'.') {
        while end > 0 && raw.as_bytes()[end - 1] == b'0' {
            end -= 1;
        }
        if end > 0 && raw.as_bytes()[end - 1] == b'.' {
            end -= 1;
        }
    }
    let mut output = Text::new();
    output.extend(&raw.as_bytes()[..end])?;
    output.extend(&raw.as_bytes()[marker..])?;
    Ok(output)
}

fn force_decimal_point(raw: &Text, exponent: bool) -> Result<Text, RuntimeError> {
    let marker = if exponent {
        raw.as_bytes()
            .iter()
            .position(|byte| matches!(byte, b'e' | b'E'))
            .ok_or_else(format_error)?
    } else {
        raw.len
    };
    if raw.as_bytes()[..marker].contains(&b'.') {
        return Ok(*raw);
    }
    let mut output = Text::new();
    output.extend(&raw.as_bytes()[..marker])?;
    output.push(b'.')?;
    output.extend(&raw.as_bytes()[marker..])?;
    Ok(output)
}

fn hex_float(
    number: f64,
    precision: Option<usize>,
    alternate: bool,
    uppercase: bool,
) -> Result<Text, RuntimeError> {
    let mut output = Text::new();
    if number.is_nan() {
        output.extend(if uppercase { b"NAN" } else { b"nan" })?;
        return Ok(output);
    }
    if number.is_infinite() {
        output.extend(if uppercase { b"INF" } else { b"inf" })?;
        return Ok(output);
    }
    let bits = number.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = bits & ((1_u64 << 52) - 1);
    let (mut lead, power) = if exponent == 0 {
        (0_u64, if mantissa == 0 { 0 } else { -1022 })
    } else {
        (1_u64, exponent - 1023)
    };
    let requested = precision.unwrap_or(13);
    let mut fraction = mantissa;
    let mut digits = requested.min(13);
    if digits < 13 {
        let shift = 4 * (13 - digits);
        let mask = (1_u64 << shift) - 1;
        let remainder = fraction & mask;
        fraction >>= shift;
        let half = 1_u64 << (shift - 1);
        let parity = if digits == 0 { lead } else { fraction };
        if remainder > half || (remainder == half && parity & 1 == 1) {
            fraction += 1;
            let overflow = 1_u64 << (4 * digits);
            if fraction == overflow {
                lead += 1;
                fraction = 0;
            }
        }
    }
    if precision.is_none() {
        while digits > 0 && fraction & 0xf == 0 {
            fraction >>= 4;
            digits -= 1;
        }
    }
    output.extend(if uppercase { b"0X" } else { b"0x" })?;
    write!(output, "{lead}").map_err(|_| format_error())?;
    if requested > 0 && (precision.is_some() || digits > 0) || alternate {
        output.push(b'.')?;
        for index in (0..digits).rev() {
            let nibble = ((fraction >> (4 * index)) & 0xf) as u8;
            let ascii = if nibble < 10 {
                b'0' + nibble
            } else if uppercase {
                b'A' + nibble - 10
            } else {
                b'a' + nibble - 10
            };
            output.push(ascii)?;
        }
        if precision.is_some() {
            for _ in digits..requested {
                output.push(b'0')?;
            }
        }
    }
    output.push(if uppercase { b'P' } else { b'p' })?;
    output.push(if power < 0 { b'-' } else { b'+' })?;
    write!(output, "{}", power.unsigned_abs()).map_err(|_| format_error())?;
    Ok(output)
}

fn float_piece(vm: &Vm, spec: Spec, value: Value) -> Result<Text, RuntimeError> {
    let number = number(vm, value)?;
    let magnitude = number.abs();
    let upper = matches!(spec.kind, b'A' | b'E' | b'F' | b'G');
    let mut raw = if matches!(spec.kind, b'a' | b'A') {
        hex_float(magnitude, spec.precision, spec.alternative, upper)?
    } else if !number.is_finite() {
        let mut special = Text::new();
        special.extend(if number.is_nan() { b"nan" } else { b"inf" })?;
        if upper {
            for byte in &mut special.bytes[..special.len] {
                *byte = byte.to_ascii_uppercase();
            }
        }
        special
    } else if matches!(spec.kind, b'e' | b'E') {
        let (scientific, _) = scientific(magnitude, spec.precision.unwrap_or(6), upper)?;
        if spec.alternative && spec.precision == Some(0) {
            force_decimal_point(&scientific, true)?
        } else {
            scientific
        }
    } else if matches!(spec.kind, b'f' | b'F') {
        let precision = spec.precision.unwrap_or(6);
        let mut fixed = Text::new();
        write!(fixed, "{magnitude:.precision$}").map_err(|_| format_error())?;
        if spec.alternative && precision == 0 {
            fixed = force_decimal_point(&fixed, false)?;
        }
        fixed
    } else {
        let precision = spec.precision.unwrap_or(6).max(1);
        let (scientific, exponent) = scientific(magnitude, precision - 1, upper)?;
        if exponent < -4 || exponent >= precision as i32 {
            if spec.alternative {
                force_decimal_point(&scientific, true)?
            } else {
                trim_decimal(&scientific, true)?
            }
        } else {
            let fractional = (precision as i32 - exponent - 1).max(0) as usize;
            let mut fixed = Text::new();
            write!(fixed, "{magnitude:.fractional$}").map_err(|_| format_error())?;
            if spec.alternative {
                force_decimal_point(&fixed, false)?
            } else {
                trim_decimal(&fixed, false)?
            }
        }
    };
    if number.is_sign_negative() {
        let mut signed = Text::new();
        signed.push(b'-')?;
        signed.extend(raw.as_bytes())?;
        raw = signed;
    } else if spec.plus || spec.space {
        let mut signed = Text::new();
        signed.push(if spec.plus { b'+' } else { b' ' })?;
        signed.extend(raw.as_bytes())?;
        raw = signed;
    }
    apply_width(spec, raw.as_bytes(), true)
}

fn number_piece(vm: &Vm, spec: Spec, value: Value) -> Result<Text, RuntimeError> {
    if matches!(
        spec.kind,
        b'a' | b'A' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G'
    ) {
        float_piece(vm, spec, value)
    } else {
        integer_piece(vm, spec, value)
    }
}

fn quote_length(vm: &Vm, value: Value) -> Result<usize, RuntimeError> {
    string::with_bytes(vm, value, |bytes| {
        let mut length = 2_usize;
        for (index, byte) in bytes.iter().copied().enumerate() {
            let width = if matches!(byte, b'"' | b'\\' | b'\n') {
                2
            } else if byte.is_ascii_control() {
                if bytes.get(index + 1).is_some_and(u8::is_ascii_digit) {
                    4
                } else {
                    2 + usize::from(byte >= 10) + usize::from(byte >= 100)
                }
            } else {
                1
            };
            length = length
                .checked_add(width)
                .ok_or(VmError::ArithmeticOverflow)?;
        }
        Ok(length)
    })
}

pub(crate) fn prepare_piece(vm: &Vm, spec: Spec, value: Value) -> Result<Piece, RuntimeError> {
    let mut text = Text::new();
    match spec.kind {
        b'q' => match value {
            Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
                return Ok(Piece::Quoted(value, quote_length(vm, value)?));
            }
            Value::Nil => text.extend(b"nil")?,
            Value::Boolean(false) => text.extend(b"false")?,
            Value::Boolean(true) => text.extend(b"true")?,
            Value::Integer(number) => {
                if number == i64::MIN {
                    write!(text, "0x{:x}", number as u64).map_err(|_| format_error())?;
                } else {
                    write!(text, "{number}").map_err(|_| format_error())?;
                }
            }
            Value::Float(number) => {
                if number.is_nan() {
                    text.extend(b"(0/0)")?;
                } else if number == f64::INFINITY {
                    text.extend(b"1e9999")?;
                } else if number == f64::NEG_INFINITY {
                    text.extend(b"-1e9999")?;
                } else {
                    if number.is_sign_negative() {
                        text.push(b'-')?;
                    }
                    let quoted = hex_float(number.abs(), None, false, false)?;
                    text.extend(quoted.as_bytes())?;
                }
            }
            _ => return Err(format_error()),
        },
        b'c' => {
            let value = integer(vm, value)?;
            text.push(value as u8)?;
            text = apply_width(spec, text.as_bytes(), false)?;
        }
        b'p' => {
            match value {
                Value::Nil => text.extend(b"(null)")?,
                Value::Object(object) => {
                    write!(text, "0x{:?}", object.identity()).map_err(|_| format_error())?
                }
                _ => text.extend(b"(null)")?,
            }
            text = apply_width(spec, text.as_bytes(), false)?;
        }
        b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'a' | b'A' | b'e' | b'E' | b'f' | b'F'
        | b'g' | b'G' => {
            text = number_piece(vm, spec, value)?;
        }
        _ => return Err(format_error()),
    }
    Ok(Piece::Small(text))
}

impl FormatState {
    pub(crate) fn append_piece(&mut self, vm: &Vm, piece: Piece) -> Result<(), RuntimeError> {
        match piece {
            Piece::Small(text) => self.append_bytes(vm, text.as_bytes()),
            Piece::Quoted(value, length) => {
                self.check_size(vm, length)?;
                self.buffer.reserve_extra(length)?;
                string::with_bytes(vm, value, |bytes| {
                    self.buffer.bytes.push(b'"');
                    for (index, byte) in bytes.iter().copied().enumerate() {
                        if matches!(byte, b'"' | b'\\' | b'\n') {
                            self.buffer.bytes.push(b'\\');
                            self.buffer.bytes.push(byte);
                        } else if byte.is_ascii_control() {
                            self.buffer.bytes.push(b'\\');
                            let three = bytes.get(index + 1).is_some_and(u8::is_ascii_digit);
                            if three {
                                self.buffer.bytes.push(b'0' + byte / 100);
                                self.buffer.bytes.push(b'0' + (byte / 10) % 10);
                                self.buffer.bytes.push(b'0' + byte % 10);
                            } else {
                                if byte >= 100 {
                                    self.buffer.bytes.push(b'0' + byte / 100);
                                }
                                if byte >= 10 {
                                    self.buffer.bytes.push(b'0' + (byte / 10) % 10);
                                }
                                self.buffer.bytes.push(b'0' + byte % 10);
                            }
                        } else {
                            self.buffer.bytes.push(byte);
                        }
                    }
                    self.buffer.bytes.push(b'"');
                    Ok(())
                })?;
                Ok(())
            }
        }
    }
}
