#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BasicBuiltin {
    Assert,
    CollectGarbage,
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
        BasicBuiltin::CollectGarbage => {
            let operation = match args.first().copied().unwrap_or(Value::Nil) {
                Value::Nil => Some(4),
                Value::Object(option) if vm.object_kind(option)? == ObjectKind::ByteString => vm
                    .with_byte_string(option, |string| match string.as_bytes() {
                        b"count" => Some(0),
                        b"isrunning" => Some(1),
                        b"stop" => Some(2),
                        b"restart" => Some(3),
                        b"collect" => Some(4),
                        b"incremental" => Some(5),
                        b"generational" => Some(6),
                        b"step" => Some(7),
                        b"param" if vm.language_profile() == rivetlua_core::LuaProfile::Lua55 => {
                            Some(8)
                        }
                        _ => None,
                    })?,
                _ => return Err(argument()),
            };
            match operation {
                Some(0) => {
                    let bytes = vm.ledger_snapshot().lua_heap_bytes;
                    result(vm, &[Value::Float(bytes as f64 / 1024.0)])
                }
                Some(1..=8) if vm.finalizer_running() => result(vm, &[Value::Nil]),
                Some(1) => result(vm, &[Value::Boolean(vm.automatic_gc_running())]),
                Some(2) => {
                    let output = result(vm, &[Value::Integer(0)])?;
                    vm.stop_automatic_gc();
                    Ok(output)
                }
                Some(3) => {
                    let output = result(vm, &[Value::Integer(0)])?;
                    vm.restart_automatic_gc();
                    Ok(output)
                }
                Some(4) => {
                    let output = result(vm, &[Value::Integer(0)])?;
                    vm.collect()?;
                    Ok(output)
                }
                Some(5 | 6) => {
                    let requested = if operation == Some(5) {
                        GcMode::Incremental
                    } else {
                        GcMode::Generational
                    };
                    let previous = vm.gc_mode();
                    let (mut values, ticket) = result(vm, &[Value::Nil])?;
                    let name = match previous {
                        GcMode::Incremental => b"incremental".as_slice(),
                        GcMode::Generational => b"generational".as_slice(),
                    };
                    let string = vm.allocate_byte_string(name)?;
                    let root = vm.add_root(RootKind::Temporary, string)?;
                    let switched = (|| {
                        if requested != previous {
                            while vm.gc_trace().phase != GcPhase::Pause {
                                vm.incremental_step(1024)?;
                            }
                            vm.set_gc_mode(requested)?;
                        }
                        Ok::<(), VmError>(())
                    })();
                    let removed = vm.remove_root(root);
                    switched?;
                    removed?;
                    values[0] = Value::Object(string);
                    Ok((values, ticket))
                }
                Some(7) => {
                    let size = match args.get(1).copied().unwrap_or(Value::Nil) {
                        Value::Nil => 0,
                        value => lua_integer(number(vm, value, None)?).ok_or_else(argument)?,
                    };
                    let (mut values, ticket) = result(vm, &[Value::Boolean(false)])?;
                    values[0] = Value::Boolean(vm.explicit_gc_step(size)?);
                    Ok((values, ticket))
                }
                Some(8) => {
                    let Value::Object(name_object) = arg(args, 1)? else {
                        return Err(argument());
                    };
                    if vm.object_kind(name_object)? != ObjectKind::ByteString {
                        return Err(argument());
                    }
                    let parameter = vm
                        .with_byte_string(name_object, |string| match string.as_bytes() {
                            b"pause" => Some(GcParameter::Pause),
                            b"stepmul" => Some(GcParameter::StepMultiplier),
                            _ => None,
                        })?
                        .ok_or_else(argument)?;
                    let previous = vm.gc_param(parameter);
                    let new_value = match args.get(2).copied().unwrap_or(Value::Nil) {
                        Value::Nil => None,
                        value => Some(lua_integer(number(vm, value, None)?).ok_or_else(argument)?),
                    };
                    let previous =
                        i64::try_from(previous).map_err(|_| VmError::ArithmeticOverflow)?;
                    let output = result(vm, &[Value::Integer(previous)])?;
                    if let Some(value) = new_value.filter(|value| *value >= 0) {
                        vm.set_gc_param(parameter, value);
                    }
                    Ok(output)
                }
                _ => Err(argument()),
            }
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
use crate::gc::GcParameter;
use crate::host::HostServiceError;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{GcMode, GcPhase, ObjectKind, RootKind, Vm, VmError};

#[cfg(test)]
mod p13_a_tests {
    use super::*;
    use crate::HostHandle;
    use rivetlua_core::{LuaProfile, Value};

    #[test]
    fn collectgarbage_count_reads_only_lua_heap_and_retries_after_result_failure() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let option = vm.allocate_byte_string(b"count").unwrap();
            let _option_root = HostHandle::<Value>::new(&mut vm, option).unwrap();
            let host = vm.allocation_ledger().reserve(4096).unwrap();
            host.commit().unwrap();
            vm.observe_shared_rss(32 * 1024 * 1024);
            let before = vm.ledger_snapshot();
            assert_eq!(before.shared_rss_observation, Some(32 * 1024 * 1024));
            let gc_before = vm.gc_trace();
            let (values, reservation) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(option)],
                0,
            )
            .unwrap();
            assert_eq!(
                values,
                [Value::Float(before.lua_heap_bytes as f64 / 1024.0)]
            );
            drop(reservation);
            assert_eq!(vm.ledger_snapshot().lua_heap_bytes, before.lua_heap_bytes);
            assert_eq!(vm.gc_trace(), gc_before);
            assert_eq!(
                vm.ledger_snapshot().host_allocation_bytes,
                before.host_allocation_bytes
            );
            assert_eq!(vm.ledger_snapshot().reserved, 0);

            vm.inject_failure_once(FailPoint::ReturnReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(option)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::ReturnReserve
                    )),
                    ..
                })
            ));
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            let (values, reservation) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(option)],
                0,
            )
            .unwrap();
            assert_eq!(
                values,
                [Value::Float(before.lua_heap_bytes as f64 / 1024.0)]
            );
            drop(reservation);

            let before_fault = vm.ledger_snapshot();
            let roots = vm.roots().total_count();
            let ordinal = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(ordinal);
            assert!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(option)],
                    0,
                )
                .is_err()
            );
            assert_eq!(
                vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
                ordinal
            );
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), before_fault);
            let (values, reservation) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(option)],
                0,
            )
            .unwrap();
            assert_eq!(
                values,
                [Value::Float(before.lua_heap_bytes as f64 / 1024.0)]
            );
            drop(reservation);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), before_fault);
            vm.allocation_ledger().refund(4096).unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

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

#[cfg(test)]
mod gc_running_tests {
    use super::*;
    use crate::HostHandle;
    use crate::{GcCycleKind, GcMode, GcPhase};
    use rivetlua_core::LuaProfile;

    #[test]
    fn mode_controls_start_generational_and_retry_after_precommit_failures() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            assert_eq!(vm.gc_mode(), GcMode::Generational);
            vm.stop_automatic_gc();
            let incremental = vm.allocate_byte_string(b"incremental").unwrap();
            let generational = vm.allocate_byte_string(b"generational").unwrap();
            let _incremental_root = HostHandle::<Value>::new(&mut vm, incremental).unwrap();
            let _generational_root = HostHandle::<Value>::new(&mut vm, generational).unwrap();
            let roots = vm.roots().total_count();
            let trace = vm.gc_trace();
            let ledger = vm.ledger_snapshot();

            vm.inject_failure_once(FailPoint::ReturnReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(incremental)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::ReturnReserve
                    )),
                    ..
                })
            ));
            assert_eq!(vm.gc_trace(), trace);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger);
            assert!(!vm.automatic_gc_running());

            vm.inject_failure_once(FailPoint::StringBytesReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(incremental)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::StringBytesReserve
                    )),
                    ..
                })
            ));
            assert_eq!(vm.gc_trace(), trace);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger);
            assert!(!vm.automatic_gc_running());

            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(incremental)],
                0,
            )
            .unwrap();
            let [Value::Object(old)] = values.as_slice() else {
                panic!("前模式應以單一 ByteString 回傳")
            };
            assert!(
                vm.with_byte_string(*old, |bytes| bytes.as_bytes() == b"generational")
                    .unwrap()
            );
            drop(ticket);
            assert_eq!(vm.gc_mode(), GcMode::Incremental);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);

            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(generational)],
                0,
            )
            .unwrap();
            let [Value::Object(old)] = values.as_slice() else {
                panic!("前模式應以單一 ByteString 回傳")
            };
            assert!(
                vm.with_byte_string(*old, |bytes| bytes.as_bytes() == b"incremental")
                    .unwrap()
            );
            drop(ticket);
            assert_eq!(vm.gc_mode(), GcMode::Generational);
            assert!(!vm.automatic_gc_running());
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn mode_same_active_cycle_stays_put_and_switch_finishes_cycle() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let generational = vm.allocate_byte_string(b"generational").unwrap();
            let incremental = vm.allocate_byte_string(b"incremental").unwrap();
            let _generational_root = HostHandle::<Value>::new(&mut vm, generational).unwrap();
            let _incremental_root = HostHandle::<Value>::new(&mut vm, incremental).unwrap();
            vm.incremental_step(1).unwrap();
            let active = vm.gc_trace();
            assert_ne!(active.phase, GcPhase::Pause);
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(generational)],
                0,
            )
            .unwrap();
            let [Value::Object(old)] = values.as_slice() else {
                panic!("相同模式應回傳 ByteString")
            };
            assert!(
                vm.with_byte_string(*old, |bytes| bytes.as_bytes() == b"generational")
                    .unwrap()
            );
            drop(ticket);
            assert_eq!(vm.gc_trace().phase, active.phase);
            assert_eq!(vm.gc_trace().transition_count, active.transition_count);
            assert_eq!(vm.gc_mode(), GcMode::Generational);

            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(incremental)],
                0,
            )
            .unwrap();
            let [Value::Object(old)] = values.as_slice() else {
                panic!("切換模式應回傳 ByteString")
            };
            assert!(
                vm.with_byte_string(*old, |bytes| bytes.as_bytes() == b"generational")
                    .unwrap()
            );
            drop(ticket);
            let completed = vm.gc_trace();
            assert_eq!(completed.phase, GcPhase::Pause);
            assert!(completed.transition_count > active.transition_count);
            assert_eq!(completed.remembered_len, 0);
            assert_eq!(vm.gc_mode(), GcMode::Incremental);
            assert!(!vm.automatic_gc_running());
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn mode_root_reserve_failure_leaves_no_root_or_return_ticket_and_retries() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let incremental = vm.allocate_byte_string(b"incremental").unwrap();
            let _option_root = HostHandle::<Value>::new(&mut vm, incremental).unwrap();
            let roots = vm.roots().total_count();
            vm.inject_failure_once(FailPoint::RootReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(incremental)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(FailPoint::RootReserve)),
                    ..
                })
            ));
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.gc_mode(), GcMode::Generational);
            assert!(!vm.automatic_gc_running());
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(incremental)],
                0,
            )
            .unwrap();
            let [Value::Object(old)] = values.as_slice() else {
                panic!("失敗後重試應回傳 ByteString")
            };
            assert!(
                vm.with_byte_string(*old, |bytes| bytes.as_bytes() == b"generational")
                    .unwrap()
            );
            drop(ticket);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.gc_mode(), GcMode::Incremental);
            vm.collect().unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn mode_finalizer_returns_nil_without_state_changes() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let incremental = vm.allocate_byte_string(b"incremental").unwrap();
            let generational = vm.allocate_byte_string(b"generational").unwrap();
            let _incremental_root = HostHandle::<Value>::new(&mut vm, incremental).unwrap();
            let _generational_root = HostHandle::<Value>::new(&mut vm, generational).unwrap();
            let target = vm.allocate_table().unwrap();
            let metatable = vm.allocate_table().unwrap();
            let key = vm.allocate_byte_string(b"__gc").unwrap();
            vm.raw_set(metatable, Value::Object(key), Value::Integer(1))
                .unwrap();
            vm.set_metatable(target, Some(metatable)).unwrap();
            vm.set_execution_running(true);
            vm.incremental_step(1).unwrap();
            for _ in 0..8192 {
                if vm.gc_trace().phase == GcPhase::Pause {
                    break;
                }
                vm.incremental_step(1).unwrap();
            }
            assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
            let (queued, _) = vm.pending_finalizer().unwrap().unwrap();
            assert_eq!(queued, target);
            vm.start_finalizer(queued).unwrap();
            let trace = vm.gc_trace();
            let roots = vm.roots().total_count();
            let ledger = vm.ledger_snapshot();
            for option in [incremental, generational] {
                let (values, ticket) = execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(option)],
                    0,
                )
                .unwrap();
                assert_eq!(values, [Value::Nil]);
                drop(ticket);
                assert_eq!(vm.gc_trace(), trace);
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.ledger_snapshot(), ledger);
                assert_eq!(vm.gc_mode(), GcMode::Generational);
                assert!(!vm.automatic_gc_running());
            }
            vm.finish_finalizer(queued).unwrap();
            vm.set_execution_running(false);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn explicit_collect_reserves_result_before_gc_and_retries_after_mark_failure() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let collect = vm.allocate_byte_string(b"collect").unwrap();
            let _option_root = HostHandle::<Value>::new(&mut vm, collect).unwrap();
            let retained = vm.allocate_byte_string(b"rooted").unwrap();
            let _retained_root = HostHandle::<Value>::new(&mut vm, retained).unwrap();

            for args in [
                Vec::new(),
                vec![Value::Nil],
                vec![Value::Object(collect), Value::Integer(99)],
            ] {
                let victim = vm.allocate_byte_string(b"unreachable").unwrap();
                let trace = vm.gc_trace();
                let roots = vm.roots().total_count();
                let ledger = vm.ledger_snapshot();
                vm.inject_failure_once(FailPoint::ReturnReserve);
                assert!(matches!(
                    execute(&mut vm, BasicBuiltin::CollectGarbage, &args, 0),
                    Err(RuntimeError {
                        kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                            FailPoint::ReturnReserve
                        )),
                        ..
                    })
                ));
                assert_eq!(vm.gc_trace(), trace);
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.ledger_snapshot(), ledger);
                assert!(!vm.automatic_gc_running());
                assert_eq!(vm.object_kind(victim), Ok(ObjectKind::ByteString));

                vm.inject_failure_once(FailPoint::MarkReserve);
                assert!(matches!(
                    execute(&mut vm, BasicBuiltin::CollectGarbage, &args, 0),
                    Err(RuntimeError {
                        kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                            FailPoint::MarkReserve
                        )),
                        ..
                    })
                ));
                assert_eq!(vm.gc_trace(), trace);
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.ledger_snapshot(), ledger);
                assert!(!vm.automatic_gc_running());
                assert_eq!(vm.object_kind(victim), Ok(ObjectKind::ByteString));

                let (values, ticket) =
                    execute(&mut vm, BasicBuiltin::CollectGarbage, &args, 0).unwrap();
                assert_eq!(values, [Value::Integer(0)]);
                drop(ticket);
                assert_eq!(vm.object_kind(victim), Err(VmError::StaleObject));
                assert_eq!(vm.object_kind(retained), Ok(ObjectKind::ByteString));
                assert!(!vm.automatic_gc_running());
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            }
        }
    }

    #[test]
    fn explicit_collect_finishes_active_cycle_then_runs_major_while_stopped() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.set_gc_major_threshold(usize::MAX).unwrap();
            let victim = vm.allocate_byte_string(b"unreachable").unwrap();
            vm.incremental_step(1).unwrap();
            let active = vm.gc_trace();
            assert_ne!(active.phase, GcPhase::Pause);
            assert_eq!(active.cycle, GcCycleKind::Minor);
            let (values, ticket) = execute(&mut vm, BasicBuiltin::CollectGarbage, &[], 0).unwrap();
            assert_eq!(values, [Value::Integer(0)]);
            drop(ticket);
            let completed = vm.gc_trace();
            assert_eq!(completed.phase, GcPhase::Pause);
            assert_eq!(completed.cycle, GcCycleKind::Major);
            assert!(completed.transition_count > active.transition_count);
            assert_eq!(vm.object_kind(victim), Err(VmError::StaleObject));
            assert!(!vm.automatic_gc_running());
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn explicit_collect_in_running_finalizer_returns_nil_without_gc_changes() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let option = vm.allocate_byte_string(b"collect").unwrap();
            let _option_root = HostHandle::<Value>::new(&mut vm, option).unwrap();
            let target = vm.allocate_table().unwrap();
            let metatable = vm.allocate_table().unwrap();
            let key = vm.allocate_byte_string(b"__gc").unwrap();
            vm.raw_set(metatable, Value::Object(key), Value::Integer(1))
                .unwrap();
            vm.set_metatable(target, Some(metatable)).unwrap();
            vm.set_execution_running(true);
            vm.incremental_step(1).unwrap();
            for _ in 0..8192 {
                if vm.gc_trace().phase == GcPhase::Pause {
                    break;
                }
                vm.incremental_step(1).unwrap();
            }
            assert_eq!(vm.gc_trace().phase, GcPhase::Pause);
            let (queued, _) = vm.pending_finalizer().unwrap().unwrap();
            assert_eq!(queued, target);
            vm.start_finalizer(queued).unwrap();
            let trace = vm.gc_trace();
            let roots = vm.roots().total_count();
            let ledger = vm.ledger_snapshot();
            for args in [Vec::new(), vec![Value::Nil], vec![Value::Object(option)]] {
                let (values, ticket) =
                    execute(&mut vm, BasicBuiltin::CollectGarbage, &args, 0).unwrap();
                assert_eq!(values, [Value::Nil]);
                drop(ticket);
                assert_eq!(vm.gc_trace(), trace);
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.ledger_snapshot(), ledger);
                assert!(!vm.automatic_gc_running());
            }
            vm.finish_finalizer(queued).unwrap();
            vm.set_execution_running(false);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn controls_commit_only_after_return_reserve_and_actual_ordinal() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let stop = vm.allocate_byte_string(b"stop").unwrap();
            let restart = vm.allocate_byte_string(b"restart").unwrap();
            let query = vm.allocate_byte_string(b"isrunning").unwrap();
            let _stop_root = HostHandle::<Value>::new(&mut vm, stop).unwrap();
            let _restart_root = HostHandle::<Value>::new(&mut vm, restart).unwrap();
            let _query_root = HostHandle::<Value>::new(&mut vm, query).unwrap();

            let roots = vm.roots().total_count();
            let gc_before = vm.gc_trace();
            let ledger_before = vm.ledger_snapshot();
            vm.inject_failure_once(FailPoint::ReturnReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(stop)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::ReturnReserve
                    )),
                    ..
                })
            ));
            assert!(vm.automatic_gc_running());
            assert_eq!(vm.gc_trace(), gc_before);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger_before);
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(stop)],
                0,
            )
            .unwrap();
            assert_eq!(values, [Value::Integer(0)]);
            drop(ticket);
            assert!(!vm.automatic_gc_running());

            vm.allocate_byte_string(b"debt while stopped").unwrap();
            let gc_stopped = vm.gc_trace();
            assert!(gc_stopped.debt_bytes > 0);
            let ledger_stopped = vm.ledger_snapshot();
            let ordinal = vm.allocation_trace().next_ordinal;
            vm.inject_allocation_failure_at(ordinal);
            assert!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(restart)],
                    0
                )
                .is_err()
            );
            let failure = vm.allocation_trace().last_failure.unwrap();
            assert_eq!(failure.attempt.ordinal, ordinal);
            assert_eq!(failure.attempt.point, Some(FailPoint::ReturnReserve));
            assert!(!vm.automatic_gc_running());
            assert_eq!(vm.gc_trace(), gc_stopped);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger_stopped);
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(restart)],
                0,
            )
            .unwrap();
            assert_eq!(values, [Value::Integer(0)]);
            drop(ticket);
            assert!(vm.automatic_gc_running());
            assert_eq!(vm.gc_trace().debt_bytes, 0);

            let gc_running = vm.gc_trace();
            let ledger_running = vm.ledger_snapshot();
            vm.inject_failure_once(FailPoint::ReturnReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(query)],
                    0
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::ReturnReserve
                    )),
                    ..
                })
            ));
            assert!(vm.automatic_gc_running());
            assert_eq!(vm.gc_trace(), gc_running);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger_running);
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(query)],
                0,
            )
            .unwrap();
            assert_eq!(values, [Value::Boolean(true)]);
            drop(ticket);
            assert_eq!(vm.gc_trace(), gc_running);
            assert_eq!(vm.ledger_snapshot(), ledger_running);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn param_and_step_commit_only_after_return_reserve() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.stop_automatic_gc();
            let step = vm.allocate_byte_string(b"step").unwrap();
            let _step_root = HostHandle::<Value>::new(&mut vm, step).unwrap();
            let trace = vm.gc_trace();
            let roots = vm.roots().total_count();
            let ledger = vm.ledger_snapshot();
            vm.inject_failure_once(FailPoint::ReturnReserve);
            assert!(matches!(
                execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(step), Value::Integer(0)],
                    0,
                ),
                Err(RuntimeError {
                    kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                        FailPoint::ReturnReserve
                    )),
                    ..
                })
            ));
            assert_eq!(vm.gc_trace(), trace);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot(), ledger);
            assert!(!vm.automatic_gc_running());
            let (values, ticket) = execute(
                &mut vm,
                BasicBuiltin::CollectGarbage,
                &[Value::Object(step), Value::Integer(0)],
                0,
            )
            .unwrap();
            assert!(matches!(values.as_slice(), [Value::Boolean(_)]));
            drop(ticket);
            assert!(!vm.automatic_gc_running());
            assert_eq!(vm.ledger_snapshot().reserved, 0);

            if profile == LuaProfile::Lua55 {
                let param = vm.allocate_byte_string(b"param").unwrap();
                let pause = vm.allocate_byte_string(b"pause").unwrap();
                let _param_root = HostHandle::<Value>::new(&mut vm, param).unwrap();
                let _pause_root = HostHandle::<Value>::new(&mut vm, pause).unwrap();
                let trace = vm.gc_trace();
                let roots = vm.roots().total_count();
                let ledger = vm.ledger_snapshot();
                vm.inject_failure_once(FailPoint::ReturnReserve);
                assert!(matches!(
                    execute(
                        &mut vm,
                        BasicBuiltin::CollectGarbage,
                        &[
                            Value::Object(param),
                            Value::Object(pause),
                            Value::Integer(500),
                        ],
                        0,
                    ),
                    Err(RuntimeError {
                        kind: RuntimeErrorKind::Heap(VmError::InjectedFailure(
                            FailPoint::ReturnReserve
                        )),
                        ..
                    })
                ));
                assert_eq!(vm.gc_trace(), trace);
                assert_eq!(vm.roots().total_count(), roots);
                assert_eq!(vm.ledger_snapshot(), ledger);
                let (values, ticket) = execute(
                    &mut vm,
                    BasicBuiltin::CollectGarbage,
                    &[Value::Object(param), Value::Object(pause)],
                    0,
                )
                .unwrap();
                assert_eq!(values, [Value::Integer(250)]);
                drop(ticket);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
            }
        }
    }
}
