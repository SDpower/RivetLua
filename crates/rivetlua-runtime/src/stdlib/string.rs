//! 以 Lua bytes 運作的 string 函式庫；暫存輸出由 VM 帳本計費。

use core::fmt::{self, Write};

use rivetlua_core::{LuaProfile, Value};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, reserve_vec};
use crate::pending_op::PrintArguments;
use crate::stdlib::pack;
use crate::stdlib::pattern::Found;
use crate::stdlib::{basic, table};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, RootKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StringBuiltin {
    Byte,
    Char,
    Find,
    Match,
    GMatch,
    GSub,
    Len,
    Lower,
    Upper,
    Rep,
    Reverse,
    Sub,
    Format,
    Dump,
    Pack,
    Unpack,
    PackSize,
}

fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringArgument)
}

struct ErrorText {
    bytes: [u8; 96],
    len: usize,
}

impl ErrorText {
    fn new() -> Self {
        Self {
            bytes: [0; 96],
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

fn argument_with_message(vm: &mut Vm, message: &[u8]) -> Result<RuntimeError, RuntimeError> {
    let mut error = argument();
    error.value = Value::Object(vm.allocate_byte_string(message)?);
    Ok(error)
}

fn char_range_error(vm: &mut Vm, index: usize) -> Result<RuntimeError, RuntimeError> {
    let mut message = ErrorText::new();
    write!(message, "bad argument #{index} to 'char' (value out of range)")
        .map_err(|_| VmError::ArithmeticOverflow)?;
    argument_with_message(vm, message.as_bytes())
}

pub(crate) fn rep_too_large_error(vm: &mut Vm) -> Result<RuntimeError, RuntimeError> {
    argument_with_message(vm, b"resulting string too large")
}

pub(crate) fn arg(args: &[Value], index: usize) -> Result<Value, RuntimeError> {
    args.get(index).copied().ok_or_else(argument)
}

pub(crate) fn integer(vm: &Vm, value: Value) -> Result<i64, RuntimeError> {
    let number = basic::number(vm, value, None)?;
    basic::lua_integer(number).ok_or_else(argument)
}

pub(crate) fn optional_integer(
    vm: &Vm,
    value: Option<Value>,
    default: i64,
) -> Result<i64, RuntimeError> {
    match value {
        None | Some(Value::Nil) => Ok(default),
        Some(value) => integer(vm, value),
    }
}

pub(crate) fn with_bytes<R>(
    vm: &Vm,
    value: Value,
    f: impl FnOnce(&[u8]) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    match value {
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            vm.with_byte_string(object, |stored| f(stored.as_bytes()))?
        }
        Value::Integer(_) | Value::Float(_) => {
            let (bytes, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            f(&bytes[..len])
        }
        _ => Err(argument()),
    }
}

pub(crate) fn max_size(profile: LuaProfile) -> usize {
    let language = match profile {
        LuaProfile::Lua54 => i32::MAX as u64,
        LuaProfile::Lua55 => i64::MAX as u64,
    };
    usize::try_from(language).unwrap_or(usize::MAX)
}

pub(crate) fn start_position(position: i64, len: usize) -> usize {
    if position > 0 {
        usize::try_from(position).unwrap_or(usize::MAX)
    } else if position == 0 {
        1
    } else {
        let backward = position.unsigned_abs() as usize;
        if backward > len {
            1
        } else {
            len - backward + 1
        }
    }
}

fn end_position(position: i64, len: usize) -> usize {
    if position >= 0 {
        usize::try_from(position).unwrap_or(usize::MAX).min(len)
    } else {
        let backward = position.unsigned_abs() as usize;
        if backward > len {
            0
        } else {
            len - backward + 1
        }
    }
}

fn range(vm: &Vm, args: &[Value], len: usize, byte: bool) -> Result<(usize, usize), RuntimeError> {
    let first = optional_integer(vm, args.get(1).copied(), 1)?;
    let last = optional_integer(vm, args.get(2).copied(), if byte { first } else { -1 })?;
    Ok((start_position(first, len), end_position(last, len)))
}

pub(crate) enum RepLength {
    Length(usize),
    TooLarge,
}

pub(crate) fn rep_len(vm: &Vm, args: &[Value]) -> Result<RepLength, RuntimeError> {
    let count = integer(vm, arg(args, 1)?)?;
    let source_len = table::string_len(vm, arg(args, 0)?)?;
    let separator_len = match args.get(2).copied() {
        None | Some(Value::Nil) => 0,
        Some(value) => table::string_len(vm, value)?,
    };
    if count <= 0 || source_len | separator_len == 0 {
        return Ok(RepLength::Length(0));
    }
    let unit = (source_len as u128)
        .checked_add(separator_len as u128)
        .ok_or(VmError::ArithmeticOverflow)?;
    let total_with_last_separator = unit
        .checked_mul(count as u128)
        .ok_or(VmError::ArithmeticOverflow)?;
    if total_with_last_separator > max_size(vm.language_profile()) as u128 {
        return Ok(RepLength::TooLarge);
    }
    let total = total_with_last_separator
        .checked_sub(separator_len as u128)
        .ok_or(VmError::ArithmeticOverflow)?;
    Ok(RepLength::Length(
        usize::try_from(total).map_err(|_| VmError::ArithmeticOverflow)?,
    ))
}

pub(crate) fn numeric_parse_units(
    vm: &Vm,
    kind: StringBuiltin,
    args: &[Value],
    available: u64,
) -> Result<usize, RuntimeError> {
    let mut total = 0_usize;
    for (index, value) in args.iter().copied().enumerate() {
        let numeric = match kind {
            StringBuiltin::Char => true,
            StringBuiltin::Byte | StringBuiltin::Sub => index == 1 || index == 2,
            StringBuiltin::Rep => index == 1,
            StringBuiltin::Format => index >= 1,
            StringBuiltin::Find | StringBuiltin::Match | StringBuiltin::GMatch => index == 2,
            StringBuiltin::GSub => index == 3,
            StringBuiltin::Pack => index >= 1,
            StringBuiltin::Unpack => index == 2,
            _ => false,
        };
        if !numeric {
            continue;
        }
        if let Value::Object(object) = value {
            if vm.object_kind(object)? == ObjectKind::ByteString {
                total = total.saturating_add(vm.with_byte_string(object, |stored| stored.len())?);
            }
        }
    }
    let cap = usize::try_from(available.saturating_add(1)).unwrap_or(usize::MAX);
    Ok(total.min(cap))
}

pub(crate) fn work_units(
    vm: &Vm,
    kind: StringBuiltin,
    args: &[Value],
    available: u64,
) -> Result<usize, RuntimeError> {
    let work = match kind {
        StringBuiltin::Byte => {
            let len = table::string_len(vm, arg(args, 0)?)?;
            let (first, last) = range(vm, args, len, true)?;
            if first > last { 1 } else { last - first + 1 }
        }
        StringBuiltin::Char => args.len().max(1),
        StringBuiltin::Rep => match rep_len(vm, args)? {
            RepLength::Length(length) => length.max(1),
            RepLength::TooLarge => return Err(argument()),
        },
        StringBuiltin::Pack => pack::pack_size(vm, args)?.max(1),
        StringBuiltin::Unpack => table::string_len(vm, arg(args, 1)?)?.max(1),
        StringBuiltin::PackSize => 1,
        StringBuiltin::GSub => {
            let base = table::string_len(vm, arg(args, 0)?)?
                .saturating_add(table::string_len(vm, arg(args, 1)?)?);
            let replacement = arg(args, 2)?;
            let text = match replacement {
                Value::Integer(_) | Value::Float(_) => true,
                Value::Object(object) => vm.object_kind(object)? == ObjectKind::ByteString,
                _ => false,
            };
            base.saturating_add(if text {
                table::string_len(vm, replacement)?
            } else {
                0
            })
            .max(1)
        }
        StringBuiltin::Find | StringBuiltin::Match | StringBuiltin::GMatch => {
            table::string_len(vm, arg(args, 0)?)?
                .saturating_add(table::string_len(vm, arg(args, 1)?)?)
                .max(1)
        }
        StringBuiltin::Len
        | StringBuiltin::Lower
        | StringBuiltin::Upper
        | StringBuiltin::Reverse
        | StringBuiltin::Sub
        | StringBuiltin::Format => table::string_len(vm, arg(args, 0)?)?.max(1),
        _ => 1,
    };
    let cap = usize::try_from(available.saturating_add(1)).unwrap_or(usize::MAX);
    Ok(work.min(cap))
}

pub(crate) struct Buffer {
    pub(crate) bytes: Vec<u8>,
    ledger: AllocationLedger,
    charge: usize,
    owner: Option<crate::alloc::AllocationCharge>,
}

impl Buffer {
    pub(crate) fn new(vm: &Vm, length: usize) -> Result<Self, RuntimeError> {
        let ledger = vm.allocation_ledger().clone();
        let mut bytes = Vec::new();
        let ticket = reserve_vec(&ledger, &mut bytes, length, FailPoint::WorkReserve)?;
        let owner = ticket.commit_charge()?;
        Ok(Self {
            bytes,
            ledger,
            charge: length,
            owner: Some(owner),
        })
    }

    pub(crate) fn empty(vm: &Vm) -> Self {
        Self {
            bytes: Vec::new(),
            ledger: vm.allocation_ledger().clone(),
            charge: 0,
            owner: None,
        }
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        self.reserve_extra(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn reserve_extra(&mut self, additional: usize) -> Result<(), RuntimeError> {
        let needed = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(VmError::ArithmeticOverflow)?;
        if needed <= self.charge {
            return Ok(());
        }
        let next = self
            .charge
            .max(1)
            .checked_mul(2)
            .unwrap_or(needed)
            .max(needed);
        let mut replacement = Vec::new();
        let ticket = reserve_vec(&self.ledger, &mut replacement, next, FailPoint::WorkReserve)?;
        let owner = ticket.commit_charge()?;
        replacement.extend_from_slice(&self.bytes);
        let old = core::mem::replace(&mut self.bytes, replacement);
        drop(old);
        self.owner = Some(owner);
        self.charge = next;
        Ok(())
    }
}

pub(crate) fn values(
    vm: &Vm,
    input: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let mut output = Vec::new();
    let ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut output,
        input.len(),
        FailPoint::ReturnReserve,
    )?;
    output.extend_from_slice(input);
    Ok((output, Some(ticket)))
}

pub(crate) fn string_result(
    vm: &mut Vm,
    buffer: &Buffer,
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let object = vm.allocate_byte_string(&buffer.bytes)?;
    values(vm, &[Value::Object(object)])
}

pub(crate) fn owned_bytes(vm: &Vm, value: Value) -> Result<Buffer, RuntimeError> {
    with_bytes(vm, value, |source| {
        let mut buffer = Buffer::new(vm, source.len())?;
        buffer.bytes.extend_from_slice(source);
        Ok(buffer)
    })
}

pub(crate) fn pattern_results(
    vm: &mut Vm,
    source: &[u8],
    found: Option<Found>,
    find: bool,
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    let Some(found) = found else {
        return values(vm, &[Value::Nil]);
    };
    with_pattern_values(vm, source, found, find, |_, result, ticket| {
        Ok((result, Some(ticket)))
    })
}

pub(crate) fn pattern_callback_arguments(
    vm: &mut Vm,
    source: &[u8],
    found: Found,
) -> Result<PrintArguments, RuntimeError> {
    with_pattern_values(vm, source, found, false, |vm, values, ticket| {
        let arguments = PrintArguments::new(vm, &values)?;
        drop(ticket);
        Ok(arguments)
    })
}

fn with_pattern_values<R>(
    vm: &mut Vm,
    source: &[u8],
    found: Found,
    find: bool,
    consume: impl FnOnce(&mut Vm, Vec<Value>, Reservation) -> Result<R, RuntimeError>,
) -> Result<R, RuntimeError> {
    let count = found.count
        + if find {
            2
        } else if found.count == 0 {
            1
        } else {
            0
        };
    let mut result = Vec::new();
    let ticket = reserve_vec(
        vm.allocation_ledger(),
        &mut result,
        count,
        FailPoint::ReturnReserve,
    )?;
    let mut roots = [None; 33];
    let built = (|| {
        if find {
            result.push(Value::Integer(
                i64::try_from(found.start + 1).map_err(|_| VmError::ArithmeticOverflow)?,
            ));
            result.push(Value::Integer(
                i64::try_from(found.end).map_err(|_| VmError::ArithmeticOverflow)?,
            ));
        }
        let items = if found.count == 0 && !find {
            1
        } else {
            found.count
        };
        for index in 0..items {
            let (first, last, position) = if found.count == 0 {
                (found.start, found.end, false)
            } else {
                let capture = found.captures[index];
                (
                    capture.start,
                    capture
                        .end
                        .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::StringPattern))?,
                    capture.position,
                )
            };
            if position {
                result.push(Value::Integer(
                    i64::try_from(first + 1).map_err(|_| VmError::ArithmeticOverflow)?,
                ));
            } else {
                let object = vm.allocate_byte_string(&source[first..last])?;
                roots[index] = Some(vm.add_root(RootKind::Temporary, object)?);
                result.push(Value::Object(object));
            }
        }
        Ok::<(), RuntimeError>(())
    })();
    let consumed = built.and_then(|()| consume(vm, result, ticket));
    for root in roots.into_iter().flatten() {
        vm.remove_root(root)?;
    }
    consumed
}

pub(crate) fn pattern_output_units(found: Option<Found>, find: bool) -> usize {
    let Some(found) = found else {
        return 1;
    };
    if found.count == 0 {
        return if find {
            2
        } else {
            found.end.saturating_sub(found.start).max(1)
        };
    }
    let mut cost = usize::from(find) * 2;
    for capture in &found.captures[..found.count] {
        cost = cost.saturating_add(if capture.position {
            1
        } else {
            capture
                .end
                .unwrap_or(capture.start)
                .saturating_sub(capture.start)
                .max(1)
        });
    }
    cost
}

pub(crate) fn execute(
    vm: &mut Vm,
    kind: StringBuiltin,
    args: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    match kind {
        StringBuiltin::Byte => with_bytes(vm, arg(args, 0)?, |source| {
            let (first, last) = range(vm, args, source.len(), true)?;
            if first > last {
                return values(vm, &[]);
            }
            let count = last - first + 1;
            if count >= i32::MAX as usize {
                return Err(argument());
            }
            let mut result = Vec::new();
            let ticket = reserve_vec(
                vm.allocation_ledger(),
                &mut result,
                count,
                FailPoint::ReturnReserve,
            )?;
            result.extend(
                source[first - 1..last]
                    .iter()
                    .map(|byte| Value::Integer(i64::from(*byte))),
            );
            Ok((result, Some(ticket)))
        }),
        StringBuiltin::Char => {
            for (index, value) in args.iter().enumerate() {
                if !(0..=255).contains(&integer(vm, *value)?) {
                    return Err(char_range_error(vm, index + 1)?);
                }
            }
            let mut buffer = Buffer::new(vm, args.len())?;
            for value in args {
                buffer.bytes.push(integer(vm, *value)? as u8);
            }
            string_result(vm, &buffer)
        }
        StringBuiltin::Len => {
            let len = table::string_len(vm, arg(args, 0)?)?;
            let len = i64::try_from(len).map_err(|_| VmError::ArithmeticOverflow)?;
            values(vm, &[Value::Integer(len)])
        }
        StringBuiltin::Lower | StringBuiltin::Upper | StringBuiltin::Reverse => {
            let buffer = with_bytes(vm, arg(args, 0)?, |source| {
                let mut buffer = Buffer::new(vm, source.len())?;
                match kind {
                    StringBuiltin::Lower => buffer
                        .bytes
                        .extend(source.iter().map(u8::to_ascii_lowercase)),
                    StringBuiltin::Upper => buffer
                        .bytes
                        .extend(source.iter().map(u8::to_ascii_uppercase)),
                    StringBuiltin::Reverse => buffer.bytes.extend(source.iter().rev().copied()),
                    _ => return Err(argument()),
                }
                Ok(buffer)
            })?;
            string_result(vm, &buffer)
        }
        StringBuiltin::Sub => {
            let buffer = with_bytes(vm, arg(args, 0)?, |source| {
                let (first, last) = range(vm, args, source.len(), false)?;
                let slice = if first <= last {
                    &source[first - 1..last]
                } else {
                    &[]
                };
                let mut buffer = Buffer::new(vm, slice.len())?;
                buffer.bytes.extend_from_slice(slice);
                Ok(buffer)
            })?;
            string_result(vm, &buffer)
        }
        StringBuiltin::Rep => {
            let count = integer(vm, arg(args, 1)?)?;
            let total = match rep_len(vm, args)? {
                RepLength::Length(length) => length,
                RepLength::TooLarge => return Err(rep_too_large_error(vm)?),
            };
            let mut buffer = Buffer::new(vm, total)?;
            if total > 0 {
                with_bytes(vm, arg(args, 0)?, |source| {
                    let append = |separator: &[u8], buffer: &mut Buffer| {
                        for i in 0..count {
                            buffer.bytes.extend_from_slice(source);
                            if i + 1 < count {
                                buffer.bytes.extend_from_slice(separator);
                            }
                        }
                    };
                    match args.get(2).copied() {
                        None | Some(Value::Nil) => append(&[], &mut buffer),
                        Some(value) => with_bytes(vm, value, |separator| {
                            append(separator, &mut buffer);
                            Ok(())
                        })?,
                    }
                    Ok(())
                })?;
            }
            string_result(vm, &buffer)
        }
        StringBuiltin::Dump => Err(RuntimeError::new(RuntimeErrorKind::HostPolicyStringDump)),
        StringBuiltin::Pack | StringBuiltin::Unpack | StringBuiltin::PackSize => {
            pack::execute(vm, kind, args)
        }
        StringBuiltin::Find
        | StringBuiltin::Match
        | StringBuiltin::GMatch
        | StringBuiltin::GSub
        | StringBuiltin::Format => Err(argument()),
    }
}

#[cfg(test)]
mod p17_b03_tests {
    use super::{StringBuiltin, execute};
    use crate::vm::{RunOutcome, RuntimeError, RuntimeErrorKind};
    use crate::{ObjectKind, RootKind, Vm, VmError};
    use rivetlua_compiler::{CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve};
    use rivetlua_core::{LuaProfile, Value, VerifyLimits};

    fn assert_error_message(vm: &mut Vm, error: RuntimeError, fragment: &[u8]) {
        assert_eq!(error.kind, RuntimeErrorKind::StringArgument);
        assert_eq!(error.diagnostic_id, "E_STRING_ARGUMENT");
        let Value::Object(message) = error.value else {
            panic!("字串錯誤應保留 Lua 可見文字")
        };
        assert!(vm
            .with_byte_string(message, |text| text
                .as_bytes()
                .windows(fragment.len())
                .any(|window| window == fragment))
            .unwrap());
        let root = vm.add_root(RootKind::Temporary, message).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(message), Ok(ObjectKind::ByteString));
        vm.remove_root(root).unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.object_kind(message), Err(VmError::StaleObject));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p17_b03_string_size_errors_keep_typed_codes_and_lua_messages() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            for value in [256, -1, i64::MAX, i64::MIN] {
                let error = match execute(
                    &mut vm,
                    StringBuiltin::Char,
                    &[Value::Integer(value)],
                ) {
                    Err(error) => error,
                    Ok(_) => panic!("超出 byte 範圍的 string.char 必須失敗"),
                };
                assert_error_message(&mut vm, error, b"out of range");
            }

            let error = match execute(
                &mut vm,
                StringBuiltin::Rep,
                &[
                    Value::Integer(1),
                    Value::Integer(i64::MAX),
                    Value::Integer(2),
                ],
            ) {
                Err(error) => error,
                Ok(_) => panic!("超過字串長度上限的 string.rep 必須失敗"),
            };
            assert_error_message(&mut vm, error, b"too large");
        }
    }

    #[test]
    fn p17_b03_string_size_errors_reach_pcall_through_gc() {
        let source = b"local a,b=pcall(string.char,256); local c,d=pcall(string.rep,'x',9223372036854775807,'y'); return a,b,c,d,string.char(0,255),string.rep('ab',2,'-')";
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let language = match profile {
                LuaProfile::Lua54 => LanguageProfile::Lua54,
                LuaProfile::Lua55 => LanguageProfile::Lua55,
            };
            let limits = CompileLimits::default();
            let tokens = lex(source, language, &limits).unwrap();
            let parsed = parse(&tokens, language, &limits).unwrap();
            let resolved = resolve(&parsed, &tokens, language, &limits).unwrap();
            let ir = lower(&resolved, &IrLimits::default()).unwrap();
            let module = emit(&ir, &VerifyLimits::default()).unwrap().verified().clone();

            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            vm.install_error_builtins(environment).unwrap();
            vm.install_string_builtins(environment).unwrap();
            vm.set_collect_every_allocation(true);
            let mut execution = vm.load_with_environment(module, Value::Object(environment)).unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("受保護的字串錯誤應返回")
            };
            drop(execution);
            assert_eq!(values.len(), 6);
            assert_eq!(values[0], Value::Boolean(false));
            assert_eq!(values[2], Value::Boolean(false));
            for (index, fragment) in [(1, b"out of range".as_slice()), (3, b"too large")] {
                let Value::Object(message) = values[index] else {
                    panic!("pcall 應交付字串錯誤訊息")
                };
                assert!(vm.with_byte_string(message, |text| text.as_bytes().windows(fragment.len()).any(|part| part == fragment)).unwrap());
            }
            for (index, expected) in [(4, b"\0\xff".as_slice()), (5, b"ab-ab".as_slice())] {
                let Value::Object(result) = values[index] else {
                    panic!("正常字串結果應為物件")
                };
                assert_eq!(vm.with_byte_string(result, |text| text.as_bytes().to_vec()).unwrap(), expected);
            }
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            vm.remove_root(environment_root).unwrap();
        }
    }
}
