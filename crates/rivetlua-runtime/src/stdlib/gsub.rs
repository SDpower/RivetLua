//! `string.gsub` 的逐次匹配、替換與可暫停 callback 狀態。

use rivetlua_core::{ObjectRef, Value};

use crate::alloc::Reservation;
use crate::pending_op::PrintArguments;
use crate::stdlib::pattern::Found;
use crate::stdlib::string::{self, Buffer};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, Vm, VmError};

pub(crate) enum Replacement {
    Text(Buffer),
    Function(Value),
    Table(Value),
}

pub(crate) struct GSubState {
    pub(crate) arguments: PrintArguments,
    pub(crate) source: Buffer,
    pub(crate) pattern: Buffer,
    pub(crate) output: Buffer,
    pub(crate) replacement: Replacement,
    pub(crate) cursor: usize,
    pub(crate) last: Option<usize>,
    pub(crate) count: i64,
    pub(crate) maximum: i64,
    pub(crate) changed: bool,
    pub(crate) anchored: bool,
    pub(crate) awaiting: Option<(usize, usize)>,
    pub(crate) callback_arguments: Option<PrintArguments>,
}

fn pattern_error() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringPattern)
}
fn argument_error() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::StringArgument)
}

impl GSubState {
    pub(crate) fn new(vm: &mut Vm, args: &[Value]) -> Result<Self, RuntimeError> {
        let source_value = string::arg(args, 0)?;
        let pattern_value = string::arg(args, 1)?;
        let replacement_value = string::arg(args, 2)?;
        let mut arguments = PrintArguments::new(vm, args)?;
        let built = (|| {
            let source = string::owned_bytes(vm, source_value)?;
            let pattern = string::owned_bytes(vm, pattern_value)?;
            let replacement = match replacement_value {
                Value::Integer(_) | Value::Float(_) => {
                    Replacement::Text(string::owned_bytes(vm, replacement_value)?)
                }
                Value::Object(object) => match vm.object_kind(object)? {
                    ObjectKind::ByteString => {
                        Replacement::Text(string::owned_bytes(vm, replacement_value)?)
                    }
                    ObjectKind::Table => Replacement::Table(replacement_value),
                    ObjectKind::Closure | ObjectKind::Builtin => {
                        Replacement::Function(replacement_value)
                    }
                    _ => return Err(argument_error()),
                },
                _ => return Err(argument_error()),
            };
            let maximum = string::optional_integer(
                vm,
                args.get(3).copied(),
                i64::try_from(source.bytes.len().saturating_add(1)).unwrap_or(i64::MAX),
            )?;
            Ok::<_, RuntimeError>((source, pattern, replacement, maximum))
        })();
        let (source, pattern, replacement, maximum) = match built {
            Ok(built) => built,
            Err(error) => {
                arguments.clear_roots(vm)?;
                return Err(error);
            }
        };
        let anchored = pattern.bytes.first() == Some(&b'^');
        Ok(Self {
            arguments,
            source,
            pattern,
            output: Buffer::empty(vm),
            replacement,
            cursor: 0,
            last: None,
            count: 0,
            maximum,
            changed: false,
            anchored,
            awaiting: None,
            callback_arguments: None,
        })
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(args) = self.callback_arguments.as_mut() {
            args.clear_roots(vm)?;
        }
        self.arguments.clear_roots(vm)
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.restore_roots(vm)?;
        if let Some(args) = self.callback_arguments.as_mut() {
            args.restore_roots(vm)?;
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.arguments.trace_children(&mut visit)?;
        if let Some(args) = &self.callback_arguments {
            args.trace_children(visit)?;
        }
        Ok(())
    }

    pub(crate) fn append(&mut self, vm: &Vm, bytes: &[u8]) -> Result<(), RuntimeError> {
        let next = self
            .output
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        if next > string::max_size(vm.language_profile()) {
            return Err(argument_error());
        }
        self.output.append(bytes)
    }

    fn capture_range(found: Found, index: usize) -> Result<(usize, usize, bool), RuntimeError> {
        if index == 0 || (index == 1 && found.count == 0) {
            return Ok((found.start, found.end, false));
        }
        let capture = found
            .captures
            .get(index - 1)
            .filter(|_| index <= found.count)
            .ok_or_else(pattern_error)?;
        Ok((
            capture.start,
            capture.end.ok_or_else(pattern_error)?,
            capture.position,
        ))
    }

    pub(crate) fn text_cost(&self, vm: &Vm, found: Found) -> Result<usize, RuntimeError> {
        let len = self.text_output_len(vm, found)?;
        let Replacement::Text(text) = &self.replacement else {
            return Err(argument_error());
        };
        Ok(len.saturating_add(text.bytes.len()))
    }

    fn text_output_len(&self, vm: &Vm, found: Found) -> Result<usize, RuntimeError> {
        let Replacement::Text(text) = &self.replacement else {
            return Err(argument_error());
        };
        let mut length = 0_usize;
        let mut cursor = 0;
        while cursor < text.bytes.len() {
            if text.bytes[cursor] != b'%' {
                length = length.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
                cursor += 1;
                continue;
            }
            let marker = *text.bytes.get(cursor + 1).ok_or_else(pattern_error)?;
            let extra = match marker {
                b'%' => 1,
                b'0'..=b'9' => {
                    let (first, last, position) =
                        Self::capture_range(found, usize::from(marker - b'0'))?;
                    if position {
                        let value = Value::Integer(
                            i64::try_from(first + 1).map_err(|_| VmError::ArithmeticOverflow)?,
                        );
                        crate::vm::basic_number_bytes(value, vm.language_profile())?.1
                    } else {
                        last - first
                    }
                }
                _ => return Err(pattern_error()),
            };
            length = length
                .checked_add(extra)
                .ok_or(VmError::ArithmeticOverflow)?;
            cursor += 2;
        }
        Ok(length)
    }

    pub(crate) fn append_text(&mut self, vm: &Vm, found: Found) -> Result<(), RuntimeError> {
        let output_len = self.text_output_len(vm, found)?;
        let next = self
            .output
            .bytes
            .len()
            .checked_add(output_len)
            .ok_or(VmError::ArithmeticOverflow)?;
        if next > string::max_size(vm.language_profile()) {
            return Err(argument_error());
        }
        self.output.reserve_extra(output_len)?;
        let Replacement::Text(text) = &self.replacement else {
            return Err(argument_error());
        };
        let bytes = &text.bytes;
        let mut cursor = 0;
        let mut literal_start = 0;
        while cursor < bytes.len() {
            if bytes[cursor] != b'%' {
                cursor += 1;
                continue;
            }
            self.output
                .bytes
                .extend_from_slice(&bytes[literal_start..cursor]);
            let marker = *bytes.get(cursor + 1).ok_or_else(pattern_error)?;
            match marker {
                b'%' => self.output.bytes.push(b'%'),
                b'0'..=b'9' => {
                    let (first, last, position) =
                        Self::capture_range(found, usize::from(marker - b'0'))?;
                    if position {
                        let value = Value::Integer(
                            i64::try_from(first + 1).map_err(|_| VmError::ArithmeticOverflow)?,
                        );
                        let (number, length) =
                            crate::vm::basic_number_bytes(value, vm.language_profile())?;
                        self.output.bytes.extend_from_slice(&number[..length]);
                    } else {
                        self.output
                            .bytes
                            .extend_from_slice(&self.source.bytes[first..last]);
                    }
                }
                _ => return Err(pattern_error()),
            }
            cursor += 2;
            literal_start = cursor;
        }
        self.output.bytes.extend_from_slice(&bytes[literal_start..]);
        self.changed = true;
        Ok(())
    }

    pub(crate) fn answer_len(&self, vm: &Vm, value: Value) -> Result<usize, RuntimeError> {
        if matches!(value, Value::Nil | Value::Boolean(false)) {
            let (start, end) = self.awaiting.ok_or_else(pattern_error)?;
            return Ok(end - start);
        }
        string::with_bytes(vm, value, |bytes| Ok(bytes.len()))
    }

    pub(crate) fn append_answer(&mut self, vm: &mut Vm, value: Value) -> Result<(), RuntimeError> {
        let (start, end) = self.awaiting.take().ok_or_else(pattern_error)?;
        if let Some(mut args) = self.callback_arguments.take() {
            args.clear_roots(vm)?;
        }
        if matches!(value, Value::Nil | Value::Boolean(false)) {
            let text = &self.source.bytes[start..end];
            let next = self
                .output
                .bytes
                .len()
                .checked_add(text.len())
                .ok_or(VmError::ArithmeticOverflow)?;
            if next > string::max_size(vm.language_profile()) {
                return Err(argument_error());
            }
            return self.output.append(text);
        }
        let bytes = string::owned_bytes(vm, value)?;
        self.append(vm, &bytes.bytes)?;
        self.changed = true;
        Ok(())
    }

    pub(crate) fn finish(
        &mut self,
        vm: &mut Vm,
    ) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
        let result = if self.changed {
            let last = &self.source.bytes[self.cursor..];
            let next = self
                .output
                .bytes
                .len()
                .checked_add(last.len())
                .ok_or(VmError::ArithmeticOverflow)?;
            if next > string::max_size(vm.language_profile()) {
                return Err(argument_error());
            }
            self.output.append(last)?;
            Value::Object(vm.allocate_byte_string(&self.output.bytes)?)
        } else {
            let original = self.arguments.values()[0];
            if matches!(original, Value::Integer(_) | Value::Float(_)) {
                Value::Object(vm.allocate_byte_string(&self.source.bytes)?)
            } else {
                original
            }
        };
        string::values(vm, &[result, Value::Integer(self.count)])
    }
}
