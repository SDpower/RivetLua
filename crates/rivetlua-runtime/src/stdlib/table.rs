//! VM 局部的 table 函式庫與排序診斷。

use rivetlua_core::{ObjectRef, Value};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, reserve_vec};
use crate::stdlib::basic;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{ObjectKind, RootId, RootKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableBuiltin {
    Concat,
    Insert,
    Remove,
    Move,
    Pack,
    Unpack,
    Sort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SortPhase {
    Forward,
    Reverse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SortStep {
    NeedLength,
    AwaitLength,
    CompareStart,
    AwaitReadLeft,
    AwaitReadRight,
    Compare,
    AwaitCompare,
    AwaitWriteFirst,
    AwaitWriteSecond,
}

#[derive(Debug)]
pub(crate) struct SortState {
    pub table: ObjectRef,
    pub comparator: Option<Value>,
    pub len: i64,
    pub i: i64,
    pub j: i64,
    pub left: Value,
    pub right: Value,
    pub phase: SortPhase,
    pub step: SortStep,
    pub trace: TableSortTrace,
    roots: [Option<RootId>; 4],
}

impl SortState {
    pub(crate) fn new(
        vm: &mut Vm,
        table: ObjectRef,
        comparator: Option<Value>,
        trace: TableSortTrace,
    ) -> Result<Self, VmError> {
        let mut state = Self {
            table,
            comparator,
            len: 0,
            i: 2,
            j: 2,
            left: Value::Nil,
            right: Value::Nil,
            phase: SortPhase::Forward,
            step: SortStep::NeedLength,
            trace,
            roots: [None; 4],
        };
        if let Err(error) = state.restore_roots(vm) {
            state.clear_roots(vm)?;
            return Err(error);
        }
        Ok(state)
    }

    pub(crate) fn set_left(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.set_slot(vm, 2, value)?;
        self.left = value;
        Ok(())
    }

    pub(crate) fn set_right(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.set_slot(vm, 3, value)?;
        self.right = value;
        Ok(())
    }

    fn set_slot(&mut self, vm: &mut Vm, index: usize, value: Value) -> Result<(), VmError> {
        let next = match value {
            Value::Object(object) => Some(vm.add_root(RootKind::Temporary, object)?),
            _ => None,
        };
        if let Some(previous) = core::mem::replace(&mut self.roots[index], next) {
            vm.remove_root(previous)?;
        }
        Ok(())
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for root in self.roots.iter_mut().rev() {
            if let Some(root) = root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        let values = [
            Value::Object(self.table),
            self.comparator.unwrap_or(Value::Nil),
            self.left,
            self.right,
        ];
        for (value, root) in values.into_iter().zip(&mut self.roots) {
            if root.is_none() {
                if let Value::Object(object) = value {
                    *root = Some(vm.add_root(RootKind::Temporary, object)?);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for value in [
            Value::Object(self.table),
            self.comparator.unwrap_or(Value::Nil),
            self.left,
            self.right,
        ] {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableOpStage {
    Start,
    AfterLength,
    Init,
    ConcatNext,
    ConcatGot,
    ConcatDone,
    UnpackNext,
    UnpackGot,
    UnpackDone,
    InsertNext,
    InsertGot,
    InsertWrote,
    InsertFinalDone,
    RemoveInitial,
    RemoveGot,
    RemoveNext,
    RemoveShiftGot,
    RemoveShiftWrote,
    RemoveFinalDone,
    MoveNext,
    MoveCompared,
    MoveGot,
    MoveWrote,
}

pub(crate) struct TableOpState {
    pub kind: TableBuiltin,
    pub args: [Value; 5],
    pub arg_count: usize,
    pub table: ObjectRef,
    pub destination: ObjectRef,
    pub stage: TableOpStage,
    pub len: i64,
    pub first: i64,
    pub last: i64,
    pub index: i64,
    pub target: i64,
    pub reverse: bool,
    pub explicit_destination: bool,
    pub hold: Value,
    pub removed: Value,
    pub output: Vec<Value>,
    pub buffer: Buffer,
    roots: [Option<RootId>; 7],
    output_roots: Vec<Option<RootId>>,
    ledger: AllocationLedger,
    output_owner: Option<crate::alloc::AllocationCharge>,
    roots_owner: Option<crate::alloc::AllocationCharge>,
}

impl TableOpState {
    pub(crate) fn new(
        vm: &mut Vm,
        kind: TableBuiltin,
        args: &[Value],
    ) -> Result<Self, RuntimeError> {
        let table = table_arg(vm, args, 0)?;
        let mut copied = [Value::Nil; 5];
        let count = args.len().min(copied.len());
        copied[..count].copy_from_slice(&args[..count]);
        let mut state = Self {
            kind,
            args: copied,
            arg_count: args.len(),
            table,
            destination: table,
            stage: TableOpStage::Start,
            len: 0,
            first: 0,
            last: 0,
            index: 0,
            target: 0,
            reverse: false,
            explicit_destination: false,
            hold: Value::Nil,
            removed: Value::Nil,
            output: Vec::new(),
            buffer: Buffer::new(vm),
            roots: [None; 7],
            output_roots: Vec::new(),
            ledger: vm.allocation_ledger().clone(),
            output_owner: None,
            roots_owner: None,
        };
        if let Err(error) = state.restore_roots(vm) {
            state.clear_roots(vm)?;
            return Err(error.into());
        }
        Ok(state)
    }

    pub(crate) fn args(&self) -> &[Value] {
        &self.args[..self.arg_count.min(self.args.len())]
    }

    pub(crate) fn set_hold(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.set_slot(vm, 5, value)?;
        self.hold = value;
        Ok(())
    }

    pub(crate) fn set_removed(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.set_slot(vm, 6, value)?;
        self.removed = value;
        Ok(())
    }

    fn set_slot(&mut self, vm: &mut Vm, index: usize, value: Value) -> Result<(), VmError> {
        let next = match value {
            Value::Object(object) => Some(vm.add_root(RootKind::Temporary, object)?),
            _ => None,
        };
        if let Some(previous) = core::mem::replace(&mut self.roots[index], next) {
            vm.remove_root(previous)?;
        }
        Ok(())
    }

    pub(crate) fn push_output(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        let next = self
            .output
            .len()
            .checked_add(1)
            .ok_or(VmError::ArithmeticOverflow)?;
        let mut output = Vec::new();
        let output_ticket = reserve_vec(&self.ledger, &mut output, next, FailPoint::ReturnReserve)?;
        output.extend_from_slice(&self.output);
        output.push(value);
        let mut roots = Vec::new();
        let roots_ticket = match reserve_vec(&self.ledger, &mut roots, next, FailPoint::WorkReserve)
        {
            Ok(ticket) => ticket,
            Err(error) => {
                drop(roots);
                drop(output);
                drop(output_ticket);
                return Err(error);
            }
        };
        roots.extend_from_slice(&self.output_roots);
        let output_owner = output_ticket.commit_charge()?;
        let roots_owner = roots_ticket.commit_charge()?;
        let root = match value {
            Value::Object(object) => match vm.add_root(RootKind::Temporary, object) {
                Ok(root) => Some(root),
                Err(error) => {
                    drop(roots);
                    drop(output);
                    drop(roots_owner);
                    drop(output_owner);
                    return Err(error);
                }
            },
            _ => None,
        };
        roots.push(root);
        let old_output = core::mem::replace(&mut self.output, output);
        let old_roots = core::mem::replace(&mut self.output_roots, roots);
        drop(old_output);
        drop(old_roots);
        self.output_owner = Some(output_owner);
        self.roots_owner = Some(roots_owner);
        Ok(())
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for root in self
            .output_roots
            .iter_mut()
            .rev()
            .chain(self.roots.iter_mut().rev())
        {
            if let Some(root) = root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for (index, value) in self
            .args
            .into_iter()
            .chain([self.hold, self.removed])
            .enumerate()
        {
            if self.roots[index].is_none() {
                if let Value::Object(object) = value {
                    self.roots[index] = Some(vm.add_root(RootKind::Temporary, object)?);
                }
            }
        }
        for (value, root) in self.output.iter().zip(&mut self.output_roots) {
            if root.is_none() {
                if let Value::Object(object) = value {
                    *root = Some(vm.add_root(RootKind::Temporary, *object)?);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for value in self.args.into_iter().chain([self.hold, self.removed]) {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        for value in &self.output {
            if let Value::Object(object) = value {
                visit(*object)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TableSortStop {
    NotStarted,
    Running,
    Completed,
    LuaError,
    Aborted,
    Allocation,
    InconsistentComparator,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TableSortTrace {
    pub comparisons: usize,
    pub swaps: usize,
    pub stop: TableSortStop,
}

impl Default for TableSortTrace {
    fn default() -> Self {
        Self {
            comparisons: 0,
            swaps: 0,
            stop: TableSortStop::NotStarted,
        }
    }
}

pub(crate) fn argument() -> RuntimeError {
    RuntimeError::new(RuntimeErrorKind::BasicArgument)
}

pub(crate) fn table_arg(vm: &Vm, args: &[Value], index: usize) -> Result<ObjectRef, RuntimeError> {
    let Some(Value::Object(table)) = args.get(index).copied() else {
        return Err(argument());
    };
    if vm.object_kind(table)? != ObjectKind::Table {
        return Err(argument());
    }
    Ok(table)
}

pub(crate) fn integer_arg(args: &[Value], index: usize) -> Result<i64, RuntimeError> {
    args.get(index)
        .copied()
        .and_then(basic::lua_integer)
        .ok_or_else(argument)
}

pub(crate) fn optional_integer(
    args: &[Value],
    index: usize,
    default: i64,
) -> Result<i64, RuntimeError> {
    match args.get(index).copied() {
        None | Some(Value::Nil) => Ok(default),
        Some(value) => basic::lua_integer(value).ok_or_else(argument),
    }
}

pub(crate) fn result(
    vm: &Vm,
    values: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
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

pub(crate) struct Buffer {
    pub(crate) bytes: Vec<u8>,
    ledger: AllocationLedger,
    charge: Option<crate::alloc::AllocationCharge>,
}

impl Buffer {
    fn new(vm: &Vm) -> Self {
        Self {
            bytes: Vec::new(),
            ledger: vm.allocation_ledger().clone(),
            charge: None,
        }
    }

    fn append(&mut self, bytes: &[u8]) -> Result<(), RuntimeError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        let mut replacement = Vec::new();
        let ticket = reserve_vec(&self.ledger, &mut replacement, next, FailPoint::WorkReserve)?;
        let charge = ticket.commit_charge()?;
        replacement.extend_from_slice(&self.bytes);
        replacement.extend_from_slice(bytes);
        let old = core::mem::replace(&mut self.bytes, replacement);
        drop(old);
        self.charge = Some(charge);
        Ok(())
    }
}

pub(crate) fn append_string(
    vm: &Vm,
    buffer: &mut Buffer,
    value: Value,
) -> Result<(), RuntimeError> {
    match value {
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            vm.with_byte_string(object, |string| buffer.append(string.as_bytes()))??;
            Ok(())
        }
        Value::Integer(_) | Value::Float(_) => {
            let (bytes, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            buffer.append(&bytes[..len])
        }
        _ => Err(argument()),
    }
}

pub(crate) fn string_len(vm: &Vm, value: Value) -> Result<usize, RuntimeError> {
    match value {
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            Ok(vm.with_byte_string(object, |string| string.len())?)
        }
        Value::Integer(_) | Value::Float(_) => {
            let (_, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            Ok(len)
        }
        _ => Err(argument()),
    }
}

pub(crate) fn border(vm: &Vm, table: ObjectRef) -> Result<i64, RuntimeError> {
    Ok(vm.with_table(table, |stored| stored.border_len())?)
}

pub(crate) fn work_units(
    vm: &Vm,
    kind: TableBuiltin,
    args: &[Value],
    available: u64,
) -> Result<usize, RuntimeError> {
    let units = match kind {
        TableBuiltin::Pack => args.len().saturating_add(1),
        TableBuiltin::Unpack => {
            let table = table_arg(vm, args, 0)?;
            let first = optional_integer(args, 1, 1)?;
            let last = optional_integer(args, 2, border(vm, table)?)?;
            if last < first {
                1
            } else {
                usize::try_from(
                    last.checked_sub(first)
                        .and_then(|n| n.checked_add(1))
                        .ok_or_else(argument)?,
                )
                .map_err(|_| VmError::ArithmeticOverflow)?
            }
        }
        TableBuiltin::Concat => {
            let table = table_arg(vm, args, 0)?;
            let separator = args.get(1).copied().unwrap_or(Value::Nil);
            let sep_len = if separator == Value::Nil {
                0
            } else {
                string_len(vm, separator)?
            };
            let first = optional_integer(args, 2, 1)?;
            let last = optional_integer(args, 3, border(vm, table)?)?;
            if last < first {
                1
            } else {
                let count = usize::try_from(
                    last.checked_sub(first)
                        .and_then(|n| n.checked_add(1))
                        .ok_or_else(argument)?,
                )
                .map_err(|_| VmError::ArithmeticOverflow)?;
                if u64::try_from(count).unwrap_or(u64::MAX) > available {
                    return Ok(count);
                }
                let mut bytes = sep_len
                    .checked_mul(count - 1)
                    .ok_or(VmError::ArithmeticOverflow)?;
                for offset in 0..count {
                    let key = first
                        .checked_add(
                            i64::try_from(offset).map_err(|_| VmError::ArithmeticOverflow)?,
                        )
                        .ok_or(VmError::ArithmeticOverflow)?;
                    bytes = bytes
                        .checked_add(string_len(vm, vm.raw_get(table, Value::Integer(key))?)?)
                        .ok_or(VmError::ArithmeticOverflow)?;
                }
                bytes
                    .checked_add(count)
                    .ok_or(VmError::ArithmeticOverflow)?
            }
        }
        TableBuiltin::Insert => {
            let table = table_arg(vm, args, 0)?;
            usize::try_from(border(vm, table)?)
                .map_err(|_| VmError::ArithmeticOverflow)?
                .saturating_add(1)
        }
        TableBuiltin::Remove => {
            let table = table_arg(vm, args, 0)?;
            usize::try_from(border(vm, table)?)
                .map_err(|_| VmError::ArithmeticOverflow)?
                .saturating_add(1)
        }
        TableBuiltin::Move => {
            let first = integer_arg(args, 1)?;
            let last = integer_arg(args, 2)?;
            if last < first {
                1
            } else {
                usize::try_from(
                    last.checked_sub(first)
                        .and_then(|n| n.checked_add(1))
                        .ok_or_else(argument)?,
                )
                .map_err(|_| VmError::ArithmeticOverflow)?
            }
        }
        TableBuiltin::Sort => 1,
    };
    Ok(units.max(1))
}

pub(crate) fn execute(
    vm: &mut Vm,
    kind: TableBuiltin,
    args: &[Value],
) -> Result<(Vec<Value>, Option<Reservation>), RuntimeError> {
    match kind {
        TableBuiltin::Pack => {
            let count = i64::try_from(args.len()).map_err(|_| VmError::ArithmeticOverflow)?;
            let table = vm.allocate_table_with_capacity(args.len(), 1)?;
            let root = vm.add_root(RootKind::Temporary, table)?;
            let packed = (|| -> Result<(), RuntimeError> {
                for (index, value) in args.iter().copied().enumerate() {
                    if value != Value::Nil {
                        let key =
                            i64::try_from(index + 1).map_err(|_| VmError::ArithmeticOverflow)?;
                        vm.raw_set(table, Value::Integer(key), value)?;
                    }
                }
                let key = vm.allocate_byte_string(b"n")?;
                vm.raw_set(table, Value::Object(key), Value::Integer(count))?;
                Ok(())
            })();
            let output = packed.and_then(|()| result(vm, &[Value::Object(table)]));
            vm.remove_root(root)?;
            output
        }
        TableBuiltin::Unpack => {
            let table = table_arg(vm, args, 0)?;
            let first = optional_integer(args, 1, 1)?;
            let last = optional_integer(args, 2, border(vm, table)?)?;
            if first > last {
                return result(vm, &[]);
            }
            let count = last
                .checked_sub(first)
                .and_then(|n| n.checked_add(1))
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n <= usize::from(u16::MAX))
                .ok_or_else(argument)?;
            let mut values = Vec::new();
            let ticket = reserve_vec(
                vm.allocation_ledger(),
                &mut values,
                count,
                FailPoint::ReturnReserve,
            )?;
            for offset in 0..count {
                let index = first
                    .checked_add(i64::try_from(offset).map_err(|_| VmError::ArithmeticOverflow)?)
                    .ok_or(VmError::ArithmeticOverflow)?;
                values.push(vm.raw_get(table, Value::Integer(index))?);
            }
            Ok((values, Some(ticket)))
        }
        TableBuiltin::Concat => {
            let table = table_arg(vm, args, 0)?;
            let separator = args.get(1).copied().unwrap_or(Value::Nil);
            if separator != Value::Nil {
                string_len(vm, separator)?;
            }
            let first = optional_integer(args, 2, 1)?;
            let last = optional_integer(args, 3, border(vm, table)?)?;
            let mut buffer = Buffer::new(vm);
            if first <= last {
                let mut index = first;
                loop {
                    if index != first && separator != Value::Nil {
                        append_string(vm, &mut buffer, separator)?;
                    }
                    append_string(vm, &mut buffer, vm.raw_get(table, Value::Integer(index))?)?;
                    if index == last {
                        break;
                    }
                    index = index.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
                }
            }
            let text = vm.allocate_byte_string(&buffer.bytes)?;
            result(vm, &[Value::Object(text)])
        }
        TableBuiltin::Insert => {
            let table = table_arg(vm, args, 0)?;
            let size = border(vm, table)?;
            let end = size.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
            let (position, value) = match args {
                [_, value] => (end, *value),
                [_, position, value] => {
                    (basic::lua_integer(*position).ok_or_else(argument)?, *value)
                }
                _ => return Err(argument()),
            };
            if position < 1 || position > end {
                return Err(argument());
            }
            let mut index = size;
            while index >= position {
                let value = vm.raw_get(table, Value::Integer(index))?;
                vm.raw_set(table, Value::Integer(index + 1), value)?;
                index -= 1;
            }
            vm.raw_set(table, Value::Integer(position), value)?;
            result(vm, &[])
        }
        TableBuiltin::Remove => {
            let table = table_arg(vm, args, 0)?;
            let size = border(vm, table)?;
            let position = optional_integer(args, 1, size)?;
            if position != size && (position < 1 || position > size.saturating_add(1)) {
                return Err(argument());
            }
            let removed = vm.raw_get(table, Value::Integer(position))?;
            let mut index = position;
            while index < size {
                let next = vm.raw_get(table, Value::Integer(index + 1))?;
                vm.raw_set(table, Value::Integer(index), next)?;
                index += 1;
            }
            vm.raw_set(table, Value::Integer(index), Value::Nil)?;
            result(vm, &[removed])
        }
        TableBuiltin::Move => {
            let source = table_arg(vm, args, 0)?;
            let first = integer_arg(args, 1)?;
            let last = integer_arg(args, 2)?;
            let target = integer_arg(args, 3)?;
            let destination = match args.get(4).copied() {
                None | Some(Value::Nil) => source,
                Some(_) => table_arg(vm, args, 4)?,
            };
            if last >= first {
                let count = last
                    .checked_sub(first)
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(argument)?;
                target.checked_add(count - 1).ok_or_else(argument)?;
                let reverse = source == destination && target > first && target <= last;
                for step in 0..count {
                    let offset = if reverse { count - step - 1 } else { step };
                    let from = first.checked_add(offset).ok_or_else(argument)?;
                    let to = target.checked_add(offset).ok_or_else(argument)?;
                    let value = vm.raw_get(source, Value::Integer(from))?;
                    vm.raw_set(destination, Value::Integer(to), value)?;
                }
            }
            result(vm, &[Value::Object(destination)])
        }
        TableBuiltin::Sort => Err(argument()),
    }
}

#[cfg(test)]
mod p13_b_tests {
    use rivetlua_core::Value;

    use super::{TableBuiltin, execute};
    use crate::{FailPoint, RootKind, Vm, VmError};

    #[test]
    fn p13_b_pack_allocation_failure_retries_without_temporary_roots() {
        let mut vm = Vm::new().unwrap();
        vm.inject_failure_once(FailPoint::TableArrayReserve);
        let input = [Value::Integer(1), Value::Nil, Value::Integer(3)];
        assert!(matches!(
            execute(&mut vm, TableBuiltin::Pack, &input),
            Err(error) if error.kind == super::RuntimeErrorKind::Heap(
                VmError::InjectedFailure(FailPoint::TableArrayReserve)
            )
        ));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let (values, ticket) = execute(&mut vm, TableBuiltin::Pack, &input).unwrap();
        drop(ticket);
        let Value::Object(table) = values[0] else {
            panic!("pack 應建立 table")
        };
        assert_eq!(vm.raw_get(table, Value::Integer(2)), Ok(Value::Nil));
        let key = vm.allocate_byte_string(b"n").unwrap();
        assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Integer(3)));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn p13_b_concat_rejects_bad_separator_on_empty_interval() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let invalid = vm.allocate_table().unwrap();
        let args = [
            Value::Object(table),
            Value::Object(invalid),
            Value::Integer(2),
            Value::Integer(1),
        ];
        assert!(matches!(
            execute(&mut vm, TableBuiltin::Concat, &args),
            Err(error) if error.kind == super::RuntimeErrorKind::BasicArgument
        ));
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
