//! P10-3 execution 所屬的 table 事件續接堆疊與暫時 root。

use rivetlua_core::{ObjectRef, Register, ResultMode, Value};

use crate::alloc::{AllocationLedger, FailPoint, checked_bytes, reserve_vec};
use crate::callback::{CallbackContext, CallbackContinuation, CallbackFn, CallbackResult};
use crate::stdlib::basic::PrintBuffer;
use crate::stdlib::format::FormatState;
use crate::stdlib::gsub::GSubState;
use crate::stdlib::math::MinMaxState;
use crate::stdlib::os::CalendarTimeState;
use crate::stdlib::package::{LoadReaderState, PathSearcherState, PreloadState, RequireState};
use crate::stdlib::table::{SortState, TableOpState, TableSortTrace};
use crate::{RootId, RootKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingTableKind {
    Get,
    Set,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PendingKind {
    Table(PendingTableKind),
    Value,
    Boolean { invert: bool },
    Call,
    Close,
    Basic,
}

pub(crate) enum BasicPending {
    HostCallback {
        state: HostCallbackPending,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    DebugHook {
        hook_function: ObjectRef,
        original: Value,
        dynamic_top: usize,
        resume_instruction: bool,
        local_current_pc: bool,
        target: Option<ObjectRef>,
        target_root: Option<RootId>,
        transfer: Option<DebugTransfer>,
        builtin_return: Option<DebugBuiltinReturn>,
    },
    OsCalendarTime {
        state: CalendarTimeState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    Preload {
        state: PreloadState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    PackagePath {
        state: PathSearcherState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    Require {
        state: RequireState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    LoadReader {
        state: LoadReaderState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    DoFile {
        outer_mode: ResultMode,
        tail_return: bool,
    },
    ToString {
        outer_mode: ResultMode,
        tail_return: bool,
    },
    Pairs {
        count: u16,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    IPairsAux {
        index: i64,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    Print {
        buffer: PrintBuffer,
        arguments: PrintArguments,
        next_argument: usize,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    StringFormat {
        state: FormatState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    StringGSub {
        state: GSubState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    MathMinMax {
        state: MinMaxState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    TableSort {
        state: SortState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
    TableOp {
        state: TableOpState,
        outer_mode: ResultMode,
        tail_return: bool,
    },
}

impl BasicPending {
    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Self::HostCallback { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::DebugHook {
            target_root,
            builtin_return,
            ..
        } = self
        {
            vm.set_debug_hook_running(false);
            if let Some(root) = target_root.take() {
                vm.remove_root(root)?;
            }
            if let Some(result) = builtin_return {
                result.values.clear_roots(vm)?;
            }
        }
        if let Self::OsCalendarTime { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::Print { arguments, .. } = self {
            arguments.clear_roots(vm)?;
        }
        if let Self::StringFormat { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::StringGSub { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::MathMinMax { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::TableOp { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::TableSort { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::LoadReader { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::Require { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::Preload { state, .. } = self {
            state.clear_roots(vm)?;
        }
        if let Self::PackagePath { state, .. } = self {
            state.clear_roots(vm)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct DebugTransfer {
    pub(crate) first: usize,
    pub(crate) count: usize,
    pub(crate) register: Option<Register>,
    pub(crate) builtin: bool,
}

pub(crate) struct DebugBuiltinReturn {
    pub(crate) values: PrintArguments,
    pub(crate) destination: Register,
    pub(crate) mode: ResultMode,
    pub(crate) tail_return: bool,
    pub(crate) next: usize,
}

pub(crate) struct HostCallbackPending {
    callback: std::rc::Rc<CallbackFn>,
    captures: PrintArguments,
    arguments: PrintArguments,
}

impl HostCallbackPending {
    pub(crate) fn new(
        vm: &mut Vm,
        continuation: CallbackContinuation,
        args: &[Value],
    ) -> Result<Self, VmError> {
        let mut captures = PrintArguments::new(vm, &continuation.captures)?;
        let arguments = match PrintArguments::new(vm, args) {
            Ok(arguments) => arguments,
            Err(error) => {
                captures.clear_roots(vm)?;
                return Err(error);
            }
        };
        Ok(Self {
            callback: continuation.callback,
            captures,
            arguments,
        })
    }

    pub(crate) fn invoke(&self, values: &[Value]) -> CallbackResult {
        (self.callback)(&mut CallbackContext::new(self.captures.values()), values)
    }

    pub(crate) fn arguments(&self) -> &[Value] {
        self.arguments.values()
    }

    pub(crate) fn capture_len(&self) -> usize {
        self.captures.values().len()
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.arguments.clear_roots(vm)?;
        self.captures.clear_roots(vm)
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.captures.restore_roots(vm)?;
        if let Err(error) = self.arguments.restore_roots(vm) {
            self.captures.clear_roots(vm)?;
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.captures.trace_children(&mut visit)?;
        self.arguments.trace_children(&mut visit)
    }
}

pub(crate) struct PrintArguments {
    values: Vec<Value>,
    roots: Vec<RootId>,
    _values_charge: Option<crate::alloc::AllocationCharge>,
    _roots_charge: Option<crate::alloc::AllocationCharge>,
}

impl PrintArguments {
    pub(crate) fn empty() -> Self {
        Self {
            values: Vec::new(),
            roots: Vec::new(),
            _values_charge: None,
            _roots_charge: None,
        }
    }

    pub(crate) fn new(vm: &mut Vm, values: &[Value]) -> Result<Self, VmError> {
        let ledger = vm.allocation_ledger().clone();
        let mut owned = Vec::new();
        let values_ticket = reserve_vec(&ledger, &mut owned, values.len(), FailPoint::WorkReserve)?;
        owned.extend_from_slice(values);
        let mut roots = Vec::new();
        let roots_ticket = reserve_vec(&ledger, &mut roots, values.len(), FailPoint::WorkReserve)?;
        let values_charge = values_ticket.commit_charge()?;
        let roots_charge = roots_ticket.commit_charge()?;
        let mut arguments = Self {
            values: owned,
            roots,
            _values_charge: Some(values_charge),
            _roots_charge: Some(roots_charge),
        };
        if let Err(error) = arguments.restore_roots(vm) {
            arguments.clear_roots(vm)?;
            return Err(error);
        }
        Ok(arguments)
    }

    pub(crate) fn values(&self) -> &[Value] {
        &self.values
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        while let Some(root) = self.roots.pop() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for value in &self.values {
            if let Value::Object(object) = value {
                match vm.add_root(RootKind::Temporary, *object) {
                    Ok(root) => self.roots.push(root),
                    Err(error) => {
                        self.clear_roots(vm)?;
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for value in &self.values {
            if let Value::Object(object) = value {
                visit(*object)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeStage {
    ReadyToInvoke,
    AwaitingReturn,
    Resuming,
}

pub(crate) struct PendingOp {
    pub(crate) kind: PendingKind,
    pub(crate) values: [Value; 5],
    pub(crate) caller_depth: usize,
    pub(crate) caller_pc: usize,
    pub(crate) caller_stack_base: usize,
    pub(crate) caller_prototype: usize,
    pub(crate) caller_module: Option<ObjectRef>,
    pub(crate) resume_pc: usize,
    pub(crate) destination: Register,
    pub(crate) result_mode: ResultMode,
    pub(crate) dynamic_top: usize,
    pub(crate) chain_steps: usize,
    pub(crate) stage: ResumeStage,
    pub(crate) basic: Option<BasicPending>,
    roots: [Option<RootId>; 5],
}

impl PendingOp {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        vm: &mut Vm,
        kind: PendingKind,
        values: [Value; 5],
        caller_depth: usize,
        caller_pc: usize,
        caller_stack_base: usize,
        caller_prototype: usize,
        caller_module: Option<ObjectRef>,
        resume_pc: usize,
        destination: Register,
        result_mode: ResultMode,
        dynamic_top: usize,
        chain_steps: usize,
    ) -> Result<Self, VmError> {
        let mut pending = Self {
            kind,
            values,
            caller_depth,
            caller_pc,
            caller_stack_base,
            caller_prototype,
            caller_module,
            resume_pc,
            destination,
            result_mode,
            dynamic_top,
            chain_steps,
            stage: ResumeStage::AwaitingReturn,
            basic: None,
            roots: [None; 5],
        };
        for (index, value) in values.into_iter().enumerate() {
            if let Value::Object(object) = value {
                match vm.add_root(RootKind::Temporary, object) {
                    Ok(root) => pending.roots[index] = Some(root),
                    Err(error) => {
                        pending.clear(vm)?;
                        return Err(error);
                    }
                }
            }
        }
        Ok(pending)
    }

    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.park_roots(vm)?;
        self.basic = None;
        Ok(())
    }

    fn park_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(basic) = self.basic.as_mut() {
            basic.clear(vm)?;
        }
        for root in self.roots.iter_mut().rev() {
            if let Some(id) = root.take() {
                vm.remove_root(id)?;
            }
        }
        Ok(())
    }

    fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for (index, value) in self.values.iter().enumerate() {
            if let Value::Object(object) = value {
                match vm.add_root(RootKind::Temporary, *object) {
                    Ok(root) => self.roots[index] = Some(root),
                    Err(error) => {
                        self.park_roots(vm)?;
                        return Err(error);
                    }
                }
            }
        }
        if let Some(BasicPending::OsCalendarTime { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::HostCallback { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::DebugHook {
            builtin_return: Some(result),
            ..
        }) = self.basic.as_mut()
        {
            result.values.restore_roots(vm)?;
        }
        if let Some(BasicPending::Print { arguments, .. }) = self.basic.as_mut() {
            arguments.restore_roots(vm)?;
        }
        if let Some(BasicPending::StringFormat { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::StringGSub { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::MathMinMax { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::TableOp { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::TableSort { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::LoadReader { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::Require { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::Preload { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        if let Some(BasicPending::PackagePath { state, .. }) = self.basic.as_mut() {
            state.restore_roots(vm)?;
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Some(module) = self.caller_module {
            visit(module)?;
        }
        for value in self.values {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        if let Some(BasicPending::OsCalendarTime { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::HostCallback { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::DebugHook {
            hook_function,
            builtin_return,
            ..
        }) = self.basic.as_ref()
        {
            visit(*hook_function)?;
            if let Some(result) = builtin_return {
                result.values.trace_children(&mut visit)?;
            }
        }
        if let Some(BasicPending::Print { arguments, .. }) = self.basic.as_ref() {
            arguments.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::StringFormat { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::StringGSub { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::MathMinMax { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::TableOp { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::TableSort { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::LoadReader { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::Require { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::Preload { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        if let Some(BasicPending::PackagePath { state, .. }) = self.basic.as_ref() {
            state.trace_children(&mut visit)?;
        }
        Ok(())
    }
}

pub(crate) struct PendingStack {
    entries: Vec<PendingOp>,
    ledger: AllocationLedger,
    charge: usize,
    charges: [Option<crate::alloc::AllocationCharge>; 2],
}

/// 成長候選容器尚未取代現有堆疊；呼叫建 frame 失敗時 Drop 即回復帳額。
pub(crate) struct PreparedPush {
    replacement: Option<Vec<PendingOp>>,
    charge: usize,
    charges: [Option<crate::alloc::AllocationCharge>; 2],
}

impl PendingStack {
    pub(crate) fn new(ledger: AllocationLedger) -> Self {
        Self {
            entries: Vec::new(),
            ledger,
            charge: 0,
            charges: [None, None],
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn basic_depth(&self) -> usize {
        self.entries
            .iter()
            .filter(|pending| pending.kind == PendingKind::Basic)
            .count()
    }

    pub(crate) fn contains_debug_hook(&self) -> bool {
        self.entries
            .iter()
            .any(|pending| matches!(pending.basic, Some(BasicPending::DebugHook { .. })))
    }

    pub(crate) fn current_local_hook_caller_depth(&self) -> Option<usize> {
        self.entries.iter().rev().find_map(|pending| {
            matches!(
                pending.basic,
                Some(BasicPending::DebugHook {
                    local_current_pc: true,
                    ..
                })
            )
            .then_some(pending.caller_depth)
        })
    }

    pub(crate) fn outermost_sort_trace(&self) -> Option<TableSortTrace> {
        self.entries
            .iter()
            .find_map(|pending| match pending.basic.as_ref() {
                Some(BasicPending::TableSort { state, .. }) => Some(state.trace),
                _ => None,
            })
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn last(&self) -> Option<&PendingOp> {
        self.entries.last()
    }

    pub(crate) fn last_mut(&mut self) -> Option<&mut PendingOp> {
        self.entries.last_mut()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, index: usize) -> Option<&PendingOp> {
        self.entries.get(index)
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    pub(crate) fn prepare_push(&self) -> Result<PreparedPush, VmError> {
        if self.entries.len() == self.entries.capacity() {
            let needed = self
                .entries
                .len()
                .checked_add(1)
                .ok_or(VmError::ArithmeticOverflow)?;
            let minimum_charge = checked_bytes(needed, core::mem::size_of::<PendingOp>())?;
            let mut replacement = Vec::new();
            let ticket = reserve_vec(
                &self.ledger,
                &mut replacement,
                needed,
                FailPoint::WorkReserve,
            )?;
            let charge = checked_bytes(replacement.capacity(), core::mem::size_of::<PendingOp>())?;
            let extra = charge
                .checked_sub(minimum_charge)
                .ok_or(VmError::LedgerInvariant)?;
            let extra_ticket = match self.ledger.reserve(extra) {
                Ok(ticket) => ticket,
                Err(error) => {
                    drop(replacement);
                    drop(ticket);
                    return Err(error);
                }
            };
            let base_charge = ticket.commit_charge()?;
            let extra_charge = extra_ticket.commit_charge()?;
            return Ok(PreparedPush {
                replacement: Some(replacement),
                charge,
                charges: [Some(base_charge), Some(extra_charge)],
            });
        }
        Ok(PreparedPush {
            replacement: None,
            charge: 0,
            charges: [None, None],
        })
    }

    pub(crate) fn push_prepared(&mut self, mut prepared: PreparedPush, pending: PendingOp) {
        if let Some(mut replacement) = prepared.replacement.take() {
            debug_assert!(replacement.capacity() >= self.entries.len() + 1);
            replacement.append(&mut self.entries);
            replacement.push(pending);
            let old_entries = core::mem::replace(&mut self.entries, replacement);
            drop(old_entries);
            self.charges = [prepared.charges[0].take(), prepared.charges[1].take()];
            self.charge = prepared.charge;
            prepared.charge = 0;
        } else {
            debug_assert!(self.entries.len() < self.entries.capacity());
            self.entries.push(pending);
        }
    }

    pub(crate) fn pop(&mut self) -> Option<PendingOp> {
        self.entries.pop()
    }

    pub(crate) fn release_empty(&mut self) -> Result<(), VmError> {
        if self.entries.is_empty() && self.charge != 0 {
            self.entries = Vec::new();
            self.charges = [None, None];
            self.charge = 0;
        }
        Ok(())
    }

    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        while let Some(mut pending) = self.entries.pop() {
            pending.clear(vm)?;
        }
        self.release_empty()
    }

    pub(crate) fn park_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for pending in &mut self.entries {
            pending.park_roots(vm)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for pending in &mut self.entries {
            if let Err(error) = pending.restore_roots(vm) {
                self.park_roots(vm)?;
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for pending in &self.entries {
            pending.trace_children(&mut visit)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod p13_a_tests {
    use rivetlua_core::{Register, ResultMode, Value};

    use super::{BasicPending, PendingKind, PendingOp, PendingStack, PrintArguments};
    use crate::alloc::FailPoint;
    use crate::stdlib::basic::PrintBuffer;
    use crate::{Vm, VmError};

    #[test]
    fn p13_a_print_pending_parks_restores_and_releases_roots_and_host_bytes() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate_table().unwrap();
        let baseline = vm.ledger_snapshot().host_allocation_bytes;
        let arguments = PrintArguments::new(&mut vm, &[Value::Object(object)]).unwrap();
        let mut pending = PendingOp::new(
            &mut vm,
            PendingKind::Basic,
            [
                Value::Object(object),
                Value::Nil,
                Value::Nil,
                Value::Nil,
                Value::Nil,
            ],
            0,
            0,
            0,
            0,
            None,
            1,
            Register(0),
            ResultMode::Fixed(1),
            0,
            1,
        )
        .unwrap();
        pending.basic = Some(BasicPending::Print {
            buffer: PrintBuffer::new(&vm),
            arguments,
            next_argument: 0,
            outer_mode: ResultMode::All,
            tail_return: false,
        });
        let mut stack = PendingStack::new(vm.allocation_ledger().clone());
        let prepared = stack.prepare_push().unwrap();
        stack.push_prepared(prepared, pending);
        assert_eq!(vm.roots().total_count(), 2);
        assert!(vm.ledger_snapshot().host_allocation_bytes > baseline);
        stack.park_roots(&mut vm).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert!(stack.last().unwrap().basic.is_some());
        stack.restore_roots(&mut vm).unwrap();
        assert_eq!(vm.roots().total_count(), 2);
        stack.clear(&mut vm).unwrap();
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().host_allocation_bytes, baseline);
    }

    #[test]
    fn p13_a_print_arguments_failure_keeps_roots_and_ledger_unchanged() {
        let mut vm = Vm::new().unwrap();
        let object = vm.allocate_table().unwrap();
        let baseline = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(matches!(
            PrintArguments::new(&mut vm, &[Value::Object(object)]),
            Err(VmError::InjectedFailure(FailPoint::WorkReserve))
        ));
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(
            vm.ledger_snapshot().host_allocation_bytes,
            baseline.host_allocation_bytes
        );
        assert_eq!(vm.ledger_snapshot().reserved, baseline.reserved);
    }
}
