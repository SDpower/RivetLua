//! 協程狀態與可由 heap 追蹤的暫停執行內容。

use rivetlua_core::{ObjectRef, Register, ResultMode, Value};

use crate::alloc::AllocationLedger;
use crate::call::CallFrame;
use crate::errors::ProtectedBoundary;
use crate::pending_op::PendingStack;
use crate::unwind::CloseUnwind;
use crate::vm::{NativeCompletion, RuntimeError};
use crate::{RootId, RootKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoroutineState {
    Suspended,
    Running,
    Normal,
    Dead,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct YieldSite {
    pub(crate) destination: Register,
    pub(crate) result_mode: ResultMode,
    pub(crate) resume_pc: usize,
    pub(crate) tail_return: bool,
}

/// 已暫停時由 Coroutine payload trace；運行或等待子協程時由各欄位 roots 保護。
pub(crate) struct ThreadContext {
    pub(crate) frame: CallFrame,
    pub(crate) callers: Vec<CallFrame>,
    pub(crate) callers_charge: usize,
    pub(crate) pending_ops: PendingStack,
    pub(crate) protected: Vec<ProtectedBoundary>,
    pub(crate) protected_charge: usize,
    pub(crate) error_root: Option<RootId>,
    pub(crate) yield_site: Option<YieldSite>,
    pub(crate) close_unwind: Option<CloseUnwind>,
    ledger: AllocationLedger,
}

impl ThreadContext {
    pub(crate) fn new(frame: CallFrame, ledger: &AllocationLedger) -> Self {
        Self {
            frame,
            callers: Vec::new(),
            callers_charge: 0,
            pending_ops: PendingStack::new(ledger.clone()),
            protected: Vec::new(),
            protected_charge: 0,
            error_root: None,
            yield_site: None,
            close_unwind: None,
            ledger: ledger.clone(),
        }
    }

    pub(crate) fn park_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        self.frame.park_roots(vm)?;
        for frame in &mut self.callers {
            frame.park_roots(vm)?;
        }
        self.pending_ops.park_roots(vm)?;
        for boundary in &mut self.protected {
            boundary.clear(vm)?;
        }
        if let Some(root) = self.error_root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        let restored = (|| {
            self.frame.restore_roots(vm)?;
            for frame in &mut self.callers {
                frame.restore_roots(vm)?;
            }
            self.pending_ops.restore_roots(vm)?;
            for boundary in &mut self.protected {
                boundary.restore_root(vm)?;
            }
            if let Some(unwind) = self.close_unwind {
                if let Value::Object(object) = unwind.error.value {
                    self.error_root = Some(vm.add_root(RootKind::Temporary, object)?);
                }
            }
            Ok::<(), RuntimeError>(())
        })();
        if restored.is_err() {
            self.park_roots(vm)?;
        }
        restored
    }

    pub(crate) fn finish(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        if let Some(root) = self.error_root.take() {
            vm.remove_root(root)?;
        }
        for boundary in &mut self.protected {
            boundary.clear(vm)?;
        }
        self.protected.clear();
        self.pending_ops.clear(vm)?;
        self.frame.close_open(vm)?;
        self.frame.clear_roots(vm)?;
        for frame in &mut self.callers {
            frame.close_open(vm)?;
            frame.clear_roots(vm)?;
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        self.frame.trace_children(&mut visit)?;
        for frame in &self.callers {
            frame.trace_children(&mut visit)?;
        }
        self.pending_ops.trace_children(&mut visit)?;
        for boundary in &self.protected {
            if let Some(Value::Object(object)) = boundary.handler {
                visit(object)?;
            }
        }
        if let Some(unwind) = self.close_unwind {
            if let Value::Object(object) = unwind.error.value {
                visit(object)?;
            }
        }
        Ok(())
    }

    pub(crate) fn read_slot(&self, slot: usize) -> Option<Value> {
        core::iter::once(&self.frame)
            .chain(&self.callers)
            .find_map(|frame| {
                slot.checked_sub(frame.stack_base)
                    .filter(|index| *index < frame.register_limit)
                    .map(|index| frame.registers[index])
            })
    }

    pub(crate) fn write_parked_slot(&mut self, slot: usize, value: Value) -> bool {
        let frame = core::iter::once(&mut self.frame)
            .chain(&mut self.callers)
            .find(|frame| {
                slot.checked_sub(frame.stack_base)
                    .is_some_and(|index| index < frame.register_limit)
            });
        if let Some(frame) = frame {
            frame.registers[slot - frame.stack_base] = value;
            true
        } else {
            false
        }
    }
}

impl Drop for ThreadContext {
    fn drop(&mut self) {
        self.ledger.refund_on_drop(self.callers_charge);
        self.callers_charge = 0;
        self.ledger.refund_on_drop(self.protected_charge);
        self.protected_charge = 0;
    }
}

pub(crate) struct Coroutine {
    pub(crate) state: CoroutineState,
    pub(crate) entry: Value,
    pub(crate) context: Option<ThreadContext>,
    pub(crate) unwind_context: Option<ThreadContext>,
    pub(crate) error: Option<Value>,
    pub(crate) native_yielded: bool,
    pub(crate) native: Option<NativeCompletion>,
    pub(crate) native_bridge: Option<ObjectRef>,
}

impl Coroutine {
    pub(crate) fn new(entry: Value) -> Self {
        Self {
            state: CoroutineState::Suspended,
            entry,
            context: None,
            unwind_context: None,
            error: None,
            native_yielded: false,
            native: None,
            native_bridge: None,
        }
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Value::Object(object) = self.entry {
            visit(object)?;
        }
        if let Some(Value::Object(object)) = self.error {
            visit(object)?;
        }
        if let Some(object) = self.native_bridge {
            visit(object)?;
        }
        if let Some(context) = &self.context {
            context.trace_children(&mut visit)?;
        }
        if let Some(context) = &self.unwind_context {
            context.trace_children(&mut visit)?;
        }
        if let Some(
            NativeCompletion::XPCallBody {
                handler: Value::Object(object),
                ..
            }
            | NativeCompletion::XPCallHandler {
                handler: Value::Object(object),
                ..
            },
        ) = self.native
        {
            visit(object)?;
        }
        Ok(())
    }
}

pub(crate) fn root_coroutine(vm: &mut Vm, object: ObjectRef) -> Result<RootId, VmError> {
    vm.add_root(RootKind::Coroutine, object)
}
