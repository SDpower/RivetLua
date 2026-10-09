//! 協程狀態與可由 heap 追蹤的暫停執行內容。

use std::any::Any;

use rivetlua_core::{ObjectRef, Register, ResultMode, Value};

use crate::alloc::{AllocationCharges, AllocationLedger};
use crate::call::CallFrame;
use crate::errors::ProtectedBoundary;
use crate::pending_op::PendingStack;
use crate::stdlib::debug::DebugHook;
use crate::unwind::CloseUnwind;
use crate::vm::{ExternalSuspended, NativeCompletion, RuntimeError};
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
    pub(crate) callers_charges: AllocationCharges,
    pub(crate) pending_ops: PendingStack,
    pub(crate) protected: Vec<ProtectedBoundary>,
    pub(crate) protected_charge: usize,
    pub(crate) protected_charges: AllocationCharges,
    pub(crate) error_root: Option<RootId>,
    pub(crate) yield_site: Option<YieldSite>,
    pub(crate) close_unwind: Option<CloseUnwind>,
}

#[derive(Clone, Copy)]
pub(crate) enum ParkedLocalSlot {
    Register(Register),
    Vararg(usize),
    VarargTable,
}

impl ThreadContext {
    pub(crate) fn new(frame: CallFrame, ledger: &AllocationLedger) -> Self {
        Self {
            frame,
            callers: Vec::new(),
            callers_charge: 0,
            callers_charges: AllocationCharges::new(),
            pending_ops: PendingStack::new(ledger.clone()),
            protected: Vec::new(),
            protected_charge: 0,
            protected_charges: AllocationCharges::new(),
            error_root: None,
            yield_site: None,
            close_unwind: None,
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

    pub(crate) fn debug_frame(&self, level: usize) -> Option<&CallFrame> {
        match level {
            0 => None,
            1 => Some(&self.frame),
            _ => self.callers.iter().rev().nth(level - 2),
        }
    }

    pub(crate) fn write_parked_debug_local(
        &mut self,
        level: usize,
        slot: ParkedLocalSlot,
        value: Value,
    ) -> bool {
        let frame = match level {
            0 => return false,
            1 => &mut self.frame,
            _ => match self.callers.iter_mut().rev().nth(level - 2) {
                Some(frame) => frame,
                None => return false,
            },
        };
        match slot {
            ParkedLocalSlot::Register(register) => {
                let index = usize::from(register.0);
                if index >= frame.register_limit || frame.roots[index].is_some() {
                    return false;
                }
                frame.registers[index] = value;
            }
            ParkedLocalSlot::Vararg(index) => {
                if index >= frame.varargs.len() || frame.vararg_roots[index].is_some() {
                    return false;
                }
                frame.varargs[index] = value;
            }
            ParkedLocalSlot::VarargTable => {
                if frame.debug_vararg_table_root.is_some() {
                    return false;
                }
                frame.debug_vararg_table = value;
            }
        }
        true
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

pub(crate) struct Coroutine {
    pub(crate) state: CoroutineState,
    pub(crate) entry: Value,
    pub(crate) context: Option<ThreadContext>,
    pub(crate) debug_revision: u64,
    pub(crate) unwind_context: Option<ThreadContext>,
    pub(crate) error: Option<Value>,
    pub(crate) native_yielded: bool,
    pub(crate) native: Option<NativeCompletion>,
    pub(crate) native_bridge: Option<ObjectRef>,
    /// 公開 C resume 暫停的完整外部執行；不佔用 VM 的活躍 callback LIFO。
    pub(crate) external_suspended: Option<ExternalSuspended>,
    pub(crate) debug_hook: Option<DebugHook>,
    /// 宿主控制配置隨 coroutine payload 回收，不屬於 Lua GC 子邊。
    pub(crate) host_attachment: Option<Box<dyn Any>>,
}

impl Coroutine {
    pub(crate) fn new(entry: Value) -> Self {
        Self {
            state: CoroutineState::Suspended,
            entry,
            context: None,
            debug_revision: 0,
            unwind_context: None,
            error: None,
            native_yielded: false,
            native: None,
            native_bridge: None,
            external_suspended: None,
            debug_hook: None,
            host_attachment: None,
        }
    }

    pub(crate) fn take_context(&mut self) -> Option<ThreadContext> {
        let context = self.context.take();
        if context.is_some() {
            self.debug_revision = self.debug_revision.saturating_add(1);
        }
        context
    }

    pub(crate) fn replace_context(&mut self, context: Option<ThreadContext>) {
        self.debug_revision = self.debug_revision.saturating_add(1);
        self.context = context;
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
        if let Some(hook) = self.debug_hook {
            visit(hook.function)?;
        }
        if let Some(context) = &self.context {
            context.trace_children(&mut visit)?;
        }
        if let Some(context) = &self.unwind_context {
            context.trace_children(&mut visit)?;
        }
        if let Some(native) = self.native {
            crate::gc::trace::trace_native(native, &mut visit)?;
        }
        if let Some(suspended) = &self.external_suspended {
            suspended.trace_children(&mut visit)?;
        }
        Ok(())
    }
}

pub(crate) fn root_coroutine(vm: &mut Vm, object: ObjectRef) -> Result<RootId, VmError> {
    vm.add_root(RootKind::Coroutine, object)
}
