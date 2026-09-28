//! P10-3 execution 所屬的 table 事件續接堆疊與暫時 root。

use rivetlua_core::{ObjectRef, Register, ResultMode, Value};

use crate::alloc::{AllocationLedger, FailPoint, checked_bytes, reserve_vec};
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResumeStage {
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
                        self.clear(vm)?;
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
        if let Some(module) = self.caller_module {
            visit(module)?;
        }
        for value in self.values {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        Ok(())
    }
}

pub(crate) struct PendingStack {
    entries: Vec<PendingOp>,
    ledger: AllocationLedger,
    charge: usize,
}

/// 成長候選容器尚未取代現有堆疊；呼叫建 frame 失敗時 Drop 即回復帳額。
pub(crate) struct PreparedPush {
    replacement: Option<Vec<PendingOp>>,
    ledger: AllocationLedger,
    charge: usize,
}

impl Drop for PreparedPush {
    fn drop(&mut self) {
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
        }
    }
}

impl PendingStack {
    pub(crate) fn new(ledger: AllocationLedger) -> Self {
        Self {
            entries: Vec::new(),
            ledger,
            charge: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn last(&self) -> Option<&PendingOp> {
        self.entries.last()
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
            let extra_ticket = self.ledger.reserve(extra)?;
            ticket.commit()?;
            if let Err(error) = extra_ticket.commit() {
                self.ledger.refund_on_drop(minimum_charge);
                return Err(error);
            }
            return Ok(PreparedPush {
                replacement: Some(replacement),
                ledger: self.ledger.clone(),
                charge,
            });
        }
        Ok(PreparedPush {
            replacement: None,
            ledger: self.ledger.clone(),
            charge: 0,
        })
    }

    pub(crate) fn push_prepared(&mut self, mut prepared: PreparedPush, pending: PendingOp) {
        if let Some(mut replacement) = prepared.replacement.take() {
            debug_assert!(replacement.capacity() >= self.entries.len() + 1);
            replacement.append(&mut self.entries);
            replacement.push(pending);
            self.entries = replacement;
            self.ledger.refund_on_drop(self.charge);
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
            self.ledger.refund(self.charge)?;
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
            pending.clear(vm)?;
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

impl Drop for PendingStack {
    fn drop(&mut self) {
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
            self.charge = 0;
        }
    }
}
