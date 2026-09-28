//! 顯式 Lua 呼叫 frame 與暫存器 root 生命週期。

use crate::alloc::{AllocationLedger, FailPoint, checked_bytes, reserve_vec};
use crate::unwind::CloseEntry;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{RootId, RootKind, Vm, VmError};
use rivetlua_core::{
    BytecodeBindingId, BytecodeExitKind, BytecodePrototype, ObjectRef, ProtoId, Register,
    ResultMode, Value,
};

/// 暫停於已驗證 ClosePath 的位置；metadata 仍由 Execution 的 VerifiedModule 持有。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingCloseSnapshot {
    pub prototype: ProtoId,
    pub close_pc: usize,
    pub path_start_pc: usize,
    pub path_offset: usize,
    pub path_kind: BytecodeExitKind,
    pub next_binding: BytecodeBindingId,
    pub next_register: Register,
    pub return_base: Option<Register>,
    pub return_mode: Option<ResultMode>,
    pub result_count: usize,
    pub retained_root_count: usize,
}

pub(crate) struct CallFrame {
    pub(crate) module: Option<ObjectRef>,
    pub(crate) closure: Option<ObjectRef>,
    pub(crate) closure_root: Option<RootId>,
    pub(crate) stack_base: usize,
    pub(crate) prototype: usize,
    pub(crate) base: usize,
    pub(crate) return_destination: Option<Register>,
    pub(crate) return_mode: ResultMode,
    pub(crate) tail_return: bool,
    pub(crate) pending_close: Option<PendingCloseSnapshot>,
    pub(crate) caller: Option<usize>,
    pub(crate) depth: usize,
    pub(crate) pc: usize,
    pub(crate) registers: Vec<Value>,
    pub(crate) roots: Vec<Option<RootId>>,
    pub(crate) varargs: Vec<Value>,
    pub(crate) vararg_roots: Vec<Option<RootId>>,
    pub(crate) vararg_charge: usize,
    pub(crate) named_vararg: Option<Register>,
    pub(crate) dynamic_top: usize,
    pub(crate) register_limit: usize,
    pub(crate) max_register_limit: usize,
    pub(crate) ledger: AllocationLedger,
    pub(crate) charge: usize,
    pub(crate) open_upvalues: Vec<OpenUpvalue>,
    pub(crate) open_charge: usize,
    pub(crate) close_entries: Vec<CloseEntry>,
    pub(crate) close_charge: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct OpenUpvalue {
    pub(crate) slot: usize,
    pub(crate) object: ObjectRef,
    pub(crate) root: Option<RootId>,
}

impl CallFrame {
    pub(crate) fn new(
        prototype: &BytecodePrototype,
        prototype_index: usize,
        module: Option<ObjectRef>,
        ledger: &AllocationLedger,
    ) -> Result<Self, RuntimeError> {
        let limit = usize::from(prototype.register_count);
        if limit > usize::from(prototype.frame.register_limit)
            || !prototype.frame.registers_start_as_nil
        {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let register_bytes = checked_bytes(limit, core::mem::size_of::<Value>())?;
        let root_bytes = checked_bytes(limit, core::mem::size_of::<Option<RootId>>())?;
        let charge = register_bytes
            .checked_add(root_bytes)
            .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let mut registers = Vec::new();
        let register_ticket = reserve_vec(
            ledger,
            &mut registers,
            limit,
            FailPoint::FrameRegistersReserve,
        )?;
        registers.resize(limit, Value::Nil);
        let mut roots = Vec::new();
        let root_ticket = reserve_vec(ledger, &mut roots, limit, FailPoint::FrameRootsReserve)?;
        roots.resize(limit, None);
        let dynamic_top = usize::from(prototype.frame.initial_top.0);
        if dynamic_top > limit || usize::from(prototype.frame.dynamic_top.0) > limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        register_ticket.commit()?;
        if let Err(error) = root_ticket.commit() {
            ledger.refund_on_drop(register_bytes);
            return Err(error.into());
        }
        Ok(Self {
            module,
            closure: None,
            closure_root: None,
            stack_base: 0,
            prototype: prototype_index,
            base: 0,
            return_destination: None,
            return_mode: ResultMode::Fixed(0),
            tail_return: false,
            pending_close: None,
            caller: None,
            depth: 0,
            pc: 0,
            registers,
            roots,
            varargs: Vec::new(),
            vararg_roots: Vec::new(),
            vararg_charge: 0,
            named_vararg: prototype.named_vararg.map(|(_, register)| register),
            dynamic_top,
            register_limit: limit,
            max_register_limit: usize::from(prototype.frame.register_limit),
            ledger: ledger.clone(),
            charge,
            open_upvalues: Vec::new(),
            open_charge: 0,
            close_entries: Vec::new(),
            close_charge: 0,
        })
    }

    pub(crate) fn add_close(
        &mut self,
        vm: &mut Vm,
        binding: BytecodeBindingId,
        register: Register,
        value: Value,
    ) -> Result<(), RuntimeError> {
        let root = if let Value::Object(object) = value {
            Some(vm.add_root(RootKind::Stack, object)?)
        } else {
            None
        };
        let ticket = match reserve_vec(
            &self.ledger,
            &mut self.close_entries,
            1,
            FailPoint::WorkReserve,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                if let Some(root) = root {
                    vm.remove_root(root)?;
                }
                return Err(error.into());
            }
        };
        if let Err(error) = ticket.commit() {
            if let Some(root) = root {
                vm.remove_root(root)?;
            }
            return Err(error.into());
        }
        self.close_entries.push(CloseEntry {
            binding,
            register,
            value,
            root,
        });
        self.close_charge += core::mem::size_of::<CloseEntry>();
        Ok(())
    }

    pub(crate) fn pop_close(&mut self, vm: &mut Vm) -> Result<Option<CloseEntry>, RuntimeError> {
        let Some(entry) = self.close_entries.last().copied() else {
            return Ok(None);
        };
        if let Some(root) = entry.root {
            vm.remove_root(root)?;
        }
        let bytes = core::mem::size_of::<CloseEntry>();
        self.ledger.refund(bytes)?;
        self.close_charge -= bytes;
        self.close_entries.pop();
        Ok(Some(CloseEntry {
            root: None,
            ..entry
        }))
    }

    pub(crate) fn index(&self, register: Register) -> Result<usize, RuntimeError> {
        let index = usize::from(register.0);
        if index >= self.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        Ok(index)
    }

    /// 開放結果超過初始 register_count 時，先備妥兩份新 storage 並計帳再替換。
    pub(crate) fn grow_for_open_results(&mut self, required: usize) -> Result<(), RuntimeError> {
        if required <= self.register_limit {
            return Ok(());
        }
        if required > self.max_register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let register_bytes = checked_bytes(required, core::mem::size_of::<Value>())?;
        let root_bytes = checked_bytes(required, core::mem::size_of::<Option<RootId>>())?;
        let new_charge = register_bytes
            .checked_add(root_bytes)
            .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let mut registers = Vec::new();
        let register_ticket = reserve_vec(
            &self.ledger,
            &mut registers,
            required,
            FailPoint::FrameRegistersReserve,
        )?;
        let mut roots = Vec::new();
        let root_ticket = reserve_vec(
            &self.ledger,
            &mut roots,
            required,
            FailPoint::FrameRootsReserve,
        )?;
        registers.extend_from_slice(&self.registers);
        registers.resize(required, Value::Nil);
        roots.extend_from_slice(&self.roots);
        roots.resize(required, None);
        register_ticket.commit()?;
        if let Err(error) = root_ticket.commit() {
            self.ledger.refund_on_drop(register_bytes);
            return Err(error.into());
        }
        if let Err(error) = self.ledger.refund(self.charge) {
            self.ledger.refund_on_drop(new_charge);
            return Err(error.into());
        }
        self.registers = registers;
        self.roots = roots;
        self.register_limit = required;
        self.charge = new_charge;
        Ok(())
    }

    pub(crate) fn read(&self, register: Register) -> Result<Value, RuntimeError> {
        self.registers
            .get(self.index(register)?)
            .copied()
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
    }

    pub(crate) fn write(
        &mut self,
        vm: &mut Vm,
        register: Register,
        value: Value,
    ) -> Result<(), RuntimeError> {
        let index = self.index(register)?;
        let new_root = if let Value::Object(object) = value {
            Some(vm.add_root(RootKind::Stack, object)?)
        } else {
            None
        };
        if let Some(old_root) = self.roots[index] {
            if let Err(error) = vm.remove_root(old_root) {
                if let Some(root) = new_root {
                    let _ = vm.remove_root(root);
                }
                return Err(error.into());
            }
        }
        self.registers[index] = value;
        self.roots[index] = new_root;
        Ok(())
    }

    /// 額外引數維持精確數量；caller 在此操作完成前持有所有來源 root。
    pub(crate) fn set_varargs(
        &mut self,
        vm: &mut Vm,
        values: &[Value],
    ) -> Result<(), RuntimeError> {
        if values.is_empty() {
            return Ok(());
        }
        let value_bytes = checked_bytes(values.len(), core::mem::size_of::<Value>())?;
        let root_bytes = checked_bytes(values.len(), core::mem::size_of::<Option<RootId>>())?;
        let charge = value_bytes
            .checked_add(root_bytes)
            .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let mut varargs = Vec::new();
        let value_ticket = reserve_vec(
            &self.ledger,
            &mut varargs,
            values.len(),
            FailPoint::FrameRegistersReserve,
        )?;
        let mut roots = Vec::new();
        let root_ticket = reserve_vec(
            &self.ledger,
            &mut roots,
            values.len(),
            FailPoint::FrameRootsReserve,
        )?;
        varargs.extend_from_slice(values);
        for value in values {
            let root = if let Value::Object(object) = value {
                match vm.add_root(RootKind::Stack, *object) {
                    Ok(root) => Some(root),
                    Err(error) => {
                        for root in roots.into_iter().flatten() {
                            vm.remove_root(root)?;
                        }
                        return Err(error.into());
                    }
                }
            } else {
                None
            };
            roots.push(root);
        }
        if let Err(error) = value_ticket.commit() {
            for root in roots.into_iter().flatten() {
                vm.remove_root(root)?;
            }
            return Err(error.into());
        }
        if let Err(error) = root_ticket.commit() {
            self.ledger.refund_on_drop(value_bytes);
            for root in roots.into_iter().flatten() {
                vm.remove_root(root)?;
            }
            return Err(error.into());
        }
        self.varargs = varargs;
        self.vararg_roots = roots;
        self.vararg_charge = charge;
        Ok(())
    }

    /// 具名 vararg 只在尚未入棧的 callee 中建立；失敗時回收未公開的 table 與鍵。
    pub(crate) fn set_named_varargs(
        &mut self,
        vm: &mut Vm,
        values: &[Value],
    ) -> Result<(ObjectRef, ObjectRef), RuntimeError> {
        let register = self
            .named_vararg
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let table = vm.allocate_table_with_capacity(values.len(), 1)?;
        if let Err(error) = self.write(vm, register, Value::Object(table)) {
            vm.reclaim(table)?;
            return Err(error);
        }
        let mut name_key = None;
        let result = (|| {
            for (index, value) in values.iter().copied().enumerate() {
                let key = i64::try_from(index + 1).map_err(|_| VmError::ArithmeticOverflow)?;
                vm.raw_set(table, Value::Integer(key), value)?;
            }
            let key = vm.allocate_byte_string(b"n")?;
            name_key = Some(key);
            let count = i64::try_from(values.len()).map_err(|_| VmError::ArithmeticOverflow)?;
            vm.raw_set(table, Value::Object(key), Value::Integer(count))?;
            name_key = None;
            Ok::<ObjectRef, VmError>(key)
        })();
        let key = match result {
            Ok(key) => key,
            Err(error) => {
                self.write(vm, register, Value::Nil)?;
                vm.reclaim(table)?;
                if let Some(key) = name_key {
                    vm.reclaim(key)?;
                }
                return Err(error.into());
            }
        };
        Ok((table, key))
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        for root in &mut self.roots {
            if let Some(id) = *root {
                vm.remove_root(id)?;
                *root = None;
            }
        }
        for root in &mut self.vararg_roots {
            if let Some(id) = *root {
                vm.remove_root(id)?;
                *root = None;
            }
        }
        if let Some(root) = self.closure_root {
            vm.remove_root(root)?;
            self.closure_root = None;
        }
        for entry in &mut self.close_entries {
            if let Some(root) = entry.root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    /// 暫停後由 coroutine payload trace 值，移除獨立 root 以便整個 thread 可回收。
    pub(crate) fn park_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        self.clear_roots(vm)?;
        for entry in &mut self.open_upvalues {
            if let Some(root) = entry.root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    /// 在 payload 暫時移出、但 coroutine handle 仍受 root 保護時恢復 frame roots。
    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        let restored = (|| {
            if let Some(closure) = self.closure {
                self.closure_root = Some(vm.add_root(RootKind::Stack, closure)?);
            }
            for (value, root) in self.registers.iter().zip(self.roots.iter_mut()) {
                if let Value::Object(object) = value {
                    *root = Some(vm.add_root(RootKind::Stack, *object)?);
                }
            }
            for (value, root) in self.varargs.iter().zip(self.vararg_roots.iter_mut()) {
                if let Value::Object(object) = value {
                    *root = Some(vm.add_root(RootKind::Stack, *object)?);
                }
            }
            for entry in &mut self.open_upvalues {
                entry.root = Some(vm.add_root(RootKind::Temporary, entry.object)?);
            }
            for entry in &mut self.close_entries {
                if let Value::Object(object) = entry.value {
                    entry.root = Some(vm.add_root(RootKind::Stack, object)?);
                }
            }
            Ok(())
        })();
        if restored.is_err() {
            self.park_roots(vm)?;
        }
        restored
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Some(module) = self.module {
            visit(module)?;
        }
        if let Some(closure) = self.closure {
            visit(closure)?;
        }
        for value in self.registers.iter().chain(&self.varargs) {
            if let Value::Object(object) = value {
                visit(*object)?;
            }
        }
        for entry in &self.open_upvalues {
            visit(entry.object)?;
        }
        for entry in &self.close_entries {
            if let Value::Object(object) = entry.value {
                visit(object)?;
            }
        }
        Ok(())
    }

    pub(crate) fn find_open(&self, slot: usize) -> Option<ObjectRef> {
        self.open_upvalues
            .iter()
            .find_map(|entry| (entry.slot == slot).then_some(entry.object))
    }

    pub(crate) fn add_open(
        &mut self,
        vm: &mut Vm,
        slot: usize,
        object: ObjectRef,
    ) -> Result<(), RuntimeError> {
        let root = vm.add_root(RootKind::Temporary, object)?;
        let ticket = match reserve_vec(
            &self.ledger,
            &mut self.open_upvalues,
            1,
            FailPoint::OpenUpvaluesReserve,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                vm.remove_root(root)?;
                return Err(error.into());
            }
        };
        if let Err(error) = ticket.commit() {
            vm.remove_root(root)?;
            return Err(error.into());
        }
        self.open_upvalues.push(OpenUpvalue {
            slot,
            object,
            root: Some(root),
        });
        self.open_charge += core::mem::size_of::<OpenUpvalue>();
        Ok(())
    }

    pub(crate) fn close_open(&mut self, vm: &mut Vm) -> Result<(), RuntimeError> {
        while let Some(entry) = self.open_upvalues.last().copied() {
            let index = entry
                .slot
                .checked_sub(self.stack_base)
                .filter(|index| *index < self.register_limit)
                .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
            let value = self.registers[index];
            vm.with_upvalue_mut(entry.object, |upvalue| upvalue.close(value))?;
            if let Some(root) = entry.root {
                vm.remove_root(root)?;
            }
            self.open_upvalues.pop();
        }
        Ok(())
    }

    pub(crate) fn close_slot(
        &mut self,
        vm: &mut Vm,
        register: Register,
    ) -> Result<(), RuntimeError> {
        let index = self.index(register)?;
        let slot = self
            .stack_base
            .checked_add(index)
            .ok_or(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let Some(position) = self
            .open_upvalues
            .iter()
            .position(|entry| entry.slot == slot)
        else {
            return Ok(());
        };
        let entry = self.open_upvalues[position];
        vm.with_upvalue_mut(entry.object, |upvalue| upvalue.close(self.registers[index]))?;
        if let Some(root) = entry.root {
            vm.remove_root(root)?;
        }
        self.open_upvalues.remove(position);
        Ok(())
    }

    pub(crate) fn release_storage(&mut self) {
        self.registers = Vec::new();
        self.roots = Vec::new();
        self.varargs = Vec::new();
        self.vararg_roots = Vec::new();
        if self.vararg_charge != 0 {
            self.ledger.refund_on_drop(self.vararg_charge);
            self.vararg_charge = 0;
        }
        self.register_limit = 0;
        self.max_register_limit = 0;
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
            self.charge = 0;
        }
        self.open_upvalues = Vec::new();
        if self.open_charge != 0 {
            self.ledger.refund_on_drop(self.open_charge);
            self.open_charge = 0;
        }
        self.close_entries = Vec::new();
        if self.close_charge != 0 {
            self.ledger.refund_on_drop(self.close_charge);
            self.close_charge = 0;
        }
    }
}

impl Drop for CallFrame {
    fn drop(&mut self) {
        self.release_storage();
    }
}
