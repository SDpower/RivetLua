//! 顯式 Lua 呼叫 frame 與暫存器 root 生命週期。

use crate::alloc::{AllocationCharges, AllocationLedger, FailPoint, checked_bytes, reserve_vec};
use crate::unwind::CloseEntry;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{RootId, RootKind, Vm, VmError};
use rivetlua_core::{
    BytecodeBindingId, BytecodeExitKind, BytecodePrototype, ObjectRef, OfficialExecutionPlan,
    OfficialPlanFrameInputSource, ProtoId, Register, ResultMode, Value,
};

#[derive(Clone, Copy, Default)]
pub(crate) struct OfficialFrameRegisters {
    pub(crate) raw: Option<Register>,
    pub(crate) guest_named: Option<Register>,
    pub(crate) active: Option<Register>,
}

impl OfficialFrameRegisters {
    pub(crate) fn from_plan(plan: &OfficialExecutionPlan, prototype: ProtoId) -> Self {
        let mut result = Self::default();
        for input in plan.frame_inputs(prototype) {
            match input.source {
                OfficialPlanFrameInputSource::OriginalVarargs => result.raw = Some(input.register),
                OfficialPlanFrameInputSource::GuestNamedVarargTable => {
                    result.guest_named = Some(input.register)
                }
                OfficialPlanFrameInputSource::ActiveVarargs => result.active = Some(input.register),
            }
        }
        result
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct VarargPayloads {
    entries: [Option<(ObjectRef, ObjectRef)>; 2],
}

impl VarargPayloads {
    pub(crate) fn reclaim(self, vm: &mut Vm) -> Result<(), RuntimeError> {
        for (table, key) in self.entries.into_iter().flatten() {
            vm.reclaim_unpublished_object(table)?;
            vm.reclaim_unpublished_object(key)?;
        }
        Ok(())
    }
}

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
    pub(crate) hook_entry: Option<bool>,
    pub(crate) tail_called: bool,
    pub(crate) call_extraargs: u8,
    pub(crate) hook_exit_fired: bool,
    pub(crate) pending_close: Option<PendingCloseSnapshot>,
    pub(crate) caller: Option<usize>,
    pub(crate) depth: usize,
    pub(crate) pc: usize,
    pub(crate) registers: Vec<Value>,
    pub(crate) roots: Vec<Option<RootId>>,
    pub(crate) varargs: Vec<Value>,
    pub(crate) vararg_roots: Vec<Option<RootId>>,
    pub(crate) vararg_charge: usize,
    vararg_value_owner: Option<crate::alloc::AllocationCharge>,
    vararg_root_owner: Option<crate::alloc::AllocationCharge>,
    pub(crate) official_raw_varargs: Option<Register>,
    pub(crate) official_raw_vararg_count: usize,
    pub(crate) named_vararg: Option<Register>,
    pub(crate) debug_vararg_table: Value,
    pub(crate) debug_vararg_table_root: Option<RootId>,
    pub(crate) dynamic_top: usize,
    pub(crate) register_limit: usize,
    pub(crate) max_register_limit: usize,
    pub(crate) ledger: AllocationLedger,
    pub(crate) charge: usize,
    register_owner: Option<crate::alloc::AllocationCharge>,
    root_owner: Option<crate::alloc::AllocationCharge>,
    pub(crate) open_upvalues: Vec<OpenUpvalue>,
    pub(crate) open_charge: usize,
    open_owner: AllocationCharges,
    pub(crate) close_entries: Vec<CloseEntry>,
    pub(crate) close_charge: usize,
    close_owners: Vec<crate::alloc::AllocationCharge>,
}

#[derive(Clone, Copy)]
pub(crate) struct OpenUpvalue {
    pub(crate) slot: usize,
    pub(crate) object: ObjectRef,
    pub(crate) root: Option<RootId>,
}

#[derive(Clone, Copy)]
enum DebugWriteSlot {
    Register(usize),
    Vararg(usize),
    VarargTable,
}

#[must_use]
pub(crate) struct DebugWrite {
    slot: DebugWriteSlot,
    previous_value: Value,
    previous_root: Option<RootId>,
}

impl DebugWrite {
    pub(crate) fn commit(self, vm: &mut Vm) -> Result<(), RuntimeError> {
        if let Some(root) = self.previous_root {
            vm.remove_root(root)?;
        }
        Ok(())
    }
}

impl CallFrame {
    /// 僅供 Execution 移交 VM parked arena 後保留無 root、無帳款的殼。
    pub(crate) fn parked_placeholder(ledger: &AllocationLedger) -> Self {
        Self {
            module: None,
            closure: None,
            closure_root: None,
            stack_base: 0,
            prototype: 0,
            base: 0,
            return_destination: None,
            return_mode: ResultMode::Fixed(0),
            tail_return: false,
            hook_entry: None,
            tail_called: false,
            call_extraargs: 0,
            hook_exit_fired: false,
            pending_close: None,
            caller: None,
            depth: 0,
            pc: 0,
            registers: Vec::new(),
            roots: Vec::new(),
            varargs: Vec::new(),
            vararg_roots: Vec::new(),
            vararg_charge: 0,
            vararg_value_owner: None,
            vararg_root_owner: None,
            official_raw_varargs: None,
            official_raw_vararg_count: 0,
            named_vararg: None,
            debug_vararg_table: Value::Nil,
            debug_vararg_table_root: None,
            dynamic_top: 0,
            register_limit: 0,
            max_register_limit: 0,
            ledger: ledger.clone(),
            charge: 0,
            register_owner: None,
            root_owner: None,
            open_upvalues: Vec::new(),
            open_charge: 0,
            open_owner: AllocationCharges::new(),
            close_entries: Vec::new(),
            close_charge: 0,
            close_owners: Vec::new(),
        }
    }

    pub(crate) fn new_native_finalizer(ledger: &AllocationLedger) -> Result<Self, RuntimeError> {
        let charge = core::mem::size_of::<Value>() + core::mem::size_of::<Option<RootId>>();
        let mut registers = Vec::new();
        let register_ticket =
            reserve_vec(ledger, &mut registers, 1, FailPoint::FrameRegistersReserve)?;
        registers.push(Value::Nil);
        let mut roots = Vec::new();
        let root_ticket = reserve_vec(ledger, &mut roots, 1, FailPoint::FrameRootsReserve)?;
        roots.push(None);
        let register_owner = register_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
        Ok(Self {
            module: None,
            closure: None,
            closure_root: None,
            stack_base: 0,
            prototype: 0,
            base: 0,
            return_destination: None,
            return_mode: ResultMode::Fixed(0),
            tail_return: false,
            hook_entry: None,
            tail_called: false,
            call_extraargs: 0,
            hook_exit_fired: false,
            pending_close: None,
            caller: None,
            depth: 0,
            pc: 0,
            registers,
            roots,
            varargs: Vec::new(),
            vararg_roots: Vec::new(),
            vararg_charge: 0,
            vararg_value_owner: None,
            vararg_root_owner: None,
            official_raw_varargs: None,
            official_raw_vararg_count: 0,
            named_vararg: None,
            debug_vararg_table: Value::Nil,
            debug_vararg_table_root: None,
            dynamic_top: 1,
            register_limit: 1,
            max_register_limit: usize::from(u16::MAX),
            ledger: ledger.clone(),
            charge,
            register_owner: Some(register_owner),
            root_owner: Some(root_owner),
            open_upvalues: Vec::new(),
            open_charge: 0,
            open_owner: AllocationCharges::new(),
            close_entries: Vec::new(),
            close_charge: 0,
            close_owners: Vec::new(),
        })
    }

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
        let register_owner = register_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
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
            hook_entry: None,
            tail_called: false,
            call_extraargs: 0,
            hook_exit_fired: false,
            pending_close: None,
            caller: None,
            depth: 0,
            pc: 0,
            registers,
            roots,
            varargs: Vec::new(),
            vararg_roots: Vec::new(),
            vararg_charge: 0,
            vararg_value_owner: None,
            vararg_root_owner: None,
            official_raw_varargs: None,
            official_raw_vararg_count: 0,
            named_vararg: prototype.named_vararg.map(|(_, register)| register),
            debug_vararg_table: Value::Nil,
            debug_vararg_table_root: None,
            dynamic_top,
            register_limit: limit,
            max_register_limit: usize::from(prototype.frame.register_limit),
            ledger: ledger.clone(),
            charge,
            register_owner: Some(register_owner),
            root_owner: Some(root_owner),
            open_upvalues: Vec::new(),
            open_charge: 0,
            open_owner: AllocationCharges::new(),
            close_entries: Vec::new(),
            close_charge: 0,
            close_owners: Vec::new(),
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
        let charge = match ticket.commit_charge() {
            Ok(charge) => charge,
            Err(error) => {
                if let Some(root) = root {
                    vm.remove_root(root)?;
                }
                return Err(error.into());
            }
        };
        if self.close_owners.try_reserve_exact(1).is_err() {
            drop(charge);
            if let Some(root) = root {
                vm.remove_root(root)?;
            }
            return Err(VmError::AllocationFailed.into());
        }
        self.close_entries.push(CloseEntry {
            binding,
            register,
            value,
            root,
        });
        self.close_charge += core::mem::size_of::<CloseEntry>();
        self.close_owners.push(charge);
        Ok(())
    }

    pub(crate) fn pop_close(&mut self, vm: &mut Vm) -> Result<Option<CloseEntry>, RuntimeError> {
        let Some(entry) = self.close_entries.last().copied() else {
            return Ok(None);
        };
        if let Some(root) = entry.root {
            vm.remove_root(root)?;
        }
        self.close_charge -= core::mem::size_of::<CloseEntry>();
        self.close_entries.pop();
        self.close_owners.pop();
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
        let register_owner = register_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
        let old_registers = core::mem::replace(&mut self.registers, registers);
        let old_roots = core::mem::replace(&mut self.roots, roots);
        drop(old_registers);
        drop(old_roots);
        self.register_owner = Some(register_owner);
        self.root_owner = Some(root_owner);
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

    pub(crate) fn begin_debug_register_write(
        &mut self,
        vm: &mut Vm,
        register: Register,
        value: Value,
    ) -> Result<DebugWrite, RuntimeError> {
        let index = self.index(register)?;
        self.begin_debug_write(vm, DebugWriteSlot::Register(index), value)
    }

    pub(crate) fn begin_debug_vararg_write(
        &mut self,
        vm: &mut Vm,
        index: usize,
        value: Value,
    ) -> Result<DebugWrite, RuntimeError> {
        if index >= self.varargs.len() {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        self.begin_debug_write(vm, DebugWriteSlot::Vararg(index), value)
    }

    pub(crate) fn begin_debug_vararg_table_write(
        &mut self,
        vm: &mut Vm,
        value: Value,
    ) -> Result<DebugWrite, RuntimeError> {
        self.begin_debug_write(vm, DebugWriteSlot::VarargTable, value)
    }

    fn begin_debug_write(
        &mut self,
        vm: &mut Vm,
        slot: DebugWriteSlot,
        value: Value,
    ) -> Result<DebugWrite, RuntimeError> {
        let new_root = if let Value::Object(object) = value {
            Some(vm.add_root(RootKind::Stack, object)?)
        } else {
            None
        };
        let (previous_value, previous_root) = match slot {
            DebugWriteSlot::Register(index) => (
                core::mem::replace(&mut self.registers[index], value),
                core::mem::replace(&mut self.roots[index], new_root),
            ),
            DebugWriteSlot::Vararg(index) => (
                core::mem::replace(&mut self.varargs[index], value),
                core::mem::replace(&mut self.vararg_roots[index], new_root),
            ),
            DebugWriteSlot::VarargTable => (
                core::mem::replace(&mut self.debug_vararg_table, value),
                core::mem::replace(&mut self.debug_vararg_table_root, new_root),
            ),
        };
        Ok(DebugWrite {
            slot,
            previous_value,
            previous_root,
        })
    }

    pub(crate) fn rollback_debug_write(
        &mut self,
        vm: &mut Vm,
        write: DebugWrite,
    ) -> Result<(), RuntimeError> {
        let current_root = match write.slot {
            DebugWriteSlot::Register(index) => {
                self.registers[index] = write.previous_value;
                core::mem::replace(&mut self.roots[index], write.previous_root)
            }
            DebugWriteSlot::Vararg(index) => {
                self.varargs[index] = write.previous_value;
                core::mem::replace(&mut self.vararg_roots[index], write.previous_root)
            }
            DebugWriteSlot::VarargTable => {
                self.debug_vararg_table = write.previous_value;
                core::mem::replace(&mut self.debug_vararg_table_root, write.previous_root)
            }
        };
        if let Some(root) = current_root.filter(|root| Some(*root) != write.previous_root) {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    /// 清除開放結果擴張的暫存值與 stack roots，保留已配置的 frame storage。
    pub(crate) fn clear_dynamic_extension_from(
        &mut self,
        vm: &mut Vm,
        start: usize,
    ) -> Result<(), RuntimeError> {
        if start > self.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        for index in start..self.register_limit {
            let register = Register(
                u16::try_from(index)
                    .map_err(|_| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?,
            );
            self.write(vm, register, Value::Nil)?;
        }
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
        let value_owner = value_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
        let old_varargs = core::mem::replace(&mut self.varargs, varargs);
        let old_roots = core::mem::replace(&mut self.vararg_roots, roots);
        drop(old_varargs);
        drop(old_roots);
        self.vararg_value_owner = Some(value_owner);
        self.vararg_root_owner = Some(root_owner);
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
        self.set_named_varargs_at(vm, register, values)
    }

    pub(crate) fn initialize_variadic_inputs(
        &mut self,
        vm: &mut Vm,
        values: &[Value],
        official: Option<OfficialFrameRegisters>,
    ) -> Result<VarargPayloads, RuntimeError> {
        let Some(official) = official else {
            let mut payloads = VarargPayloads::default();
            if self.named_vararg.is_some() {
                payloads.entries[0] = Some(self.set_named_varargs(vm, values)?);
            } else {
                self.set_varargs(vm, values)?;
            }
            return Ok(payloads);
        };
        // official 的 raw 與 guest named 同屬一次未發布交易；任一份失敗
        // 須還原整體 debt，成功則交由下一個安全配置點推進自動 GC。
        let gc = vm.defer_automatic_gc();
        let result = (|| {
            let mut payloads = VarargPayloads::default();
            if let Some(register) = official.raw {
                payloads.entries[0] = Some(self.set_named_varargs_at(vm, register, values)?);
            }
            if let Some(register) = official.guest_named {
                match self.set_named_varargs_at(vm, register, values) {
                    Ok(payload) => payloads.entries[1] = Some(payload),
                    Err(error) => {
                        if let Some(raw) = official.raw {
                            self.write(vm, raw, Value::Nil)?;
                        }
                        payloads.reclaim(vm)?;
                        return Err(error);
                    }
                }
            }
            if official.raw.is_none() && official.guest_named.is_none() {
                self.set_varargs(vm, values)?;
            }
            self.official_raw_varargs = official.raw;
            self.official_raw_vararg_count = if official.raw.is_some() {
                values.len()
            } else {
                0
            };
            Ok(payloads)
        })();
        vm.finish_deferred_automatic_gc(gc, result.is_ok());
        result
    }

    fn set_named_varargs_at(
        &mut self,
        vm: &mut Vm,
        register: Register,
        values: &[Value],
    ) -> Result<(ObjectRef, ObjectRef), RuntimeError> {
        let gc = vm.defer_automatic_gc();
        let result = self.set_named_varargs_at_inner(vm, register, values);
        vm.finish_deferred_automatic_gc(gc, result.is_ok());
        result
    }

    fn set_named_varargs_at_inner(
        &mut self,
        vm: &mut Vm,
        register: Register,
        values: &[Value],
    ) -> Result<(ObjectRef, ObjectRef), RuntimeError> {
        let table = vm.allocate_table_with_capacity(values.len(), 1)?;
        if let Err(error) = self.write(vm, register, Value::Object(table)) {
            vm.reclaim_unpublished_object(table)?;
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
                vm.reclaim_unpublished_object(table)?;
                if let Some(key) = name_key {
                    vm.reclaim_unpublished_object(key)?;
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
        if let Some(root) = self.debug_vararg_table_root.take() {
            vm.remove_root(root)?;
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
            if let Value::Object(object) = self.debug_vararg_table {
                self.debug_vararg_table_root = Some(vm.add_root(RootKind::Stack, object)?);
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
        if let Value::Object(object) = self.debug_vararg_table {
            visit(object)?;
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
        let needed = self
            .open_upvalues
            .len()
            .checked_add(1)
            .ok_or(VmError::ArithmeticOverflow)?;
        let mut replacement = Vec::new();
        let mut new_charges = AllocationCharges::new();
        if let Err(error) = new_charges.try_reserve(1) {
            vm.remove_root(root)?;
            return Err(error.into());
        }
        let ticket = match reserve_vec(
            &self.ledger,
            &mut replacement,
            needed,
            FailPoint::OpenUpvaluesReserve,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                vm.remove_root(root)?;
                return Err(error.into());
            }
        };
        replacement.extend_from_slice(&self.open_upvalues);
        replacement.push(OpenUpvalue {
            slot,
            object,
            root: Some(root),
        });
        let owner = ticket.commit_charge()?;
        new_charges.push_prepared(owner);
        let old = core::mem::replace(&mut self.open_upvalues, replacement);
        drop(old);
        self.open_owner = new_charges;
        self.open_charge = checked_bytes(needed, core::mem::size_of::<OpenUpvalue>())?;
        Ok(())
    }

    /// 捕獲失敗時回復原 prefix；先完成所有 allocation/admission，再移除新 cell。
    pub(crate) fn rollback_open_prefix(
        &mut self,
        vm: &mut Vm,
        original: usize,
    ) -> Result<(), RuntimeError> {
        if original > self.open_upvalues.len() {
            return Err(VmError::LedgerInvariant.into());
        }
        let bytes = checked_bytes(original, core::mem::size_of::<OpenUpvalue>())?;
        let mut replacement = Vec::new();
        if original != 0 {
            self.ledger.checkpoint(FailPoint::OpenUpvaluesReserve)?;
            replacement
                .try_reserve_exact(original)
                .map_err(|_| VmError::AllocationFailed)?;
        }
        replacement.extend_from_slice(&self.open_upvalues[..original]);
        let prepared = self.open_owner.prepare_normalize(bytes)?;
        // 此處只查既有 root/slot；後續 remove_root/reclaim 對這些未發布的
        // open upvalue 不再分配記憶體，失敗僅表示原有內部身分不變條件已壞。
        for entry in &self.open_upvalues[original..] {
            if let Some(root) = entry.root {
                if vm.roots().active_object(root) != Some(entry.object) {
                    return Err(VmError::StaleRoot.into());
                }
            }
            if vm.object_kind(entry.object)? != crate::ObjectKind::Upvalue {
                return Err(VmError::WrongObjectType.into());
            }
        }
        for entry in self.open_upvalues[original..].iter().rev() {
            if let Some(root) = entry.root {
                vm.remove_root(root)?;
            }
            vm.reclaim_unpublished_object(entry.object)?;
        }
        let old = core::mem::replace(&mut self.open_upvalues, replacement);
        drop(old);
        self.open_owner = self.open_owner.commit_normalize(prepared);
        self.open_charge = bytes;
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
            vm.close_upvalue(entry.object, value)?;
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
        vm.close_upvalue(entry.object, self.registers[index])?;
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
        self.vararg_value_owner = None;
        self.vararg_root_owner = None;
        self.vararg_charge = 0;
        self.register_limit = 0;
        self.max_register_limit = 0;
        self.register_owner = None;
        self.root_owner = None;
        self.charge = 0;
        self.open_upvalues = Vec::new();
        self.open_owner = AllocationCharges::new();
        self.open_charge = 0;
        self.close_entries = Vec::new();
        self.close_owners.clear();
        self.close_charge = 0;
    }
}

impl Drop for CallFrame {
    fn drop(&mut self) {
        self.release_storage();
    }
}
