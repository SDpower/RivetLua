//! 顯式 Lua 呼叫 frame 與暫存器 root 生命週期。

use core::cell::Cell;
use core::ops::{Deref, DerefMut};
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{StateAllocator, ThinBlock};

use crate::alloc::{AllocationCharge, AllocationCharges, AllocationLedger, FailPoint, Reservation, checked_bytes, reserve_state_vec_host};
use crate::heap::{CapiShutdownRoot, CapiStackCapacity};
use crate::unwind::CloseEntry;
use crate::vm::{DebugFrameId, DebugPublishedToken, RuntimeError, RuntimeErrorKind, next_debug_frame_id};
use crate::roots::StackRoot;
use crate::policy::VmPolicy;
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
    data: Option<ThinBlock<FrameData>>,
}

#[derive(Clone, Copy)]
pub(crate) struct FrameSpec {
    register_count: u16,
    register_limit: u16,
    registers_start_as_nil: bool,
    initial_top: Register,
    dynamic_top: Register,
    named_vararg: Option<Register>,
}

impl From<&BytecodePrototype> for FrameSpec {
    fn from(prototype: &BytecodePrototype) -> Self {
        Self {
            register_count: prototype.register_count,
            register_limit: prototype.frame.register_limit,
            registers_start_as_nil: prototype.frame.registers_start_as_nil,
            initial_top: prototype.frame.initial_top,
            dynamic_top: prototype.frame.dynamic_top,
            named_vararg: prototype.named_vararg.map(|(_, register)| register),
        }
    }
}

fn reserve_frame_vec<T>(
    vm: &mut Vm,
    values: &mut AllocVec<T, StateAllocator>,
    additional: usize,
    point: FailPoint,
    module: Option<ObjectRef>,
) -> Result<Reservation, VmError> {
    let ledger = vm.allocation_ledger().clone();
    let before = ledger.backing_allocator().refusal_count();
    let error = match reserve_state_vec_host(&ledger, values, additional, point) {
        Ok(ticket) => return Ok(ticket),
        Err(error) => error,
    };
    let root = module.map(Value::Object);
    if !vm.emergency_collect_after_refusal_with_borrowed_roots(before, root.as_slice())? {
        return Err(error);
    }
    reserve_state_vec_host(&ledger, values, additional, point)
}

fn reserve_frame_vec_with_roots<T>(
    vm: &mut Vm,
    values: &mut AllocVec<T, StateAllocator>,
    additional: usize,
    point: FailPoint,
    module: Option<ObjectRef>,
    borrowed_roots: &[Value],
) -> Result<Reservation, VmError> {
    let ledger = vm.allocation_ledger().clone();
    let before = ledger.backing_allocator().refusal_count();
    let error = match reserve_state_vec_host(&ledger, values, additional, point) {
        Ok(ticket) => return Ok(ticket),
        Err(error) => error,
    };
    let module_root = module.map(Value::Object);
    if !vm.emergency_collect_after_refusal_with_borrowed_root_slices(
        before,
        borrowed_roots,
        module_root.as_slice(),
    )? {
        return Err(error);
    }
    reserve_state_vec_host(&ledger, values, additional, point)
}

fn reserve_close_owners(
    vm: &mut Vm,
    owners: &mut AllocVec<crate::alloc::AllocationCharge, StateAllocator>,
    module: Option<ObjectRef>,
) -> Result<(), VmError> {
    let allocator = vm.allocation_ledger().backing_allocator();
    let before = allocator.refusal_count();
    if owners.try_reserve_exact(1).is_ok() {
        return Ok(());
    }
    if allocator.refusal_count() == before {
        return Err(VmError::AllocationFailed);
    }
    let borrowed = module.map(Value::Object);
    if !vm.emergency_collect_after_refusal_with_borrowed_roots(before, borrowed.as_slice())? {
        return Err(VmError::AllocationFailed);
    }
    owners.try_reserve_exact(1).map_err(|_| VmError::AllocationFailed)
}

pub(crate) struct FrameData {
    pub(crate) debug_id: DebugFrameId,
    pub(crate) debug_publication: Cell<Option<DebugPublishedToken>>,
    pub(crate) module: Option<ObjectRef>,
    pub(crate) closure: Option<ObjectRef>,
    pub(crate) closure_root: Option<StackRoot>,
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
    pub(crate) registers: AllocVec<Value, StateAllocator>,
    pub(crate) roots: AllocVec<Option<StackRoot>, StateAllocator>,
    capi_root_capacity: Option<CapiStackCapacity>,
    pub(crate) varargs: AllocVec<Value, StateAllocator>,
    pub(crate) vararg_roots: AllocVec<Option<StackRoot>, StateAllocator>,
    pub(crate) vararg_charge: usize,
    vararg_value_owner: Option<crate::alloc::AllocationCharge>,
    vararg_root_owner: Option<crate::alloc::AllocationCharge>,
    pub(crate) official_raw_varargs: Option<Register>,
    pub(crate) official_raw_vararg_count: usize,
    pub(crate) named_vararg: Option<Register>,
    pub(crate) debug_vararg_table: Value,
    pub(crate) debug_vararg_table_root: Option<StackRoot>,
    pub(crate) dynamic_top: usize,
    pub(crate) register_limit: usize,
    pub(crate) max_register_limit: usize,
    pub(crate) ledger: AllocationLedger,
    pub(crate) charge: usize,
    backing_limit: usize,
    register_owner: Option<crate::alloc::AllocationCharge>,
    root_owner: Option<crate::alloc::AllocationCharge>,
    pub(crate) open_upvalues: AllocVec<OpenUpvalue, StateAllocator>,
    pub(crate) open_charge: usize,
    open_owner: AllocationCharges,
    pub(crate) close_entries: AllocVec<CloseEntry, StateAllocator>,
    pub(crate) close_charge: usize,
    close_owners: AllocVec<crate::alloc::AllocationCharge, StateAllocator>,
    header_owner: Option<crate::alloc::AllocationCharge>,
}

struct PreparedFrameBackings {
    registers: AllocVec<Value, StateAllocator>,
    roots: AllocVec<Option<StackRoot>, StateAllocator>,
    register_owner: AllocationCharge,
    root_owner: AllocationCharge,
    capacity: usize,
    charge: usize,
}

/// 只保存已準備的 storage 與新 roots；提交前不修改原 frame。
pub(crate) struct PreparedFrameWrite {
    first: usize,
    end: usize,
    prepared_roots: AllocVec<(usize, StackRoot), StateAllocator>,
    prepared_root_owner: Option<AllocationCharge>,
    backings: Option<PreparedFrameBackings>,
    capi_root_capacity: Option<CapiStackCapacity>,
}

impl PreparedFrameWrite {
    /// 所有可能失敗的配置均已完成；提交只搬移 storage、roots 和純量狀態。
    pub(crate) fn commit(
        mut self,
        frame: &mut FrameData,
        values: &[Value],
        dynamic_top: Option<usize>,
        pc: Option<usize>,
    ) {
        if let Some(backings) = self.backings.take() {
            let old_registers = core::mem::replace(&mut frame.registers, backings.registers);
            let old_roots = core::mem::replace(&mut frame.roots, backings.roots);
            let old_register_owner = frame.register_owner.replace(backings.register_owner);
            let old_root_owner = frame.root_owner.replace(backings.root_owner);
            frame.backing_limit = backings.capacity;
            frame.charge = backings.charge;
            drop(old_registers);
            drop(old_roots);
            drop(old_register_owner);
            drop(old_root_owner);
        } else if self.end > frame.register_limit {
            // prepare 已核對兩份 backing 的容量；此處不會呼叫 allocator。
            frame.registers.resize(self.end, Value::Nil);
            frame.roots.resize(self.end, None);
        }
        if let Some(capacity) = self.capi_root_capacity.take() {
            frame.capi_root_capacity = Some(capacity);
        }
        let prepared = core::mem::replace(
            &mut self.prepared_roots,
            AllocVec::new_in(frame.ledger.backing_allocator()),
        );
        let mut roots = prepared.into_iter().peekable();
        for index in self.first..self.end {
            let value = values.get(index - self.first).copied().unwrap_or(Value::Nil);
            let same_root = matches!(value, Value::Object(object)
                if frame.registers[index] == Value::Object(object) && frame.roots[index].is_some());
            if !same_root {
                let replacement = if roots.peek().is_some_and(|(slot, _)| *slot == index) {
                    roots.next().map(|(_, root)| root)
                } else {
                    None
                };
                drop(core::mem::replace(&mut frame.roots[index], replacement));
            }
            frame.registers[index] = value;
        }
        frame.register_limit = frame.register_limit.max(self.end);
        if let Some(top) = dynamic_top {
            frame.dynamic_top = top;
        }
        if let Some(pc) = pc {
            frame.pc = pc;
        }
    }
}

pub(crate) struct FrameStorageCache {
    slots: [Option<CallFrame>; 32],
    len: usize,
}

impl Default for FrameStorageCache {
    fn default() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
        }
    }
}

impl FrameStorageCache {
    fn peek(&self, limit: usize) -> Option<&CallFrame> {
        for index in (0..self.len).rev() {
            let frame = self.slots[index].as_ref()?;
            if frame.backing_limit >= limit {
                return Some(frame);
            }
        }
        None
    }

    fn take(&mut self, limit: usize) -> Option<CallFrame> {
        for index in (0..self.len).rev() {
            if self.slots[index].as_ref()?.backing_limit < limit {
                continue;
            }
            let frame = self.slots[index].take();
            for next in index..self.len - 1 {
                self.slots[next] = self.slots[next + 1].take();
            }
            self.len -= 1;
            return frame;
        }
        None
    }

    pub(crate) fn recycle(&mut self, frame: &mut CallFrame) {
        frame.clear_for_cache();
        if self.len == self.slots.len() {
            frame.release_storage();
            return;
        }
        self.slots[self.len] = Some(core::mem::replace(frame, CallFrame::parked_placeholder()));
        self.len += 1;
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
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
    previous_root: Option<StackRoot>,
}

impl DebugWrite {
    pub(crate) fn commit(self, _vm: &mut Vm) -> Result<(), RuntimeError> {
        drop(self.previous_root);
        Ok(())
    }
}

impl FrameData {
    fn ensure_capi_root_capacity(&mut self, vm: &mut Vm, needed: usize)
        -> Result<(), RuntimeError> {
        if self.module.is_some()
            && self.capi_root_capacity.as_ref().is_none_or(|held| held.capacity() < needed)
        {
            if let Some(capacity) = vm.capi_frame_root_capacity(needed)? {
                self.capi_root_capacity = Some(capacity);
            }
        }
        Ok(())
    }

    pub(crate) fn prepare_write(
        &self,
        vm: &mut Vm,
        first: usize,
        count: usize,
        values: &[Value],
        allow_growth: bool,
    ) -> Result<PreparedFrameWrite, RuntimeError> {
        let end = first.checked_add(count)
            .filter(|end| *end <= self.max_register_limit
                && (allow_growth || *end <= self.register_limit))
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))?;
        let allocator = self.ledger.backing_allocator();
        let mut prepared = PreparedFrameWrite {
            first,
            end,
            prepared_roots: AllocVec::new_in(allocator.clone()),
            prepared_root_owner: None,
            backings: None,
            capi_root_capacity: None,
        };
        if end > self.register_limit && self.module.is_some() {
            let needed = end.checked_add(self.varargs.len()).and_then(|n| n.checked_add(1))
                .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?;
            if self.capi_root_capacity.as_ref().is_none_or(|held| held.capacity() < needed) {
                prepared.capi_root_capacity = vm.capi_frame_root_capacity(needed)?;
            }
        }
        let new_roots = (first..end).filter(|index| {
            let value = values.get(*index - first).copied().unwrap_or(Value::Nil);
            matches!(value, Value::Object(object)
                if self.registers.get(*index) != Some(&Value::Object(object))
                    || self.roots.get(*index).is_none_or(Option::is_none))
        }).count();
        if new_roots != 0 {
            let mut ticket = reserve_frame_vec_with_roots(
                vm, &mut prepared.prepared_roots, new_roots,
                FailPoint::FrameRootsReserve, self.module, values,
            )?;
            let owner = match ticket.commit_charge_in_place() {
                Ok(owner) => owner,
                Err(error) => {
                    drop(prepared);
                    drop(ticket);
                    return Err(error.into());
                }
            };
            prepared.prepared_root_owner = Some(owner);
            for index in first..end {
                let value = values.get(index - first).copied().unwrap_or(Value::Nil);
                if let Value::Object(object) = value {
                    let same_root = self.registers.get(index) == Some(&value)
                        && self.roots.get(index).is_some_and(Option::is_some);
                    if !same_root {
                        let root = vm.add_stack_root_with_borrowed_roots(object, values)?;
                        prepared.prepared_roots.push((index, root));
                    }
                }
            }
        }
        if end > self.backing_limit {
            let capacity = end.max(self.backing_limit.saturating_mul(2))
                .min(self.max_register_limit);
            let register_bytes = checked_bytes(capacity, core::mem::size_of::<Value>())?;
            let root_bytes = checked_bytes(capacity, core::mem::size_of::<Option<StackRoot>>())?;
            let charge = register_bytes.checked_add(root_bytes)
                .ok_or(VmError::ArithmeticOverflow)?;
            let mut registers = AllocVec::new_in(allocator.clone());
            let mut register_ticket = reserve_frame_vec_with_roots(
                vm, &mut registers, capacity, FailPoint::FrameRegistersReserve,
                self.module, values,
            )?;
            let mut roots = AllocVec::new_in(allocator);
            let mut root_ticket = match reserve_frame_vec_with_roots(
                vm, &mut roots, capacity, FailPoint::FrameRootsReserve,
                self.module, values,
            ) {
                Ok(ticket) => ticket,
                Err(error) => {
                    drop(roots);
                    drop(registers);
                    drop(register_ticket);
                    return Err(error.into());
                }
            };
            registers.extend_from_slice(&self.registers);
            roots.extend_from_slice(&self.roots);
            registers.resize(end, Value::Nil);
            roots.resize(end, None);
            let register_owner = match register_ticket.commit_charge_in_place() {
                Ok(owner) => owner,
                Err(error) => {
                    drop(roots);
                    drop(registers);
                    drop(root_ticket);
                    drop(register_ticket);
                    return Err(error.into());
                }
            };
            drop(register_ticket);
            let root_owner = match root_ticket.commit_charge_in_place() {
                Ok(owner) => owner,
                Err(error) => {
                    drop(roots);
                    drop(registers);
                    drop(root_ticket);
                    drop(register_owner);
                    return Err(error.into());
                }
            };
            drop(root_ticket);
            prepared.backings = Some(PreparedFrameBackings {
                registers, roots, register_owner, root_owner, capacity, charge,
            });
        }
        Ok(prepared)
    }

    fn rollback_register_root(
        &mut self,
        vm: &mut Vm,
        register: Register,
    ) -> Result<(), RuntimeError> {
        self.write(vm, register, Value::Nil)?;
        let index = self.index(register)?;
        drop(self.roots[index].take());
        vm.compact_roots();
        Ok(())
    }

    #[inline(always)]
    fn set_root_slot(
        vm: &mut Vm,
        slot: &mut Option<StackRoot>,
        object: Option<ObjectRef>,
    ) -> Result<(), RuntimeError> {
        if let Some(root) = slot {
            vm.set_stack_root(root, object)?;
        } else if let Some(object) = object {
            *slot = Some(vm.add_stack_root(object)?);
        }
        Ok(())
    }

    pub(crate) fn root_closure(&mut self, vm: &mut Vm, object: ObjectRef) -> Result<(), RuntimeError> {
        Self::set_root_slot(vm, &mut self.closure_root, Some(object))?;
        self.closure = Some(object);
        Ok(())
    }
}

impl CallFrame {
    /// 停放後的空 handle 沒有配置或 Lua root。
    pub(crate) fn parked_placeholder() -> Self {
        Self { data: None }
    }

    pub(crate) fn data(&self) -> Option<&FrameData> {
        self.data.as_deref()
    }

    pub(crate) fn trace_children(
        &self,
        visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Some(data) = self.data() {
            data.trace_children(visit)
        } else {
            Ok(())
        }
    }

    pub(crate) fn release_storage(&mut self) {
        if let Some(data) = self.data.as_mut() {
            data.release_storage();
        }
    }

    /// 關閉期的原生 finalizer frame 清除語意值，保留已計費 backing 供下一輪使用。
    pub(crate) fn shutdown_retain_storage(&mut self) -> Result<(), RuntimeError> {
        let data = self.data.as_mut()
            .ok_or(RuntimeError::new(RuntimeErrorKind::TerminalExecution))?;
        if data.module.is_some() || data.closure.is_some() || data.pending_close.is_some()
            || !data.open_upvalues.is_empty() || !data.close_entries.is_empty()
            || !data.varargs.is_empty() || data.registers.is_empty()
        {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        data.registers.fill(Value::Nil);
        data.dynamic_top = 1;
        data.register_limit = 1;
        data.pc = 0;
        Ok(())
    }

    /// 關閉期純 C closer 的單一正式 frame；在第一個 closer 前準備三格與真根。
    pub(crate) fn prepare_shutdown_call_storage(
        &mut self,
        vm: &mut Vm,
        anchor: ObjectRef,
    ) -> Result<(), RuntimeError> {
        let data = self.data.as_mut()
            .ok_or(RuntimeError::new(RuntimeErrorKind::TerminalExecution))?;
        let nil = [Value::Nil; 3];
        let prepared = data.prepare_write(vm, 0, nil.len(), &nil, true)?;
        prepared.commit(data, &nil, Some(1), None);
        for index in 0..nil.len() {
            if data.roots[index].is_none() {
                let root = vm.add_stack_root_with_borrowed_roots(anchor, &[Value::Object(anchor)])?;
                vm.set_stack_root(&root, None)?;
                data.roots[index] = Some(root);
            }
        }
        data.register_limit = 1;
        Ok(())
    }

    /// 只重綁預備好的根；C stack 在本次呼叫返回前仍保活整組來源值。
    pub(crate) fn shutdown_set_call(
        &mut self,
        vm: &mut Vm,
        function: Value,
        args: &[Value],
    ) -> Result<(), RuntimeError> {
        let data = self.data.as_mut()
            .ok_or(RuntimeError::new(RuntimeErrorKind::TerminalExecution))?;
        let count = args.len().checked_add(1)
            .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?;
        if count > 3 || count > data.registers.len() || count > data.roots.len()
            || data.register_limit != 1 || data.dynamic_top != 1
            || data.registers.iter().any(|value| *value != Value::Nil)
            || data.roots[..count].iter().any(Option::is_none)
        {
            return Err(RuntimeError::new(RuntimeErrorKind::TerminalExecution));
        }
        vm.check_owned_value(function)?;
        for &value in args {
            vm.check_owned_value(value)?;
        }
        for (index, value) in core::iter::once(function).chain(args.iter().copied()).enumerate() {
            let object = match value { Value::Object(object) => Some(object), _ => None };
            if let Err(error) = vm.set_stack_root(
                data.roots[index].as_ref().ok_or(VmError::LedgerInvariant)?, object,
            ) {
                for root in data.roots[..index].iter().flatten() {
                    let _ = vm.set_stack_root(root, None);
                }
                return Err(error.into());
            }
        }
        for (index, value) in core::iter::once(function).chain(args.iter().copied()).enumerate() {
            data.registers[index] = value;
        }
        data.register_limit = count;
        data.dynamic_top = count;
        Ok(())
    }

    fn allocate(mut data: FrameData, vm: &mut Vm, module: Option<ObjectRef>) -> Result<Self, RuntimeError> {
        let ledger = vm.allocation_ledger().clone();
        let allocator = ledger.backing_allocator();
        let mut retried = false;
        let block = loop {
            let ticket = ledger.reserve_host_vec(
                StateAllocator::thin_block_size::<FrameData>(),
                FailPoint::CallFrameReserve,
                allocator.is_lua(),
            )?;
            let before = allocator.refusal_count();
            match allocator.clone().thin_uninit::<FrameData>(0) {
                Ok(block) => break (block, ticket),
                Err(_) => {
                    let error = if allocator.refusal_count() != before {
                        ticket.physical_reserve_failure()
                    } else {
                        ticket.rust_reserve_failure()
                    };
                    drop(ticket);
                    let root = module.map(Value::Object);
                    if retried || !vm.emergency_collect_after_refusal_with_borrowed_roots(before, root.as_slice())? {
                        return Err(error.into());
                    }
                    retried = true;
                }
            }
        };
        data.header_owner = Some(block.1.commit_charge()?);
        Ok(Self { data: Some(block.0.write(data)) })
    }

    pub(crate) fn new_native_finalizer(vm: &mut Vm) -> Result<Self, RuntimeError> {
        let debug_id = next_debug_frame_id()?;
        let ledger = vm.allocation_ledger().clone();
        let allocator = ledger.backing_allocator();
        let charge = core::mem::size_of::<Value>() + core::mem::size_of::<Option<StackRoot>>();
        let mut registers = AllocVec::new_in(allocator.clone());
        let register_ticket = reserve_frame_vec(vm, &mut registers, 1, FailPoint::FrameRegistersReserve, None)?;
        registers.push(Value::Nil);
        let mut roots = AllocVec::new_in(allocator.clone());
        let root_ticket = reserve_frame_vec(vm, &mut roots, 1, FailPoint::FrameRootsReserve, None)?;
        roots.push(None);
        let register_owner = register_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
        Self::allocate(FrameData {
            debug_id,
            debug_publication: Cell::new(None),
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
            capi_root_capacity: None,
            varargs: AllocVec::new_in(allocator.clone()),
            vararg_roots: AllocVec::new_in(allocator.clone()),
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
            max_register_limit: if vm.policy() == VmPolicy::Compatibility {
                1_000_000
            } else {
                usize::from(u16::MAX)
            },
            ledger: ledger.clone(),
            charge,
            backing_limit: 1,
            register_owner: Some(register_owner),
            root_owner: Some(root_owner),
            open_upvalues: AllocVec::new_in(allocator.clone()),
            open_charge: 0,
            open_owner: AllocationCharges::new_in(allocator.clone()),
            close_entries: AllocVec::new_in(allocator),
            close_charge: 0,
            close_owners: AllocVec::new_in(ledger.backing_allocator()),
            header_owner: None,
        }, vm, None)
    }

    pub(crate) fn new(
        spec: FrameSpec,
        prototype_index: usize,
        module: Option<ObjectRef>,
        vm: &mut Vm,
    ) -> Result<Self, RuntimeError> {
        Self::new_with_cache(spec, prototype_index, module, vm, None)
    }

    pub(crate) fn new_with_cache(
        spec: FrameSpec,
        prototype_index: usize,
        module: Option<ObjectRef>,
        vm: &mut Vm,
        cache: Option<&mut FrameStorageCache>,
    ) -> Result<Self, RuntimeError> {
        let ledger = vm.allocation_ledger().clone();
        let allocator = ledger.backing_allocator();
        let limit = usize::from(spec.register_count);
        if limit > usize::from(spec.register_limit)
            || !spec.registers_start_as_nil
        {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let register_bytes = checked_bytes(limit, core::mem::size_of::<Value>())?;
        let root_bytes = checked_bytes(limit, core::mem::size_of::<Option<StackRoot>>())?;
        let charge = register_bytes
            .checked_add(root_bytes)
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let dynamic_top = usize::from(spec.initial_top.0);
        if dynamic_top > limit || usize::from(spec.dynamic_top.0) > limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        let max_register_limit = if vm.policy() == VmPolicy::Compatibility {
            1_000_000
        } else {
            usize::from(spec.register_limit)
        };
        let debug_id = next_debug_frame_id()?;
        if let Some(mut frame) = cache.and_then(|cache| cache.take(limit)) {
            frame.reset_for_call(spec, prototype_index, module, dynamic_top, limit, max_register_limit, debug_id);
            frame.ensure_capi_root_capacity(vm, limit.checked_add(1)
                .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::StackLimit))?)?;
            return Ok(frame);
        }
        let mut registers = AllocVec::new_in(allocator.clone());
        let register_ticket = reserve_frame_vec(vm, &mut registers, limit, FailPoint::FrameRegistersReserve, module)?;
        let mut roots = AllocVec::new_in(allocator.clone());
        let root_ticket = reserve_frame_vec(vm, &mut roots, limit, FailPoint::FrameRootsReserve, module)?;
        let register_owner = register_ticket.commit_charge()?;
        let root_owner = root_ticket.commit_charge()?;
        registers.resize(limit, Value::Nil);
        roots.resize(limit, None);
        let capi_root_capacity = if module.is_some() {
            vm.capi_frame_root_capacity(limit.checked_add(1)
                .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::StackLimit))?)?
        } else { None };
        Self::allocate(FrameData {
            debug_id,
            debug_publication: Cell::new(None),
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
            capi_root_capacity,
            varargs: AllocVec::new_in(allocator.clone()),
            vararg_roots: AllocVec::new_in(allocator.clone()),
            vararg_charge: 0,
            vararg_value_owner: None,
            vararg_root_owner: None,
            official_raw_varargs: None,
            official_raw_vararg_count: 0,
            named_vararg: spec.named_vararg,
            debug_vararg_table: Value::Nil,
            debug_vararg_table_root: None,
            dynamic_top,
            register_limit: limit,
            max_register_limit,
            ledger: ledger.clone(),
            charge,
            backing_limit: limit,
            register_owner: Some(register_owner),
            root_owner: Some(root_owner),
            open_upvalues: AllocVec::new_in(allocator.clone()),
            open_charge: 0,
            open_owner: AllocationCharges::new_in(allocator.clone()),
            close_entries: AllocVec::new_in(allocator),
            close_charge: 0,
            close_owners: AllocVec::new_in(ledger.backing_allocator()),
            header_owner: None,
        }, vm, module)
    }

    /// 僅重用已回收且全部必要根槽為空的純量呼叫 frame；資格不足交回通用建構子。
    pub(crate) fn try_new_recycled_scalar(
        spec: FrameSpec,
        prototype_index: usize,
        module: Option<ObjectRef>,
        copied: usize,
        vm: &mut Vm,
        cache: &mut FrameStorageCache,
    ) -> Result<Option<Self>, RuntimeError> {
        let limit = usize::from(spec.register_count);
        if limit > usize::from(spec.register_limit) || !spec.registers_start_as_nil {
            return Ok(None);
        }
        let dynamic_top = usize::from(spec.initial_top.0);
        if dynamic_top > limit || usize::from(spec.dynamic_top.0) > limit {
            return Ok(None);
        }
        let Some(copied_end) = copied.checked_add(1).filter(|end| *end <= limit) else {
            return Ok(None);
        };
        let Some(needed) = limit.checked_add(1) else {
            return Ok(None);
        };
        let (Ok(register_bytes), Ok(root_bytes)) = (
            checked_bytes(limit, core::mem::size_of::<Value>()),
            checked_bytes(limit, core::mem::size_of::<Option<StackRoot>>()),
        ) else {
            return Ok(None);
        };
        if register_bytes.checked_add(root_bytes).is_none() {
            return Ok(None);
        }
        let Some(frame) = cache.peek(limit) else {
            return Ok(None);
        };
        if frame.registers.len() != limit
            || frame.roots.len() != limit
            || !frame.varargs.is_empty()
            || !frame.vararg_roots.is_empty()
            || !frame.closure_root.as_ref().is_some_and(|root| {
                root.is_unique_private() && !root.has_object()
            })
            || !frame.roots[1..copied_end].iter().all(Option::is_none)
        {
            return Ok(None);
        }

        let max_register_limit = if vm.policy() == VmPolicy::Compatibility {
            1_000_000
        } else {
            usize::from(spec.register_limit)
        };
        let debug_id = next_debug_frame_id()?;
        let Some(mut frame) = cache.take(limit) else {
            return Ok(None);
        };
        frame.reset_for_call(
            spec, prototype_index, module, dynamic_top, limit, max_register_limit, debug_id,
        );
        frame.ensure_capi_root_capacity(vm, needed)?;
        Ok(Some(frame))
    }
}

impl FrameData {
    fn clear_for_cache(&mut self) {
        debug_assert!(self.open_upvalues.is_empty());
        debug_assert!(self.roots.iter().flatten().all(|root| !root.has_object()));
        debug_assert!(self.closure_root.as_ref().is_none_or(|root| !root.has_object()));
        self.debug_publication.set(None);
        self.registers.fill(Value::Nil);
        // 快取中的 frame 不受 root 訪客巡覽；兩個重用入口會在啟用前覆寫呼叫身分與配置界限。
        self.tail_return = false;
        self.call_extraargs = 0;
        self.hook_exit_fired = false;
        self.pending_close = None;
        self.pc = 0;
        // 兩組冷資料的 charge 為零時，backing 與 owner 本已為空。
        if self.vararg_charge != 0 {
            self.varargs = AllocVec::new_in(self.ledger.backing_allocator());
            self.vararg_roots = AllocVec::new_in(self.ledger.backing_allocator());
            self.vararg_value_owner = None;
            self.vararg_root_owner = None;
            self.vararg_charge = 0;
        }
        self.official_raw_varargs = None;
        self.official_raw_vararg_count = 0;
        self.debug_vararg_table = Value::Nil;
        self.debug_vararg_table_root = None;
        if self.open_charge != 0 {
            self.open_upvalues = AllocVec::new_in(self.ledger.backing_allocator());
            self.open_owner = AllocationCharges::new_in(self.ledger.backing_allocator());
            self.open_charge = 0;
        }
        self.close_entries = AllocVec::new_in(self.ledger.backing_allocator());
        self.close_owners = AllocVec::new_in(self.ledger.backing_allocator());
        self.close_charge = 0;
    }

    fn reset_for_call(&mut self, spec: FrameSpec, prototype_index: usize, module: Option<ObjectRef>, dynamic_top: usize, limit: usize, max_register_limit: usize, debug_id: DebugFrameId) {
        self.registers.resize(limit, Value::Nil);
        self.roots.resize(limit, None);
        self.debug_id = debug_id;
        self.debug_publication.set(None);
        self.module = module;
        self.prototype = prototype_index;
        self.named_vararg = spec.named_vararg;
        self.dynamic_top = dynamic_top;
        self.register_limit = limit;
        self.max_register_limit = max_register_limit;
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
        let ticket = match reserve_frame_vec(vm, &mut self.close_entries, 1, FailPoint::WorkReserve, self.module) {
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
        if let Err(error) = reserve_close_owners(vm, &mut self.close_owners, self.module) {
            drop(charge);
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

    #[inline(always)]
    pub(crate) fn index(&self, register: Register) -> Result<usize, RuntimeError> {
        let index = usize::from(register.0);
        if index >= self.register_limit {
            return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
        }
        Ok(index)
    }

    /// 開放結果超過初始 register_count 時，預備新增的尾端 slot 再提交。
    pub(crate) fn grow_for_open_results(&mut self, vm: &mut Vm, required: usize) -> Result<(), RuntimeError> {
        if required <= self.register_limit {
            return Ok(());
        }
        let previous = self.register_limit;
        let prepared = self.prepare_write(vm, previous, required - previous, &[], true)?;
        prepared.commit(self, &[], None, None);
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn read(&self, register: Register) -> Result<Value, RuntimeError> {
        self.registers
            .get(self.index(register)?)
            .copied()
            .ok_or_else(|| RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds))
    }

    #[inline(always)]
    pub(crate) fn read_verified(&self, register: Register) -> Value {
        // 固定 operand 已由 bytecode verifier 與活躍 frame 的建構檢查界限。
        self.registers[usize::from(register.0)]
    }

    #[inline(always)]
    pub(crate) fn write(
        &mut self,
        vm: &mut Vm,
        register: Register,
        value: Value,
    ) -> Result<(), RuntimeError> {
        self.index(register)?;
        self.write_verified(vm, register, value)
    }

    #[inline(always)]
    pub(crate) fn write_verified(
        &mut self,
        vm: &mut Vm,
        register: Register,
        value: Value,
    ) -> Result<(), RuntimeError> {
        let index = usize::from(register.0);
        let object = match value { Value::Object(object) => Some(object), _ => None };
        Self::set_root_slot(vm, &mut self.roots[index], object)?;
        self.registers[index] = value;
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn write_ordinary_verified(
        &mut self,
        vm: &mut Vm,
        register: Register,
        value: Value,
    ) -> Result<(), RuntimeError> {
        let index = usize::from(register.0);
        // 純量續寫不改變已清空的 stack root；物件交回完整驗證與屏障。
        if !matches!(value, Value::Object(_))
            && !matches!(self.registers[index], Value::Object(_))
        {
            self.registers[index] = value;
            Ok(())
        } else {
            self.write_verified(vm, register, value)
        }
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
            Some(vm.add_stack_root(object)?)
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

    fn write_capi_debug_slot(
        &mut self, vm: &mut Vm, slot: DebugWriteSlot, value: Value,
        source: Option<&CapiShutdownRoot>,
    ) -> Result<(), RuntimeError> {
        let (target, root) = match slot {
            DebugWriteSlot::Register(index) => {
                if index >= self.register_limit {
                    return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
                }
                (&mut self.registers[index], &mut self.roots[index])
            }
            DebugWriteSlot::Vararg(index) => {
                if index >= self.varargs.len() {
                    return Err(RuntimeError::new(RuntimeErrorKind::RegisterOutOfBounds));
                }
                (&mut self.varargs[index], &mut self.vararg_roots[index])
            }
            DebugWriteSlot::VarargTable =>
                (&mut self.debug_vararg_table, &mut self.debug_vararg_table_root),
        };
        match value {
            Value::Object(object) if root.is_none() => {
                *root = Some(vm.capi_frame_root_from_source(object, source)?);
            }
            Value::Object(object) => vm.set_stack_root(root.as_ref().ok_or(VmError::LedgerInvariant)?, Some(object))?,
            _ => {
                if let Some(root) = root {
                    vm.set_stack_root(root, None)?;
                }
            }
        }
        *target = value;
        Ok(())
    }

    pub(crate) fn write_capi_debug_register(
        &mut self, vm: &mut Vm, register: Register, value: Value,
        source: Option<&CapiShutdownRoot>,
    ) -> Result<(), RuntimeError> {
        let index = self.index(register)?;
        self.write_capi_debug_slot(vm, DebugWriteSlot::Register(index), value, source)
    }

    pub(crate) fn write_capi_debug_vararg(
        &mut self, vm: &mut Vm, index: usize, value: Value,
        source: Option<&CapiShutdownRoot>,
    ) -> Result<(), RuntimeError> {
        self.write_capi_debug_slot(vm, DebugWriteSlot::Vararg(index), value, source)
    }

    pub(crate) fn write_capi_debug_vararg_table(
        &mut self, vm: &mut Vm, value: Value,
        source: Option<&CapiShutdownRoot>,
    ) -> Result<(), RuntimeError> {
        self.write_capi_debug_slot(vm, DebugWriteSlot::VarargTable, value, source)
    }

    pub(crate) fn rollback_debug_write(
        &mut self,
        _vm: &mut Vm,
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
        drop(current_root);
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
            Self::set_root_slot(vm, &mut self.roots[index], None)?;
            self.registers[index] = Value::Nil;
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
        let root_bytes = checked_bytes(values.len(), core::mem::size_of::<Option<StackRoot>>())?;
        let charge = value_bytes
            .checked_add(root_bytes)
            .ok_or(RuntimeError::new(RuntimeErrorKind::Heap(
                VmError::ArithmeticOverflow,
            )))?;
        let needed = self.register_limit.checked_add(values.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(RuntimeError::new(RuntimeErrorKind::StackLimit))?;
        self.ensure_capi_root_capacity(vm, needed)?;
        let mut varargs = AllocVec::new_in(self.ledger.backing_allocator());
        let value_ticket = reserve_frame_vec(vm, &mut varargs, values.len(), FailPoint::FrameRegistersReserve, self.module)?;
        let mut roots = AllocVec::new_in(self.ledger.backing_allocator());
        let root_ticket = reserve_frame_vec(vm, &mut roots, values.len(), FailPoint::FrameRootsReserve, self.module)?;
        varargs.extend_from_slice(values);
        for value in values {
            let root = if let Value::Object(object) = value {
                match vm.add_stack_root(*object) {
                    Ok(root) => Some(root),
                    Err(error) => {
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
                            self.rollback_register_root(vm, raw)?;
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
                self.rollback_register_root(vm, register)?;
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
            if let Some(root) = root {
                vm.set_stack_root(root, None)?;
            }
        }
        for root in &mut self.vararg_roots {
            if let Some(root) = root {
                vm.set_stack_root(root, None)?;
            }
        }
        if let Some(root) = &self.debug_vararg_table_root {
            vm.set_stack_root(root, None)?;
        }
        if let Some(root) = &self.closure_root {
            vm.set_stack_root(root, None)?;
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
                Self::set_root_slot(vm, &mut self.closure_root, Some(closure))?;
            }
            for (value, root) in self.registers.iter().zip(self.roots.iter_mut()) {
                if let Value::Object(object) = value {
                    Self::set_root_slot(vm, root, Some(*object))?;
                }
            }
            for (value, root) in self.varargs.iter().zip(self.vararg_roots.iter_mut()) {
                if let Value::Object(object) = value {
                    Self::set_root_slot(vm, root, Some(*object))?;
                }
            }
            if let Value::Object(object) = self.debug_vararg_table {
                Self::set_root_slot(vm, &mut self.debug_vararg_table_root, Some(object))?;
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
        let mut replacement = AllocVec::new_in(self.ledger.backing_allocator());
        let mut new_charges = AllocationCharges::new_in(self.ledger.backing_allocator());
        let before = self.ledger.backing_allocator().refusal_count();
        let metadata_reserve = new_charges.try_reserve(1).or_else(|error| {
            let module = self.module.map(Value::Object);
            if vm.emergency_collect_after_refusal_with_borrowed_roots(before, module.as_slice())? {
                new_charges.try_reserve(1)
            } else {
                Err(error)
            }
        });
        if let Err(error) = metadata_reserve {
            vm.remove_root(root)?;
            return Err(error.into());
        }
        let ticket = match reserve_frame_vec(vm, &mut replacement, needed, FailPoint::OpenUpvaluesReserve, self.module) {
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
        let allocator = self.ledger.backing_allocator();
        let mut replacement = AllocVec::new_in(allocator.clone());
        let mut next_owner = AllocationCharges::new_in(allocator.clone());
        if original != 0 {
            if allocator.is_lua() {
                let ticket = reserve_frame_vec(vm, &mut replacement, original, FailPoint::OpenUpvaluesReserve, self.module)?;
                next_owner.try_reserve(1)?;
                next_owner.push_prepared(ticket.commit_charge()?);
            } else {
                self.ledger.checkpoint(FailPoint::OpenUpvaluesReserve)?;
                replacement.try_reserve_exact(original).map_err(|_| VmError::AllocationFailed)?;
            }
        }
        replacement.extend_from_slice(&self.open_upvalues[..original]);
        let prepared = if allocator.is_lua() { None } else { Some(self.open_owner.prepare_normalize(bytes)?) };
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
        self.open_owner = match prepared {
            Some(prepared) => self.open_owner.commit_normalize(prepared),
            None => next_owner,
        };
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
        self.registers = AllocVec::new_in(self.ledger.backing_allocator());
        self.roots = AllocVec::new_in(self.ledger.backing_allocator());
        self.capi_root_capacity = None;
        self.closure_root = None;
        self.varargs = AllocVec::new_in(self.ledger.backing_allocator());
        self.vararg_roots = AllocVec::new_in(self.ledger.backing_allocator());
        self.debug_vararg_table_root = None;
        self.vararg_value_owner = None;
        self.vararg_root_owner = None;
        self.vararg_charge = 0;
        self.register_limit = 0;
        self.max_register_limit = 0;
        self.register_owner = None;
        self.root_owner = None;
        self.charge = 0;
        self.backing_limit = 0;
        self.open_upvalues = AllocVec::new_in(self.ledger.backing_allocator());
        self.open_owner = AllocationCharges::new_in(self.ledger.backing_allocator());
        self.open_charge = 0;
        self.close_entries = AllocVec::new_in(self.ledger.backing_allocator());
        self.close_owners = AllocVec::new_in(self.ledger.backing_allocator());
        self.close_charge = 0;
    }
}

impl Deref for CallFrame {
    type Target = FrameData;

    fn deref(&self) -> &Self::Target {
        self.data.as_deref().expect("停放中的 frame 不可讀取")
    }
}

impl DerefMut for CallFrame {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data.as_deref_mut().expect("停放中的 frame 不可寫入")
    }
}

impl Drop for CallFrame {
    fn drop(&mut self) {
        self.release_storage();
    }
}


