//! Closure 保存已驗證模組身分及共享 upvalue 物件參照。

use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::StateAllocator;

use rivetlua_core::{HostFunctionId, ObjectRef, ProtoId, Value};

use crate::VmError;
use crate::alloc::{AllocationCharge, AllocationLedger, FailPoint, reserve_state_vec_lua};
use crate::errors::Builtin;

pub struct Closure {
    module: ObjectRef,
    prototype: ProtoId,
    upvalues: AllocVec<ObjectRef, StateAllocator>,
    environment: Option<Value>,
    environment_cell: Option<ObjectRef>,
    _charge: Option<AllocationCharge>,
}

impl Closure {
    pub(crate) fn new(
        module: ObjectRef,
        prototype: ProtoId,
        captures: &[ObjectRef],
        environment: Option<Value>,
        ledger: &AllocationLedger,
    ) -> Result<Self, VmError> {
        let mut upvalues = AllocVec::new_in(ledger.backing_allocator());
        let charge = if !captures.is_empty() {
            let ticket = reserve_state_vec_lua(
                ledger,
                &mut upvalues,
                captures.len(),
                FailPoint::ClosureCapturesReserve,
            )?;
            upvalues.extend_from_slice(captures);
            Some(ticket.commit_charge()?)
        } else {
            None
        };
        Ok(Self {
            module,
            prototype,
            upvalues,
            environment,
            environment_cell: None,
            _charge: charge,
        })
    }

    pub const fn prototype(&self) -> ProtoId {
        self.prototype
    }

    pub(crate) const fn module(&self) -> ObjectRef {
        self.module
    }

    pub(crate) fn upvalue(&self, index: usize) -> Option<ObjectRef> {
        self.upvalues.get(index).copied()
    }

    pub(crate) fn replace_upvalue(&mut self, index: usize, value: ObjectRef) -> Option<ObjectRef> {
        self.upvalues
            .get_mut(index)
            .map(|slot| core::mem::replace(slot, value))
    }

    pub(crate) fn environment(&self) -> Option<Value> {
        self.environment
    }

    pub(crate) fn environment_cell(&self) -> Option<ObjectRef> {
        self.environment_cell
    }

    pub(crate) fn has_environment(&self) -> bool {
        self.environment.is_some() || self.environment_cell.is_some()
    }

    pub(crate) fn set_environment_cell(&mut self, cell: ObjectRef) {
        self.environment = None;
        self.environment_cell = Some(cell);
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        visit(self.module)?;
        if let Some(Value::Object(environment)) = self.environment {
            visit(environment)?;
        }
        if let Some(cell) = self.environment_cell {
            visit(cell)?;
        }
        for &upvalue in &self.upvalues {
            visit(upvalue)?;
        }
        Ok(())
    }
}

/// C closure 僅保存宿主函式 capability；真正的 C 指標由 C API group 持有。
pub(crate) struct CClosure {
    function: HostFunctionId,
    upvalues: AllocVec<ObjectRef, StateAllocator>,
    builtin: Option<Builtin>,
    _charge: Option<AllocationCharge>,
}

impl CClosure {
    pub(crate) fn new(
        function: HostFunctionId,
        captures: &[Option<ObjectRef>],
        ledger: &AllocationLedger,
    ) -> Result<Self, VmError> {
        let mut upvalues = AllocVec::new_in(ledger.backing_allocator());
        if captures.iter().any(Option::is_none) {
            return Err(VmError::LedgerInvariant);
        }
        let charge = if !captures.is_empty() {
            let ticket = reserve_state_vec_lua(
                ledger,
                &mut upvalues,
                captures.len(),
                FailPoint::ClosureCapturesReserve,
            )?;
            for &cell in captures {
                upvalues.push(cell.ok_or(VmError::LedgerInvariant)?);
            }
            Some(ticket.commit_charge()?)
        } else {
            None
        };
        Ok(Self {
            function,
            upvalues,
            builtin: None,
            _charge: charge,
        })
    }

    pub(crate) fn with_builtin(mut self, builtin: Builtin) -> Self {
        self.builtin = Some(builtin);
        self
    }

    pub(crate) const fn builtin(&self) -> Option<Builtin> {
        self.builtin
    }

    pub(crate) const fn function(&self) -> HostFunctionId {
        self.function
    }

    pub(crate) fn upvalue(&self, index: usize) -> Option<ObjectRef> {
        self.upvalues.get(index).copied()
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for &cell in &self.upvalues {
            visit(cell)?;
        }
        if let Some(builtin) = self.builtin {
            builtin.trace_children(&mut visit)?;
        }
        Ok(())
    }
}
