//! Closure 保存已驗證模組身分及共享 upvalue 物件參照。

use core::mem::size_of;

use rivetlua_core::{ObjectRef, ProtoId, Value};

use crate::VmError;
use crate::alloc::{AllocationLedger, FailPoint, checked_bytes, reserve_vec};

pub struct Closure {
    module: ObjectRef,
    prototype: ProtoId,
    upvalues: Vec<ObjectRef>,
    environment: Option<Value>,
    ledger: AllocationLedger,
    charge: usize,
}

impl Closure {
    pub(crate) fn new(
        module: ObjectRef,
        prototype: ProtoId,
        captures: &[ObjectRef],
        environment: Option<Value>,
        ledger: &AllocationLedger,
    ) -> Result<Self, VmError> {
        let mut upvalues = Vec::new();
        let charge = checked_bytes(captures.len(), size_of::<ObjectRef>())?;
        if !captures.is_empty() {
            let ticket = reserve_vec(
                ledger,
                &mut upvalues,
                captures.len(),
                FailPoint::ClosureCapturesReserve,
            )?;
            upvalues.extend_from_slice(captures);
            ticket.commit()?;
        }
        Ok(Self {
            module,
            prototype,
            upvalues,
            environment,
            ledger: ledger.clone(),
            charge,
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

    pub(crate) fn environment(&self) -> Option<Value> {
        self.environment
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        visit(self.module)?;
        if let Some(Value::Object(environment)) = self.environment {
            visit(environment)?;
        }
        for &upvalue in &self.upvalues {
            visit(upvalue)?;
        }
        Ok(())
    }
}

impl Drop for Closure {
    fn drop(&mut self) {
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
            self.charge = 0;
        }
    }
}
