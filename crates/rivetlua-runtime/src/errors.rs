//! P11 的 Lua 錯誤值、受保護呼叫邊界與三個必要內建入口。

use std::rc::Rc;

use rivetlua_core::{Register, ResultMode, Value};

use crate::call::PendingCloseSnapshot;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{HostHandle, RootId, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Builtin {
    Error,
    PCall,
    XPCall,
    CoroutineCreate,
    CoroutineResume,
    CoroutineYield,
    CoroutineStatus,
    CoroutineClose,
    CoroutineWrap,
    CoroutineWrapped(rivetlua_core::ObjectRef),
}

/// 宿主可保留的 Lua error；最後一份複本丟棄時釋放物件 root。
#[derive(Clone)]
pub struct LuaError {
    pub kind: RuntimeErrorKind,
    pub diagnostic_id: &'static str,
    pub value: Value,
    pub source_pc: Option<usize>,
    pub source_prototype: Option<usize>,
    pub source_depth: Option<usize>,
    _root: Option<Rc<HostHandle<Value>>>,
}

impl LuaError {
    pub(crate) fn from_runtime(
        vm: &mut Vm,
        error: RuntimeError,
        prototype: usize,
        depth: usize,
        pc: usize,
    ) -> Result<Self, VmError> {
        let root = if let Value::Object(object) = error.value {
            Some(Rc::new(HostHandle::new(vm, object)?))
        } else {
            None
        };
        Ok(Self {
            kind: error.kind,
            diagnostic_id: error.diagnostic_id,
            value: error.value,
            source_pc: Some(error.source_pc.unwrap_or(pc)),
            source_prototype: Some(error.source_prototype.unwrap_or(prototype)),
            source_depth: Some(error.source_depth.unwrap_or(depth)),
            _root: root,
        })
    }
}

impl core::fmt::Debug for LuaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LuaError")
            .field("kind", &self.kind)
            .field("diagnostic_id", &self.diagnostic_id)
            .field("value", &self.value)
            .field("source_pc", &self.source_pc)
            .field("source_prototype", &self.source_prototype)
            .field("source_depth", &self.source_depth)
            .finish()
    }
}

impl PartialEq for LuaError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.diagnostic_id == other.diagnostic_id
            && self.value == other.value
            && self.source_pc == other.source_pc
            && self.source_prototype == other.source_prototype
            && self.source_depth == other.source_depth
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedStage {
    Body,
    Handler,
}

/// caller 保持在 CallFrame 堆疊，handler 另外持有 root 以跨錯誤 unwind。
pub(crate) struct ProtectedBoundary {
    pub(crate) caller_depth: usize,
    pub(crate) caller_pc: usize,
    pub(crate) resume_pc: usize,
    pub(crate) destination: Register,
    pub(crate) result_mode: ResultMode,
    pub(crate) tail_return: bool,
    pub(crate) inline_target: bool,
    pub(crate) handler: Option<Value>,
    pub(crate) handler_root: Option<RootId>,
    pub(crate) stage: ProtectedStage,
    pub(crate) handler_depth: Option<usize>,
    pub(crate) handler_errors: u8,
    pub(crate) close_scope: Option<PendingCloseSnapshot>,
}

impl ProtectedBoundary {
    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.handler_root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_root(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(Value::Object(object)) = self.handler {
            self.handler_root = Some(vm.add_root(crate::RootKind::Temporary, object)?);
        }
        Ok(())
    }
}

pub(crate) fn explicit_error(value: Value, pc: usize) -> RuntimeError {
    let mut error = RuntimeError::new(RuntimeErrorKind::Thrown);
    error.value = value;
    error.source_pc = Some(pc);
    error
}
