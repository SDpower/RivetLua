//! 強邊與活躍執行 root 的封閉來源分類。

use rivetlua_core::{ObjectRef, Value};

use crate::heap::VmError;
use crate::vm::{NativeCompletion, NativeProtected};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveRootKind {
    ModuleRoot,
    Frame,
    CallerFrame,
    PendingOp,
    ProtectedHandler,
    ErrorRoot,
    CloseError,
    ActiveCoroutine,
    ResumeContext,
    ResumeOwner,
    ResumeChild,
    ResumeContinuation,
    ResumeHandler,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RefField {
    Child,
    TableKey,
    TableValue,
    Metatable,
    UserValue,
    Upvalue,
    Coroutine,
}

pub(crate) fn trace_value(
    value: Value,
    mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
) -> Result<(), VmError> {
    match value {
        Value::Object(object) => visit(object)?,
        Value::Nil
        | Value::Boolean(_)
        | Value::Integer(_)
        | Value::Float(_)
        | Value::LightUserdata(_)
        | Value::CFunction(_) => {}
    }
    Ok(())
}

pub(crate) fn trace_native(
    native: NativeCompletion,
    mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
) -> Result<(), VmError> {
    match native {
        NativeCompletion::PCall { .. } => {}
        NativeCompletion::XPCallBody { handler, .. }
        | NativeCompletion::XPCallHandler { handler, .. } => {
            trace_value(handler, &mut visit)?;
        }
        NativeCompletion::Resume {
            outer,
            parent,
            protected,
            ..
        } => {
            visit(outer)?;
            if let Some(parent) = parent {
                visit(parent)?;
            }
            if let Some(protected) = protected {
                trace_protected(protected, &mut visit)?;
            }
        }
    }
    Ok(())
}

pub(crate) fn trace_protected(
    protected: NativeProtected,
    mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
) -> Result<(), VmError> {
    match protected {
        NativeProtected::PCall { .. } => {}
        NativeProtected::XPCall { handler } => trace_value(handler, &mut visit)?,
    }
    Ok(())
}
