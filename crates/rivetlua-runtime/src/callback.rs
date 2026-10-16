//! 宿主回呼只回傳動作；Lua 執行與暫停由原執行器管理。

use crate::rust_alloc::vec::Vec;

use crate::rust_alloc::rc::Rc;

use rivetlua_core::Value;

use crate::{ObjectKind, Vm, VmError};

/// 回呼或 continuation 可要求執行器採取的動作。
pub enum CallbackResult {
    Return(Vec<Value>),
    Throw(Value),
    Yield {
        values: Vec<Value>,
        continuation: CallbackContinuation,
    },
    Call {
        target: Value,
        args: Vec<Value>,
        continuation: CallbackContinuation,
    },
    Resume {
        coroutine: Value,
        args: Vec<Value>,
        continuation: CallbackContinuation,
    },
}

pub type CallbackFn = dyn Fn(&mut CallbackContext<'_>, &[Value]) -> CallbackResult;

/// continuation 的 Lua 捕獲值由執行器驗證並在暫停期間追蹤。
pub struct CallbackContinuation {
    pub(crate) callback: Rc<CallbackFn>,
    pub(crate) captures: Vec<Value>,
}

impl CallbackContinuation {
    pub fn new(captures: Vec<Value>, callback: Rc<CallbackFn>) -> Self {
        Self { callback, captures }
    }
}

/// 只提供目前回呼的顯式 Lua 捕獲與動作建構，不借出 VM。
pub struct CallbackContext<'a> {
    captures: &'a [Value],
    vm: &'a mut Vm,
    error: Option<VmError>,
}

impl<'a> CallbackContext<'a> {
    pub(crate) fn new(captures: &'a [Value], vm: &'a mut Vm) -> Self {
        Self {
            captures,
            vm,
            error: None,
        }
    }

    pub(crate) fn finish(&self) -> Result<(), VmError> {
        self.error.map_or(Ok(()), Err)
    }

    /// 僅在本次 callback 借用期間讀取 Lua 型別；陳舊或外 VM 物件保留原錯誤。
    pub fn value_type(&mut self, value: Value) -> Result<&'static str, VmError> {
        let kind = match value {
            Value::Nil => Ok("nil"),
            Value::Boolean(_) => Ok("boolean"),
            Value::Integer(_) | Value::Float(_) => Ok("number"),
            Value::LightUserdata(_) => Ok("userdata"),
            Value::CFunction(id) if id.vm() == self.vm.id() => Ok("function"),
            Value::CFunction(_) => Err(VmError::WrongVm),
            Value::Object(object) => self.vm.object_kind(object).and_then(|kind| {
                match kind {
                    ObjectKind::ByteString => Ok("string"),
                    ObjectKind::Table => Ok("table"),
                    ObjectKind::Userdata | ObjectKind::File => Ok("userdata"),
                    ObjectKind::Closure | ObjectKind::CClosure | ObjectKind::Builtin => {
                        Ok("function")
                    }
                    ObjectKind::Coroutine => Ok("thread"),
                    ObjectKind::Value | ObjectKind::Upvalue | ObjectKind::Module => {
                        Err(VmError::WrongObjectType)
                    }
                }
            }),
        };
        if let Err(error) = kind {
            self.error.get_or_insert(error);
        }
        kind
    }

    /// 不執行 guest code，也不套用 `__metatable` 遮蔽；結果由 callback 的既有 capture／call 持根。
    pub fn raw_metamethod(&mut self, value: Value, name: &[u8]) -> Result<Value, VmError> {
        let result = match value {
            Value::CFunction(id) if id.vm() != self.vm.id() => Err(VmError::WrongVm),
            _ => self.vm.lookup_raw_metafield_value(value, name),
        };
        if let Err(error) = result {
            self.error.get_or_insert(error);
        }
        result
    }

    pub fn capture(&self, index: usize) -> Option<Value> {
        self.captures.get(index).copied()
    }

    pub fn call(
        &self,
        target: Value,
        args: Vec<Value>,
        continuation: CallbackContinuation,
    ) -> CallbackResult {
        CallbackResult::Call {
            target,
            args,
            continuation,
        }
    }

    pub fn resume(
        &self,
        coroutine: Value,
        args: Vec<Value>,
        continuation: CallbackContinuation,
    ) -> CallbackResult {
        CallbackResult::Resume {
            coroutine,
            args,
            continuation,
        }
    }

    pub fn yield_with(
        &self,
        values: Vec<Value>,
        continuation: CallbackContinuation,
    ) -> CallbackResult {
        CallbackResult::Yield {
            values,
            continuation,
        }
    }
}
