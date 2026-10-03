//! 宿主回呼只回傳動作；Lua 執行與暫停由原執行器管理。

use std::rc::Rc;

use rivetlua_core::Value;

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
}

impl<'a> CallbackContext<'a> {
    pub(crate) fn new(captures: &'a [Value]) -> Self {
        Self { captures }
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
