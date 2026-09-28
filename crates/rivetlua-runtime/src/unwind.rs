//! `<close>` 宣告值及其獨立 root；由所屬 CallFrame 管理生命週期。

use rivetlua_core::{BytecodeBindingId, Register, Value};

use crate::RootId;
use crate::vm::RuntimeError;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CloseEntry {
    pub(crate) binding: BytecodeBindingId,
    pub(crate) register: Register,
    pub(crate) value: Value,
    pub(crate) root: Option<RootId>,
}

/// protected LuaError 暫停時保留原錯誤；handler 返回後繼續逐筆關閉。
#[derive(Clone, Copy, Debug)]
pub(crate) struct CloseUnwind {
    pub(crate) error: RuntimeError,
    pub(crate) caller_depth: usize,
    pub(crate) include_root: bool,
    pub(crate) finish: CloseFinish,
    pub(crate) failed: bool,
    pub(crate) waiting_depth: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CloseFinish {
    Protected,
    Host,
    Coroutine { wrap: bool },
}
