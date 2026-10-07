//! 開放與關閉的捕捉值；slot 使用 Execution 內的穩定位址編號。

use rivetlua_core::{ObjectRef, Value, VmId};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum UpvalueState {
    Open {
        thread: VmId,
        coroutine: Option<ObjectRef>,
        slot: usize,
    },
    Closed(Value),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Upvalue {
    state: UpvalueState,
    identity: Option<ObjectRef>,
}

impl Upvalue {
    pub(crate) const fn open(thread: VmId, coroutine: Option<ObjectRef>, slot: usize) -> Self {
        Self {
            state: UpvalueState::Open {
                thread,
                coroutine,
                slot,
            },
            identity: None,
        }
    }

    pub const fn state(&self) -> UpvalueState {
        self.state
    }

    pub const fn identity(&self) -> Option<ObjectRef> {
        self.identity
    }

    pub(crate) fn set_identity(&mut self, identity: ObjectRef) {
        self.identity = Some(identity);
    }

    pub(crate) fn close(&mut self, value: Value) {
        self.state = UpvalueState::Closed(value);
    }

    pub(crate) fn set_closed(&mut self, value: Value) {
        self.state = UpvalueState::Closed(value);
    }
}
