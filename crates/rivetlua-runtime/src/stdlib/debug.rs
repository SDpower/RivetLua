//! 受 VM 專屬 capability 控制的 debug 入口與公開能力矩陣。

use crate::host::DebugPermission;
use rivetlua_core::ObjectRef;

/// 單一 Lua thread 的 count hook；coroutine 以自身 payload 持有強邊。
#[derive(Clone, Copy, Debug)]
pub(crate) struct DebugHook {
    pub function: ObjectRef,
    pub count: usize,
    pub remaining: usize,
}

impl DebugHook {
    pub(crate) fn new(function: ObjectRef, count: usize) -> Self {
        Self {
            function,
            count,
            remaining: count,
        }
    }

    pub(crate) fn tick(&mut self) -> bool {
        if self.remaining > 1 {
            self.remaining -= 1;
            false
        } else {
            self.remaining = self.count;
            true
        }
    }
}

pub(crate) fn decimal_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 10 {
        value /= 10;
        len += 1;
    }
    len
}

pub(crate) fn append_decimal(buffer: &mut Vec<u8>, mut value: usize) {
    let mut digits = [0_u8; 20];
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    buffer.extend_from_slice(&digits[index..]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DebugBuiltin {
    GetInfo,
    GetLocal,
    SetLocal,
    GetUpvalue,
    SetUpvalue,
    UpvalueId,
    UpvalueJoin,
    Traceback,
    SetHook,
    GetHook,
    GetMetatable,
    SetMetatable,
    GetRegistry,
    GetUserValue,
    SetUserValue,
    Debug,
    SetCStackLimit,
}

impl DebugBuiltin {
    pub(crate) const fn permission(self) -> Option<DebugPermission> {
        match self {
            Self::GetInfo => Some(DebugPermission::Info),
            Self::GetUpvalue => Some(DebugPermission::Upvalues),
            Self::Traceback => Some(DebugPermission::Traceback),
            Self::SetHook | Self::GetHook => Some(DebugPermission::CountHook),
            Self::GetMetatable => Some(DebugPermission::MetatableRead),
            Self::SetMetatable => Some(DebugPermission::TableMetatableWrite),
            Self::GetLocal
            | Self::SetLocal
            | Self::SetUpvalue
            | Self::UpvalueId
            | Self::UpvalueJoin
            | Self::GetRegistry
            | Self::GetUserValue
            | Self::SetUserValue
            | Self::Debug
            | Self::SetCStackLimit => None,
        }
    }
}
