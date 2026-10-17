//! 受 VM 專屬 capability 控制的 debug 入口與公開能力矩陣。

use crate::rust_alloc::vec::Vec;

use crate::host::DebugPermission;
use rivetlua_core::ObjectRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DebugHookEvent {
    Line(Option<u32>),
    Count,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DebugHookEvents {
    pub first: DebugHookEvent,
    pub followup_line: Option<Option<u32>>,
}

/// 單一 Lua thread 的 hook；coroutine 以自身 payload 持有強邊。
#[derive(Clone, Copy, Debug)]
pub(crate) struct DebugHook {
    pub function: ObjectRef,
    pub count: usize,
    pub remaining: usize,
    pub line: bool,
    pub call: bool,
    pub ret: bool,
    pub last_line: Option<u32>,
    pub last_pc: Option<usize>,
    pub last_prototype: Option<(ObjectRef, usize)>,
    pub last_line_event: bool,
}

impl DebugHook {
    #[cfg(test)]
    pub(crate) fn new(function: ObjectRef, count: usize) -> Self {
        Self::with_line(function, count, false)
    }

    pub(crate) fn with_line(function: ObjectRef, count: usize, line: bool) -> Self {
        Self {
            function,
            count,
            remaining: count,
            line,
            call: false,
            ret: false,
            last_line: None,
            last_pc: None,
            last_prototype: None,
            last_line_event: false,
        }
    }

    pub(crate) fn tick(&mut self) -> bool {
        if self.count == 0 {
            return false;
        }
        if self.remaining > 1 {
            self.remaining -= 1;
            false
        } else {
            self.remaining = self.count;
            true
        }
    }

    pub(crate) fn event(
        &mut self,
        module: Option<ObjectRef>,
        prototype: usize,
        source_pc: usize,
        line: Option<u32>,
        counted: bool,
        stripped_first_instruction: bool,
    ) -> Option<DebugHookEvents> {
        let count = counted && self.tick();
        let location = module.map(|module| (module, prototype));
        let changed = self.last_prototype != location || self.last_line != line;
        let backwards = self.last_prototype == location
            && self.last_pc.is_some_and(|previous| source_pc < previous);
        let send_line = self.line
            && (stripped_first_instruction
                || (line.is_some() && (changed || (backwards && !self.last_line_event))));
        if line.is_some() || stripped_first_instruction {
            self.last_prototype = location;
            self.last_pc = Some(source_pc);
            self.last_line = line;
        }
        self.last_line_event = send_line;
        if count {
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: send_line.then_some(line),
            })
        } else if send_line {
            Some(DebugHookEvents {
                first: DebugHookEvent::Line(line),
                followup_line: None,
            })
        } else {
            None
        }
    }

    pub(crate) fn prime(
        &mut self,
        module: Option<ObjectRef>,
        prototype: usize,
        source_pc: usize,
        line: Option<u32>,
    ) {
        if line.is_some() {
            self.last_prototype = module.map(|module| (module, prototype));
            self.last_pc = Some(source_pc);
            self.last_line = line;
            self.last_line_event = false;
        }
    }
}

#[cfg(test)]
mod hook_event_tests {
    use super::{DebugHook, DebugHookEvent, DebugHookEvents};
    use rivetlua_core::ObjectRef;

    #[test]
    fn stripped_entry_distinguishes_nil_line_from_count_and_primes_return() {
        let function = ObjectRef::new_opaque().unwrap();
        let caller = ObjectRef::new_opaque().unwrap();
        let stripped = ObjectRef::new_opaque().unwrap();
        let mut hook = DebugHook::with_line(function, 2, true);

        assert_eq!(
            hook.event(Some(caller), 0, 0, Some(10), true, false),
            Some(DebugHookEvents {
                first: DebugHookEvent::Line(Some(10)),
                followup_line: None,
            })
        );
        assert_eq!(
            hook.event(Some(caller), 0, 1, Some(10), true, false),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: None,
            })
        );
        assert_eq!(
            hook.event(Some(stripped), 1, 0, None, true, true),
            Some(DebugHookEvents {
                first: DebugHookEvent::Line(None),
                followup_line: None,
            })
        );
        assert_eq!(
            hook.event(Some(stripped), 1, 1, None, true, false),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: None,
            })
        );

        hook.prime(Some(caller), 0, 1, Some(10));
        assert_eq!(hook.event(Some(caller), 0, 2, Some(10), true, false), None);
        assert_eq!(
            hook.event(Some(stripped), 1, 0, None, true, true),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: Some(None),
            })
        );
        assert_eq!(hook.event(Some(stripped), 1, 1, None, false, false), None);
        assert_eq!(
            hook.event(Some(stripped), 1, 0, None, true, true),
            Some(DebugHookEvents {
                first: DebugHookEvent::Line(None),
                followup_line: None,
            })
        );

        let mut every_instruction = DebugHook::with_line(function, 1, true);
        assert_eq!(
            every_instruction.event(Some(caller), 0, 0, Some(10), true, false),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: Some(Some(10)),
            })
        );
        assert_eq!(
            every_instruction.event(Some(caller), 0, 1, Some(10), true, false),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: None,
            })
        );
        assert_eq!(
            every_instruction.event(Some(stripped), 1, 0, None, true, true),
            Some(DebugHookEvents {
                first: DebugHookEvent::Count,
                followup_line: Some(None),
            })
        );
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
            Self::SetHook | Self::GetHook => None,
            Self::GetMetatable => Some(DebugPermission::MetatableRead),
            Self::SetMetatable => Some(DebugPermission::TableMetatableWrite),
            Self::GetLocal => Some(DebugPermission::LocalInspection),
            Self::SetLocal => Some(DebugPermission::LocalMutation),
            Self::GetRegistry => Some(DebugPermission::RegistryRead),
            Self::GetUserValue => Some(DebugPermission::UserValueRead),
            Self::SetUserValue => Some(DebugPermission::UserValueWrite),
            Self::SetUpvalue => Some(DebugPermission::UpvalueMutation),
            Self::UpvalueId | Self::UpvalueJoin => Some(DebugPermission::UpvalueIdentity),
            Self::Debug => Some(DebugPermission::Console),
            Self::SetCStackLimit => None,
        }
    }
}
