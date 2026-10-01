//! 封閉宿主 OS 能力的 Lua 入口。

use rivetlua_core::ObjectRef;

use crate::host::HostCalendar;
use crate::{RootId, RootKind, Vm, VmError};

pub(crate) struct CalendarTimeState {
    pub(crate) table: ObjectRef,
    pub(crate) next_field: usize,
    pub(crate) awaiting_field: bool,
    pub(crate) normalized: Option<HostCalendar>,
    pub(crate) epoch: i64,
    pub(crate) fields: [i64; 6],
    pub(crate) daylight_saving: Option<bool>,
    pub(crate) key: Option<ObjectRef>,
    table_root: Option<RootId>,
    key_root: Option<RootId>,
}

impl CalendarTimeState {
    pub(crate) fn new(vm: &mut Vm, table: ObjectRef) -> Result<Self, VmError> {
        Ok(Self {
            table,
            next_field: 0,
            awaiting_field: false,
            normalized: None,
            epoch: 0,
            fields: [0; 6],
            daylight_saving: None,
            key: None,
            table_root: Some(vm.add_root(RootKind::Temporary, table)?),
            key_root: None,
        })
    }

    pub(crate) fn set_key(&mut self, vm: &mut Vm, key: ObjectRef) -> Result<(), VmError> {
        self.clear_key(vm)?;
        self.key_root = Some(vm.add_root(RootKind::Temporary, key)?);
        self.key = Some(key);
        Ok(())
    }

    pub(crate) fn clear_key(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.key_root.take() {
            vm.remove_root(root)?;
        }
        self.key = None;
        Ok(())
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.key_root.take() {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.table_root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.table_root = Some(vm.add_root(RootKind::Temporary, self.table)?);
        if let Some(key) = self.key {
            if let Err(error) = self.set_key(vm, key) {
                self.clear_roots(vm)?;
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        visit(self.table)?;
        if let Some(key) = self.key {
            visit(key)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OsBuiltin {
    Clock,
    Date,
    Difftime,
    Execute,
    Exit,
    GetEnv,
    Remove,
    Rename,
    SetLocale,
    Time,
    TmpName,
}
