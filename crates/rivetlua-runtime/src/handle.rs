//! VM 綁定的宿主 root 所有權。

use core::marker::PhantomData;

use rivetlua_core::{ObjectId, ObjectRef, Value};

use crate::heap::{Vm, VmError};
use crate::roots::{RootId, RootLease};

/// 每個實例持有一筆 host root；轉移不增根，`try_clone` 另建一筆根。
pub struct HostHandle<T> {
    id: ObjectId,
    object: ObjectRef,
    root: RootId,
    lease: RootLease,
    marker: PhantomData<T>,
}

impl<T> HostHandle<T> {
    pub fn new(vm: &mut Vm, object: ObjectRef) -> Result<Self, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        let (root, lease) = vm.add_host_root(object)?;
        Ok(Self {
            id,
            object,
            root,
            lease,
            marker: PhantomData,
        })
    }

    pub const fn object_id(&self) -> ObjectId {
        self.id
    }

    pub const fn root_id(&self) -> RootId {
        self.root
    }

    /// 需再次提供原 VM；先驗 VM，再驗 root 與物件世代。
    pub fn read(&self, vm: &Vm) -> Result<Value, VmError> {
        if vm.id() != self.id.vm {
            return Err(VmError::WrongVm);
        }
        if !self.lease.is_active() {
            return Err(VmError::StaleObject);
        }
        vm.read(self.object)
    }

    /// 複製需在原 VM 中新增一筆可檢查的 host root。
    pub fn try_clone(&self, vm: &mut Vm) -> Result<Self, VmError> {
        self.read(vm)?;
        Self::new(vm, self.object)
    }
}

impl<T> Drop for HostHandle<T> {
    fn drop(&mut self) {
        self.lease.deactivate();
    }
}
