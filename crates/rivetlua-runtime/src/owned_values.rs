//! C 相容層與 VM 交接時使用的單一、可計費值擁有者。

use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::StateAllocator;
use rivetlua_core::{Value, VmId};

use crate::alloc::AllocationCharge;
use crate::alloc::{FailPoint, reserve_vec};
use crate::heap::{CapiShutdownRoot, HostAllocationCharge, Vm, VmError};
use crate::roots::{RootKind, StackRoot};
use crate::rust_alloc::vec::Vec;

/// 值 backing 與各物件的暫存根一同轉移，不提供無失敗複製。
#[doc(hidden)]
pub struct OwnedValues {
    values: AllocVec<Value, StateAllocator>,
    roots: AllocVec<Option<StackRoot>, StateAllocator>,
    values_charge: Option<AllocationCharge>,
    roots_charge: Option<AllocationCharge>,
    parked: bool,
    vm_id: Option<VmId>,
    shutdown_spare: Option<(AllocVec<StackRoot, StateAllocator>, AllocationCharge)>,
}

impl OwnedValues {
    pub(crate) fn empty(allocator: StateAllocator) -> Self {
        Self {
            values: AllocVec::new_in(allocator.clone()),
            roots: AllocVec::new_in(allocator),
            values_charge: None,
            roots_charge: None,
            parked: false,
            vm_id: None,
            shutdown_spare: None,
        }
    }

    #[doc(hidden)]
    pub fn try_copy_from(vm: &mut Vm, source: &[Value]) -> Result<Self, VmError> {
        Self::try_build(vm, source, None, &[], source.len(), None)
    }

    pub(crate) fn new(vm: &mut Vm, source: &[Value]) -> Result<Self, VmError> {
        Self::try_copy_from(vm, source)
    }

    #[doc(hidden)]
    pub fn try_copy_pair(
        vm: &mut Vm,
        first: &[Value],
        second: &[Value],
    ) -> Result<Self, VmError> {
        let capacity = first.len().checked_add(second.len()).ok_or(VmError::ArithmeticOverflow)?;
        Self::try_build(vm, first, None, second, capacity, None)
    }

    pub(crate) fn try_copy_with_middle(
        vm: &mut Vm,
        first: &[Value],
        middle: Value,
        last: &[Value],
    ) -> Result<Self, VmError> {
        vm.check_owned_value(middle)?;
        for &value in first.iter().chain(last) {
            vm.check_owned_value(value)?;
        }
        let capacity = first.len().checked_add(last.len())
            .and_then(|len| len.checked_add(1))
            .ok_or(VmError::ArithmeticOverflow)?;
        let middle_root = match middle {
            Value::Object(object) => Some(vm.add_root_with_borrowed_root_slices(
                RootKind::Temporary, object, first, last,
            )?),
            _ => None,
        };
        let built = Self::try_build(vm, first, Some(middle), last, capacity, None);
        let cleanup = middle_root.map(|root| vm.remove_root(root)).transpose();
        let built = built?;
        cleanup?;
        Ok(built)
    }

    pub(crate) fn try_with_capacity(vm: &mut Vm, capacity: usize) -> Result<Self, VmError> {
        Self::try_with_capacity_borrowed(vm, capacity, &[])
    }

    pub(crate) fn try_with_capacity_borrowed(
        vm: &mut Vm,
        capacity: usize,
        borrowed: &[Value],
    ) -> Result<Self, VmError> {
        for &value in borrowed {
            vm.check_owned_value(value)?;
        }
        let mut owner = Self::empty(vm.capi_backing_allocator());
        owner.vm_id = Some(vm.id());
        if capacity != 0 {
            owner.values_charge = Some(vm.reserve_owned_values_backing(
                &mut owner.values, capacity, borrowed, &[],
            )?);
            owner.roots_charge = Some(vm.reserve_owned_values_backing(
                &mut owner.roots, capacity, borrowed, &[],
            )?);
        }
        Ok(owner)
    }

    /// 關閉期先配置所有值與真根；後續僅重綁既有 root 與搬移 slot。
    pub(crate) fn prepare_shutdown(vm: &mut Vm, capacity: usize) -> Result<Self, VmError> {
        let anchor = vm.main_thread_identity().ok_or(VmError::LedgerInvariant)?;
        let mut owner = Self::try_with_capacity(vm, capacity)?;
        let mut spare = AllocVec::new_in(vm.capi_backing_allocator());
        let charge = vm.reserve_owned_values_backing(&mut spare, capacity, &[Value::Object(anchor)], &[])?;
        for _ in 0..capacity {
            let root = match vm.add_stack_root(anchor) {
                Ok(root) => root,
                Err(error) => {
                    drop(spare);
                    drop(charge);
                    return Err(error);
                }
            };
            if let Err(error) = vm.set_stack_root(&root, None) {
                drop(root);
                drop(spare);
                drop(charge);
                return Err(error);
            }
            spare.push(root);
        }
        owner.shutdown_spare = Some((spare, charge));
        Ok(owner)
    }

    pub(crate) fn shutdown_reusable(&self) -> bool {
        self.shutdown_spare.is_some()
    }


    pub(crate) fn shutdown_set_values(&mut self, vm: &mut Vm, source: &[Value]) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if self.parked || self.shutdown_spare.is_none() || !self.values.is_empty()
            || source.len() > self.values.capacity() || source.len() > self.roots.capacity()
        {
            return Err(VmError::LedgerInvariant);
        }
        for &value in source {
            vm.check_owned_value(value)?;
        }
        for &value in source {
            let root = self.shutdown_spare.as_mut().ok_or(VmError::LedgerInvariant)?
                .0.pop().ok_or(VmError::LedgerInvariant)?;
            let object = match value { Value::Object(object) => Some(object), _ => None };
            if let Err(error) = vm.set_stack_root(&root, object) {
                self.shutdown_spare.as_mut().ok_or(VmError::LedgerInvariant)?.0.push(root);
                self.shutdown_clear(vm)?;
                return Err(error);
            }
            self.roots.push(Some(root));
            self.values.push(value);
        }
        Ok(())
    }

    fn shutdown_clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        while let Some(root) = self.roots.pop() {
            let root = root.ok_or(VmError::LedgerInvariant)?;
            vm.set_stack_root(&root, None)?;
            self.shutdown_spare.as_mut().ok_or(VmError::LedgerInvariant)?.0.push(root);
        }
        self.values.clear();
        self.parked = false;
        Ok(())
    }

    /// 已備妥兩份 backing 後，填入不含 GC 物件的值；持有唯讀 VM view 時不配置。
    pub(crate) fn push_scalar(&mut self, value: Value) -> Result<(), VmError> {
        if self.parked
            || matches!(value, Value::Object(_) | Value::CFunction(_))
            || self.values.len() == self.values.capacity()
            || self.roots.len() == self.roots.capacity()
        {
            return Err(VmError::LedgerInvariant);
        }
        self.values.push(value);
        self.roots.push(None);
        Ok(())
    }

    #[doc(hidden)]
    pub fn capi_from_backing(
        vm: &mut Vm,
        values: AllocVec<Value, StateAllocator>,
        charge: HostAllocationCharge,
    ) -> Result<Self, VmError> {
        let checked = vm.check_owned_values_backing(&values, &charge).and_then(|()| {
            for &value in &values {
                vm.check_owned_value(value)?;
            }
            Ok(())
        });
        if let Err(error) = checked {
            drop(values);
            drop(charge);
            return Err(error);
        }
        if values.is_empty() {
            drop(values);
            drop(charge);
            let mut owner = Self::empty(vm.capi_backing_allocator());
            owner.vm_id = Some(vm.id());
            return Ok(owner);
        }
        let mut owner = Self {
            values,
            roots: AllocVec::new_in(vm.capi_backing_allocator()),
            values_charge: Some(charge.into_owned_charge()),
            roots_charge: None,
            parked: false,
            vm_id: Some(vm.id()),
            shutdown_spare: None,
        };
        owner.roots_charge = Some(vm.reserve_owned_values_backing(
            &mut owner.roots, owner.values.len(), &owner.values, &[],
        )?);
        if let Err(error) = Self::append_roots(vm, &mut owner.roots, &owner.values) {
            Self::remove_staged_roots(vm, &mut owner.roots)?;
            return Err(error);
        }
        Ok(owner)
    }

    #[doc(hidden)]
    pub fn as_slice(&self) -> &[Value] {
        &self.values
    }

    pub(crate) fn values(&self) -> &[Value] {
        self.as_slice()
    }

    pub(crate) fn export_host(mut self, vm: &mut Vm) -> Result<Vec<Value>, VmError> {
        self.check_vm(vm)?;
        let mut values = Vec::new();
        if !self.is_empty() {
            let ticket = reserve_vec(vm.allocation_ledger(), &mut values, self.len(), FailPoint::ReturnReserve)?;
            values.extend_from_slice(self.as_slice());
            drop(ticket);
        }
        self.clear_roots(vm)?;
        Ok(values)
    }

    #[doc(hidden)]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    #[doc(hidden)]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub(crate) fn try_push(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if self.parked || self.shutdown_spare.is_some() {
            return Err(VmError::LedgerInvariant);
        }
        vm.check_owned_value(value)?;
        if self.values.len() < self.values.capacity() && self.roots.len() < self.roots.capacity() {
            let root = self.root_for_new_value(vm, value)?;
            self.values.push(value);
            self.roots.push(root);
            return Ok(());
        }
        let capacity = self.growth_capacity()?;
        let replacement = Self::try_build(
            vm, &self.values, None, &[value], capacity, Some((&self.roots, false)),
        )?;
        *self = replacement;
        Ok(())
    }

    pub(crate) fn try_prepend(&mut self, vm: &mut Vm, value: Value) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if self.parked || self.shutdown_spare.is_some() {
            return Err(VmError::LedgerInvariant);
        }
        vm.check_owned_value(value)?;
        if self.values.len() < self.values.capacity() && self.roots.len() < self.roots.capacity() {
            let root = self.root_for_new_value(vm, value)?;
            self.values.insert(0, value);
            self.roots.insert(0, root);
            return Ok(());
        }
        let capacity = self.growth_capacity()?;
        let replacement = Self::try_build(
            vm, &[value], None, &self.values, capacity, Some((&self.roots, true)),
        )?;
        *self = replacement;
        Ok(())
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.roots.truncate(len);
        self.values.truncate(len);
    }

    pub(crate) fn remove_first_scalar(&mut self) -> Result<Value, VmError> {
        if self.parked || self.roots.first().is_some_and(Option::is_some) {
            return Err(VmError::LedgerInvariant);
        }
        let value = *self.values.first().ok_or(VmError::LedgerInvariant)?;
        self.roots.remove(0);
        self.values.remove(0);
        Ok(value)
    }

    pub(crate) fn try_set(&mut self, vm: &mut Vm, index: usize, value: Value) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if self.parked || self.shutdown_spare.is_some() {
            return Err(VmError::LedgerInvariant);
        }
        vm.check_owned_value(value)?;
        let old = self.roots.get(index).ok_or(VmError::LedgerInvariant)?;
        let next = self.root_for_new_value(vm, value)?;
        if let Some(root) = old {
            if let Err(error) = vm.remove_root(root.id()) {
                if let Some(next) = next {
                    vm.remove_root(next.id())?;
                }
                return Err(error);
            }
        }
        self.roots[index] = next;
        self.values[index] = value;
        Ok(())
    }

    /// Parked debug hook 的回傳值由 core trace 保活；C 來源值在覆寫前仍有 stack root。
    pub(crate) fn capi_set_parked(
        &mut self,
        vm: &Vm,
        index: usize,
        value: Value,
        source: Option<&CapiShutdownRoot>,
    ) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if !self.parked || self.shutdown_spare.is_some()
            || self.values.get(index).is_none()
            || self.roots.get(index).is_none_or(Option::is_some)
        {
            return Err(VmError::LedgerInvariant);
        }
        vm.check_owned_value(value)?;
        if let Value::Object(object) = value {
            let source = source.ok_or(VmError::StaleRoot)?;
            if source.value(vm)? != Some(Value::Object(object)) {
                return Err(VmError::StaleRoot);
            }
        }
        self.values[index] = value;
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(rivetlua_core::ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for &value in &self.values {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        Ok(())
    }

    /// 只在上層已把 `trace_children` 接入 GC 後呼叫。
    pub(crate) fn park_roots(&mut self) {
        if !self.parked {
            if self.shutdown_spare.is_none() {
                for root in &mut self.roots {
                    *root = None;
                }
            }
            self.parked = true;
        }
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if self.shutdown_spare.is_some() {
            return self.shutdown_clear(vm);
        }
        for root in &mut self.roots {
            if let Some(root) = root.take() {
                vm.remove_root(root.id())?;
            }
        }
        self.parked = true;
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.check_vm(vm)?;
        if !self.parked {
            return Ok(());
        }
        if self.shutdown_spare.is_some() {
            self.parked = false;
            return Ok(());
        }
        let mut roots = AllocVec::new_in(vm.capi_backing_allocator());
        let charge = if self.values.is_empty() {
            None
        } else {
            Some(vm.reserve_owned_values_backing(
                &mut roots, self.values.len(), &self.values, &[],
            )?)
        };
        if let Err(error) = Self::append_roots(vm, &mut roots, &self.values) {
            let cleanup = Self::remove_staged_roots(vm, &mut roots);
            drop(roots);
            drop(charge);
            cleanup?;
            return Err(error);
        }
        let old_roots = core::mem::replace(&mut self.roots, roots);
        let old_charge = core::mem::replace(&mut self.roots_charge, charge);
        drop(old_roots);
        drop(old_charge);
        self.parked = false;
        Ok(())
    }

    fn try_build(
        vm: &mut Vm,
        first: &[Value],
        middle: Option<Value>,
        second: &[Value],
        capacity: usize,
        reused_roots: Option<(&[Option<StackRoot>], bool)>,
    ) -> Result<Self, VmError> {
        for &value in first.iter().chain(middle.iter()).chain(second) {
            vm.check_owned_value(value)?;
        }
        let len = first.len().checked_add(second.len())
            .and_then(|len| len.checked_add(usize::from(middle.is_some())))
            .ok_or(VmError::ArithmeticOverflow)?;
        if capacity < len {
            return Err(VmError::LedgerInvariant);
        }
        if let Some((roots, prepend)) = reused_roots {
            if middle.is_some() {
                return Err(VmError::LedgerInvariant);
            }
            let (old_values, new_values) = if prepend { (second, first) } else { (first, second) };
            if roots.len() != old_values.len() || new_values.len() != 1 {
                return Err(VmError::LedgerInvariant);
            }
        }
        let mut owner = Self::empty(vm.capi_backing_allocator());
        owner.vm_id = Some(vm.id());
        if len == 0 {
            return Ok(owner);
        }
        owner.values_charge = Some(vm.reserve_owned_values_backing(
            &mut owner.values, capacity, first, second,
        )?);
        owner.values.extend_from_slice(first);
        if let Some(middle) = middle {
            owner.values.push(middle);
        }
        owner.values.extend_from_slice(second);
        owner.roots_charge = Some(vm.reserve_owned_values_backing(
            &mut owner.roots, capacity, &owner.values, &[],
        )?);
        if let Some((old_roots, prepend)) = reused_roots {
            if prepend {
                Self::append_one_root(vm, &mut owner.roots, first[0], &owner.values)?;
                owner.roots.extend(old_roots.iter().cloned());
            } else {
                owner.roots.extend(old_roots.iter().cloned());
                Self::append_one_root(vm, &mut owner.roots, second[0], &owner.values)?;
            }
        } else if let Err(error) = Self::append_roots(vm, &mut owner.roots, &owner.values) {
            Self::remove_staged_roots(vm, &mut owner.roots)?;
            return Err(error);
        }
        Ok(owner)
    }

    fn append_roots(
        vm: &mut Vm,
        roots: &mut AllocVec<Option<StackRoot>, StateAllocator>,
        values: &[Value],
    ) -> Result<(), VmError> {
        for &value in values {
            Self::append_one_root(vm, roots, value, values)?;
        }
        Ok(())
    }

    fn append_one_root(
        vm: &mut Vm,
        roots: &mut AllocVec<Option<StackRoot>, StateAllocator>,
        value: Value,
        borrowed_roots: &[Value],
    ) -> Result<(), VmError> {
        roots.push(match value {
            Value::Object(object) => Some(vm.add_stack_root_with_borrowed_roots(object, borrowed_roots)?),
            _ => None,
        });
        Ok(())
    }

    fn remove_staged_roots(
        vm: &mut Vm,
        roots: &mut AllocVec<Option<StackRoot>, StateAllocator>,
    ) -> Result<(), VmError> {
        for root in roots {
            if let Some(root) = root.take() {
                vm.remove_root(root.id())?;
            }
        }
        Ok(())
    }

    fn root_for_new_value(&self, vm: &mut Vm, value: Value) -> Result<Option<StackRoot>, VmError> {
        match value {
            Value::Object(object) => {
                Ok(Some(vm.add_stack_root_with_borrowed_roots(object, &self.values)?))
            }
            _ => Ok(None),
        }
    }

    fn growth_capacity(&self) -> Result<usize, VmError> {
        let len = self.values.len().checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
        self.values.capacity().max(self.roots.capacity()).max(1)
            .checked_mul(2).map(|capacity| capacity.max(len))
            .ok_or(VmError::ArithmeticOverflow)
    }

    pub(crate) fn check_vm(&self, vm: &Vm) -> Result<(), VmError> {
        if self.vm_id.is_some_and(|id| id != vm.id()) {
            return Err(VmError::WrongVm);
        }
        Ok(())
    }
}

impl core::ops::Deref for OwnedValues {
    type Target = [Value];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}


