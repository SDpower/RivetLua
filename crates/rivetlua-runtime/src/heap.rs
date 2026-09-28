//! P06-1 最小非移動 heap 與 slot 生命週期。

use core::mem::size_of;

use rivetlua_core::{Generation, ObjectId, ObjectRef, SlotId, Value, VerifiedModule, VmId};

use crate::alloc::{
    AllocationLedger, FailPoint, LedgerSnapshot, Reservation, checked_bytes, reserve_vec,
};
use crate::closure::Closure;
use crate::coroutine::{Coroutine, CoroutineState, ThreadContext};
use crate::errors::Builtin;
use crate::roots::{RootId, RootKind, RootLease, RootSet};
use crate::string::ByteString;
use crate::table::Table;
use crate::upvalue::{Upvalue, UpvalueState};

/// 公開的 slot 狀態，不暴露 heap 配置或可變借用。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotState {
    Occupied,
    Free,
    Retired,
}

/// Heap 物件 payload 的分類；不改變 `Value::Object` 身分。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    Value,
    ByteString,
    Table,
    Closure,
    Builtin,
    Coroutine,
    Upvalue,
    Module,
}

/// VM 邊界的可檢查結果。P06 後續步驟補上配置計帳。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmError {
    VmIdExhausted,
    AllocationFailed,
    IdentityExhausted,
    RootIdExhausted,
    WrongVm,
    StaleObject,
    StaleRoot,
    WrongObjectType,
    NilTableKey,
    NaNTableKey,
    ArithmeticOverflow,
    LedgerInvariant,
    InjectedFailure(FailPoint),
}

impl VmError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::VmIdExhausted => "E_VM_ID_EXHAUSTED",
            Self::AllocationFailed => "E_ALLOCATION_FAILED",
            Self::IdentityExhausted => "E_IDENTITY_EXHAUSTED",
            Self::RootIdExhausted => "E_ROOT_ID_EXHAUSTED",
            Self::WrongVm => "E_WRONG_VM",
            Self::StaleObject => "E_STALE_HANDLE",
            Self::StaleRoot => "E_STALE_ROOT",
            Self::WrongObjectType => "E_WRONG_OBJECT_TYPE",
            Self::NilTableKey => "E_TABLE_KEY_NIL",
            Self::NaNTableKey => "E_TABLE_KEY_NAN",
            Self::ArithmeticOverflow => "E_ALLOCATION_FAILED",
            Self::LedgerInvariant => "E_ALLOCATION_FAILED",
            Self::InjectedFailure(_) => "E_ALLOCATION_FAILED",
        }
    }
}

struct HeapObject {
    payload: HeapPayload,
    children: Vec<ObjectRef>,
}

enum HeapPayload {
    Value(Value),
    ByteString(ByteString),
    Table(Table),
    Closure(Closure),
    Builtin(Builtin),
    Coroutine(Coroutine),
    Upvalue(Upvalue),
    Module(VerifiedModule),
}

impl HeapObject {
    fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        match &self.payload {
            HeapPayload::Value(Value::Object(child)) => visit(*child)?,
            HeapPayload::Table(table) => table.trace_children(&mut visit)?,
            HeapPayload::Closure(closure) => closure.trace_children(&mut visit)?,
            HeapPayload::Builtin(Builtin::CoroutineWrapped(coroutine)) => visit(*coroutine)?,
            HeapPayload::Coroutine(coroutine) => coroutine.trace_children(&mut visit)?,
            HeapPayload::Upvalue(upvalue) => match upvalue.state() {
                UpvalueState::Closed(Value::Object(child)) => visit(child)?,
                UpvalueState::Open {
                    coroutine: Some(child),
                    ..
                } => visit(child)?,
                _ => {}
            },
            _ => {}
        }
        for &child in &self.children {
            visit(child)?;
        }
        Ok(())
    }
}

enum Slot {
    Occupied {
        generation: Generation,
        reference: ObjectRef,
        // 唯一元素不再增減；Vec 只搬移指標，中間的物件配置維持原址。
        object: Vec<HeapObject>,
    },
    Free {
        generation: Generation,
    },
    Retired,
}

impl Slot {
    fn state(&self) -> SlotState {
        match self {
            Self::Occupied { .. } => SlotState::Occupied,
            Self::Free { .. } => SlotState::Free,
            Self::Retired => SlotState::Retired,
        }
    }
}

/// P06 最小 VM。所有公開存取均用完整 ObjectId 重新驗證。
pub struct Vm {
    id: VmId,
    slots: Vec<Slot>,
    roots: RootSet,
    ledger: AllocationLedger,
    collect_every_allocation: bool,
}

impl Vm {
    pub fn new() -> Result<Self, VmError> {
        let id = VmId::new_unique().ok_or(VmError::VmIdExhausted)?;
        Ok(Self {
            id,
            slots: Vec::new(),
            roots: RootSet::new(id),
            ledger: AllocationLedger::new(usize::MAX),
            collect_every_allocation: false,
        })
    }

    pub const fn id(&self) -> VmId {
        self.id
    }

    pub fn slot_state(&self, slot: SlotId) -> Option<SlotState> {
        self.slots.get(slot.index()).map(Slot::state)
    }

    pub const fn roots(&self) -> &RootSet {
        &self.roots
    }

    pub fn ledger_snapshot(&self) -> LedgerSnapshot {
        self.ledger.snapshot()
    }

    pub(crate) const fn allocation_ledger(&self) -> &AllocationLedger {
        &self.ledger
    }

    pub fn set_allocation_limit(&mut self, limit: usize) {
        self.ledger.set_limit(limit);
    }

    pub fn inject_failure_once(&mut self, point: FailPoint) {
        self.ledger.fail_once_at(point);
    }

    /// 測試模式：每次成功配置後執行一次完整收集。
    pub fn set_collect_every_allocation(&mut self, enabled: bool) {
        self.collect_every_allocation = enabled;
    }

    pub fn add_root(&mut self, kind: RootKind, object: ObjectRef) -> Result<RootId, VmError> {
        self.checked_slot(object)?;
        self.roots.add(&self.ledger, kind, object)
    }

    pub fn remove_root(&mut self, root: RootId) -> Result<ObjectRef, VmError> {
        self.roots.remove(&self.ledger, root)
    }

    pub(crate) fn add_host_root(
        &mut self,
        object: ObjectRef,
    ) -> Result<(RootId, RootLease), VmError> {
        self.checked_slot(object)?;
        self.roots.add_host(&self.ledger, object)
    }

    pub fn allocate(&mut self, value: Value) -> Result<ObjectRef, VmError> {
        if let Value::Object(child) = value {
            self.checked_slot(child)?;
        }
        self.allocate_payload(HeapPayload::Value(value))
    }

    /// 建立完整內容的 byte string；失敗時 payload 與帳本票據均丟棄。
    pub fn allocate_byte_string(&mut self, bytes: &[u8]) -> Result<ObjectRef, VmError> {
        let (string, ticket) = ByteString::try_from_bytes(&self.ledger, bytes)?;
        let reference = self.allocate_payload(HeapPayload::ByteString(string))?;
        ticket.commit()?;
        Ok(reference)
    }

    /// 複製期間保護來源；建立新 payload 時也沿用配置器的短期 root。
    pub fn clone_byte_string(&mut self, source: ObjectRef) -> Result<ObjectRef, VmError> {
        let root = self.add_root(RootKind::Temporary, source)?;
        let result = (|| {
            let (string, ticket) = self.with_byte_string(source, |string| {
                ByteString::try_from_bytes(&self.ledger, string.as_bytes())
            })??;
            let reference = self.allocate_payload(HeapPayload::ByteString(string))?;
            ticket.commit()?;
            Ok(reference)
        })();
        let removed = self.remove_root(root);
        removed?;
        result
    }

    pub fn allocate_table(&mut self) -> Result<ObjectRef, VmError> {
        self.allocate_table_with_capacity(0, 0)
    }

    /// 將本階段唯一三個內建入口安裝至宿主提供的環境。
    pub fn install_error_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let result = (|| {
            for (name, builtin) in [
                (b"error".as_slice(), Builtin::Error),
                (b"pcall".as_slice(), Builtin::PCall),
                (b"xpcall".as_slice(), Builtin::XPCall),
            ] {
                self.install_one_builtin(environment, name, builtin)?;
            }
            Ok(())
        })();
        self.remove_root(env_root)?;
        result
    }

    /// 安裝本階段必要的 coroutine 入口。
    pub fn install_coroutine_builtins(&mut self, environment: ObjectRef) -> Result<(), VmError> {
        if self.object_kind(environment)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        let env_root = self.add_root(RootKind::Temporary, environment)?;
        let result = (|| {
            let table = self.allocate_table()?;
            let table_root = self.add_root(RootKind::Temporary, table)?;
            let installed = (|| {
                for (name, builtin) in [
                    (b"create".as_slice(), Builtin::CoroutineCreate),
                    (b"resume".as_slice(), Builtin::CoroutineResume),
                    (b"yield".as_slice(), Builtin::CoroutineYield),
                    (b"status".as_slice(), Builtin::CoroutineStatus),
                    (b"close".as_slice(), Builtin::CoroutineClose),
                    (b"wrap".as_slice(), Builtin::CoroutineWrap),
                ] {
                    self.install_one_builtin(table, name, builtin)?;
                }
                let key = self.allocate_byte_string(b"coroutine")?;
                let key_root = self.add_root(RootKind::Temporary, key)?;
                let result = self.raw_set(environment, Value::Object(key), Value::Object(table));
                self.remove_root(key_root)?;
                result
            })();
            self.remove_root(table_root)?;
            installed
        })();
        self.remove_root(env_root)?;
        result
    }

    fn install_one_builtin(
        &mut self,
        environment: ObjectRef,
        name: &[u8],
        builtin: Builtin,
    ) -> Result<(), VmError> {
        let key = self.allocate_byte_string(name)?;
        let key_root = match self.add_root(RootKind::Temporary, key) {
            Ok(root) => root,
            Err(error) => {
                self.reclaim(key)?;
                return Err(error);
            }
        };
        let result = (|| {
            let value = self.allocate_payload(HeapPayload::Builtin(builtin))?;
            let value_root = match self.add_root(RootKind::Temporary, value) {
                Ok(root) => root,
                Err(error) => {
                    self.reclaim(value)?;
                    return Err(error);
                }
            };
            let inserted = self.raw_set(environment, Value::Object(key), Value::Object(value));
            self.remove_root(value_root)?;
            if inserted.is_err() {
                self.reclaim(value)?;
            }
            inserted
        })();
        self.remove_root(key_root)?;
        if result.is_err() {
            self.reclaim(key)?;
        }
        result
    }

    pub(crate) fn builtin(&self, object: ObjectRef) -> Result<Builtin, VmError> {
        let Slot::Occupied { object: entry, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        match &entry[0].payload {
            HeapPayload::Builtin(builtin) => Ok(*builtin),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn allocate_coroutine(&mut self, entry: Value) -> Result<ObjectRef, VmError> {
        if let Value::Object(object) = entry {
            self.checked_slot(object)?;
        }
        self.allocate_payload(HeapPayload::Coroutine(Coroutine::new(entry)))
    }

    pub(crate) fn allocate_coroutine_wrapper(
        &mut self,
        coroutine: ObjectRef,
    ) -> Result<ObjectRef, VmError> {
        self.with_coroutine(coroutine, |_| ())?;
        self.allocate_payload(HeapPayload::Builtin(Builtin::CoroutineWrapped(coroutine)))
    }

    pub(crate) fn with_coroutine<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Coroutine) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object: entry, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        match &entry[0].payload {
            HeapPayload::Coroutine(co) => Ok(f(co)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn with_coroutine_mut<R>(
        &mut self,
        object: ObjectRef,
        f: impl FnOnce(&mut Coroutine) -> R,
    ) -> Result<R, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(object)?;
        let Slot::Occupied { object: entry, .. } = &mut self.slots[id.slot.index()] else {
            return Err(VmError::StaleObject);
        };
        match &mut entry[0].payload {
            HeapPayload::Coroutine(co) => Ok(f(co)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn coroutine_state(&self, object: ObjectRef) -> Result<CoroutineState, VmError> {
        self.with_coroutine(object, |co| co.state)
    }

    pub(crate) fn take_coroutine_context(
        &mut self,
        object: ObjectRef,
    ) -> Result<Option<ThreadContext>, VmError> {
        self.with_coroutine_mut(object, |co| co.context.take())
    }

    pub(crate) fn coroutine_stack_read(
        &self,
        object: ObjectRef,
        slot: usize,
    ) -> Result<Option<Value>, VmError> {
        self.with_coroutine(object, |co| {
            co.context
                .as_ref()
                .and_then(|context| context.read_slot(slot))
        })
    }

    pub(crate) fn coroutine_stack_write(
        &mut self,
        object: ObjectRef,
        slot: usize,
        value: Value,
    ) -> Result<bool, VmError> {
        if let Value::Object(child) = value {
            self.checked_slot(child)?;
        }
        self.with_coroutine_mut(object, |co| {
            co.context
                .as_mut()
                .is_some_and(|context| context.write_parked_slot(slot, value))
        })
    }

    pub(crate) fn allocate_closure(&mut self, closure: Closure) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Closure(closure))
    }

    pub(crate) fn allocate_upvalue(&mut self, upvalue: Upvalue) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Upvalue(upvalue))
    }

    pub(crate) fn allocate_module(&mut self, module: VerifiedModule) -> Result<ObjectRef, VmError> {
        self.allocate_payload(HeapPayload::Module(module))
    }

    /// 預留空 array 與 hash bucket；兩者成功且 heap 物件建成後才提交帳額。
    pub fn allocate_table_with_capacity(
        &mut self,
        array_capacity: usize,
        hash_capacity: usize,
    ) -> Result<ObjectRef, VmError> {
        let (table, array_ticket, hash_ticket) =
            Table::try_new(&self.ledger, array_capacity, hash_capacity)?;
        let reference = self.allocate_payload(HeapPayload::Table(table))?;
        array_ticket.commit()?;
        hash_ticket.commit()?;
        Ok(reference)
    }

    fn allocate_payload(&mut self, payload: HeapPayload) -> Result<ObjectRef, VmError> {
        let free = self
            .slots
            .iter()
            .position(|slot| matches!(slot, Slot::Free { .. }));
        let slot_ticket = if free.is_none() {
            Some(reserve_vec(
                &self.ledger,
                &mut self.slots,
                1,
                FailPoint::SlotReserve,
            )?)
        } else {
            None
        };

        let mut object = Vec::new();
        let object_ticket = reserve_vec(&self.ledger, &mut object, 1, FailPoint::ObjectReserve)?;
        self.ledger.checkpoint(FailPoint::ObjectInitialize)?;
        object.push(HeapObject {
            payload,
            children: Vec::new(),
        });

        let (slot, generation) = match free {
            Some(index) => {
                let Slot::Free { generation } = self.slots[index] else {
                    unreachable!("找到的空 slot 必須仍為空")
                };
                (SlotId::new(index), generation)
            }
            None => {
                let index = self.slots.len();
                let generation = Generation::new(0);
                (SlotId::new(index), generation)
            }
        };
        let reference = ObjectRef::new_runtime(ObjectId::new(self.id, slot, generation))
            .ok_or(VmError::IdentityExhausted)?;
        let occupied = Slot::Occupied {
            generation,
            reference,
            object,
        };
        match free {
            Some(index) => self.slots[index] = occupied,
            None => self.slots.push(occupied),
        }
        if self.collect_every_allocation {
            let temporary = match self.roots.add(&self.ledger, RootKind::Temporary, reference) {
                Ok(root) => root,
                Err(error) => {
                    self.rollback_new_object(slot.index(), free, generation);
                    return Err(error);
                }
            };
            let collection = self.collect();
            let removal = self.roots.remove(&self.ledger, temporary);
            if let Err(error) = removal {
                self.rollback_new_object(slot.index(), free, generation);
                return Err(error);
            }
            if let Err(error) = collection {
                self.rollback_new_object(slot.index(), free, generation);
                return Err(error);
            }
        }
        object_ticket.commit()?;
        if let Some(ticket) = slot_ticket {
            ticket.commit()?;
        }
        Ok(reference)
    }

    fn rollback_new_object(&mut self, index: usize, free: Option<usize>, generation: Generation) {
        if free.is_some() {
            self.slots[index] = Slot::Free { generation };
        } else {
            self.slots.pop();
        }
    }

    /// 增加受驗證的物件欄位邊；失敗不修改原有邊。
    pub fn add_child(&mut self, parent: ObjectRef, child: ObjectRef) -> Result<(), VmError> {
        self.checked_slot(parent)?;
        self.checked_slot(child)?;
        let id = parent.identity().ok_or(VmError::StaleObject)?;
        let index = id.slot.index();
        let mut children = {
            let Slot::Occupied { object, .. } = &mut self.slots[index] else {
                return Err(VmError::StaleObject);
            };
            std::mem::take(&mut object[0].children)
        };

        // 唯有受控帳本與 Vec 預留位於欄位暫離期間；不呼叫 GC 或宿主回呼。
        let reservation = self.reserve_child_growth(&mut children);
        {
            let Slot::Occupied { object, .. } = &mut self.slots[index] else {
                unreachable!("預留期間 VM 未重入，parent slot 必須仍為 occupied")
            };
            object[0].children = children;
        }
        let ticket = reservation?;
        ticket.commit()?;
        // 已有容量且無可失敗邊界；以短借用完成唯一圖變更。
        let Slot::Occupied { object, .. } = &mut self.slots[index] else {
            unreachable!("提交後 parent slot 必須仍為 occupied")
        };
        object[0].children.push(child);
        Ok(())
    }

    /// `&self` 使呼叫端無法在借用 heap 內部 children 時跨越配置邊界。
    fn reserve_child_growth(&self, children: &mut Vec<ObjectRef>) -> Result<Reservation, VmError> {
        reserve_vec(&self.ledger, children, 1, FailPoint::ChildReserve)
    }

    fn enqueue(
        &self,
        object: ObjectRef,
        marks: &mut [bool],
        work: &mut Vec<ObjectRef>,
    ) -> Result<(), VmError> {
        self.checked_slot(object)?;
        let slot = object.identity().ok_or(VmError::StaleObject)?.slot.index();
        if !marks[slot] {
            marks[slot] = true;
            // work 已預留所有 slot 的容量，每個 slot 最多入列一次。
            work.push(object);
        }
        Ok(())
    }

    /// 從六類 root 及物件欄位標記，並實際釋放所有不可達物件。
    pub fn collect(&mut self) -> Result<usize, VmError> {
        let mut marks = Vec::new();
        let _marks_ticket = reserve_vec(
            &self.ledger,
            &mut marks,
            self.slots.len(),
            FailPoint::MarkReserve,
        )?;
        marks.resize(self.slots.len(), false);
        let mut work = Vec::new();
        let _work_ticket = reserve_vec(
            &self.ledger,
            &mut work,
            self.slots.len(),
            FailPoint::WorkReserve,
        )?;

        self.roots
            .try_visit_all(|object| self.enqueue(object, &mut marks, &mut work))?;
        while let Some(reference) = work.pop() {
            let Slot::Occupied { object, .. } = self.checked_slot(reference)? else {
                return Err(VmError::StaleObject);
            };
            object[0].trace_children(|child| self.enqueue(child, &mut marks, &mut work))?;
        }

        let mut reclaimed = 0;
        for index in 0..self.slots.len() {
            if marks[index] {
                continue;
            }
            let Slot::Occupied { reference, .. } = &self.slots[index] else {
                continue;
            };
            self.reclaim(*reference)?;
            reclaimed += 1;
        }
        self.roots.compact();
        Ok(reclaimed)
    }

    fn checked_slot(&self, object: ObjectRef) -> Result<&Slot, VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        if id.vm != self.id {
            return Err(VmError::WrongVm);
        }
        let slot = self
            .slots
            .get(id.slot.index())
            .ok_or(VmError::StaleObject)?;
        match slot {
            Slot::Occupied {
                generation,
                reference,
                ..
            } if *generation == id.generation && *reference == object => Ok(slot),
            _ => Err(VmError::StaleObject),
        }
    }

    pub fn read(&self, object: ObjectRef) -> Result<Value, VmError> {
        self.with_value(object, |value| *value)
    }

    pub fn object_kind(&self, object: ObjectRef) -> Result<ObjectKind, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        Ok(match object[0].payload {
            HeapPayload::Value(_) => ObjectKind::Value,
            HeapPayload::ByteString(_) => ObjectKind::ByteString,
            HeapPayload::Table(_) => ObjectKind::Table,
            HeapPayload::Closure(_) => ObjectKind::Closure,
            HeapPayload::Builtin(_) => ObjectKind::Builtin,
            HeapPayload::Coroutine(_) => ObjectKind::Coroutine,
            HeapPayload::Upvalue(_) => ObjectKind::Upvalue,
            HeapPayload::Module(_) => ObjectKind::Module,
        })
    }

    /// 借用僅限此回呼；呼叫者不能持有 heap 的可變借用。
    ///
    /// ```
    /// use rivetlua_core::Value;
    /// use rivetlua_runtime::Vm;
    /// let mut vm = Vm::new().unwrap();
    /// let object = vm.allocate(Value::Integer(1)).unwrap();
    /// assert_eq!(vm.with_value(object, |value| *value), Ok(Value::Integer(1)));
    /// vm.allocate(Value::Integer(2)).unwrap();
    /// ```
    ///
    /// ```compile_fail
    /// use rivetlua_core::Value;
    /// use rivetlua_runtime::Vm;
    /// let mut vm = Vm::new().unwrap();
    /// let object = vm.allocate(Value::Integer(1)).unwrap();
    /// vm.with_value(object, |_| {
    ///     vm.allocate(Value::Integer(2)).unwrap();
    /// }).unwrap();
    /// ```
    pub fn with_value<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Value) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Value(value) => Ok(f(value)),
            HeapPayload::ByteString(_)
            | HeapPayload::Table(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_) => Err(VmError::WrongObjectType),
        }
    }

    /// 借用 byte string 僅限回呼期間；回呼不能跨越 VM 可變配置。
    pub fn with_byte_string<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&ByteString) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::ByteString(string) => Ok(f(string)),
            HeapPayload::Value(_)
            | HeapPayload::Table(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_) => Err(VmError::WrongObjectType),
        }
    }

    pub fn with_table<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Table) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Table(table) => Ok(f(table)),
            HeapPayload::Value(_)
            | HeapPayload::ByteString(_)
            | HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_) => Err(VmError::WrongObjectType),
        }
    }

    pub fn with_closure<R>(
        &self,
        object: ObjectRef,
        f: impl FnOnce(&Closure) -> R,
    ) -> Result<R, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(object)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Closure(closure) => Ok(f(closure)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn module(&self, reference: ObjectRef) -> Result<&VerifiedModule, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(reference)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Module(module) => Ok(module),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn upvalue_state(&self, reference: ObjectRef) -> Result<UpvalueState, VmError> {
        let Slot::Occupied { object, .. } = self.checked_slot(reference)? else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &object[0].payload {
            HeapPayload::Upvalue(upvalue) => Ok(upvalue.state()),
            _ => Err(VmError::WrongObjectType),
        }
    }

    pub(crate) fn with_upvalue_mut<R>(
        &mut self,
        reference: ObjectRef,
        f: impl FnOnce(&mut Upvalue) -> R,
    ) -> Result<R, VmError> {
        let id = reference.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(reference)?;
        let Slot::Occupied { object, .. } = &mut self.slots[id.slot.index()] else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &mut object[0].payload {
            HeapPayload::Upvalue(upvalue) => Ok(f(upvalue)),
            _ => Err(VmError::WrongObjectType),
        }
    }

    /// table 內部短借用；回呼只使用帳本，不能重入 VM 或觸發 GC。
    pub(crate) fn with_table_mut<R>(
        &mut self,
        reference: ObjectRef,
        f: impl FnOnce(&mut Table, &AllocationLedger) -> Result<R, VmError>,
    ) -> Result<R, VmError> {
        let id = reference.identity().ok_or(VmError::StaleObject)?;
        self.checked_slot(reference)?;
        let ledger = self.ledger.clone();
        let Slot::Occupied { object, .. } = &mut self.slots[id.slot.index()] else {
            unreachable!("checked_slot 只回傳 occupied")
        };
        match &mut object[0].payload {
            HeapPayload::Table(table) => f(table, &ledger),
            _ => Err(VmError::WrongObjectType),
        }
    }

    /// P06-2 收集器將接管回收時機；本步只在 crate 內提供 slot 轉移。
    pub(crate) fn reclaim(&mut self, object: ObjectRef) -> Result<(), VmError> {
        let id = object.identity().ok_or(VmError::StaleObject)?;
        let Slot::Occupied { object: stored, .. } = self.checked_slot(object)? else {
            return Err(VmError::StaleObject);
        };
        let object_bytes = size_of::<HeapObject>();
        let child_bytes = checked_bytes(stored[0].children.len(), size_of::<ObjectRef>())?;
        let payload_bytes = match &stored[0].payload {
            HeapPayload::ByteString(string) => string.len(),
            HeapPayload::Value(_) => 0,
            HeapPayload::Table(table) => table.charge_bytes()?,
            HeapPayload::Closure(_)
            | HeapPayload::Builtin(_)
            | HeapPayload::Coroutine(_)
            | HeapPayload::Upvalue(_)
            | HeapPayload::Module(_) => 0,
        };
        let refund = object_bytes
            .checked_add(child_bytes)
            .and_then(|total| total.checked_add(payload_bytes))
            .ok_or(VmError::ArithmeticOverflow)?;
        self.ledger.refund(refund)?;
        let slot = &mut self.slots[id.slot.index()];
        *slot = match id.generation.next() {
            Some(next) => Slot::Free { generation: next },
            None => Slot::Retired,
        };
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_generation_for_test(
        &mut self,
        object: ObjectRef,
        generation: Generation,
    ) -> ObjectRef {
        let id = object.identity().unwrap();
        assert_eq!(id.vm, self.id);
        let Slot::Occupied {
            generation: current,
            reference,
            ..
        } = &mut self.slots[id.slot.index()]
        else {
            panic!("測試需要 occupied slot")
        };
        assert_eq!(*current, id.generation);
        *current = generation;
        *reference = ObjectRef::new_runtime(ObjectId::new(self.id, id.slot, generation)).unwrap();
        *reference
    }
}
