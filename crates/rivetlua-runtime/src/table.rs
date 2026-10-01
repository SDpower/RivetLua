//! P08 的 table 儲存與可儲存鍵分類。

use core::hash::{Hash, Hasher};
use core::mem::size_of;
use std::collections::hash_map::DefaultHasher;

use rivetlua_core::{ObjectId, ObjectRef, Value};

use crate::alloc::{AllocationLedger, FailPoint, Reservation, checked_bytes, reserve_vec};
use crate::gc::WeakMode;
use crate::gc::trace::RefField;
use crate::{ByteString, ObjectKind, RootId, RootKind, Vm, VmError};

/// 保留 array 欄位與 hash bucket；以 raw 語意讀寫。
pub struct Table {
    metatable: Option<ObjectRef>,
    weak_mode: WeakMode,
    array: Vec<Option<Value>>,
    hash: Vec<Option<(CanonicalKey, Value)>>,
}

impl Table {
    pub(crate) fn try_new(
        ledger: &AllocationLedger,
        array_capacity: usize,
        hash_capacity: usize,
    ) -> Result<(Self, Reservation, Reservation), VmError> {
        let mut array = Vec::new();
        let array_ticket = reserve_vec(
            ledger,
            &mut array,
            array_capacity,
            FailPoint::TableArrayReserve,
        )?;
        array.resize_with(array_capacity, || None);
        let mut hash = Vec::new();
        let hash_ticket = reserve_vec(
            ledger,
            &mut hash,
            hash_capacity,
            FailPoint::TableHashReserve,
        )?;
        hash.resize_with(hash_capacity, || None);
        Ok((
            Self {
                metatable: None,
                weak_mode: WeakMode::Strong,
                array,
                hash,
            },
            array_ticket,
            hash_ticket,
        ))
    }

    pub(crate) const fn metatable(&self) -> Option<ObjectRef> {
        self.metatable
    }

    pub(crate) fn set_metatable(&mut self, metatable: Option<ObjectRef>) {
        self.metatable = metatable;
    }

    pub(crate) const fn weak_mode(&self) -> WeakMode {
        self.weak_mode
    }

    pub(crate) fn set_weak_mode(&mut self, mode: WeakMode) {
        self.weak_mode = mode;
    }

    pub(crate) fn mode_value(&self) -> Value {
        self.hash.iter().flatten().find_map(|(key, value)| {
            if matches!(&key.kind, KeyKind::ByteString(string) if string.bytes.as_bytes() == b"__mode") {
                Some(*value)
            } else {
                None
            }
        }).unwrap_or(Value::Nil)
    }

    pub(crate) fn finalizer_value(&self) -> Value {
        self.hash.iter().flatten().find_map(|(key, value)| {
            if matches!(&key.kind, KeyKind::ByteString(string) if string.bytes.as_bytes() == b"__gc") {
                Some(*value)
            } else {
                None
            }
        }).unwrap_or(Value::Nil)
    }

    pub fn is_empty(&self) -> bool {
        self.array.iter().all(Option::is_none) && self.hash.iter().all(Option::is_none)
    }

    pub fn array_capacity(&self) -> usize {
        self.array.len()
    }

    pub fn hash_capacity(&self) -> usize {
        self.hash.len()
    }

    pub(crate) fn charge_bytes(&self) -> Result<usize, VmError> {
        let array_bytes = checked_bytes(self.array.len(), size_of::<Option<Value>>())?;
        let hash_bytes =
            checked_bytes(self.hash.len(), size_of::<Option<(CanonicalKey, Value)>>())?;
        array_bytes
            .checked_add(hash_bytes)
            .ok_or(VmError::ArithmeticOverflow)
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Some(metatable) = self.metatable {
            visit(metatable)?;
        }
        for value in self.array.iter().flatten() {
            if let Value::Object(object) = value {
                visit(*object)?;
            }
        }
        for (key, value) in self.hash.iter().flatten() {
            if let Some(object) = key.source_object() {
                visit(object)?;
            }
            if let Value::Object(object) = value {
                visit(*object)?;
            }
        }
        Ok(())
    }

    pub(crate) fn trace_gc_children(
        &self,
        mut is_string: impl FnMut(ObjectRef) -> Result<bool, VmError>,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if self.weak_mode == WeakMode::Strong {
            return self.trace_children(visit);
        }
        if let Some(metatable) = self.metatable {
            visit(metatable)?;
        }
        for value in self.array.iter().flatten() {
            if let Value::Object(object) = value {
                if self.weak_mode == WeakMode::Keys || is_string(*object)? {
                    visit(*object)?;
                }
            }
        }
        for (key, value) in self.hash.iter().flatten() {
            if let Some(object) = key.source_object() {
                if self.weak_mode == WeakMode::Values
                    || key.class() == CanonicalKeyClass::ByteString
                {
                    visit(object)?;
                }
            }
            if let Value::Object(object) = value {
                let live_key_without_scan = matches!(
                    key.class(),
                    CanonicalKeyClass::Integer
                        | CanonicalKeyClass::Float
                        | CanonicalKeyClass::Boolean
                        | CanonicalKeyClass::ByteString
                );
                let strong_value = match self.weak_mode {
                    WeakMode::Keys => live_key_without_scan,
                    WeakMode::Values | WeakMode::All => is_string(*object)?,
                    WeakMode::Strong => true,
                };
                if strong_value {
                    visit(*object)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn visit_ephemeron_pairs(
        &self,
        mut visit: impl FnMut(Option<ObjectRef>, ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if self.weak_mode != WeakMode::Keys {
            return Ok(());
        }
        for (key, value) in self.hash.iter().flatten() {
            if let Value::Object(value) = value {
                let key = match &key.kind {
                    KeyKind::Object(key) => Some(key.source),
                    _ => None,
                };
                visit(key, *value)?;
            }
        }
        Ok(())
    }

    pub(crate) fn clear_dead_weak_pairs(
        &mut self,
        mut is_dead: impl FnMut(ObjectRef) -> Result<bool, VmError>,
        clear_values: bool,
        clear_keys: bool,
    ) -> Result<usize, VmError> {
        if self.weak_mode == WeakMode::Strong {
            return Ok(0);
        }
        let mut cleared = 0;
        if clear_values && matches!(self.weak_mode, WeakMode::Values | WeakMode::All) {
            for entry in &mut self.array {
                if let Some(Value::Object(object)) = entry {
                    if is_dead(*object)? {
                        *entry = None;
                        cleared += 1;
                    }
                }
            }
        }
        for entry in &mut self.hash {
            let Some((key, value)) = entry else {
                continue;
            };
            let dead_key = if clear_keys && matches!(self.weak_mode, WeakMode::Keys | WeakMode::All)
            {
                match &key.kind {
                    KeyKind::Object(key) => is_dead(key.source)?,
                    _ => false,
                }
            } else {
                false
            };
            let dead_value =
                if clear_values && matches!(self.weak_mode, WeakMode::Values | WeakMode::All) {
                    match value {
                        Value::Object(object) => is_dead(*object)?,
                        _ => false,
                    }
                } else {
                    false
                };
            if dead_key || dead_value {
                *entry = None;
                cleared += 1;
            }
        }
        Ok(cleared)
    }

    fn bucket(key: &CanonicalKey, count: usize) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) % count
    }

    fn probe(start: usize, step: usize, count: usize) -> usize {
        if step < count - start {
            start + step
        } else {
            step - (count - start)
        }
    }

    fn find_hash(&self, key: &CanonicalKey) -> Option<usize> {
        let count = self.hash.len();
        if count == 0 {
            return None;
        }
        let start = Self::bucket(key, count);
        (0..count)
            .map(|step| Self::probe(start, step, count))
            .find(|&index| {
                self.hash[index]
                    .as_ref()
                    .is_some_and(|(stored, _)| stored == key)
            })
    }

    fn insert_bucket(
        buckets: &mut [Option<(CanonicalKey, Value)>],
        entry: (CanonicalKey, Value),
    ) -> Result<(), VmError> {
        let count = buckets.len();
        if count == 0 {
            return Err(VmError::LedgerInvariant);
        }
        let start = Self::bucket(&entry.0, count);
        for step in 0..count {
            let index = Self::probe(start, step, count);
            if buckets[index].is_none() {
                buckets[index] = Some(entry);
                return Ok(());
            }
        }
        Err(VmError::LedgerInvariant)
    }

    fn get(&self, key: &CanonicalKey) -> Value {
        if let Some(index) = key.array_index() {
            if let Some(Some(value)) = self.array.get(index) {
                return *value;
            }
        }
        self.find_hash(key)
            .and_then(|index| self.hash[index].as_ref().map(|(_, value)| *value))
            .unwrap_or(Value::Nil)
    }

    /// 回傳一個 Lua 合法邊界；從 1 起尋找第一個缺席的整數欄位。
    pub(crate) fn border_len(&self) -> i64 {
        let mut border = 0_i64;
        while let Some(next) = border.checked_add(1) {
            let key = CanonicalKey {
                kind: KeyKind::Integer(next),
            };
            if self.get(&key) == Value::Nil {
                break;
            }
            border = next;
        }
        border
    }

    /// 供內部驗證的 raw 欄位遍歷；輸出次序不屬於契約。
    #[allow(dead_code)]
    pub(crate) fn for_each_raw(
        &self,
        mut visit: impl FnMut(Value, Value) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for (index, value) in self.array.iter().enumerate() {
            if let Some(value) = value {
                let key = i64::try_from(index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .ok_or(VmError::ArithmeticOverflow)?;
                visit(Value::Integer(key), *value)?;
            }
        }
        for (key, value) in self.hash.iter().flatten() {
            visit(key.as_value(), *value)?;
        }
        Ok(())
    }

    fn grow_array_and_insert(
        &mut self,
        ledger: &AllocationLedger,
        index: usize,
        value: Value,
    ) -> Result<(), VmError> {
        let old_capacity = self.array.len();
        let new_capacity = old_capacity
            .checked_mul(2)
            .map(|doubled| doubled.max(4))
            .ok_or(VmError::ArithmeticOverflow)?;
        let new_bytes = checked_bytes(new_capacity, size_of::<Option<Value>>())?;
        let old_bytes = checked_bytes(old_capacity, size_of::<Option<Value>>())?;
        let mut next = Vec::new();
        let ticket = reserve_vec(ledger, &mut next, new_capacity, FailPoint::TableArrayGrow)?;
        next.resize_with(new_capacity, || None);
        next[..old_capacity].copy_from_slice(&self.array);
        ledger.checkpoint(FailPoint::TableInsert)?;
        ticket.commit()?;
        if let Err(error) = ledger.refund_lua(old_bytes) {
            ledger.refund_lua_on_drop(new_bytes);
            return Err(error);
        }
        next[index] = Some(value);
        self.array = next;
        Ok(())
    }

    fn grow_hash_and_insert(
        &mut self,
        ledger: &AllocationLedger,
        key: CanonicalKey,
        value: Value,
    ) -> Result<(), VmError> {
        let old_capacity = self.hash.len();
        let new_capacity = old_capacity
            .checked_mul(2)
            .map(|doubled| doubled.max(4))
            .ok_or(VmError::ArithmeticOverflow)?;
        let bucket_size = size_of::<Option<(CanonicalKey, Value)>>();
        let new_bytes = checked_bytes(new_capacity, bucket_size)?;
        let old_bytes = checked_bytes(old_capacity, bucket_size)?;
        let mut next = Vec::new();
        let ticket = reserve_vec(ledger, &mut next, new_capacity, FailPoint::TableHashGrow)?;
        next.resize_with(new_capacity, || None);
        ledger.checkpoint(FailPoint::TableRehash)?;
        ledger.checkpoint(FailPoint::TableInsert)?;
        ticket.commit()?;
        if let Err(error) = ledger.refund_lua(old_bytes) {
            ledger.refund_lua_on_drop(new_bytes);
            return Err(error);
        }
        let old = core::mem::replace(&mut self.hash, next);
        for entry in old.into_iter().flatten() {
            Self::insert_bucket(&mut self.hash, entry)?;
        }
        Self::insert_bucket(&mut self.hash, (key, value))
    }

    fn set(
        &mut self,
        ledger: &AllocationLedger,
        key: CanonicalKey,
        value: Value,
    ) -> Result<(), VmError> {
        let array_index = key.array_index();
        if let Some(index) = array_index {
            if let Some(Some(stored)) = self.array.get_mut(index) {
                if value == Value::Nil {
                    self.array[index] = None;
                } else {
                    *stored = value;
                }
                return Ok(());
            }
        }
        if let Some(index) = self.find_hash(&key) {
            if value == Value::Nil {
                self.hash[index] = None;
            } else if let Some((_, stored)) = &mut self.hash[index] {
                *stored = value;
            }
            return Ok(());
        }
        if value == Value::Nil {
            return Ok(());
        }
        if let Some(index) = array_index {
            if index < self.array.len() {
                ledger.checkpoint(FailPoint::TableInsert)?;
                self.array[index] = Some(value);
                return Ok(());
            }
            if index == self.array.len() {
                return self.grow_array_and_insert(ledger, index, value);
            }
        }
        let count = self.hash.iter().filter(|entry| entry.is_some()).count();
        let capacity = self.hash.len();
        if capacity == 0 || count >= capacity || count + 1 > capacity - capacity / 4 {
            self.grow_hash_and_insert(ledger, key, value)
        } else {
            ledger.checkpoint(FailPoint::TableInsert)?;
            Self::insert_bucket(&mut self.hash, (key, value))
        }
    }

    /// 僅供 installer 的已存在 byte-key rollback；不重新建立 canonical key。
    fn restore_existing_byte_key(&mut self, name: &[u8], value: Value) -> Result<(), VmError> {
        let Some(index) = self.hash.iter().position(|entry| {
            entry.as_ref().is_some_and(|(key, _)| {
                matches!(&key.kind, KeyKind::ByteString(string) if string.bytes.as_bytes() == name)
            })
        }) else {
            return Err(VmError::LedgerInvariant);
        };
        if value == Value::Nil {
            self.hash[index] = None;
        } else if let Some((_, stored)) = &mut self.hash[index] {
            *stored = value;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalKeyClass {
    Integer,
    Float,
    Boolean,
    ByteString,
    Object,
}

struct StringKey {
    source: ObjectRef,
    bytes: ByteString,
    ledger: AllocationLedger,
}

impl Drop for StringKey {
    fn drop(&mut self) {
        self.ledger.refund_lua_on_drop(self.bytes.len());
    }
}

struct ObjectKey {
    source: ObjectRef,
    id: ObjectId,
}

enum KeyKind {
    Integer(i64),
    Float(f64),
    Boolean(bool),
    ByteString(StringKey),
    Object(ObjectKey),
}

/// 可儲存的寫鍵；建構時排除 nil 與 NaN，並正規化精確整數 float。
pub struct CanonicalKey {
    kind: KeyKind,
}

impl CanonicalKey {
    pub fn class(&self) -> CanonicalKeyClass {
        match self.kind {
            KeyKind::Integer(_) => CanonicalKeyClass::Integer,
            KeyKind::Float(_) => CanonicalKeyClass::Float,
            KeyKind::Boolean(_) => CanonicalKeyClass::Boolean,
            KeyKind::ByteString(_) => CanonicalKeyClass::ByteString,
            KeyKind::Object(_) => CanonicalKeyClass::Object,
        }
    }

    /// 供 table 之後的 trace 使用；基本值不持有 heap 參照。
    pub(crate) fn source_object(&self) -> Option<ObjectRef> {
        match &self.kind {
            KeyKind::ByteString(key) => Some(key.source),
            KeyKind::Object(key) => Some(key.source),
            _ => None,
        }
    }

    fn array_index(&self) -> Option<usize> {
        match &self.kind {
            KeyKind::Integer(value) if *value > 0 => usize::try_from(*value).ok()?.checked_sub(1),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn as_value(&self) -> Value {
        match &self.kind {
            KeyKind::Integer(value) => Value::Integer(*value),
            KeyKind::Float(value) => Value::Float(*value),
            KeyKind::Boolean(value) => Value::Boolean(*value),
            KeyKind::ByteString(key) => Value::Object(key.source),
            KeyKind::Object(key) => Value::Object(key.source),
        }
    }
}

impl core::fmt::Debug for CanonicalKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CanonicalKey")
            .field("class", &self.class())
            .field("source", &self.source_object())
            .finish_non_exhaustive()
    }
}

impl PartialEq for CanonicalKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.kind, &other.kind) {
            (KeyKind::Integer(a), KeyKind::Integer(b)) => a == b,
            (KeyKind::Float(a), KeyKind::Float(b)) => a == b,
            (KeyKind::Boolean(a), KeyKind::Boolean(b)) => a == b,
            (KeyKind::ByteString(a), KeyKind::ByteString(b)) => a.bytes == b.bytes,
            (KeyKind::Object(a), KeyKind::Object(b)) => a.id == b.id,
            _ => false,
        }
    }
}

impl Eq for CanonicalKey {}

impl Hash for CanonicalKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.kind {
            KeyKind::Integer(value) => {
                0u8.hash(state);
                value.hash(state);
            }
            KeyKind::Float(value) => {
                1u8.hash(state);
                value.to_bits().hash(state);
            }
            KeyKind::Boolean(value) => {
                2u8.hash(state);
                value.hash(state);
            }
            KeyKind::ByteString(key) => {
                3u8.hash(state);
                key.bytes.hash(state);
            }
            KeyKind::Object(key) => {
                4u8.hash(state);
                key.id.hash(state);
            }
        }
    }
}

impl Vm {
    /// 呼叫端先根住舊值並完成 TableValue write barrier，再以此無配置回滾。
    pub(crate) fn restore_existing_byte_key(
        &mut self,
        table: ObjectRef,
        name: &[u8],
        value: Value,
    ) -> Result<(), VmError> {
        if let Value::Object(object) = value {
            self.object_kind(object)?;
        }
        self.with_table_mut(table, |stored, _| {
            stored.restore_existing_byte_key(name, value)
        })
    }

    pub fn canonical_key(&self, value: Value) -> Result<Option<CanonicalKey>, VmError> {
        let kind = match value {
            Value::Nil => return Ok(None),
            Value::Integer(value) => KeyKind::Integer(value),
            Value::Boolean(value) => KeyKind::Boolean(value),
            Value::Float(value) if value.is_nan() => return Ok(None),
            Value::Float(value) => {
                const TWO_TO_63: f64 = 9_223_372_036_854_775_808.0;
                if value.is_finite()
                    && value >= -TWO_TO_63
                    && value < TWO_TO_63
                    && value.fract() == 0.0
                {
                    KeyKind::Integer(value as i64)
                } else {
                    KeyKind::Float(value)
                }
            }
            Value::Object(source) => match self.object_kind(source)? {
                ObjectKind::ByteString => {
                    let (bytes, ticket) = self.with_byte_string(source, |string| {
                        ByteString::try_from_bytes(self.allocation_ledger(), string.as_bytes())
                    })??;
                    ticket.commit()?;
                    KeyKind::ByteString(StringKey {
                        source,
                        bytes,
                        ledger: self.allocation_ledger().clone(),
                    })
                }
                ObjectKind::Value
                | ObjectKind::Table
                | ObjectKind::Closure
                | ObjectKind::Builtin
                | ObjectKind::Coroutine
                | ObjectKind::Upvalue
                | ObjectKind::Module
                | ObjectKind::File => KeyKind::Object(ObjectKey {
                    source,
                    id: source.identity().ok_or(VmError::StaleObject)?,
                }),
            },
        };
        Ok(Some(CanonicalKey { kind }))
    }

    pub fn raw_get(&self, table: ObjectRef, key: Value) -> Result<Value, VmError> {
        if self.object_kind(table)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        if matches!(key, Value::Nil) || matches!(key, Value::Float(value) if value.is_nan()) {
            return Ok(Value::Nil);
        }
        let Some(key) = self.canonical_key(key)? else {
            return Ok(Value::Nil);
        };
        self.with_table(table, |stored| stored.get(&key))
    }

    fn remove_temporary_roots(&mut self, roots: &mut [Option<RootId>; 3]) -> Result<(), VmError> {
        for root in roots.iter_mut().rev() {
            if let Some(id) = root.take() {
                self.remove_root(id)?;
            }
        }
        Ok(())
    }

    pub fn raw_set(&mut self, table: ObjectRef, key: Value, value: Value) -> Result<(), VmError> {
        if self.object_kind(table)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        match key {
            Value::Nil => return Err(VmError::NilTableKey),
            Value::Float(number) if number.is_nan() => return Err(VmError::NaNTableKey),
            _ => {}
        }
        if let Value::Object(object) = key {
            self.write_ref(table, RefField::TableKey, object)?;
        }
        if let Value::Object(object) = value {
            self.write_ref(table, RefField::TableValue, object)?;
        }
        let mut roots = [None; 3];
        let objects = [
            Some(table),
            match key {
                Value::Object(object) => Some(object),
                _ => None,
            },
            match value {
                Value::Object(object) => Some(object),
                _ => None,
            },
        ];
        for (index, object) in objects.into_iter().enumerate() {
            if let Some(object) = object {
                match self.add_root(RootKind::Temporary, object) {
                    Ok(root) => roots[index] = Some(root),
                    Err(error) => {
                        self.remove_temporary_roots(&mut roots)?;
                        return Err(error);
                    }
                }
            }
        }
        let result = (|| {
            let canonical = self.canonical_key(key)?.ok_or(VmError::LedgerInvariant)?;
            self.with_table_mut(table, |stored, ledger| stored.set(ledger, canonical, value))
        })();
        self.remove_temporary_roots(&mut roots)?;
        result
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use rivetlua_core::{SlotId, Value};

    use crate::{
        CanonicalKey, CanonicalKeyClass, FailPoint, HostHandle, ObjectKind, RootKind, Table, Vm,
        VmError,
    };

    fn hash(key: &CanonicalKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn canonical_key_numeric_boolean_and_invalid_matrix() {
        let vm = Vm::new().unwrap();
        let one = vm.canonical_key(Value::Integer(1)).unwrap().unwrap();
        let one_float = vm.canonical_key(Value::Float(1.0)).unwrap().unwrap();
        assert_eq!(one.class(), CanonicalKeyClass::Integer);
        assert!(one == one_float);
        assert_eq!(hash(&one), hash(&one_float));
        let zero = vm.canonical_key(Value::Integer(0)).unwrap().unwrap();
        let negative_zero = vm.canonical_key(Value::Float(-0.0)).unwrap().unwrap();
        assert!(zero == negative_zero);
        assert_eq!(hash(&zero), hash(&negative_zero));
        let half = vm.canonical_key(Value::Float(1.5)).unwrap().unwrap();
        assert_eq!(half.class(), CanonicalKeyClass::Float);
        assert!(half != one);
        let infinity = vm
            .canonical_key(Value::Float(f64::INFINITY))
            .unwrap()
            .unwrap();
        assert_eq!(infinity.class(), CanonicalKeyClass::Float);
        assert!(infinity != half);
        let max_integer = vm.canonical_key(Value::Integer(i64::MAX)).unwrap().unwrap();
        let rounded_max = vm
            .canonical_key(Value::Float(i64::MAX as f64))
            .unwrap()
            .unwrap();
        assert_eq!(rounded_max.class(), CanonicalKeyClass::Float);
        assert!(rounded_max != max_integer);
        let min_integer = vm.canonical_key(Value::Integer(i64::MIN)).unwrap().unwrap();
        let exact_min = vm
            .canonical_key(Value::Float(i64::MIN as f64))
            .unwrap()
            .unwrap();
        assert!(min_integer == exact_min);
        let below_min = vm
            .canonical_key(Value::Float((i64::MIN as f64) * 2.0))
            .unwrap()
            .unwrap();
        assert_eq!(below_min.class(), CanonicalKeyClass::Float);
        assert!(below_min != min_integer);
        assert!(vm.canonical_key(Value::Nil).unwrap().is_none());
        assert!(vm.canonical_key(Value::Float(f64::NAN)).unwrap().is_none());
        let yes = vm.canonical_key(Value::Boolean(true)).unwrap().unwrap();
        let no = vm.canonical_key(Value::Boolean(false)).unwrap().unwrap();
        assert_eq!(yes.class(), CanonicalKeyClass::Boolean);
        assert!(yes != no);
        assert!(no != zero);
    }

    #[test]
    fn canonical_key_string_bytes_and_full_object_identity() {
        let mut a = Vm::new().unwrap();
        let mut b = Vm::new().unwrap();
        let first = a.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        let second = a.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        let different = a.allocate_byte_string(&[0, 0x80, 0xfe]).unwrap();
        let foreign = b.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        assert_eq!(a.object_kind(first), Ok(ObjectKind::ByteString));
        let before_keys = a.ledger_snapshot().committed;
        a.set_allocation_limit(before_keys);
        assert_eq!(
            a.canonical_key(Value::Object(first)),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(a.ledger_snapshot().reserved, 0);
        assert_eq!(a.ledger_snapshot().committed, before_keys);
        a.set_allocation_limit(usize::MAX);
        a.inject_failure_once(FailPoint::StringBytesReserve);
        assert_eq!(
            a.canonical_key(Value::Object(first)),
            Err(VmError::InjectedFailure(FailPoint::StringBytesReserve))
        );
        assert_eq!(a.ledger_snapshot().committed, before_keys);
        assert_eq!(a.ledger_snapshot().reserved, 0);
        let first_key = a.canonical_key(Value::Object(first)).unwrap().unwrap();
        let second_key = a.canonical_key(Value::Object(second)).unwrap().unwrap();
        let different_key = a.canonical_key(Value::Object(different)).unwrap().unwrap();
        let foreign_key = b.canonical_key(Value::Object(foreign)).unwrap().unwrap();
        assert_eq!(first_key.class(), CanonicalKeyClass::ByteString);
        assert!(first_key == second_key && second_key == foreign_key);
        assert_eq!(hash(&first_key), hash(&second_key));
        assert_eq!(hash(&first_key), hash(&foreign_key));
        assert!(first_key != different_key);
        assert!(a.ledger_snapshot().committed > before_keys);
        drop(first_key);
        drop(second_key);
        drop(different_key);
        assert_eq!(a.ledger_snapshot().committed, before_keys);
        drop(foreign_key);

        let old = a.allocate(Value::Integer(1)).unwrap();
        assert_eq!(a.object_kind(old), Ok(ObjectKind::Value));
        assert_eq!(
            a.canonical_key(Value::Object(rivetlua_core::ObjectRef::from_id(
                old.identity().unwrap()
            ))),
            Err(VmError::StaleObject)
        );
        let other_slot = a.allocate(Value::Integer(2)).unwrap();
        let other_vm = b.allocate(Value::Integer(1)).unwrap();
        let old_key = a.canonical_key(Value::Object(old)).unwrap().unwrap();
        let slot_key = a.canonical_key(Value::Object(other_slot)).unwrap().unwrap();
        let vm_key = b.canonical_key(Value::Object(other_vm)).unwrap().unwrap();
        assert_eq!(old_key.class(), CanonicalKeyClass::Object);
        assert!(old_key != slot_key && old_key != vm_key);
        assert!(slot_key != vm_key);
        let mut generation_vm = Vm::new().unwrap();
        let original = generation_vm.allocate(Value::Integer(1)).unwrap();
        let original_key = generation_vm
            .canonical_key(Value::Object(original))
            .unwrap()
            .unwrap();
        assert_eq!(generation_vm.collect().unwrap(), 1);
        let replacement = generation_vm.allocate(Value::Integer(3)).unwrap();
        assert_eq!(
            replacement.identity().unwrap().slot,
            original.identity().unwrap().slot
        );
        let new_key = generation_vm
            .canonical_key(Value::Object(replacement))
            .unwrap()
            .unwrap();
        assert!(original_key != new_key);
        assert_eq!(a.collect().unwrap(), 5);
        assert_eq!(
            a.canonical_key(Value::Object(old)),
            Err(VmError::StaleObject)
        );
        assert_eq!(
            a.canonical_key(Value::Object(other_vm)),
            Err(VmError::WrongVm)
        );
    }

    #[test]
    fn canonical_key_table_payload_identity_and_host_root_survive_collection() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
        let address = vm
            .with_table(table, |value| {
                assert!(value.is_empty());
                assert_eq!(value.array_capacity(), 0);
                assert_eq!(value.hash_capacity(), 0);
                value as *const Table as usize
            })
            .unwrap();
        let handle = HostHandle::<Table>::new(&mut vm, table).unwrap();
        vm.set_collect_every_allocation(true);
        vm.allocate(Value::Integer(8)).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(handle.object_id(), table.identity().unwrap());
        assert_eq!(
            vm.with_table(table, |value| value as *const Table as usize),
            Ok(address)
        );
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        drop(handle);
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(
            vm.with_table(table, |value| value.is_empty()),
            Err(VmError::StaleObject)
        );
    }

    #[test]
    fn canonical_key_table_size_quota_and_failpoints_roll_back() {
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        assert_eq!(
            vm.allocate_table_with_capacity(usize::MAX, 0),
            Err(VmError::ArithmeticOverflow)
        );
        assert_eq!(
            vm.allocate_table_with_capacity(0, usize::MAX),
            Err(VmError::ArithmeticOverflow)
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.slot_state(SlotId::new(0)), None);

        let mut vm = Vm::new().unwrap();
        let array_charge = 2 * core::mem::size_of::<Option<Value>>();
        vm.set_allocation_limit(array_charge);
        assert_eq!(
            vm.allocate_table_with_capacity(2, 3),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.ledger_snapshot().committed, 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.slot_state(SlotId::new(0)), None);
        vm.set_allocation_limit(0);
        assert_eq!(
            vm.allocate_table_with_capacity(1, 1),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.slot_state(SlotId::new(0)), None);

        for point in [
            FailPoint::TableArrayReserve,
            FailPoint::TableHashReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
            FailPoint::MarkReserve,
            FailPoint::WorkReserve,
        ] {
            let mut vm = Vm::new().unwrap();
            vm.set_collect_every_allocation(true);
            let before = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate_table_with_capacity(2, 3),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.slot_state(SlotId::new(0)), None);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table_with_capacity(2, 3).unwrap();
        vm.with_table(table, |value| {
            assert!(value.is_empty());
            assert_eq!(value.array_capacity(), 2);
            assert_eq!(value.hash_capacity(), 3);
        })
        .unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let before_collect = vm.ledger_snapshot().committed;
        assert_eq!(vm.collect().unwrap(), 1);
        assert!(vm.ledger_snapshot().committed < before_collect);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn raw_table_missing_false_delete_and_invalid_keys() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        vm.raw_set(table, Value::Integer(1), Value::Boolean(false))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Float(1.0)),
            Ok(Value::Boolean(false))
        );
        vm.raw_set(table, Value::Integer(1), Value::Nil).unwrap();
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        let before = vm.ledger_snapshot();
        assert_eq!(vm.raw_get(table, Value::Nil), Ok(Value::Nil));
        assert_eq!(vm.raw_get(table, Value::Float(f64::NAN)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_set(table, Value::Nil, Value::Integer(4)),
            Err(VmError::NilTableKey)
        );
        assert_eq!(
            vm.raw_set(table, Value::Float(f64::NAN), Value::Integer(4)),
            Err(VmError::NaNTableKey)
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
        assert!(vm.with_table(table, |value| value.is_empty()).unwrap());
    }

    #[test]
    fn raw_table_collisions_array_growth_hash_rehash_and_string_keys() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table_with_capacity(0, 4).unwrap();
        let mut collision = None;
        for first in 100..140 {
            for second in (first + 1)..140 {
                let a = vm.canonical_key(Value::Integer(first)).unwrap().unwrap();
                let b = vm.canonical_key(Value::Integer(second)).unwrap().unwrap();
                if hash(&a) % 4 == hash(&b) % 4 {
                    collision = Some((first, second));
                    break;
                }
            }
            if collision.is_some() {
                break;
            }
        }
        let (first, second) = collision.unwrap();
        vm.raw_set(table, Value::Integer(first), Value::Integer(11))
            .unwrap();
        vm.raw_set(table, Value::Integer(second), Value::Integer(22))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Integer(first)),
            Ok(Value::Integer(11))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(second)),
            Ok(Value::Integer(22))
        );
        vm.raw_set(table, Value::Integer(first), Value::Nil)
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Integer(second)),
            Ok(Value::Integer(22))
        );
        vm.raw_set(table, Value::Integer(first), Value::Integer(11))
            .unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Integer(1))
            .unwrap();
        vm.raw_set(table, Value::Integer(5), Value::Integer(5))
            .unwrap();
        for key in 200..230 {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
        }
        assert!(
            vm.with_table(table, |value| value.array_capacity())
                .unwrap()
                >= 5
        );
        assert!(vm.with_table(table, |value| value.hash_capacity()).unwrap() > 4);
        assert_eq!(
            vm.raw_get(table, Value::Integer(first)),
            Ok(Value::Integer(11))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(second)),
            Ok(Value::Integer(22))
        );
        for key in 200..230 {
            assert_eq!(
                vm.raw_get(table, Value::Integer(key)),
                Ok(Value::Integer(key))
            );
        }
        let a = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        let b = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        vm.raw_set(table, Value::Object(a), Value::Boolean(false))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(b)),
            Ok(Value::Boolean(false))
        );
        vm.raw_set(table, Value::Object(b), Value::Nil).unwrap();
        assert_eq!(vm.raw_get(table, Value::Object(a)), Ok(Value::Nil));
    }

    #[test]
    fn raw_table_failed_insert_growth_and_rehash_preserve_old_fields_and_ledger() {
        for point in [
            FailPoint::RootReserve,
            FailPoint::TableInsert,
            FailPoint::TableArrayGrow,
            FailPoint::TableHashGrow,
            FailPoint::TableRehash,
        ] {
            let mut vm = Vm::new().unwrap();
            let table = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Integer(7))
                .unwrap();
            vm.raw_set(table, Value::Integer(100), Value::Integer(9))
                .unwrap();
            let attempted = match point {
                FailPoint::TableArrayGrow => 5,
                FailPoint::TableHashGrow | FailPoint::TableRehash => {
                    vm.raw_set(table, Value::Integer(101), Value::Integer(10))
                        .unwrap();
                    vm.raw_set(table, Value::Integer(102), Value::Integer(11))
                        .unwrap();
                    103
                }
                _ => 104,
            };
            let before = vm.ledger_snapshot();
            let capacities = vm
                .with_table(table, |value| {
                    (value.array_capacity(), value.hash_capacity())
                })
                .unwrap();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.raw_set(table, Value::Integer(attempted), Value::Integer(12)),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(7)));
            assert_eq!(
                vm.raw_get(table, Value::Integer(100)),
                Ok(Value::Integer(9))
            );
            assert_eq!(vm.raw_get(table, Value::Integer(attempted)), Ok(Value::Nil));
            assert_eq!(
                vm.with_table(table, |value| (
                    value.array_capacity(),
                    value.hash_capacity()
                ))
                .unwrap(),
                capacities
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().total_count(), 0);
        }
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let before = vm.ledger_snapshot();
        vm.set_allocation_limit(before.committed);
        assert_eq!(
            vm.raw_set(table, Value::Integer(1), Value::Integer(7)),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.roots().total_count(), 0);

        for key in [1, 100] {
            let mut vm = Vm::new().unwrap();
            let table = vm.allocate_table().unwrap();
            let base = vm.ledger_snapshot().committed;
            let probe = vm.add_root(RootKind::Temporary, table).unwrap();
            let root_charge = vm.ledger_snapshot().committed - base;
            vm.remove_root(probe).unwrap();
            vm.set_allocation_limit(base + root_charge);
            assert_eq!(
                vm.raw_set(table, Value::Integer(key), Value::Integer(7)),
                Err(VmError::AllocationFailed)
            );
            assert!(vm.with_table(table, |stored| stored.is_empty()).unwrap());
            assert_eq!(vm.ledger_snapshot().committed, base);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.roots().total_count(), 0);
        }

        for allowed_roots in [1, 2] {
            let mut vm = Vm::new().unwrap();
            let table = vm.allocate_table().unwrap();
            let key = vm.allocate(Value::Integer(1)).unwrap();
            let value = vm.allocate(Value::Integer(2)).unwrap();
            let base = vm.ledger_snapshot().committed;
            let probe = vm.add_root(RootKind::Temporary, table).unwrap();
            let root_charge = vm.ledger_snapshot().committed - base;
            vm.remove_root(probe).unwrap();
            vm.set_allocation_limit(base + allowed_roots * root_charge);
            assert_eq!(
                vm.raw_set(table, Value::Object(key), Value::Object(value)),
                Err(VmError::AllocationFailed)
            );
            assert!(vm.with_table(table, |stored| stored.is_empty()).unwrap());
            assert_eq!(vm.ledger_snapshot().committed, base);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let key = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        let base = vm.ledger_snapshot().committed;
        let probe = vm.add_root(RootKind::Temporary, table).unwrap();
        let root_charge = vm.ledger_snapshot().committed - base;
        vm.remove_root(probe).unwrap();
        vm.set_allocation_limit(base + 2 * root_charge);
        assert_eq!(
            vm.raw_set(table, Value::Object(key), Value::Integer(1)),
            Err(VmError::AllocationFailed)
        );
        assert!(vm.with_table(table, |stored| stored.is_empty()).unwrap());
        assert_eq!(vm.ledger_snapshot().committed, base);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.roots().total_count(), 0);
    }

    #[test]
    fn raw_table_traces_object_key_and_value_until_delete() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        let key = vm.allocate(Value::Integer(1)).unwrap();
        let value = vm.allocate_byte_string(&[0, 0x80]).unwrap();
        vm.raw_set(table, Value::Object(key), Value::Object(value))
            .unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(
            vm.raw_get(table, Value::Object(key)),
            Ok(Value::Object(value))
        );
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        assert_eq!(vm.collect().unwrap(), 2);
        assert_eq!(
            vm.raw_get(table, Value::Object(key)),
            Err(VmError::StaleObject)
        );
        let string_key = vm.allocate_byte_string(&[0, 0x80]).unwrap();
        vm.raw_set(table, Value::Object(string_key), Value::Integer(4))
            .unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        let equal_bytes = vm.allocate_byte_string(&[0, 0x80]).unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(equal_bytes)),
            Ok(Value::Integer(4))
        );
        vm.raw_set(table, Value::Object(equal_bytes), Value::Nil)
            .unwrap();
        assert_eq!(vm.collect().unwrap(), 2);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
    }

    #[test]
    fn table_length_byte_string_dense_and_hole_borders() {
        let mut vm = Vm::new().unwrap();
        let string = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        assert_eq!(vm.with_byte_string(string, |value| value.len()), Ok(3));

        let table = vm.allocate_table().unwrap();
        assert_eq!(vm.with_table(table, |value| value.border_len()), Ok(0));
        for key in 1..=3 {
            vm.raw_set(table, Value::Integer(key), Value::Boolean(false))
                .unwrap();
        }
        assert_eq!(vm.with_table(table, |value| value.border_len()), Ok(3));

        vm.raw_set(table, Value::Integer(2), Value::Nil).unwrap();
        vm.raw_set(table, Value::Integer(100), Value::Integer(100))
            .unwrap();
        let border = vm.with_table(table, |value| value.border_len()).unwrap();
        assert!(border >= 1);
        assert_ne!(vm.raw_get(table, Value::Integer(border)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_get(table, Value::Integer(border + 1)),
            Ok(Value::Nil)
        );

        vm.raw_set(table, Value::Integer(1), Value::Nil).unwrap();
        assert_eq!(vm.with_table(table, |value| value.border_len()), Ok(0));
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
    }

    #[test]
    fn table_iteration_raw_fields_once_and_terminates() {
        #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
        enum SeenKey {
            Integer(i64),
            Boolean(bool),
            Bytes(Vec<u8>),
        }

        let profile =
            std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
        assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
        let expected = BTreeMap::from([
            (SeenKey::Integer(1), (Value::Integer(11), 1)),
            (SeenKey::Integer(3), (Value::Integer(33), 1)),
            (SeenKey::Integer(100), (Value::Integer(1000), 1)),
            (SeenKey::Boolean(true), (Value::Boolean(false), 1)),
            (SeenKey::Bytes(vec![0, 0x80]), (Value::Integer(88), 1)),
        ]);

        for order in [[0, 1, 2, 3, 4], [4, 3, 2, 1, 0]] {
            let mut vm = Vm::new().unwrap();
            let table = vm.allocate_table().unwrap();
            let string = vm.allocate_byte_string(&[0, 0x80]).unwrap();
            let fields = [
                (Value::Integer(1), Value::Integer(11)),
                (Value::Integer(3), Value::Integer(33)),
                (Value::Integer(100), Value::Integer(1000)),
                (Value::Boolean(true), Value::Boolean(false)),
                (Value::Object(string), Value::Integer(88)),
            ];
            for index in order {
                let (key, value) = fields[index];
                vm.raw_set(table, key, value).unwrap();
            }
            vm.raw_set(table, Value::Integer(3), Value::Nil).unwrap();
            vm.raw_set(table, Value::Integer(3), Value::Integer(33))
                .unwrap();

            let mut seen = BTreeMap::new();
            vm.with_table(table, |stored| {
                stored.for_each_raw(|key, value| {
                    let key = match key {
                        Value::Integer(number) => SeenKey::Integer(number),
                        Value::Boolean(boolean) => SeenKey::Boolean(boolean),
                        Value::Object(object) => SeenKey::Bytes(
                            vm.with_byte_string(object, |string| string.as_bytes().to_vec())?,
                        ),
                        _ => panic!("本案例僅建立整數、布林與 byte string 鍵"),
                    };
                    let entry = seen.entry(key).or_insert((value, 0));
                    assert_eq!(entry.0, value);
                    entry.1 += 1;
                    Ok(())
                })
            })
            .unwrap()
            .unwrap();
            assert_eq!(seen, expected);
            println!(
                "P08_CASE\tTAB-010\t{profile}\tinput_order={order:?}\texpected_fields=5\tactual={seen:?}"
            );
        }
    }

    #[test]
    fn table_gc_forced_collection_traces_all_key_and_value_regions_then_reclaims() {
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();

        let string_key = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
        let string_key_root = vm.add_root(RootKind::Host, string_key).unwrap();
        let string_value = vm.allocate_byte_string(&[0, 0x41]).unwrap();
        let string_value_root = vm.add_root(RootKind::Host, string_value).unwrap();
        vm.raw_set(
            table,
            Value::Object(string_key),
            Value::Object(string_value),
        )
        .unwrap();
        vm.remove_root(string_key_root).unwrap();
        vm.remove_root(string_value_root).unwrap();

        let object_key = vm.allocate(Value::Integer(41)).unwrap();
        let object_key_root = vm.add_root(RootKind::Host, object_key).unwrap();
        let object_value = vm.allocate(Value::Integer(42)).unwrap();
        let object_value_root = vm.add_root(RootKind::Host, object_value).unwrap();
        vm.raw_set(
            table,
            Value::Object(object_key),
            Value::Object(object_value),
        )
        .unwrap();
        vm.remove_root(object_key_root).unwrap();
        vm.remove_root(object_value_root).unwrap();

        let array_value = vm.allocate(Value::Integer(77)).unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Object(array_value))
            .unwrap();
        for key in 2..=8 {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
            assert_eq!(vm.collect().unwrap(), 0);
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        for key in 100..112 {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
            assert_eq!(vm.collect().unwrap(), 0);
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
        assert_eq!(vm.roots().total_count(), 1);
        assert_eq!(
            vm.raw_get(table, Value::Object(string_key)),
            Ok(Value::Object(string_value))
        );
        assert_eq!(
            vm.raw_get(table, Value::Object(object_key)),
            Ok(Value::Object(object_value))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(array_value))
        );
        assert_eq!(
            vm.with_byte_string(string_key, |string| string.as_bytes().to_vec()),
            Ok(vec![0, 0x80, 0xff])
        );

        let transient = vm.allocate_byte_string(&[0x55]).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(
            vm.with_byte_string(transient, |string| string.len()),
            Err(VmError::StaleObject)
        );
        assert_eq!(vm.collect().unwrap(), 0);

        let before_key_delete = vm.ledger_snapshot().committed;
        vm.raw_set(table, Value::Object(string_key), Value::Nil)
            .unwrap();
        assert_eq!(vm.ledger_snapshot().committed + 3, before_key_delete);
        vm.raw_set(table, Value::Object(object_key), Value::Nil)
            .unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Nil).unwrap();
        assert_eq!(vm.collect().unwrap(), 5);
        assert_eq!(
            vm.with_byte_string(string_key, |string| string.len()),
            Err(VmError::StaleObject)
        );
        assert_eq!(vm.read(object_value), Err(VmError::StaleObject));
        assert_eq!(vm.roots().total_count(), 1);
        let bucket_bytes = vm
            .with_table(table, |stored| stored.charge_bytes().unwrap())
            .unwrap();
        vm.remove_root(table_root).unwrap();
        let before_table_collect = vm.ledger_snapshot().committed;
        assert_eq!(vm.collect().unwrap(), 1);
        let table_refund = before_table_collect - vm.ledger_snapshot().committed;
        let baseline = vm.ledger_snapshot();
        let object = vm.allocate(Value::Integer(0)).unwrap();
        let object_bytes = vm.ledger_snapshot().committed - baseline.committed;
        assert_eq!(table_refund, object_bytes + bucket_bytes);
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(vm.read(object), Err(VmError::StaleObject));
        assert_eq!(vm.ledger_snapshot(), baseline);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn table_allocation_failure_preserves_fields_roots_and_accounted_buckets() {
        let mut vm = Vm::new().unwrap();
        vm.set_collect_every_allocation(true);
        let table = vm.allocate_table().unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        vm.raw_set(table, Value::Integer(1), Value::Integer(7))
            .unwrap();
        for key in 100..=102 {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
        }
        let capacities = vm
            .with_table(table, |stored| {
                (
                    stored.array_capacity(),
                    stored.hash_capacity(),
                    stored.charge_bytes().unwrap(),
                )
            })
            .unwrap();
        let before = vm.ledger_snapshot();
        let roots = vm.roots().total_count();

        for (point, key) in [
            (FailPoint::TableInsert, 103),
            (FailPoint::TableArrayGrow, 5),
            (FailPoint::TableHashGrow, 103),
            (FailPoint::TableRehash, 103),
        ] {
            vm.inject_failure_once(point);
            assert_eq!(
                vm.raw_set(table, Value::Integer(key), Value::Integer(999)),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.raw_get(table, Value::Integer(key)), Ok(Value::Nil));
            assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(7)));
            for old in 100..=102 {
                assert_eq!(
                    vm.raw_get(table, Value::Integer(old)),
                    Ok(Value::Integer(old))
                );
            }
            assert_eq!(
                vm.with_table(table, |stored| (
                    stored.array_capacity(),
                    stored.hash_capacity(),
                    stored.charge_bytes().unwrap()
                ))
                .unwrap(),
                capacities
            );
            assert_eq!(vm.ledger_snapshot(), before);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            assert_eq!(vm.collect().unwrap(), 0);
        }

        let probe = vm.add_root(RootKind::Temporary, table).unwrap();
        let root_charge = vm.ledger_snapshot().committed - before.committed;
        vm.remove_root(probe).unwrap();
        vm.set_allocation_limit(before.committed + root_charge);
        assert_eq!(
            vm.raw_set(table, Value::Integer(103), Value::Integer(999)),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.roots().total_count(), roots);
        vm.set_allocation_limit(usize::MAX);

        for capacities in [(usize::MAX, 0), (0, usize::MAX)] {
            let snapshot = vm.ledger_snapshot();
            assert_eq!(
                vm.allocate_table_with_capacity(capacities.0, capacities.1),
                Err(VmError::ArithmeticOverflow)
            );
            assert_eq!(vm.ledger_snapshot(), snapshot);
            assert_eq!(vm.roots().total_count(), roots);
        }
        for point in [
            FailPoint::TableArrayReserve,
            FailPoint::TableHashReserve,
            FailPoint::SlotReserve,
            FailPoint::ObjectReserve,
            FailPoint::ObjectInitialize,
            FailPoint::RootReserve,
            FailPoint::MarkReserve,
            FailPoint::WorkReserve,
        ] {
            let snapshot = vm.ledger_snapshot();
            vm.inject_failure_once(point);
            assert_eq!(
                vm.allocate_table_with_capacity(2, 3),
                Err(VmError::InjectedFailure(point))
            );
            assert_eq!(vm.ledger_snapshot(), snapshot);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.collect().unwrap(), 0);
        }
        let string_key = vm.allocate_byte_string(&[0, 0x80]).unwrap();
        let snapshot = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::StringBytesReserve);
        assert_eq!(
            vm.raw_set(table, Value::Object(string_key), Value::Integer(9)),
            Err(VmError::InjectedFailure(FailPoint::StringBytesReserve))
        );
        assert_eq!(vm.ledger_snapshot(), snapshot);
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(7)));
        vm.remove_root(table_root).unwrap();
        assert_eq!(vm.collect().unwrap(), 1);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}
