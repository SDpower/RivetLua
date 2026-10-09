//! P08 的 table 儲存與可儲存鍵分類。

use core::hash::{Hash, Hasher};
use core::mem::size_of;
use std::collections::hash_map::DefaultHasher;

use rivetlua_core::{ObjectId, ObjectRef, Value};

use crate::alloc::{
    AllocationCharge, AllocationLedger, FailPoint, PairedLuaCharges, Reservation, checked_bytes,
    reserve_vec,
};
use crate::gc::WeakMode;
use crate::{ByteString, ObjectKind, Vm, VmError};

/// 保留 array 欄位與 hash bucket；以 raw 語意讀寫。
pub struct Table {
    metatable: Option<ObjectRef>,
    weak_mode: WeakMode,
    array: Vec<Option<Value>>,
    hash: Vec<Option<(CanonicalKey, Value)>>,
    charges: PairedLuaCharges,
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
        let hash_ticket = match reserve_vec(
            ledger,
            &mut hash,
            hash_capacity,
            FailPoint::TableHashReserve,
        ) {
            Ok(ticket) => ticket,
            Err(error) => {
                drop(hash);
                drop(array);
                drop(array_ticket);
                return Err(error);
            }
        };
        hash.resize_with(hash_capacity, || None);
        Ok((
            Self {
                metatable: None,
                weak_mode: WeakMode::Strong,
                array,
                hash,
                charges: PairedLuaCharges::new(ledger.clone()),
            },
            array_ticket,
            hash_ticket,
        ))
    }

    pub(crate) fn install_initial_charges(
        &mut self,
        array: AllocationCharge,
        hash: AllocationCharge,
    ) {
        self.charges.replace_first(array);
        self.charges.replace_second(hash);
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
        self.hash
            .iter()
            .flatten()
            .find_map(|(key, value)| {
                if *value != Value::Nil && key.string_bytes() == Some(b"__mode".as_slice()) {
                    Some(*value)
                } else {
                    None
                }
            })
            .unwrap_or(Value::Nil)
    }

    pub(crate) fn finalizer_value(&self) -> Value {
        self.hash
            .iter()
            .flatten()
            .find_map(|(key, value)| {
                if *value != Value::Nil && key.string_bytes() == Some(b"__gc".as_slice()) {
                    Some(*value)
                } else {
                    None
                }
            })
            .unwrap_or(Value::Nil)
    }

    pub fn is_empty(&self) -> bool {
        self.array.iter().all(Option::is_none) && self.live_hash_count() == 0
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
            if *value == Value::Nil {
                continue;
            }
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
            if *value == Value::Nil {
                continue;
            }
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
                        | CanonicalKeyClass::LightUserdata
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
            if *value == Value::Nil {
                continue;
            }
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
        ledger: &AllocationLedger,
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
            if *value == Value::Nil {
                continue;
            }
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
                if dead_key {
                    *entry = None;
                } else {
                    key.make_dead(ledger)?;
                    *value = Value::Nil;
                }
                cleared += 1;
            }
        }
        if !self.hash.is_empty() && self.hash.iter().all(Option::is_none) {
            self.hash = Vec::new();
            self.charges.clear_second();
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
        self.find_any_hash(key).filter(|&index| {
            self.hash[index]
                .as_ref()
                .is_some_and(|(_, value)| *value != Value::Nil)
        })
    }

    fn live_hash_count(&self) -> usize {
        self.hash
            .iter()
            .flatten()
            .filter(|(_, value)| *value != Value::Nil)
            .count()
    }

    fn find_any_hash(&self, key: &CanonicalKey) -> Option<usize> {
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

    fn empty_bucket(
        buckets: &[Option<(CanonicalKey, Value)>],
        key: &CanonicalKey,
    ) -> Result<usize, VmError> {
        let count = buckets.len();
        if count == 0 {
            return Err(VmError::LedgerInvariant);
        }
        let start = Self::bucket(key, count);
        for step in 0..count {
            let index = Self::probe(start, step, count);
            if buckets[index].is_none() {
                return Ok(index);
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
            if *value != Value::Nil {
                visit(key.as_value(), *value)?;
            }
        }
        Ok(())
    }

    /// Lua next 以 bucket 位置續走；已刪除的欄位仍可作為前一鍵。
    pub(crate) fn next_raw(
        &self,
        vm: &Vm,
        previous: Value,
    ) -> Result<Option<(Value, Value)>, crate::vm::RuntimeError> {
        use crate::vm::{RuntimeError, RuntimeErrorKind};
        let mut array_start = 0;
        let mut hash_start = 0;
        if previous != Value::Nil {
            let mut found = false;
            let mut empty_array_match = None;
            for index in 0..self.array.len() {
                let number = i64::try_from(index)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or(VmError::ArithmeticOverflow)?;
                if vm.raw_equal_value(Value::Integer(number), previous)? {
                    if self.array[index].is_some() {
                        array_start = index + 1;
                        found = true;
                    } else {
                        empty_array_match = Some(index);
                    }
                    break;
                }
            }
            if !found {
                let mut matched_hash = None;
                for (index, entry) in self.hash.iter().enumerate() {
                    if let Some((key, _)) = entry
                        && key.matches_previous(vm, previous)?
                    {
                        matched_hash = Some(index);
                        break;
                    }
                }
                if let Some(index) = matched_hash {
                    hash_start = index + 1;
                    array_start = self.array.len();
                    found = true;
                }
                if !found {
                    if let Some(index) = empty_array_match {
                        array_start = index + 1;
                        found = true;
                    }
                }
            }
            if !found {
                return Err(RuntimeError::new(RuntimeErrorKind::InvalidNextKey));
            }
        }
        for index in array_start..self.array.len() {
            if let Some(value) = self.array[index] {
                let number = i64::try_from(index)
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or(VmError::ArithmeticOverflow)?;
                return Ok(Some((Value::Integer(number), value)));
            }
        }
        for (key, value) in self.hash.iter().skip(hash_start).flatten() {
            if *value != Value::Nil {
                return Ok(Some((key.as_value(), *value)));
            }
        }
        Ok(None)
    }

    fn prepare_set(
        &self,
        ledger: &AllocationLedger,
        mut key: CanonicalKey,
        value: Value,
    ) -> Result<PreparedTableMutation, VmError> {
        let array_index = key.array_index();
        if let Some(index) = array_index {
            if self.array.get(index).is_some_and(Option::is_some) {
                return Ok(PreparedTableMutation::ArraySlot { index, value });
            }
        }
        if let Some(index) = self.find_hash(&key) {
            if value == Value::Nil {
                key.make_dead(ledger)?;
            }
            return Ok(PreparedTableMutation::HashSlot {
                index,
                value,
                dead_key: (value == Value::Nil).then_some(key),
            });
        }
        if value == Value::Nil {
            return Ok(PreparedTableMutation::Noop);
        }
        if let Some(index) = self.find_any_hash(&key) {
            let needed = self
                .live_hash_count()
                .checked_add(1)
                .ok_or(VmError::ArithmeticOverflow)?;
            let capacity = self.hash.len();
            if needed <= capacity - capacity / 4 {
                ledger.checkpoint(FailPoint::TableInsert)?;
                return Ok(PreparedTableMutation::HashReplace { index, key, value });
            }
        }
        if let Some(index) = array_index {
            if index < self.array.len() {
                ledger.checkpoint(FailPoint::TableInsert)?;
                return Ok(PreparedTableMutation::ArraySlot { index, value });
            }
            if index == self.array.len() {
                let old_capacity = self.array.len();
                let new_capacity = old_capacity
                    .checked_mul(2)
                    .map(|doubled| doubled.max(4))
                    .ok_or(VmError::ArithmeticOverflow)?;
                let new_bytes = checked_bytes(new_capacity, size_of::<Option<Value>>())?;
                let old_bytes = checked_bytes(old_capacity, size_of::<Option<Value>>())?;
                let mut next = Vec::new();
                let ticket =
                    reserve_vec(ledger, &mut next, new_capacity, FailPoint::TableArrayGrow)?;
                next.resize_with(new_capacity, || None);
                next[..old_capacity].copy_from_slice(&self.array);
                ledger.checkpoint(FailPoint::TableInsert)?;
                next[index] = Some(value);
                return Ok(PreparedTableMutation::GrowArray {
                    next,
                    ticket: Some(ticket),
                    charge: None,
                    old_bytes,
                    new_bytes,
                    value,
                });
            }
        }
        let count = self.live_hash_count();
        let occupied = self.hash.iter().filter(|entry| entry.is_some()).count();
        let capacity = self.hash.len();
        let needed = count.checked_add(1).ok_or(VmError::ArithmeticOverflow)?;
        if capacity == 0 || occupied >= capacity || needed > capacity - capacity / 4 {
            let new_capacity = capacity
                .checked_mul(2)
                .map(|doubled| doubled.max(1))
                .ok_or(VmError::ArithmeticOverflow)?;
            if needed > new_capacity {
                return Err(VmError::LedgerInvariant);
            }
            let bucket_size = size_of::<Option<(CanonicalKey, Value)>>();
            let new_bytes = checked_bytes(new_capacity, bucket_size)?;
            let old_bytes = checked_bytes(capacity, bucket_size)?;
            let mut next = Vec::new();
            let ticket = reserve_vec(ledger, &mut next, new_capacity, FailPoint::TableHashGrow)?;
            next.resize_with(new_capacity, || None);
            ledger.checkpoint(FailPoint::TableRehash)?;
            ledger.checkpoint(FailPoint::TableInsert)?;
            Ok(PreparedTableMutation::GrowHash {
                next,
                ticket: Some(ticket),
                charge: None,
                old_bytes,
                new_bytes,
                existing_count: count,
                key,
                value,
            })
        } else {
            ledger.checkpoint(FailPoint::TableInsert)?;
            let index = Self::empty_bucket(&self.hash, &key)?;
            Ok(PreparedTableMutation::HashInsert { index, key, value })
        }
    }

    /// refs 的兩個非 nil 整數欄位在原表上共同預備；任何配置或 checkpoint
    /// 失敗時，原 array/hash、GC edge 與帳本提交狀態都尚未改變。
    fn prepare_ref_pair(
        &self,
        ledger: &AllocationLedger,
        first: (i64, Value),
        second: (i64, Value),
    ) -> Result<PreparedRefPair, VmError> {
        let values = if first.0 == second.0 {
            [None, Some(second)]
        } else {
            [Some(first), Some(second)]
        };
        if values
            .iter()
            .flatten()
            .any(|(_, value)| *value == Value::Nil)
        {
            return Err(VmError::LedgerInvariant);
        }

        // 低整數鍵可使兩次寫入共用一次 array grow；稀疏鍵仍留在 hash。
        let mut array_len = self.array.len();
        for _ in 0..2 {
            let boundary = values.iter().flatten().any(|(key, _)| {
                let canonical = CanonicalKey {
                    kind: KeyKind::Integer(*key),
                };
                canonical.array_index() == Some(array_len) && self.find_hash(&canonical).is_none()
            });
            if !boundary {
                break;
            }
            array_len = array_len
                .checked_mul(2)
                .map(|doubled| doubled.max(4))
                .ok_or(VmError::ArithmeticOverflow)?;
        }

        let mut slots = [None; 2];
        let mut hash_inserts = 0usize;
        for (ordinal, item) in values.iter().enumerate() {
            let Some((key, _)) = item else { continue };
            let canonical = CanonicalKey {
                kind: KeyKind::Integer(*key),
            };
            let array_index = canonical.array_index();
            slots[ordinal] = Some(
                if let Some(index) = array_index
                    && self.array.get(index).is_some_and(Option::is_some)
                {
                    RefPairSlot::Array(index)
                } else if let Some(index) = self.find_any_hash(&canonical) {
                    if self.hash[index]
                        .as_ref()
                        .is_some_and(|(_, value)| *value == Value::Nil)
                    {
                        ledger.checkpoint(FailPoint::TableInsert)?;
                        hash_inserts = hash_inserts
                            .checked_add(1)
                            .ok_or(VmError::ArithmeticOverflow)?;
                    }
                    RefPairSlot::HashExisting(index)
                } else if let Some(index) = array_index.filter(|index| *index < array_len) {
                    ledger.checkpoint(FailPoint::TableInsert)?;
                    RefPairSlot::Array(index)
                } else {
                    ledger.checkpoint(FailPoint::TableInsert)?;
                    hash_inserts = hash_inserts
                        .checked_add(1)
                        .ok_or(VmError::ArithmeticOverflow)?;
                    RefPairSlot::HashNew(0)
                },
            );
        }

        let array_growth = if array_len > self.array.len() {
            let old_bytes = checked_bytes(self.array.len(), size_of::<Option<Value>>())?;
            let new_bytes = checked_bytes(array_len, size_of::<Option<Value>>())?;
            let mut next = Vec::new();
            let ticket = reserve_vec(ledger, &mut next, array_len, FailPoint::TableArrayGrow)?;
            next.resize_with(array_len, || None);
            next[..self.array.len()].copy_from_slice(&self.array);
            Some(RefPairGrowth {
                next,
                ticket: Some(ticket),
                charge: None,
                old_bytes,
                new_bytes,
            })
        } else {
            None
        };

        let old_hash_count = self.live_hash_count();
        let occupied_hash_count = self.hash.iter().filter(|entry| entry.is_some()).count();
        let required_hash = old_hash_count
            .checked_add(hash_inserts)
            .ok_or(VmError::ArithmeticOverflow)?;
        let mut hash_len = self.hash.len();
        while required_hash > hash_len.saturating_sub(hash_len / 4)
            || occupied_hash_count
                .checked_add(hash_inserts)
                .ok_or(VmError::ArithmeticOverflow)?
                > hash_len
        {
            hash_len = hash_len
                .checked_mul(2)
                .map(|doubled| doubled.max(1))
                .ok_or(VmError::ArithmeticOverflow)?;
        }
        let hash_growth = if hash_len > self.hash.len() {
            let old_bytes =
                checked_bytes(self.hash.len(), size_of::<Option<(CanonicalKey, Value)>>())?;
            let new_bytes = checked_bytes(hash_len, size_of::<Option<(CanonicalKey, Value)>>())?;
            let mut next = Vec::new();
            let ticket = reserve_vec(ledger, &mut next, hash_len, FailPoint::TableHashGrow)?;
            next.resize_with(hash_len, || None);
            ledger.checkpoint(FailPoint::TableRehash)?;
            Some(RefPairGrowth {
                next,
                ticket: Some(ticket),
                charge: None,
                old_bytes,
                new_bytes,
            })
        } else {
            None
        };

        let mut next_hash_slot = old_hash_count;
        let mut claimed = [None; 2];
        for (ordinal, slot) in slots.iter_mut().enumerate() {
            match slot {
                Some(RefPairSlot::HashExisting(index)) if hash_growth.is_some() => {
                    if self.hash[*index]
                        .as_ref()
                        .is_some_and(|(_, value)| *value == Value::Nil)
                    {
                        *slot = Some(RefPairSlot::HashNew(next_hash_slot));
                        next_hash_slot += 1;
                    } else {
                        *index = self.hash[..*index]
                            .iter()
                            .flatten()
                            .filter(|(_, value)| *value != Value::Nil)
                            .count();
                    }
                }
                Some(RefPairSlot::HashNew(index)) if hash_growth.is_some() => {
                    *index = next_hash_slot;
                    next_hash_slot += 1;
                }
                Some(RefPairSlot::HashNew(index)) => {
                    let Some((key, _)) = values[ordinal] else {
                        return Err(VmError::LedgerInvariant);
                    };
                    let canonical = CanonicalKey {
                        kind: KeyKind::Integer(key),
                    };
                    let start = Self::bucket(&canonical, self.hash.len());
                    let Some(empty) = (0..self.hash.len())
                        .map(|step| Self::probe(start, step, self.hash.len()))
                        .find(|candidate| {
                            self.hash[*candidate].is_none() && !claimed.contains(&Some(*candidate))
                        })
                    else {
                        return Err(VmError::LedgerInvariant);
                    };
                    *index = empty;
                    claimed[ordinal] = Some(empty);
                }
                _ => {}
            }
        }
        Ok(PreparedRefPair {
            entries: [
                values[0]
                    .zip(slots[0])
                    .map(|((key, value), slot)| RefPairEntry { key, value, slot }),
                values[1]
                    .zip(slots[1])
                    .map(|((key, value), slot)| RefPairEntry { key, value, slot }),
            ],
            array_growth,
            hash_growth,
        })
    }

    /// 僅供 installer 的已存在 byte-key rollback；不重新建立 canonical key。
    fn restore_existing_byte_key(
        &mut self,
        _ledger: &AllocationLedger,
        name: &[u8],
        value: Value,
    ) -> Result<(), VmError> {
        let Some(index) = self.hash.iter().position(|entry| {
            entry.as_ref().is_some_and(|(key, stored)| {
                *stored != Value::Nil && key.string_bytes() == Some(name)
            })
        }) else {
            return Err(VmError::LedgerInvariant);
        };
        if value == Value::Nil {
            self.hash[index] = None;
            if self.hash.iter().all(Option::is_none) {
                self.hash = Vec::new();
                self.charges.clear_second();
            }
        } else if let Some((_, stored)) = &mut self.hash[index] {
            *stored = value;
        }
        Ok(())
    }
}

/// raw_set 的欄位準備；建構期間不改動原表，發布後沒有配置或可失敗出口。
pub(crate) enum PreparedTableMutation {
    Noop,
    ArraySlot {
        index: usize,
        value: Value,
    },
    HashSlot {
        index: usize,
        value: Value,
        dead_key: Option<CanonicalKey>,
    },
    HashReplace {
        index: usize,
        key: CanonicalKey,
        value: Value,
    },
    HashInsert {
        index: usize,
        key: CanonicalKey,
        value: Value,
    },
    GrowArray {
        next: Vec<Option<Value>>,
        ticket: Option<Reservation>,
        charge: Option<AllocationCharge>,
        old_bytes: usize,
        new_bytes: usize,
        value: Value,
    },
    GrowHash {
        next: Vec<Option<(CanonicalKey, Value)>>,
        ticket: Option<Reservation>,
        charge: Option<AllocationCharge>,
        old_bytes: usize,
        new_bytes: usize,
        existing_count: usize,
        key: CanonicalKey,
        value: Value,
    },
}

impl PreparedTableMutation {
    pub(crate) fn new_edges(&self) -> (Option<ObjectRef>, Option<ObjectRef>) {
        let (key, value) = match self {
            Self::Noop => return (None, None),
            Self::ArraySlot { value, .. }
            | Self::HashSlot { value, .. }
            | Self::GrowArray { value, .. } => (None, value),
            Self::HashReplace { key, value, .. }
            | Self::HashInsert { key, value, .. }
            | Self::GrowHash { key, value, .. } => (key.source_object(), value),
        };
        let value = match value {
            Value::Object(object) => Some(*object),
            _ => None,
        };
        (key, value)
    }

    fn commit_growth(
        ticket: &mut Option<Reservation>,
        charge: &mut Option<AllocationCharge>,
    ) -> Result<(), VmError> {
        let ticket = ticket.take().ok_or(VmError::LedgerInvariant)?;
        *charge = Some(ticket.commit_charge()?);
        Ok(())
    }

    pub(crate) fn commit_accounting(&mut self, _ledger: &AllocationLedger) -> Result<(), VmError> {
        match self {
            Self::GrowArray { ticket, charge, .. } | Self::GrowHash { ticket, charge, .. } => {
                Self::commit_growth(ticket, charge)
            }
            _ => Ok(()),
        }
    }

    pub(crate) fn apply(self, table: &mut Table) {
        match self {
            Self::Noop => {}
            Self::ArraySlot { index, value } => {
                table.array[index] = (value != Value::Nil).then_some(value);
            }
            Self::HashSlot {
                index,
                value,
                dead_key,
            } => {
                if value == Value::Nil {
                    table.hash[index] = dead_key.map(|key| (key, Value::Nil));
                } else if let Some((_, stored)) = &mut table.hash[index] {
                    *stored = value;
                }
            }
            Self::HashReplace { index, key, value } => {
                table.hash[index] = Some((key, value));
            }
            Self::HashInsert { index, key, value } => {
                table.hash[index] = Some((key, value));
            }
            Self::GrowArray { next, charge, .. } => {
                let old = core::mem::replace(&mut table.array, next);
                drop(old);
                if let Some(charge) = charge {
                    table.charges.replace_first(charge);
                }
            }
            Self::GrowHash {
                mut next,
                charge,
                existing_count,
                key,
                value,
                ..
            } => {
                // prepare 已證明 existing_count + 1 <= next.len()；find_hash 掃遍
                // 所有 bucket，因此連續 placement 與原先從 hash 起點探測等價。
                let old = core::mem::take(&mut table.hash);
                for (index, entry) in old
                    .into_iter()
                    .flatten()
                    .filter(|(_, value)| *value != Value::Nil)
                    .enumerate()
                {
                    next[index] = Some(entry);
                }
                next[existing_count] = Some((key, value));
                table.hash = next;
                if let Some(charge) = charge {
                    table.charges.replace_second(charge);
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum RefPairSlot {
    Array(usize),
    HashExisting(usize),
    HashNew(usize),
}

#[derive(Clone, Copy)]
struct RefPairEntry {
    key: i64,
    value: Value,
    slot: RefPairSlot,
}

struct RefPairGrowth<T> {
    next: Vec<T>,
    ticket: Option<Reservation>,
    charge: Option<AllocationCharge>,
    old_bytes: usize,
    new_bytes: usize,
}

/// 最多兩個整數欄位的共同預備結果；提交後不再配置或檢查失敗點。
pub(crate) struct PreparedRefPair {
    entries: [Option<RefPairEntry>; 2],
    array_growth: Option<RefPairGrowth<Option<Value>>>,
    hash_growth: Option<RefPairGrowth<Option<(CanonicalKey, Value)>>>,
}

impl PreparedRefPair {
    fn value_edges(&self) -> [Option<ObjectRef>; 2] {
        self.entries
            .map(|entry| match entry.map(|entry| entry.value) {
                Some(Value::Object(object)) => Some(object),
                _ => None,
            })
    }

    pub(crate) fn commit_accounting(&mut self, _ledger: &AllocationLedger) -> Result<(), VmError> {
        // 先驗證總量，避免已提交第一張票據後才因第二筆加總溢位退出。
        self.array_growth
            .as_ref()
            .map_or(0, |growth| growth.new_bytes)
            .checked_add(
                self.hash_growth
                    .as_ref()
                    .map_or(0, |growth| growth.new_bytes),
            )
            .ok_or(VmError::ArithmeticOverflow)?;
        self.array_growth
            .as_ref()
            .map_or(0, |growth| growth.old_bytes)
            .checked_add(
                self.hash_growth
                    .as_ref()
                    .map_or(0, |growth| growth.old_bytes),
            )
            .ok_or(VmError::ArithmeticOverflow)?;
        if let Some(growth) = &mut self.array_growth {
            growth.charge = Some(
                growth
                    .ticket
                    .take()
                    .ok_or(VmError::LedgerInvariant)?
                    .commit_charge()?,
            );
        }
        if let Some(growth) = &mut self.hash_growth {
            growth.charge = Some(
                growth
                    .ticket
                    .take()
                    .ok_or(VmError::LedgerInvariant)?
                    .commit_charge()?,
            );
        }
        Ok(())
    }

    pub(crate) fn apply(self, table: &mut Table) {
        if let Some(growth) = self.array_growth {
            let old = core::mem::replace(&mut table.array, growth.next);
            drop(old);
            if let Some(charge) = growth.charge {
                table.charges.replace_first(charge);
            }
        }
        if let Some(mut growth) = self.hash_growth {
            let old = core::mem::take(&mut table.hash);
            for (ordinal, entry) in old
                .into_iter()
                .flatten()
                .filter(|(_, value)| *value != Value::Nil)
                .enumerate()
            {
                growth.next[ordinal] = Some(entry);
            }
            table.hash = growth.next;
            if let Some(charge) = growth.charge {
                table.charges.replace_second(charge);
            }
        }
        for entry in self.entries.into_iter().flatten() {
            match entry.slot {
                RefPairSlot::Array(index) => table.array[index] = Some(entry.value),
                RefPairSlot::HashExisting(index) => {
                    if let Some((_, value)) = &mut table.hash[index] {
                        *value = entry.value;
                    }
                }
                RefPairSlot::HashNew(index) => {
                    table.hash[index] = Some((
                        CanonicalKey {
                            kind: KeyKind::Integer(entry.key),
                        },
                        entry.value,
                    ));
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalKeyClass {
    Integer,
    Float,
    Boolean,
    LightUserdata,
    CFunction,
    ByteString,
    Object,
}

struct StringKey {
    source: ObjectRef,
    bytes: ByteString,
    _charge: Option<crate::alloc::AllocationCharge>,
    _slot_charge: crate::alloc::AllocationCharge,
    _slot_extra_charge: Option<crate::alloc::AllocationCharge>,
}

struct LongStringKey(Vec<StringKey>);

impl LongStringKey {
    fn get(&self) -> &StringKey {
        &self.0[0]
    }

    fn get_mut(&mut self) -> &mut StringKey {
        &mut self.0[0]
    }
}

impl Drop for LongStringKey {
    fn drop(&mut self) {
        let entry = self.0.pop();
        self.0 = Vec::new();
        drop(entry);
    }
}

#[derive(Clone, Copy)]
struct InlineStringKey {
    source: ObjectRef,
    len: u8,
    bytes: [u8; 8],
}

impl InlineStringKey {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl StringKey {
    fn make_dead(&mut self, ledger: &AllocationLedger) -> Result<(), VmError> {
        if self.bytes.shared_external().is_some() {
            let (copy, ticket) = ByteString::try_from_bytes(ledger, self.bytes.as_bytes())?;
            let charge = ticket.commit_charge()?;
            self.bytes = copy;
            self._charge = Some(charge);
        }
        Ok(())
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
    LightUserdata(usize),
    CFunction(rivetlua_core::HostFunctionId),
    ShortString(InlineStringKey),
    ByteString(LongStringKey),
    DeadShortString(InlineStringKey),
    Object(ObjectKey),
}

/// 可儲存的寫鍵；建構時排除 nil 與 NaN，並正規化精確整數 float。
pub struct CanonicalKey {
    kind: KeyKind,
}

impl CanonicalKey {
    fn make_dead(&mut self, ledger: &AllocationLedger) -> Result<(), VmError> {
        if let KeyKind::ShortString(key) = &self.kind {
            self.kind = KeyKind::DeadShortString(*key);
            return Ok(());
        }
        if let KeyKind::ByteString(key) = &mut self.kind {
            key.get_mut().make_dead(ledger)?;
        }
        Ok(())
    }

    fn string_bytes(&self) -> Option<&[u8]> {
        match &self.kind {
            KeyKind::ShortString(key) | KeyKind::DeadShortString(key) => Some(key.as_bytes()),
            KeyKind::ByteString(key) => Some(key.get().bytes.as_bytes()),
            _ => None,
        }
    }

    fn matches_previous(&self, vm: &Vm, previous: Value) -> Result<bool, crate::vm::RuntimeError> {
        if let Some(bytes) = self.string_bytes() {
            return match previous {
                Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
                    Ok(vm.with_byte_string(object, |value| value.as_bytes() == bytes)?)
                }
                _ => Ok(false),
            };
        }
        match (&self.kind, previous) {
            (KeyKind::Object(key), Value::Object(object)) => Ok(object.identity() == Some(key.id)),
            (KeyKind::Object(_), _) => Ok(false),
            _ => vm.raw_equal_value(self.as_value(), previous),
        }
    }
    pub fn class(&self) -> CanonicalKeyClass {
        match self.kind {
            KeyKind::Integer(_) => CanonicalKeyClass::Integer,
            KeyKind::Float(_) => CanonicalKeyClass::Float,
            KeyKind::Boolean(_) => CanonicalKeyClass::Boolean,
            KeyKind::LightUserdata(_) => CanonicalKeyClass::LightUserdata,
            KeyKind::CFunction(_) => CanonicalKeyClass::CFunction,
            KeyKind::ShortString(_) | KeyKind::ByteString(_) | KeyKind::DeadShortString(_) => {
                CanonicalKeyClass::ByteString
            }
            KeyKind::Object(_) => CanonicalKeyClass::Object,
        }
    }

    /// 供 table 之後的 trace 使用；基本值不持有 heap 參照。
    pub(crate) fn source_object(&self) -> Option<ObjectRef> {
        match &self.kind {
            KeyKind::ShortString(key) => Some(key.source),
            KeyKind::ByteString(key) => Some(key.get().source),
            KeyKind::DeadShortString(key) => Some(key.source),
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
            KeyKind::LightUserdata(value) => Value::LightUserdata(*value),
            KeyKind::CFunction(value) => Value::CFunction(*value),
            KeyKind::ShortString(key) => Value::Object(key.source),
            KeyKind::ByteString(key) => Value::Object(key.get().source),
            KeyKind::DeadShortString(key) => Value::Object(key.source),
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
        if let (Some(left), Some(right)) = (self.string_bytes(), other.string_bytes()) {
            return left == right;
        }
        match (&self.kind, &other.kind) {
            (KeyKind::Integer(a), KeyKind::Integer(b)) => a == b,
            (KeyKind::Float(a), KeyKind::Float(b)) => a == b,
            (KeyKind::Boolean(a), KeyKind::Boolean(b)) => a == b,
            (KeyKind::LightUserdata(a), KeyKind::LightUserdata(b)) => a == b,
            (KeyKind::CFunction(a), KeyKind::CFunction(b)) => a == b,
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
            KeyKind::LightUserdata(value) => {
                5u8.hash(state);
                value.hash(state);
            }
            KeyKind::CFunction(value) => {
                6u8.hash(state);
                value.hash(state);
            }
            KeyKind::ShortString(key) => {
                3u8.hash(state);
                key.as_bytes().hash(state);
            }
            KeyKind::ByteString(key) => {
                3u8.hash(state);
                key.get().bytes.hash(state);
            }
            KeyKind::DeadShortString(key) => {
                3u8.hash(state);
                key.as_bytes().hash(state);
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
        self.with_table_mut(table, |stored, ledger| {
            stored.restore_existing_byte_key(ledger, name, value)
        })
    }

    pub fn canonical_key(&self, value: Value) -> Result<Option<CanonicalKey>, VmError> {
        let kind = match value {
            Value::Nil => return Ok(None),
            Value::Integer(value) => KeyKind::Integer(value),
            Value::Boolean(value) => KeyKind::Boolean(value),
            Value::LightUserdata(value) => KeyKind::LightUserdata(value),
            Value::CFunction(value) => {
                if value.vm() != self.id() {
                    return Err(VmError::WrongVm);
                }
                KeyKind::CFunction(value)
            }
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
                ObjectKind::ByteString => self.with_byte_string(source, |string| {
                    if string.len() <= 8 {
                        let mut bytes = [0; 8];
                        bytes[..string.len()].copy_from_slice(string.as_bytes());
                        return Ok(KeyKind::ShortString(InlineStringKey {
                            source,
                            len: string.len() as u8,
                            bytes,
                        }));
                    }
                    let ledger = self.allocation_ledger();
                    let (bytes, byte_charge) = if let Some(shared) = string.shared_external() {
                        (shared, None)
                    } else {
                        let (copy, byte_ticket) =
                            ByteString::try_from_bytes(ledger, string.as_bytes())?;
                        (copy, Some(byte_ticket.commit_charge()?))
                    };
                    let mut stored = Vec::new();
                    let ticket = reserve_vec(ledger, &mut stored, 1, FailPoint::TableKeyReserve)?;
                    let extra = stored.capacity() - 1;
                    let extra_charge = if extra == 0 {
                        None
                    } else {
                        let bytes = checked_bytes(extra, size_of::<StringKey>())?;
                        Some(
                            ledger
                                .reserve_lua_backing_excess(bytes, FailPoint::TableKeyReserve)?
                                .commit_charge()?,
                        )
                    };
                    let slot_charge = ticket.commit_charge()?;
                    stored.push(StringKey {
                        source,
                        bytes,
                        _charge: byte_charge,
                        _slot_charge: slot_charge,
                        _slot_extra_charge: extra_charge,
                    });
                    Ok(KeyKind::ByteString(LongStringKey(stored)))
                })??,
                ObjectKind::Value
                | ObjectKind::Table
                | ObjectKind::Userdata
                | ObjectKind::Closure
                | ObjectKind::CClosure
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

    pub fn raw_set(&mut self, table: ObjectRef, key: Value, value: Value) -> Result<(), VmError> {
        self.raw_set_with_new_key_source(table, key, value)
            .map(|_| ())
    }

    /// 與一般 raw_set 共用同一預備／發布交易；只回報本次真正新增的 key edge 來源。
    pub(crate) fn raw_set_with_new_key_source(
        &mut self,
        table: ObjectRef,
        key: Value,
        value: Value,
    ) -> Result<Option<ObjectRef>, VmError> {
        if self.object_kind(table)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        if let Value::CFunction(id) = value {
            if id.vm() != self.id() {
                return Err(VmError::WrongVm);
            }
        }
        match key {
            Value::Nil => return Err(VmError::NilTableKey),
            Value::Float(number) if number.is_nan() => return Err(VmError::NaNTableKey),
            _ => {}
        }
        // 準備期只有帳本預留、Vec 及純身分/hash 檢查；沒有 VM 物件配置、
        // GC、finalizer 或宿主回呼，因此 table/key/value 無須暫存 root。
        let canonical = self.canonical_key(key)?.ok_or(VmError::LedgerInvariant)?;
        let ledger = self.allocation_ledger().clone();
        let mutation = self.with_table(table, |stored| {
            stored.prepare_set(&ledger, canonical, value)
        })??;
        let (key_edge, value_edge) = mutation.new_edges();
        let barrier = self.prepare_table_write_barrier(table, key_edge, value_edge)?;
        self.commit_prepared_table_write(table, barrier, mutation)?;
        Ok(key_edge)
    }

    /// C auxiliary refs 專用：兩個非 nil 整數欄位共用一次準備與發布。
    /// key 相同時依參數順序以第二個值為最終欄位值。
    #[doc(hidden)]
    pub fn raw_set_ref_pair(
        &mut self,
        table: ObjectRef,
        first: (i64, Value),
        second: (i64, Value),
    ) -> Result<(), VmError> {
        if self.object_kind(table)? != ObjectKind::Table {
            return Err(VmError::WrongObjectType);
        }
        for value in [first.1, second.1] {
            if let Value::CFunction(id) = value {
                if id.vm() != self.id() {
                    return Err(VmError::WrongVm);
                }
            }
        }
        let ledger = self.allocation_ledger().clone();
        let mutation = self.with_table(table, |stored| {
            stored.prepare_ref_pair(&ledger, first, second)
        })??;
        let [first_edge, second_edge] = mutation.value_edges();
        let barrier = self.prepare_table_ref_barrier(table, first_edge, second_edge)?;
        self.commit_prepared_ref_pair(table, barrier, mutation)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    use rivetlua_core::{LuaProfile, ObjectRef, SlotId, Value};

    use crate::{
        AllocationDomain, CanonicalKey, CanonicalKeyClass, FailPoint, GcAge, GcColor, GcMode,
        GcPhase, HostHandle, ObjectKind, RootKind, Table, Vm, VmError, WeakMode,
    };

    #[test]
    fn b13_dead_key_layout_preserves_live_bucket_and_table() {
        #[allow(dead_code)]
        struct BaselineTableFields {
            metatable: Option<ObjectRef>,
            weak_mode: WeakMode,
            array: Vec<Option<Value>>,
            hash: Vec<Option<(CanonicalKey, Value)>>,
            charges: crate::alloc::PairedLuaCharges,
        }
        assert!(std::mem::size_of::<CanonicalKey>() <= std::mem::size_of::<super::StringKey>());
        assert_eq!(
            std::mem::size_of::<Table>(),
            std::mem::size_of::<BaselineTableFields>()
        );
        eprintln!(
            "B13 layout table={} key={} bucket={} string_key={}",
            std::mem::size_of::<Table>(),
            std::mem::size_of::<CanonicalKey>(),
            std::mem::size_of::<Option<(CanonicalKey, Value)>>(),
            std::mem::size_of::<super::StringKey>(),
        );
    }

    #[test]
    fn b14_table_charge_metadata_fits_shared_ledger_layout() {
        assert!(std::mem::size_of::<Table>() <= 160);
    }

    #[test]
    fn b14_short_key_does_not_expand_live_hash_bucket() {
        assert!(std::mem::size_of::<Option<(CanonicalKey, Value)>>() <= 104);
    }

    #[test]
    fn b14_short_embedded_nul_key_uses_charged_bucket_without_key_copy() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table_with_capacity(0, 1).unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let key = vm.allocate_byte_string(&[0, b'a', 0]).unwrap();
        let key_root = vm.add_root(RootKind::Host, key).unwrap();
        let before = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(key), Value::Integer(7))
            .unwrap();
        assert_eq!(vm.ledger_snapshot().lua_heap_bytes, before);
        let equal = vm.allocate_byte_string(&[0, b'a', 0]).unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Object(equal)),
            Ok(Value::Integer(7))
        );
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        assert_eq!(vm.raw_get(table, Value::Object(equal)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_next_value(table, Value::Object(equal)).unwrap(),
            None
        );
        vm.remove_root(key_root).unwrap();
        vm.remove_root(table_root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
    }

    #[test]
    fn b14_long_key_charges_actual_slot_capacity_until_rehash() {
        let mut vm = Vm::new().unwrap();
        let probe = vm.ledger_probe();
        let table = vm.allocate_table_with_capacity(0, 1).unwrap();
        let table_root = vm.add_root(RootKind::Host, table).unwrap();
        let bytes = [0, 0x80, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let key = vm.allocate_byte_string(&bytes).unwrap();
        let key_root = vm.add_root(RootKind::Host, key).unwrap();
        let before_insert = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Object(key), Value::Integer(1))
            .unwrap();
        let slot_capacity = vm
            .with_table(table, |stored| {
                let Some((canonical, _)) = stored.hash[0].as_ref() else {
                    unreachable!("已插入的唯一 hash 欄位須存在")
                };
                let super::KeyKind::ByteString(long) = &canonical.kind else {
                    unreachable!("長 byte key 應使用已計費的 slot backing")
                };
                long.0.capacity()
            })
            .unwrap();
        assert!(slot_capacity >= 1);
        let slot_bytes = slot_capacity * core::mem::size_of::<super::StringKey>();
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes - before_insert,
            bytes.len() + slot_bytes
        );
        vm.raw_set(table, Value::Object(key), Value::Nil).unwrap();
        vm.remove_root(key_root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
        let before_rehash = vm.ledger_snapshot().lua_heap_bytes;
        vm.raw_set(table, Value::Boolean(true), Value::Integer(2))
            .unwrap();
        let bucket_bytes = core::mem::size_of::<Option<(CanonicalKey, Value)>>();
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes + bytes.len() + slot_bytes,
            before_rehash + bucket_bytes
        );
        vm.remove_root(table_root).unwrap();
        vm.collect_major().unwrap();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    fn hash(key: &CanonicalKey) -> u64 {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn ref_pair_atomic_sparse_growth_barrier_and_weak_value_lifetime() {
        for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
            let mut failures = Vec::new();
            let mut successes = Vec::new();
            for offset in 0..10 {
                let mut vm = Vm::new_with_profile(profile).unwrap();
                let table = vm.allocate_table().unwrap();
                let root = vm.add_root(RootKind::Host, table).unwrap();
                let before = (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().total_count(),
                );
                let next = vm.allocation_trace().next_ordinal;
                vm.inject_allocation_failure_at(next + offset);
                let result =
                    vm.raw_set_ref_pair(table, (3, Value::Integer(0)), (100, Value::Integer(7)));
                if result.is_err() {
                    assert_eq!(vm.raw_get(table, Value::Integer(3)), Ok(Value::Nil));
                    assert_eq!(vm.raw_get(table, Value::Integer(100)), Ok(Value::Nil));
                    assert_eq!(
                        (
                            vm.ledger_snapshot(),
                            vm.gc_trace(),
                            vm.roots().total_count()
                        ),
                        before,
                    );
                    let failure = vm.allocation_trace().last_failure.unwrap();
                    assert_eq!(failure.attempt.ordinal, next + offset);
                    assert!(failure.attempt.site.file.ends_with("table.rs"));
                    failures.push((offset, failure.attempt.domain, failure.attempt.point));
                } else {
                    assert_eq!(vm.raw_get(table, Value::Integer(3)), Ok(Value::Integer(0)));
                    assert_eq!(
                        vm.raw_get(table, Value::Integer(100)),
                        Ok(Value::Integer(7))
                    );
                    vm.inject_allocation_failure_at(u64::MAX);
                    vm.raw_set_ref_pair(table, (3, Value::Integer(8)), (101, Value::Integer(9)))
                        .unwrap();
                    assert_eq!(
                        vm.raw_get(table, Value::Integer(100)),
                        Ok(Value::Integer(7))
                    );
                    assert_eq!(
                        vm.raw_get(table, Value::Integer(101)),
                        Ok(Value::Integer(9))
                    );
                    successes.push(offset);
                }
                vm.remove_root(root).unwrap();
            }
            assert_eq!(
                failures,
                vec![(0, AllocationDomain::LuaHeap, Some(FailPoint::TableHashGrow))]
            );
            assert_eq!(successes, (1..10).collect::<Vec<_>>());

            let mut vm = Vm::new_with_profile(profile).unwrap();
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
            let table = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, table).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
            let child = vm.allocate_table().unwrap();
            let before = (vm.ledger_snapshot(), vm.gc_trace());
            vm.inject_failure_once(FailPoint::RememberedReserve);
            assert_eq!(
                vm.raw_set_ref_pair(table, (3, Value::Integer(0)), (100, Value::Object(child))),
                Err(VmError::InjectedFailure(FailPoint::RememberedReserve)),
            );
            assert_eq!(vm.raw_get(table, Value::Integer(3)), Ok(Value::Nil));
            assert_eq!(vm.raw_get(table, Value::Integer(100)), Ok(Value::Nil));
            assert_eq!((vm.ledger_snapshot(), vm.gc_trace()), before);
            vm.raw_set_ref_pair(table, (3, Value::Integer(0)), (100, Value::Object(child)))
                .unwrap();
            assert_eq!(vm.gc_trace().remembered_len, 1);
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
            vm.raw_set_ref_pair(table, (3, Value::Integer(0)), (100, Value::Integer(0)))
                .unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
            vm.remove_root(root).unwrap();

            let mut vm = Vm::new_with_profile(profile).unwrap();
            let table = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, table).unwrap();
            let metatable = vm.allocate_table().unwrap();
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let weak_mode = vm.allocate_byte_string(b"v").unwrap();
            vm.raw_set(metatable, Value::Object(mode_key), Value::Object(weak_mode))
                .unwrap();
            vm.set_metatable(table, Some(metatable)).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.with_table(table, Table::weak_mode), Ok(WeakMode::Values));
            let child = vm.allocate_table().unwrap();
            vm.raw_set_ref_pair(table, (3, Value::Integer(0)), (100, Value::Object(child)))
                .unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
            assert_eq!(vm.raw_get(table, Value::Integer(100)), Ok(Value::Nil));
            vm.remove_root(root).unwrap();
        }
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
        let bytes = [0, 0x80, 0xff, 1, 2, 3, 4, 5, 6];
        let different_bytes = [0, 0x80, 0xff, 1, 2, 3, 4, 5, 7];
        let first = a.allocate_byte_string(&bytes).unwrap();
        let second = a.allocate_byte_string(&bytes).unwrap();
        let different = a.allocate_byte_string(&different_bytes).unwrap();
        let foreign = b.allocate_byte_string(&bytes).unwrap();
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
        a.inject_failure_once(FailPoint::TableKeyReserve);
        assert_eq!(
            a.canonical_key(Value::Object(first)),
            Err(VmError::InjectedFailure(FailPoint::TableKeyReserve))
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
    fn hash_single_bucket_growth_failures_and_reuse_keep_exact_ledger() {
        let mut vm = Vm::new().unwrap();
        let probe = vm.ledger_probe();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        let baseline = vm.ledger_snapshot().lua_heap_bytes;
        let bucket_bytes = core::mem::size_of::<Option<(CanonicalKey, Value)>>();

        for (key, capacity) in [(100, 1), (101, 2), (102, 4)] {
            let before = vm.ledger_snapshot();
            let old_capacity = vm
                .with_table(table, |stored| stored.hash_capacity())
                .unwrap();
            for point in [
                FailPoint::TableHashGrow,
                FailPoint::TableRehash,
                FailPoint::TableInsert,
            ] {
                vm.inject_failure_once(point);
                assert_eq!(
                    vm.raw_set(table, Value::Integer(key), Value::Integer(key)),
                    Err(VmError::InjectedFailure(point)),
                    "{key} {point:?}"
                );
                assert_eq!(vm.raw_get(table, Value::Integer(key)), Ok(Value::Nil));
                assert_eq!(
                    vm.with_table(table, |stored| stored.hash_capacity()),
                    Ok(old_capacity)
                );
                assert_eq!(vm.ledger_snapshot(), before);
            }
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
            assert_eq!(
                vm.with_table(table, |stored| stored.hash_capacity()),
                Ok(capacity)
            );
            assert_eq!(
                vm.ledger_snapshot().lua_heap_bytes - baseline,
                capacity * bucket_bytes
            );
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            for previous in 100..=key {
                assert_eq!(
                    vm.raw_get(table, Value::Integer(previous)),
                    Ok(Value::Integer(previous))
                );
            }
        }

        vm.raw_set(table, Value::Integer(101), Value::Nil).unwrap();
        let before_reuse = vm.ledger_snapshot();
        vm.raw_set(table, Value::Integer(103), Value::Integer(103))
            .unwrap();
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(4));
        assert_eq!(vm.ledger_snapshot(), before_reuse);
        assert_eq!(
            vm.raw_get(table, Value::Integer(100)),
            Ok(Value::Integer(100))
        );
        assert_eq!(vm.raw_get(table, Value::Integer(101)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_get(table, Value::Integer(102)),
            Ok(Value::Integer(102))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(103)),
            Ok(Value::Integer(103))
        );

        vm.raw_set(table, Value::Integer(101), Value::Integer(101))
            .unwrap();
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(8));
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes - baseline,
            8 * bucket_bytes
        );
        vm.collect_major().unwrap();
        for key in 100..=103 {
            assert_eq!(
                vm.raw_get(table, Value::Integer(key)),
                Ok(Value::Integer(key))
            );
        }
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert!(vm.ledger_snapshot().lua_heap_bytes < baseline);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }

    #[test]
    fn deleting_final_hash_entry_keeps_dead_positions_until_rehash() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        let baseline = vm.ledger_snapshot().lua_heap_bytes;
        let bucket_bytes = core::mem::size_of::<Option<(CanonicalKey, Value)>>();
        for key in [100, 101, 102] {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
        }
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(4));
        vm.raw_set(table, Value::Integer(101), Value::Nil).unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Integer(100)),
            Ok(Value::Integer(100))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(102)),
            Ok(Value::Integer(102))
        );
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(4));
        vm.raw_set(table, Value::Integer(100), Value::Nil).unwrap();
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes - baseline,
            4 * bucket_bytes
        );
        vm.raw_set(table, Value::Integer(102), Value::Nil).unwrap();
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(4));
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes,
            baseline + 4 * bucket_bytes
        );
        for key in [100, 101, 102] {
            assert_eq!(vm.raw_get(table, Value::Integer(key)), Ok(Value::Nil));
            assert_eq!(vm.raw_next_value(table, Value::Integer(key)).unwrap(), None);
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.raw_set(table, Value::Integer(103), Value::Integer(103))
            .unwrap();
        assert_eq!(
            vm.raw_get(table, Value::Integer(103)),
            Ok(Value::Integer(103))
        );
        vm.raw_set(table, Value::Integer(104), Value::Integer(104))
            .unwrap();
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(8));
        assert_eq!(
            vm.ledger_snapshot().lua_heap_bytes,
            baseline + 8 * bucket_bytes
        );
        vm.remove_root(root).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
        assert!(vm.ledger_snapshot().lua_heap_bytes < baseline);
    }

    #[test]
    fn raw_table_failed_insert_growth_and_rehash_preserve_old_fields_and_ledger() {
        for point in [
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
            if key == 100 {
                // 壓縮後單一 bucket 小於暫時 root；先占一格，讓拒絕發生於
                // 同時需要 root 與兩格 hash grow 的交易，而非把上限放寬。
                vm.raw_set(table, Value::Integer(99), Value::Integer(9))
                    .unwrap();
            }
            let base = vm.ledger_snapshot().committed;
            let probe = vm.add_root(RootKind::Temporary, table).unwrap();
            let root_charge = vm.ledger_snapshot().committed - base;
            vm.remove_root(probe).unwrap();
            vm.set_allocation_limit(base + root_charge);
            assert_eq!(
                vm.raw_set(table, Value::Integer(key), Value::Integer(7)),
                Err(VmError::AllocationFailed),
                "key={key}"
            );
            if key == 100 {
                assert_eq!(vm.raw_get(table, Value::Integer(99)), Ok(Value::Integer(9)));
                assert_eq!(vm.raw_get(table, Value::Integer(key)), Ok(Value::Nil));
                assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(1));
            } else {
                assert!(vm.with_table(table, |stored| stored.is_empty()).unwrap());
            }
            assert_eq!(vm.ledger_snapshot().committed, base);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.roots().total_count(), 0);
        }

        for allowed_roots in [1, 2] {
            let mut vm = Vm::new().unwrap();
            let table = vm.allocate_table().unwrap();
            // 初次 hash 只需一個 bucket；先填滿兩個 bucket，使此處仍測得
            // object key/value 暫存 root 與 hash 成長同時超額時的原子回滾。
            for key in [100, 101] {
                vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                    .unwrap();
            }
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
            assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Nil));
            assert_eq!(
                vm.raw_get(table, Value::Integer(100)),
                Ok(Value::Integer(100))
            );
            assert_eq!(
                vm.raw_get(table, Value::Integer(101)),
                Ok(Value::Integer(101))
            );
            assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(2));
            assert_eq!(vm.ledger_snapshot().committed, base);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(vm.roots().total_count(), 0);
        }

        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        for key in [100, 101] {
            vm.raw_set(table, Value::Integer(key), Value::Integer(key))
                .unwrap();
        }
        let key = vm
            .allocate_byte_string(&[0, 0x80, 0xff, 1, 2, 3, 4, 5, 6])
            .unwrap();
        let base = vm.ledger_snapshot().committed;
        let probe = vm.add_root(RootKind::Temporary, table).unwrap();
        let root_charge = vm.ledger_snapshot().committed - base;
        vm.remove_root(probe).unwrap();
        vm.set_allocation_limit(base + 2 * root_charge);
        assert_eq!(
            vm.raw_set(table, Value::Object(key), Value::Integer(1)),
            Err(VmError::AllocationFailed)
        );
        assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Nil));
        assert_eq!(
            vm.raw_get(table, Value::Integer(100)),
            Ok(Value::Integer(100))
        );
        assert_eq!(
            vm.raw_get(table, Value::Integer(101)),
            Ok(Value::Integer(101))
        );
        assert_eq!(vm.with_table(table, |stored| stored.hash_capacity()), Ok(2));
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
        assert_eq!(vm.ledger_snapshot().committed, before_key_delete);
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
        let string_key = vm
            .allocate_byte_string(&[0, 0x80, 1, 2, 3, 4, 5, 6, 7])
            .unwrap();
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

    #[test]
    fn generational_failed_raw_set_does_not_publish_remembered_or_barrier_state() {
        for active in [false, true] {
            let mut vm = Vm::new().unwrap();
            assert_eq!(vm.gc_mode(), GcMode::Generational);
            vm.stop_automatic_gc();
            vm.set_gc_promotion_survivals(1).unwrap();
            let table = vm.allocate_table().unwrap();
            let table_root = vm.add_root(RootKind::Host, table).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
            if active {
                for _ in 0..128 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause
                        && vm.gc_color(table) == Ok(GcColor::Black)
                    {
                        break;
                    }
                }
                assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                assert_eq!(vm.gc_color(table), Ok(GcColor::Black));
            }
            let key = vm.allocate_byte_string(b"young-key").unwrap();
            let value = vm.allocate_table().unwrap();
            if active {
                assert_eq!(vm.gc_color(key), Ok(GcColor::White));
                assert_eq!(vm.gc_color(value), Ok(GcColor::White));
            }

            for point in [
                FailPoint::StringBytesReserve,
                FailPoint::TableHashGrow,
                FailPoint::TableRehash,
                FailPoint::TableInsert,
                FailPoint::RememberedReserve,
            ] {
                let before_ledger = vm.ledger_snapshot();
                let before_gc = vm.gc_trace();
                let before_roots = vm.roots().total_count();
                let before_capacities = vm
                    .with_table(table, |stored| {
                        (stored.array_capacity(), stored.hash_capacity())
                    })
                    .unwrap();
                vm.inject_failure_once(point);
                assert_eq!(
                    vm.raw_set(table, Value::Object(key), Value::Object(value)),
                    Err(VmError::InjectedFailure(point)),
                    "active={active} {point:?}"
                );
                assert_eq!(vm.ledger_snapshot(), before_ledger, "{point:?}");
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                assert_eq!(vm.roots().total_count(), before_roots, "{point:?}");
                assert_eq!(vm.gc_trace(), before_gc, "active={active} {point:?}");
                assert_eq!(
                    vm.with_table(table, |stored| {
                        (stored.array_capacity(), stored.hash_capacity())
                    }),
                    Ok(before_capacities)
                );
                assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Nil));
            }

            vm.raw_set(table, Value::Object(key), Value::Object(value))
                .unwrap();
            assert_eq!(
                vm.raw_get(table, Value::Object(key)),
                Ok(Value::Object(value))
            );
            assert_eq!(vm.gc_trace().remembered_len, 1);
            if active {
                assert_ne!(vm.gc_color(key), Ok(GcColor::White));
                assert_ne!(vm.gc_color(value), Ok(GcColor::White));
                vm.collect().unwrap();
            } else {
                vm.collect_minor().unwrap();
            }
            assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
            assert_eq!(vm.object_kind(value), Ok(ObjectKind::Table));
            assert_eq!(
                vm.raw_get(table, Value::Object(key)),
                Ok(Value::Object(value))
            );
            vm.remove_root(table_root).unwrap();
            vm.collect_major().unwrap();
            assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }

    #[test]
    fn raw_set_does_not_consume_root_reserve_or_root_new_value_during_prepare() {
        let mut vm = Vm::new().unwrap();
        let table = vm.allocate_table().unwrap();
        let value = vm.allocate_table().unwrap();
        let before_roots = vm.roots().total_count();
        vm.inject_failure_once(FailPoint::RootReserve);
        vm.raw_set(table, Value::Integer(1), Value::Object(value))
            .unwrap();
        assert_eq!(vm.roots().total_count(), before_roots);
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(
            vm.raw_get(table, Value::Integer(1)),
            Ok(Value::Object(value))
        );
        assert_eq!(
            vm.add_root(RootKind::Temporary, table),
            Err(VmError::InjectedFailure(FailPoint::RootReserve))
        );
        assert_eq!(vm.roots().total_count(), before_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }

    #[test]
    fn equal_byte_key_replacement_does_not_publish_temporary_source_edge() {
        let mut vm = Vm::new().unwrap();
        vm.stop_automatic_gc();
        vm.set_gc_promotion_survivals(1).unwrap();
        let table = vm.allocate_table().unwrap();
        let root = vm.add_root(RootKind::Host, table).unwrap();
        let stored_key = vm.allocate_byte_string(b"same").unwrap();
        vm.raw_set(table, Value::Object(stored_key), Value::Integer(1))
            .unwrap();
        vm.collect().unwrap();
        assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
        let temporary_source = vm.allocate_byte_string(b"same").unwrap();
        let remembered = vm.gc_trace().remembered_len;
        vm.raw_set(table, Value::Object(temporary_source), Value::Integer(2))
            .unwrap();
        assert_eq!(vm.gc_trace().remembered_len, remembered);
        assert_eq!(
            vm.raw_get(table, Value::Object(stored_key)),
            Ok(Value::Integer(2))
        );
        vm.collect_minor().unwrap();
        assert_eq!(vm.object_kind(temporary_source), Err(VmError::StaleObject));
        assert_eq!(vm.object_kind(stored_key), Ok(ObjectKind::ByteString));
        vm.remove_root(root).unwrap();
    }

    #[test]
    fn weak_key_remembered_edge_and_string_exception_survive_prepare() {
        for string_key in [false, true] {
            let mut vm = Vm::new().unwrap();
            vm.stop_automatic_gc();
            vm.set_gc_promotion_survivals(1).unwrap();
            let table = vm.allocate_table().unwrap();
            let metatable = vm.allocate_table().unwrap();
            let mode_key = vm.allocate_byte_string(b"__mode").unwrap();
            let mode = vm.allocate_byte_string(b"k").unwrap();
            vm.raw_set(metatable, Value::Object(mode_key), Value::Object(mode))
                .unwrap();
            vm.set_metatable(table, Some(metatable)).unwrap();
            let root = vm.add_root(RootKind::Host, table).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.with_table(table, Table::weak_mode), Ok(WeakMode::Keys));
            let key = if string_key {
                vm.allocate_byte_string(b"weak-string").unwrap()
            } else {
                vm.allocate_table().unwrap()
            };
            vm.raw_set(table, Value::Object(key), Value::Integer(3))
                .unwrap();
            assert_eq!(vm.gc_trace().remembered_len, 1);
            vm.collect_minor().unwrap();
            if string_key {
                assert_eq!(vm.object_kind(key), Ok(ObjectKind::ByteString));
                assert_eq!(vm.raw_get(table, Value::Object(key)), Ok(Value::Integer(3)));
            } else {
                assert_eq!(vm.object_kind(key), Err(VmError::StaleObject));
                assert!(vm.with_table(table, Table::is_empty).unwrap());
                assert_eq!(vm.with_table(table, Table::hash_capacity), Ok(0));
                let replacement = vm.allocate_table().unwrap();
                vm.raw_set(table, Value::Object(replacement), Value::Integer(4))
                    .unwrap();
                assert_eq!(
                    vm.raw_get(table, Value::Object(replacement)),
                    Ok(Value::Integer(4))
                );
            }
            vm.remove_root(root).unwrap();
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        }
    }
}
