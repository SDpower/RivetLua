//! P01 值分類與不透明物件身分。

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_OPAQUE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_VM_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_RUNTIME_TOKEN: AtomicU64 = AtomicU64::new(1);

/// 每個 VM 建立時取得的唯一身分。全域流水號只用於區分 VM，不能單獨識別物件。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct VmId(NonZeroU64);

impl VmId {
    /// 取得唯一 VM 身分；耗盡時回傳 None，不繞回舊 VM。
    pub fn new_unique() -> Option<Self> {
        let id = NEXT_VM_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        NonZeroU64::new(id).map(Self)
    }
}

/// VM 內的 slot 索引；其本身不是物件身分。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SlotId(usize);

impl SlotId {
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    pub const fn index(self) -> usize {
        self.0
    }
}

/// slot 每次回收後的世代。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }

    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(next) => Some(Self(next)),
            None => None,
        }
    }
}

/// 完整 heap 物件身分。建立此值不代表物件存在；runtime 每次存取仍須驗證。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ObjectId {
    pub vm: VmId,
    pub slot: SlotId,
    pub generation: Generation,
}

impl ObjectId {
    pub const fn new(vm: VmId, slot: SlotId, generation: Generation) -> Self {
        Self {
            vm,
            slot,
            generation,
        }
    }
}

/// 不透明物件身分。
///
/// P01 的舊 opaque 身分保留作值分類；runtime 只接受完整 heap 身分。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ObjectRef(ObjectRefKind);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
enum ObjectRefKind {
    Opaque(NonZeroU64),
    Heap {
        id: ObjectId,
        token: Option<NonZeroU64>,
    },
}

impl ObjectRef {
    /// 配置新的不透明身分；配置器耗盡時回傳 None。
    pub fn new_opaque() -> Option<Self> {
        let id = NEXT_OPAQUE_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        NonZeroU64::new(id).map(|id| Self(ObjectRefKind::Opaque(id)))
    }

    /// 包裝未驗證的完整身分；單憑公開欄位不能建立可解參照的物件。
    pub const fn from_id(id: ObjectId) -> Self {
        Self(ObjectRefKind::Heap { id, token: None })
    }

    /// 取得本次配置的唯一驗證 token；runtime 必須保存並逐次比對原參照。
    /// 即使呼叫者自行建立此值，也無法重建已配置物件的 token。
    pub fn new_runtime(id: ObjectId) -> Option<Self> {
        let token = NEXT_RUNTIME_TOKEN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        Some(Self(ObjectRefKind::Heap {
            id,
            token: Some(NonZeroU64::new(token)?),
        }))
    }

    /// 取得完整 heap 身分；舊 P01 opaque 值不具有 heap 身分。
    pub const fn identity(self) -> Option<ObjectId> {
        match self.0 {
            ObjectRefKind::Opaque(_) => None,
            ObjectRefKind::Heap { id, .. } => Some(id),
        }
    }
}

/// P01 唯一的值分類。
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    Nil,
    Boolean(bool),
    Integer(i64),
    Float(f64),
    Object(ObjectRef),
}

/// 不攜帶 payload 的值分類，可用於錯誤與報告。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueKind {
    Nil,
    Boolean,
    Integer,
    Float,
    Object,
}

impl Value {
    /// 取得值的分類且不轉換 payload。
    pub const fn kind(self) -> ValueKind {
        match self {
            Self::Nil => ValueKind::Nil,
            Self::Boolean(_) => ValueKind::Boolean,
            Self::Integer(_) => ValueKind::Integer,
            Self::Float(_) => ValueKind::Float,
            Self::Object(_) => ValueKind::Object,
        }
    }

    /// Lua 真值：只有 nil 與 false 為假。
    pub const fn is_truthy(self) -> bool {
        !matches!(self, Self::Nil | Self::Boolean(false))
    }
}

/// 保留操作數的 `and` 選擇規則；不負責求值第二個操作數。
pub const fn select_and(left: Value, right: Value) -> Value {
    if left.is_truthy() { right } else { left }
}

/// 保留操作數的 `or` 選擇規則；不負責求值第二個操作數。
pub const fn select_or(left: Value, right: Value) -> Value {
    if left.is_truthy() { left } else { right }
}

#[cfg(test)]
mod tests {
    use super::{ObjectRef, Value, ValueKind, select_and, select_or};

    #[test]
    fn every_value_has_an_unambiguous_kind() {
        let object = ObjectRef::new_opaque().unwrap();
        assert_eq!(Value::Nil.kind(), ValueKind::Nil);
        assert_eq!(Value::Boolean(false).kind(), ValueKind::Boolean);
        assert_eq!(Value::Integer(0).kind(), ValueKind::Integer);
        assert_eq!(Value::Float(f64::NAN).kind(), ValueKind::Float);
        assert_eq!(Value::Object(object).kind(), ValueKind::Object);
    }

    #[test]
    fn object_identity_is_opaque_and_comparable() {
        let first = ObjectRef::new_opaque().unwrap();
        let same = first;
        let second = ObjectRef::new_opaque().unwrap();
        assert_eq!(first, same);
        assert_ne!(first, second);
    }

    #[test]
    fn float_payloads_keep_ieee_categories() {
        assert!(matches!(Value::Float(f64::NAN), Value::Float(value) if value.is_nan()));
        assert!(matches!(Value::Float(f64::INFINITY), Value::Float(value) if value.is_infinite()));
        assert!(matches!(Value::Float(-0.0), Value::Float(value) if value.is_sign_negative()));
    }

    #[test]
    fn truthiness_and_selection_keep_original_values() {
        let object = Value::Object(ObjectRef::new_opaque().unwrap());
        assert!(!Value::Nil.is_truthy());
        assert!(!Value::Boolean(false).is_truthy());
        assert!(Value::Integer(0).is_truthy());
        assert!(object.is_truthy());
        assert_eq!(
            select_and(Value::Integer(0), Value::Integer(7)),
            Value::Integer(7)
        );
        assert_eq!(select_or(object, Value::Integer(8)), object);
        assert_eq!(select_and(Value::Nil, Value::Integer(7)), Value::Nil);
        assert_eq!(select_or(Value::Nil, Value::Integer(8)), Value::Integer(8));
    }
}
