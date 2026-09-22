//! P01 值分類與不透明物件身分。

use core::num::NonZeroU64;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_OBJECT_ID: AtomicU64 = AtomicU64::new(1);

/// 不透明物件身分。
///
/// 這個型別不暴露裸指標、heap slot 或可變 heap 存取。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ObjectRef(NonZeroU64);

impl ObjectRef {
    /// 配置新的不透明身分；配置器耗盡時回傳 None。
    pub fn new_opaque() -> Option<Self> {
        let id = NEXT_OBJECT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok()?;
        NonZeroU64::new(id).map(Self)
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
