use rivetlua_core::{ObjectRef, Value, ValueKind};

#[test]
fn public_value_api_preserves_categories_and_object_identity() {
    let object = ObjectRef::new_opaque().unwrap();
    assert_eq!(Value::Nil.kind(), ValueKind::Nil);
    assert_eq!(Value::Boolean(true).kind(), ValueKind::Boolean);
    assert_eq!(Value::Integer(0).kind(), ValueKind::Integer);
    assert_eq!(Value::Float(-0.0).kind(), ValueKind::Float);
    assert_eq!(Value::Object(object).kind(), ValueKind::Object);
    assert_eq!(object, object);
}
