use rivetlua_core::{Generation, ObjectId, ObjectRef, SlotId, Value, ValueKind, VmId};

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

#[test]
fn object_values_compare_all_heap_identity_fields() {
    let vm_a = VmId::new_unique().unwrap();
    let vm_b = VmId::new_unique().unwrap();
    let first = ObjectRef::from_id(ObjectId::new(vm_a, SlotId::new(0), Generation::new(0)));
    let foreign = ObjectRef::from_id(ObjectId::new(vm_b, SlotId::new(0), Generation::new(0)));
    let next_slot = ObjectRef::from_id(ObjectId::new(vm_a, SlotId::new(1), Generation::new(0)));
    let next_generation =
        ObjectRef::from_id(ObjectId::new(vm_a, SlotId::new(0), Generation::new(1)));
    assert_eq!(Value::Object(first).kind(), ValueKind::Object);
    assert_ne!(first, foreign);
    assert_ne!(first, next_slot);
    assert_ne!(first, next_generation);
    assert_eq!(first, ObjectRef::from_id(first.identity().unwrap()));
    assert!(ObjectRef::new_opaque().unwrap().identity().is_none());
}
