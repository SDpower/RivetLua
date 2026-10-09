use rivetlua_capi::stack::{
    StackError, StateOwner, lua_gettop, lua_rawgeti, lua_settop, luaL_ref, luaL_unref,
};
use rivetlua_core::Value;
use rivetlua_runtime::{ObjectKind, RootKind, VmError};

#[cfg(feature = "lua55")]
const REGISTRY: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY: i32 = -1_001_000;

#[test]
fn abi_neg003_rejects_foreign_and_stale_handles_without_mutation() {
    let owner = StateOwner::new().unwrap();
    let foreign = StateOwner::new().unwrap();
    let owner_probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let foreign_probe = foreign.with_vm(|vm| vm.ledger_probe()).unwrap();
    let object = owner
        .with_vm(|vm| vm.allocate_byte_string(b"p16-neg003").unwrap())
        .unwrap();
    let initial = foreign
        .with_vm(|vm| (vm.roots().count(RootKind::Host), vm.ledger_snapshot()))
        .unwrap();
    assert_eq!(
        foreign.push_value(Value::Object(object)),
        Err(StackError::Runtime(VmError::WrongVm))
    );
    assert_eq!(unsafe { lua_gettop(foreign.as_ptr()) }, 0);
    assert_eq!(
        foreign
            .with_vm(|vm| (vm.roots().count(RootKind::Host), vm.ledger_snapshot()))
            .unwrap(),
        initial
    );

    owner.push_value(Value::Object(object)).unwrap();
    let reference = unsafe { luaL_ref(owner.as_ptr(), REGISTRY) };
    assert!(reference >= 0);
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 0);
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
        Ok(ObjectKind::ByteString)
    );
    assert_eq!(
        unsafe { lua_rawgeti(owner.as_ptr(), REGISTRY, reference.into()) },
        4
    );
    unsafe {
        lua_settop(owner.as_ptr(), 0);
        luaL_unref(owner.as_ptr(), REGISTRY, reference);
    }
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
        Err(VmError::StaleObject)
    );
    let stale_id = object.identity().unwrap();
    let replacement = owner
        .with_vm(|vm| vm.allocate_byte_string(b"new").unwrap())
        .unwrap();
    let replacement_id = replacement.identity().unwrap();
    assert_eq!(replacement_id.vm, stale_id.vm);
    assert_eq!(replacement_id.slot, stale_id.slot);
    assert_ne!(replacement_id.generation, stale_id.generation);
    let before = owner
        .with_vm(|vm| (vm.roots().count(RootKind::Host), vm.ledger_snapshot()))
        .unwrap();
    assert_eq!(
        owner.push_value(Value::Object(object)),
        Err(StackError::Runtime(VmError::StaleObject))
    );
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 0);
    assert_eq!(
        owner
            .with_vm(|vm| (vm.roots().count(RootKind::Host), vm.ledger_snapshot()))
            .unwrap(),
        before
    );
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(replacement)).unwrap(),
        Ok(ObjectKind::ByteString)
    );
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.object_kind(replacement)).unwrap(),
        Err(VmError::StaleObject)
    );
    drop(owner);
    drop(foreign);
    assert_eq!(owner_probe.snapshot().committed, 0);
    assert_eq!(owner_probe.snapshot().reserved, 0);
    assert_eq!(foreign_probe.snapshot().committed, 0);
    assert_eq!(foreign_probe.snapshot().reserved, 0);
}
