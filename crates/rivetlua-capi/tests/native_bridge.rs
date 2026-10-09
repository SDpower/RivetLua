use std::any::Any;
use std::cell::RefCell;
use std::ffi::c_int;
use std::mem::size_of;
use std::rc::Rc;

use rivetlua_capi::stack::{
    StackError, StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushcclosure,
    lua_pushinteger, lua_pushstring, lua_rawset, lua_setmetatable, lua_settop, lua_tointegerx,
    lua_type,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, EnvironmentSource, FrameLayout, Instruction, LuaProfile, ProtoId,
    RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, Value, VerifiedModule, VerifyLimits,
    verified_module_allocation_bytes, verify_module,
};
use rivetlua_runtime::{AllocationFailureKind, RootKind};

unsafe extern "C" {
    fn lua_gc(state: *mut lua_State, what: c_int, ...) -> c_int;
}

struct DropMarker {
    id: usize,
    order: Rc<RefCell<Vec<usize>>>,
}

impl Drop for DropMarker {
    fn drop(&mut self) {
        self.order.borrow_mut().push(self.id);
    }
}

fn module(profile: LuaProfile) -> VerifiedModule {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let environment = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    verify_module(
        BytecodeModule {
            format_version: RVLU_V2,
            profile,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 3,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 4096,
                    initial_top: Register(3),
                    dynamic_top: Register(3),
                    return_base: Register(0),
                    environment: Register(2),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(2),
                global_environment_binding: environment,
                binding_registers: vec![(environment, Register(2))],
                constants: vec![BytecodeConstant::String(vec![b'x'; 256])],
                upvalues: vec![],
                instructions: vec![BytecodeInstruction {
                    instruction: Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(0),
                    },
                    span,
                    close_path: None,
                }],
                close_paths: vec![],
            }],
        },
        profile,
        &VerifyLimits::default(),
    )
    .unwrap()
}

fn active_profile() -> LuaProfile {
    if cfg!(feature = "lua55") {
        LuaProfile::Lua55
    } else {
        LuaProfile::Lua54
    }
}

#[test]
fn native_lease_cancel_failure_and_reverse_group_drop() {
    let order = Rc::new(RefCell::new(Vec::new()));
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();

    let ticket = owner.reserve_native_lease(101).unwrap();
    assert!(owner.with_vm(|vm| vm.ledger_snapshot().reserved).unwrap() >= 101);
    drop(ticket);
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);

    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(vm.allocation_trace().next_ordinal))
        .unwrap();
    assert!(owner.reserve_native_lease(101).is_err());
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);

    let first: Rc<dyn Any> = Rc::new(DropMarker {
        id: 1,
        order: order.clone(),
    });
    owner
        .reserve_native_lease(101)
        .unwrap()
        .publish(first)
        .unwrap();
    let second: Rc<dyn Any> = Rc::new(DropMarker {
        id: 2,
        order: order.clone(),
    });
    sibling
        .reserve_native_lease(202)
        .unwrap()
        .publish(second)
        .unwrap();
    let held = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    assert!(held.host_allocation_bytes >= before.host_allocation_bytes + 303);
    assert_eq!(held.reserved, 0);
    drop(owner);
    assert!(order.borrow().is_empty());
    drop(sibling);
    assert_eq!(&*order.borrow(), &[2, 1]);
}

thread_local! {
    static FINALIZER_ORDER: RefCell<Option<Rc<RefCell<Vec<usize>>>>> = const { RefCell::new(None) };
}

unsafe extern "C" fn mark_finalized(_state: *mut lua_State) -> c_int {
    FINALIZER_ORDER.with(|slot| {
        if let Some(order) = slot.borrow().as_ref() {
            order.borrow_mut().push(0);
        }
    });
    0
}

fn install_finalizable_table(state: *mut lua_State) {
    // SAFETY：有效 state；__gc 回呼只記錄順序且不跳轉。
    unsafe {
        lua_createtable(state, 0, 0);
        lua_createtable(state, 0, 1);
        lua_pushstring(state, c"__gc".as_ptr());
        lua_pushcclosure(state, Some(mark_finalized), 0);
        lua_rawset(state, -3);
        assert_eq!(lua_setmetatable(state, -2), 1);
        lua_settop(state, 0);
    }
}

#[test]
fn vm_finalizer_runs_while_native_lease_is_alive() {
    let order = Rc::new(RefCell::new(Vec::new()));
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = Some(order.clone()));
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let lease: Rc<dyn Any> = Rc::new(DropMarker {
        id: 1,
        order: order.clone(),
    });
    owner
        .reserve_native_lease(37)
        .unwrap()
        .publish(lease)
        .unwrap();

    install_finalizable_table(state);
    // SAFETY：C driver 以 checkpoint 執行 full GC 與 C __gc，不讓回呼跨越 Rust VM 借用。
    assert_eq!(unsafe { lua_gc(state, 2) }, 0);
    assert_eq!(&*order.borrow(), &[0]);
    drop(owner);
    assert_eq!(&*order.borrow(), &[0, 1]);
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = None);
}

#[test]
fn rust_owner_close_runs_finalizer_before_lease_and_invalidates_owner() {
    let order = Rc::new(RefCell::new(Vec::new()));
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = Some(order.clone()));
    let mut owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let lease: Rc<dyn Any> = Rc::new(DropMarker {
        id: 1,
        order: order.clone(),
    });
    let weak_lease = Rc::downgrade(&lease);
    owner
        .reserve_native_lease(37)
        .unwrap()
        .publish(lease)
        .unwrap();
    install_finalizable_table(state);

    owner.close_with_finalizers().unwrap();
    assert_eq!(&*order.borrow(), &[0, 1]);
    assert!(weak_lease.upgrade().is_none());
    assert!(owner.as_ptr().is_null());
    assert_eq!(owner.with_vm(|_| ()), Err(StackError::InvalidState));
    assert_eq!(owner.close_with_finalizers(), Err(StackError::InvalidState));
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = None);
}

#[test]
fn rust_owner_close_rejects_sibling_and_busy_borrow_without_consuming_owner() {
    let mut owner = StateOwner::new().unwrap();
    let mut sibling = owner.new_sibling().unwrap();
    assert_eq!(
        sibling.close_with_finalizers(),
        Err(StackError::InvalidState)
    );
    assert_eq!(
        sibling.with_vm(|_| owner.close_with_finalizers()),
        Ok(Err(StackError::Busy))
    );
    assert!(!owner.as_ptr().is_null());
    owner.push_value(Value::Integer(17)).unwrap();
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
    owner.close_with_finalizers().unwrap();
    assert!(owner.as_ptr().is_null());
}

#[test]
fn rust_owner_close_allocation_failure_preserves_prefix_lease_and_retry() {
    let order = Rc::new(RefCell::new(Vec::new()));
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = Some(order.clone()));
    let mut owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let lease: Rc<dyn Any> = Rc::new(DropMarker {
        id: 1,
        order: order.clone(),
    });
    let weak_lease = Rc::downgrade(&lease);
    owner
        .reserve_native_lease(37)
        .unwrap()
        .publish(lease)
        .unwrap();
    install_finalizable_table(state);
    fill_primitive_prefix(&owner);
    let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();

    let failed = owner.close_with_finalizers();
    assert!(matches!(failed, Err(StackError::Runtime(_))), "{failed:?}");
    assert_eq!(
        owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
            .unwrap(),
        ordinal
    );
    assert_eq!(owner.as_ptr(), state);
    assert_primitive_prefix(state);
    assert_eq!(&*order.borrow(), &[]);
    assert!(weak_lease.upgrade().is_some());
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);

    owner.close_with_finalizers().unwrap();
    assert_eq!(&*order.borrow(), &[0, 1]);
    assert!(weak_lease.upgrade().is_none());
    assert!(owner.as_ptr().is_null());
    FINALIZER_ORDER.with(|slot| *slot.borrow_mut() = None);
}

#[test]
fn verified_module_stack_root_profile_and_gc_refund() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let profile = active_profile();
    let foreign = if profile == LuaProfile::Lua55 {
        LuaProfile::Lua54
    } else {
        LuaProfile::Lua55
    };
    let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    assert!(owner.push_verified_module(module(foreign)).is_err());
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), before);
    assert_eq!(unsafe { lua_gettop(state) }, 0);

    let verified = module(profile);
    let retained =
        verified_module_allocation_bytes(&verified).unwrap() - size_of::<VerifiedModule>();
    owner.push_verified_module(verified).unwrap();
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(unsafe { lua_type(state, -1) }, 6);
    let held = owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 1);
            vm.collect().unwrap();
            vm.ledger_snapshot()
        })
        .unwrap();
    assert!(held.host_allocation_bytes >= before.host_allocation_bytes + retained);
    assert_eq!(held.reserved, 0);
    unsafe { lua_settop(state, 0) };
    let released = owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            vm.ledger_snapshot()
        })
        .unwrap();
    assert!(held.host_allocation_bytes >= released.host_allocation_bytes + retained);
    assert_eq!(released.reserved, 0);
}

fn fill_primitive_prefix(owner: &StateOwner) {
    for index in 0..20 {
        owner.push_value(Value::Integer(1000 + index)).unwrap();
    }
}

fn assert_primitive_prefix(state: *mut lua_State) {
    unsafe {
        assert_eq!(lua_gettop(state), 20);
        for index in 0..20 {
            assert_eq!(
                lua_tointegerx(state, index + 1, std::ptr::null_mut()),
                i64::from(1000 + index)
            );
        }
    }
}

#[test]
fn verified_module_stack_to_host_root_each_allocation_ordinal() {
    let verified = module(active_profile());
    let capacity_probe = StateOwner::new().unwrap();
    fill_primitive_prefix(&capacity_probe);
    let before_capacity = capacity_probe.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    capacity_probe.push_value(Value::Integer(1020)).unwrap();
    unsafe { lua_settop(capacity_probe.as_ptr(), 20) };
    let after_capacity = capacity_probe.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    let capacity_delta = after_capacity
        .host_allocation_bytes
        .checked_sub(before_capacity.host_allocation_bytes)
        .unwrap();
    assert!(capacity_delta > 0);

    let dry = StateOwner::new().unwrap();
    fill_primitive_prefix(&dry);
    let dry_start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    dry.push_verified_module(verified.clone()).unwrap();
    let dry_end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    let attempts = dry_end - dry_start;
    assert!(attempts >= 3, "未涵蓋 stack／module／root 分配：{attempts}");
    eprintln!("B2 VerifiedModule dry allocation attempts={attempts}");
    assert_eq!(unsafe { lua_gettop(dry.as_ptr()) }, 21);
    assert_eq!(unsafe { lua_type(dry.as_ptr(), -1) }, 6);

    let mut failed = 0u64;
    for offset in 0..attempts {
        let owner = StateOwner::new().unwrap();
        fill_primitive_prefix(&owner);
        let state = owner.as_ptr();
        let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        let start = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(start + offset))
            .unwrap();
        let result = owner.push_verified_module(verified.clone());
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap()
            .expect("dry run 的每個 ordinal 都須實際到達失敗注入點");
        assert_eq!(failure.attempt.ordinal, start + offset);
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        eprintln!(
            "B2 VerifiedModule offset={offset} ordinal={} domain={:?} point={:?}",
            failure.attempt.ordinal, failure.attempt.domain, failure.attempt.point
        );
        assert!(
            result.is_err(),
            "注入 allocation failure 卻成功：offset={offset} failure={failure:?}"
        );
        failed += 1;
        assert_primitive_prefix(state);
        owner
            .with_vm(|vm| {
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                assert_eq!(vm.roots().count(RootKind::Temporary), 0);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.collect().unwrap();
                let after = vm.ledger_snapshot();
                assert_eq!(after.reserved, 0);
                assert!(
                    after.host_allocation_bytes <= baseline.host_allocation_bytes + capacity_delta,
                    "offset={offset} baseline={baseline:?} after={after:?}"
                );
            })
            .unwrap();
    }
    assert_eq!(failed, attempts);
    eprintln!("B2 VerifiedModule failed={failed}/attempts={attempts}");
}

unsafe extern "C" fn open_integer(state: *mut lua_State) -> c_int {
    unsafe { lua_pushinteger(state, 41) };
    1
}

#[test]
fn protected_requiref_keeps_prefix_and_cached_result() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    unsafe { lua_pushinteger(state, 73) };
    // SAFETY：測試 opener 不跳轉、同步返回；state 與函式在整段呼叫期間有效。
    assert_eq!(
        unsafe { owner.requiref_protected(c"native_bridge_b2", open_integer, true) },
        Ok(0)
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 73);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 41);
        lua_settop(state, 1);
    }
    // SAFETY：先前快取 truthy；同一有效 state 與無跳轉 opener。
    assert_eq!(
        unsafe { owner.requiref_protected(c"native_bridge_b2", open_integer, false) },
        Ok(0)
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 41);
    }
}
