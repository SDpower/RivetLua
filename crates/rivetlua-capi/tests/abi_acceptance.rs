use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use rivetlua_capi::error::{ErrorClass, Reject, prepare};
use rivetlua_capi::stack::{
    StateOwner, lua_gettop, lua_newuserdatauv, lua_rawgeti, lua_settop, lua_touserdata, luaL_ref,
    luaL_unref,
};
use rivetlua_capi::trampoline::{Action, Checkpoint, Outcome, protect};
use rivetlua_runtime::{AllocationDomain, FailPoint, ObjectKind, RootKind, VmError};

#[cfg(feature = "lua55")]
const REGISTRY: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY: i32 = -1_001_000;

struct DropGuard(Arc<AtomicUsize>);

impl Drop for DropGuard {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn abi003_refs_userdata_survive_gc_and_release_ledger() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    let baseline = owner
        .with_vm(|vm| (vm.roots().count(RootKind::Host), vm.ledger_snapshot()))
        .unwrap();
    let pointer = unsafe { lua_newuserdatauv(state, 32, 0) };
    assert!(!pointer.is_null());
    // SAFETY：pointer 為仍由 C stack 保活的 32-byte userdata。
    unsafe { pointer.cast::<u8>().write(0x5a) };
    let object = owner
        .with_vm(|vm| {
            let mut found = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host && vm.object_kind(object) == Ok(ObjectKind::Userdata) {
                    found.push(object);
                }
            });
            assert_eq!(found.len(), 1);
            found[0]
        })
        .unwrap();
    let reference = unsafe { luaL_ref(state, REGISTRY) };
    assert!(reference >= 0);
    assert_eq!(unsafe { lua_gettop(state) }, 0);
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    assert_eq!(unsafe { lua_rawgeti(state, REGISTRY, reference.into()) }, 7);
    assert_eq!(unsafe { lua_touserdata(state, -1) }, pointer);
    // SAFETY：registry ref 與新 stack slot 在本次讀取期間保活 userdata。
    assert_eq!(unsafe { pointer.cast::<u8>().read() }, 0x5a);
    unsafe {
        lua_settop(state, 0);
        luaL_unref(state, REGISTRY, reference);
    }
    owner.with_vm(|vm| vm.collect()).unwrap().unwrap();
    owner
        .with_vm(|vm| {
            assert_eq!(vm.object_kind(object), Err(VmError::StaleObject));
            assert_eq!(vm.roots().count(RootKind::Host), baseline.0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

#[test]
fn abi004_internal_adapter_ledger_every_allocation_ordinal_rolls_back() {
    let dry = StateOwner::new().unwrap();
    let start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(!unsafe { lua_newuserdatauv(dry.as_ptr(), 17, 3) }.is_null());
    let end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert!(end > start);
    let count = end - start;
    drop(dry);

    let mut observed = Vec::new();
    for offset in 0..count {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        let before = owner
            .with_vm(|vm| {
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().count(RootKind::Host),
                )
            })
            .unwrap();
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
            .unwrap();
        assert!(
            unsafe { lua_newuserdatauv(state, 17, 3) }.is_null(),
            "offset={offset}"
        );
        let after = owner
            .with_vm(|vm| {
                let failure = vm.allocation_trace().last_failure.unwrap();
                observed.push((failure.attempt.domain, failure.attempt.point));
                (
                    vm.ledger_snapshot(),
                    vm.gc_trace(),
                    vm.roots().count(RootKind::Host),
                )
            })
            .unwrap();
        assert_eq!(after, before, "offset={offset}");
        assert_eq!(unsafe { lua_gettop(state) }, 0);
        assert!(!unsafe { lua_newuserdatauv(state, 17, 3) }.is_null());
        unsafe { lua_settop(state, 0) };
        drop(owner);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
    assert_eq!(observed.len() as u64, count);
    assert_eq!(
        observed,
        [
            (
                AllocationDomain::LuaHeap,
                Some(FailPoint::UserdataBytesReserve)
            ),
            (
                AllocationDomain::LuaHeap,
                Some(FailPoint::UserdataUservaluesReserve)
            ),
            (AllocationDomain::LuaHeap, Some(FailPoint::SlotReserve)),
            (AllocationDomain::LuaHeap, Some(FailPoint::ObjectReserve)),
            (AllocationDomain::Host, None),
            (AllocationDomain::Host, None),
        ]
    );
}

#[test]
fn abi_neg001_live_rust_guard_rejects_missing_c_checkpoint() {
    let drops = Arc::new(AtomicUsize::new(0));
    let owner = StateOwner::new().unwrap();
    let checkpoint = Checkpoint {
        state: owner.as_ptr(),
        generation: 0,
        token: 0,
    };
    let attempt = {
        let _guard = DropGuard(drops.clone());
        // SAFETY：state 由 owner 保活；刻意沒有合法 C checkpoint，只驗證拒絕碼。
        unsafe { prepare(checkpoint, ErrorClass::Lua) }
    };
    assert_eq!(attempt, Action::Reject(Reject::NoCheckpoint));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 0);
}

#[test]
fn abi_neg002_panic_is_caught_and_foreign_unwind_boundary_is_static() {
    let boundary = include_str!("../src/trampoline.rs");
    assert!(boundary.contains("catch_unwind(AssertUnwindSafe"));
    assert!(boundary.contains("type ActionFn = unsafe extern \"C\" fn"));
    assert!(!boundary.contains("extern \"C-unwind\""));

    let drops = Arc::new(AtomicUsize::new(0));
    let owner = StateOwner::new().unwrap();
    let marker = Cell::new(false);
    let outcome = unsafe {
        protect(owner.as_ptr(), |_| {
            let _guard = DropGuard(drops.clone());
            marker.set(true);
            panic!("P16 panic 邊界拒絕測試");
        })
    };
    assert!(marker.get());
    assert_eq!(outcome, Outcome::Rejected(Reject::Panic));
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 0);
}
