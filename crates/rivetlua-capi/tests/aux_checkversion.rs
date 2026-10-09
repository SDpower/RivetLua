use rivetlua_capi::error::{ErrorClass, consume, prepare_checkversion};
use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_gettop, lua_pushinteger, lua_rawequal, lua_settop, lua_tolstring,
};
use rivetlua_capi::trampoline::{Action, Outcome, protect};
use rivetlua_core::ObjectRef;
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, GcMode, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind,
};

const MEMORY_ERROR: &[u8] = b"not enough memory";
const NUMERIC_ERROR: &[u8] = b"core and library have incompatible numeric types";
const NUMSIZES: usize = 16 * std::mem::size_of::<i64>() + std::mem::size_of::<f64>();
#[cfg(feature = "lua54")]
const CORE_VERSION: f64 = 504.0;
#[cfg(feature = "lua55")]
const CORE_VERSION: f64 = 505.0;

type Snapshot = (
    LedgerSnapshot,
    AllocationTrace,
    GcTrace,
    Vec<(RootKind, RootId, ObjectRef)>,
);

fn snapshot(owner: &StateOwner) -> Snapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (
                vm.ledger_snapshot(),
                vm.allocation_trace(),
                vm.gc_trace(),
                roots,
            )
        })
        .unwrap()
}

fn read_top(state: *mut lua_State) -> Vec<u8> {
    let mut len = 0;
    // SAFETY：呼叫時頂端是仍被 pending/stack root 保活的 byte string。
    let pointer = unsafe { lua_tolstring(state, -1, &mut len) };
    assert!(!pointer.is_null());
    // SAFETY：指標只在下一個 mutating C API 之前借讀；len 由 lua_tolstring 寫入。
    let bytes = unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) }.to_vec();
    // SAFETY：StringView 保證 C view 另有一個 NUL 終止位元組。
    assert_eq!(unsafe { *pointer.add(len) }, 0);
    bytes
}

fn check(state: *mut lua_State, version: f64, sizes: usize) -> Outcome {
    // SAFETY：呼叫端持有有效 StateOwner，action 僅準備錯誤並返回；C 只在 Rust frame 退出後跳轉。
    unsafe {
        protect(state, |checkpoint| unsafe {
            prepare_checkversion(checkpoint, version, sizes)
        })
    }
}

fn consume_error(state: *mut lua_State) -> Result<ErrorClass, rivetlua_capi::error::Reject> {
    // SAFETY：呼叫端的 StateOwner 持續保活此 state。
    unsafe { consume(state) }
}

fn emergency_object(owner: &StateOwner) -> ObjectRef {
    owner
        .with_vm(|vm| {
            let mut registry_roots = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Registry {
                    registry_roots.push(object);
                }
            });
            assert_eq!(
                registry_roots.len(),
                3,
                "registry、emergency 與 hook bridge 各有一個永久 root"
            );
            assert_eq!(
                registry_roots
                    .iter()
                    .filter(|&&object| vm.object_kind(object) == Ok(ObjectKind::Table))
                    .count(),
                1
            );
            assert_eq!(
                registry_roots
                    .iter()
                    .filter(|&&object| vm.object_kind(object) == Ok(ObjectKind::ByteString))
                    .count(),
                1
            );
            assert_eq!(
                registry_roots
                    .iter()
                    .filter(|&&object| vm.object_kind(object) == Ok(ObjectKind::CClosure))
                    .count(),
                1
            );
            let object = registry_roots
                .into_iter()
                .find(|&object| vm.object_kind(object) == Ok(ObjectKind::ByteString))
                .expect("永久 emergency byte string");
            assert_eq!(
                vm.with_byte_string(object, |string| string.as_bytes().to_vec())
                    .unwrap(),
                MEMORY_ERROR
            );
            object
        })
        .unwrap()
}

#[test]
fn aux_checkversion_a48_emergency_root_survives_gc_and_is_shared_by_siblings() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let object = emergency_object(&owner);
    assert_eq!(emergency_object(&sibling), object);
    for mode in [GcMode::Incremental, GcMode::Generational] {
        owner
            .with_vm(|vm| {
                vm.set_gc_mode(mode).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(object), Ok(ObjectKind::ByteString));
                assert_eq!(
                    vm.with_byte_string(object, |string| string.as_bytes().to_vec())
                        .unwrap(),
                    MEMORY_ERROR
                );
            })
            .unwrap();
        assert_eq!(emergency_object(&sibling), object);
    }
}

#[test]
fn aux_checkversion_a48_checkpoint_capacity_failure_never_runs_action() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let first_attempt = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(first_attempt))
        .unwrap();
    let mut called = 0;
    // SAFETY：owner 在整個同步 C checkpoint 期間保活 state。
    let failed = unsafe {
        protect(state, |_| {
            called += 1;
            Action::Return(71)
        })
    };
    assert!(matches!(failed, Outcome::Rejected(_)), "{failed:?}");
    assert_eq!(called, 0, "預留容量失敗時不得執行 action");
    let failure = owner
        .with_vm(|vm| vm.allocation_trace().last_failure)
        .unwrap();
    assert!(failure.is_some(), "必須實際命中 allocation failpoint");
    // SAFETY：失敗不得留下半個 checkpoint；同一 state 必須可重試。
    assert_eq!(
        unsafe {
            protect(state, |_| {
                called += 1;
                Action::Return(72)
            })
        },
        Outcome::Normal(72)
    );
    assert_eq!(called, 1);
}

#[test]
fn aux_checkversion_a48_normal_priority_exact_bytes_and_nested_top() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 state；既有 slot 提供 checkpoint 所需備用容量。
    unsafe { lua_pushinteger(state, 91) };
    let before = snapshot(&owner);
    assert_eq!(check(state, CORE_VERSION, NUMSIZES), Outcome::Normal(0));
    assert_eq!(snapshot(&owner), before);
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    let version_expected =
        format!("version mismatch: app. needs 0.0, Lua core provides {CORE_VERSION:.1}")
            .into_bytes();
    let negative_zero_expected =
        format!("version mismatch: app. needs -0.0, Lua core provides {CORE_VERSION:.1}")
            .into_bytes();
    let fractional_expected =
        format!("version mismatch: app. needs 12.5, Lua core provides {CORE_VERSION:.1}")
            .into_bytes();
    for (version, sizes, expected) in [
        (CORE_VERSION, NUMSIZES + 1, NUMERIC_ERROR),
        (0.0, NUMSIZES, version_expected.as_slice()),
        (-0.0, NUMSIZES, negative_zero_expected.as_slice()),
        (12.5, NUMSIZES, fractional_expected.as_slice()),
        (0.0, NUMSIZES + 1, NUMERIC_ERROR),
    ] {
        assert_eq!(
            check(state, version, sizes),
            Outcome::Raised(ErrorClass::Lua)
        );
        assert_eq!(unsafe { lua_gettop(state) }, 1);
        let pending = snapshot(&owner);
        assert_eq!(pending.3.len(), before.3.len() + 1);
        assert!(pending.0.lua_heap_bytes > before.0.lua_heap_bytes);
        assert!(pending.1.next_ordinal > before.1.next_ordinal);
        assert_eq!(consume_error(state), Ok(ErrorClass::Lua));
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(read_top(state), expected);
        // SAFETY：移除本次錯誤 slot，下一次 mismatch 從相同 stack top 開始。
        unsafe { lua_settop(state, 1) };
    }

    let mut inner_called = 0;
    // SAFETY：兩層 C checkpoint 只讓 Rust action 回傳後在各自 C frame 跳轉。
    let outer = unsafe {
        protect(state, |outer| {
            let outcome = unsafe {
                protect(state, |inner| {
                    inner_called += 1;
                    unsafe { prepare_checkversion(inner, CORE_VERSION, NUMSIZES + 1) }
                })
            };
            assert_eq!(outcome, Outcome::Raised(ErrorClass::Lua));
            assert_eq!(consume_error(state), Ok(ErrorClass::Lua));
            assert_eq!(read_top(state), NUMERIC_ERROR);
            unsafe { lua_settop(state, 1) };
            unsafe { prepare_checkversion(outer, CORE_VERSION, NUMSIZES + 1) }
        })
    };
    assert_eq!(outer, Outcome::Raised(ErrorClass::Lua));
    assert_eq!(inner_called, 1);
    assert_eq!(consume_error(state), Ok(ErrorClass::Lua));
    assert_eq!(read_top(state), NUMERIC_ERROR);
    unsafe { lua_settop(state, 1) };
}

#[test]
fn aux_checkversion_a48_message_allocation_failpoints_are_atomic_and_reusable() {
    let mut failure_domains = Vec::new();
    let mut failure_sites = Vec::new();
    let mut successes = 0;
    for offset in 0..32 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        unsafe { lua_pushinteger(state, 47) };
        let emergency = emergency_object(&owner);
        let before = snapshot(&owner);
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(before.1.next_ordinal + offset))
            .unwrap();
        let result = check(state, CORE_VERSION, NUMSIZES + 1);
        let pending = snapshot(&owner);
        if let Some(failure) = pending.1.last_failure {
            assert_eq!(failure.kind, AllocationFailureKind::Injection);
            assert_eq!(result, Outcome::Raised(ErrorClass::Allocation));
            assert_eq!(pending.0, before.0, "offset={offset}");
            assert_eq!(pending.3, before.3, "offset={offset}");
            failure_domains.push(failure.attempt.domain);
            failure_sites.push(failure.attempt.site.file);
            assert_eq!(consume_error(state), Ok(ErrorClass::Allocation));
            assert_eq!(read_top(state), MEMORY_ERROR);
            owner
                .push_value(rivetlua_core::Value::Object(emergency))
                .unwrap();
            assert_eq!(unsafe { lua_rawequal(state, -1, -2) }, 1);
            unsafe { lua_settop(state, 1) };
        } else {
            assert_eq!(result, Outcome::Raised(ErrorClass::Lua));
            assert_eq!(consume_error(state), Ok(ErrorClass::Lua));
            assert_eq!(read_top(state), NUMERIC_ERROR);
            unsafe { lua_settop(state, 1) };
            successes += 1;
            break;
        }
    }
    assert_eq!(successes, 1, "32 個 ordinal 內必須掃到完整成功路徑");
    assert!(failure_domains.contains(&AllocationDomain::Host));
    assert!(failure_domains.contains(&AllocationDomain::LuaHeap));
    assert!(failure_sites.iter().any(|site| site.ends_with("roots.rs")));
}
