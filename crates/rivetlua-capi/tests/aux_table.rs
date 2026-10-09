use std::ffi::{CString, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushinteger, lua_settop,
    luaL_getsubtable,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, GcAge, GcColor, GcMode, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, Vm, VmError,
};

unsafe extern "C" {
    fn rivetlua_capi_test_prime_a4a(state: *mut lua_State);
    fn rivetlua_capi_test_public_protected_a4a(
        state: *mut lua_State,
        operation: i32,
        index: i32,
        name: *const i8,
        key: i64,
        entries: *const c_void,
        nup: i32,
        inject_offset: i32,
        injection_start: *mut u64,
    ) -> i32;
}

fn protected_subtable(
    owner: &StateOwner,
    index: i32,
    name: *const i8,
    inject_offset: i32,
) -> (i32, u64) {
    let mut start = 0;
    // SAFETY：C 夾具在 lua_pcall callback 內執行 public API，錯誤在 C frame 擷取。
    let status = unsafe {
        rivetlua_capi_test_public_protected_a4a(
            owner.as_ptr(),
            8,
            index,
            name,
            0,
            std::ptr::null(),
            0,
            inject_offset,
            &mut start,
        )
    };
    (status, start)
}

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_REGISTRY_INDEX: i32 = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_REGISTRY_INDEX: i32 = -(i32::MAX / 2 + 1000);

type Roots = Vec<(RootKind, RootId, ObjectRef)>;
type Snapshot = (LedgerSnapshot, GcTrace, Roots);

fn snapshot(owner: &StateOwner) -> Snapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap()
}

fn only_added_host(before: &Roots, after: &Roots) -> ObjectRef {
    let added: Vec<_> = after
        .iter()
        .filter(|(kind, id, _)| {
            *kind == RootKind::Host && !before.iter().any(|(_, old, _)| old == id)
        })
        .map(|(_, _, object)| *object)
        .collect();
    assert_eq!(added.len(), 1);
    added[0]
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).2;
    // SAFETY：owner 持有有效 state。
    unsafe { lua_createtable(owner.as_ptr(), 0, 0) };
    only_added_host(&before, &snapshot(owner).2)
}

fn registry(vm: &Vm) -> ObjectRef {
    let mut found = Vec::new();
    vm.visit_roots(|kind, _, object| {
        if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
            found.push(object);
        }
    });
    assert_eq!(found.len(), 1);
    found[0]
}

fn globals(vm: &Vm) -> ObjectRef {
    let Value::Object(object) = vm.raw_get(registry(vm), Value::Integer(2)).unwrap() else {
        panic!()
    };
    object
}

fn named(owner: &StateOwner, table: ObjectRef, name: &[u8]) -> Value {
    owner
        .with_vm(|vm| {
            vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
                .unwrap()
        })
        .unwrap()
}

fn subtable(owner: &StateOwner, index: i32, name: &CString) -> i32 {
    // SAFETY：owner 與 C 字串在本次呼叫期間有效；無效 index 由入口拒絕。
    unsafe { luaL_getsubtable(owner.as_ptr(), index, name.as_ptr()) }
}

fn direct_table_registry_names_and_identity() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let parent = add_table(&owner);
    let before = snapshot(&owner).2;
    assert_eq!(subtable(&owner, 1, &CString::new("child").unwrap()), 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    let child = only_added_host(&before, &snapshot(&owner).2);
    assert_eq!(named(&owner, parent, b"child"), Value::Object(child));
    owner
        .with_vm(|vm| {
            assert_eq!(vm.with_table(child, |stored| stored.is_empty()), Ok(true));
            vm.raw_set_byte_string_key(child, b"self", Value::Object(child))
                .unwrap();
        })
        .unwrap();
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();

    let before = snapshot(&owner).2;
    assert_eq!(subtable(&owner, -1, &CString::new("child").unwrap()), 1);
    assert_eq!(only_added_host(&before, &snapshot(&owner).2), child);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    unsafe { lua_settop(state, 1) };
    assert_eq!(snapshot(&owner).2, before);

    owner.push_value(Value::Object(parent)).unwrap();
    assert_eq!(subtable(&owner, -1, &CString::new("relative").unwrap()), 0);
    assert_eq!(unsafe { lua_gettop(state) }, 3);
    unsafe { lua_settop(state, 1) };

    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(parent, b"self", Value::Object(parent))
                .unwrap()
        })
        .unwrap();
    let before = snapshot(&owner).2;
    assert_eq!(subtable(&owner, 1, &CString::new("self").unwrap()), 1);
    assert_eq!(only_added_host(&before, &snapshot(&owner).2), parent);
    unsafe { lua_settop(state, 1) };

    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    assert_eq!(
        subtable(&owner, REGISTRY_INDEX, &CString::new("shared").unwrap()),
        0
    );
    let shared = named(&owner, reg, b"shared");
    assert!(matches!(shared, Value::Object(_)));
    unsafe { lua_settop(state, 1) };
    let sibling = owner.new_sibling().unwrap();
    let before = snapshot(&owner).2;
    assert_eq!(
        subtable(&sibling, REGISTRY_INDEX, &CString::new("shared").unwrap()),
        1
    );
    assert_eq!(
        only_added_host(&before, &snapshot(&owner).2),
        match shared {
            Value::Object(object) => object,
            _ => unreachable!(),
        }
    );
    unsafe { lua_settop(sibling.as_ptr(), 0) };

    for (source, visible) in [
        (CString::new("").unwrap(), b"".as_slice()),
        (CString::new("prefix").unwrap(), b"prefix"),
        (CString::new(vec![b'q'; 256]).unwrap(), &[b'q'; 256][..]),
    ] {
        assert_eq!(subtable(&owner, 1, &source), 0);
        assert!(matches!(named(&owner, parent, visible), Value::Object(_)));
        unsafe { lua_settop(state, 1) };
    }
    let embedded = b"nul\0ignored\0";
    // SAFETY：靜態 buffer 有 NUL 結尾；只讀第一個 NUL 前 bytes。
    assert_eq!(
        unsafe { luaL_getsubtable(state, 1, embedded.as_ptr().cast()) },
        0
    );
    assert!(matches!(named(&owner, parent, b"nul"), Value::Object(_)));
    assert_eq!(named(&owner, parent, b"nul\0ignored"), Value::Nil);
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(parent, b"child", Value::Nil)
                .unwrap();
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Err(VmError::StaleObject));
        })
        .unwrap();
    unsafe { lua_settop(state, 0) };
}

fn overwrite_non_table_and_metamethod() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let parent = add_table(&owner);
    let old_string = owner
        .with_vm(|vm| vm.allocate_byte_string(b"old").unwrap())
        .unwrap();
    let global_table = owner.with_vm(|vm| globals(vm)).unwrap();
    let builtin = owner
        .with_vm(|vm| {
            vm.install_error_builtins(global_table).unwrap();
            let key = vm.allocate_byte_string(b"error").unwrap();
            vm.raw_get(global_table, Value::Object(key)).unwrap()
        })
        .unwrap();
    for (name, initial) in [
        (b"nil".as_slice(), Value::Nil),
        (b"scalar", Value::Integer(17)),
        (b"string", Value::Object(old_string)),
        (b"function", builtin),
    ] {
        owner
            .with_vm(|vm| vm.raw_set_byte_string_key(parent, name, initial).unwrap())
            .unwrap();
        let name = CString::new(name).unwrap();
        let before = snapshot(&owner).2;
        assert_eq!(subtable(&owner, 1, &name), 0);
        let child = only_added_host(&before, &snapshot(&owner).2);
        assert_eq!(named(&owner, parent, name.as_bytes()), Value::Object(child));
        unsafe { lua_settop(state, 1) };
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(old_string), Err(VmError::StaleObject));
        })
        .unwrap();

    let fallback = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    let metatable = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(metatable, b"__index", Value::Object(fallback))
                .unwrap();
            vm.raw_set_byte_string_key(metatable, b"__newindex", Value::Object(fallback))
                .unwrap();
            vm.set_metatable(parent, Some(metatable)).unwrap();
        })
        .unwrap();
    assert_eq!(
        subtable(&owner, 1, &CString::new("direct_table").unwrap()),
        0
    );
    assert_eq!(named(&owner, parent, b"direct_table"), Value::Nil);
    assert!(matches!(
        named(&owner, fallback, b"direct_table"),
        Value::Object(_)
    ));
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(metatable, b"__index", builtin)
                .unwrap();
            vm.raw_set_byte_string_key(metatable, b"__newindex", builtin)
                .unwrap();
        })
        .unwrap();
    let name = CString::new("direct_function").unwrap();
    assert_eq!(protected_subtable(&owner, 1, name.as_ptr(), -1).0, -2);
    assert_eq!(named(&owner, parent, b"direct_function"), Value::Nil);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    unsafe { lua_settop(state, 0) };
}

fn invalid_states_and_indices() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：提前註冊夾具 callback，使錯誤前後 root 比較只涵蓋待測入口。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let parent = add_table(&owner);
    unsafe { lua_pushinteger(state, 41) };
    let name = CString::new("invalid").unwrap();
    let before = snapshot(&owner);
    for index in [0, 2, 3, 99, -99, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert_eq!(protected_subtable(&owner, index, name.as_ptr(), -1).0, -2);
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert_eq!(snapshot(&owner).2, before.2);
    }
    assert_eq!(protected_subtable(&owner, 1, std::ptr::null(), -1).0, -2);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(named(&owner, parent, b"invalid"), Value::Nil);
    unsafe { lua_settop(state, 0) };
}

fn gc_barrier_and_weak_modes() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let parent = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause
                    && vm.gc_color(parent) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            assert_eq!(vm.gc_color(parent), Ok(GcColor::Black));
        })
        .unwrap();
    assert_eq!(
        subtable(&owner, 1, &CString::new("incremental").unwrap()),
        0
    );
    let Value::Object(child) = named(&owner, parent, b"incremental") else {
        panic!()
    };
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：提前登錄夾具 callback，避免 failpoint 在夾具 setup 被消耗。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let parent = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(parent), Ok(GcAge::Old));
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause
                    && vm.gc_color(parent) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_eq!(vm.gc_color(parent), Ok(GcColor::Black));
        })
        .unwrap();
    let before = snapshot(&owner);
    let name = CString::new("young").unwrap();
    assert_eq!(protected_subtable(&owner, 1, name.as_ptr(), -14).0, -4);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(named(&owner, parent, b"young"), Value::Nil);
    assert_eq!(subtable(&owner, 1, &name), 0);
    let Value::Object(child) = named(&owner, parent, b"young") else {
        panic!()
    };
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
    unsafe { lua_settop(state, 1) };
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
        })
        .unwrap();

    for mode in [b"k".as_slice(), b"v", b"kv"] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let parent = add_table(&owner);
        owner
            .with_vm(|vm| {
                let mt = vm.allocate_table().unwrap();
                let mode_value = vm.allocate_byte_string(mode).unwrap();
                vm.raw_set_byte_string_key(mt, b"__mode", Value::Object(mode_value))
                    .unwrap();
                vm.set_metatable(parent, Some(mt)).unwrap();
            })
            .unwrap();
        assert_eq!(subtable(&owner, 1, &CString::new("weak").unwrap()), 0);
        let Value::Object(child) = named(&owner, parent, b"weak") else {
            panic!()
        };
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
            })
            .unwrap();
        unsafe { lua_settop(state, 1) };
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        if mode == b"k" {
            assert_eq!(named(&owner, parent, b"weak"), Value::Object(child));
        } else {
            assert_eq!(named(&owner, parent, b"weak"), Value::Nil);
            assert_eq!(
                owner.with_vm(|vm| vm.object_kind(child)).unwrap(),
                Err(VmError::StaleObject)
            );
        }
    }
}

fn ordinal_case(action: i32) -> (StateOwner, ObjectRef, CString, Option<ObjectRef>) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：先登錄夾具 callback，failpoint 只涵蓋 subtable 本身。
    unsafe { rivetlua_capi_test_prime_a4a(state) };
    let parent = add_table(&owner);
    let name = CString::new(match action {
        0 => "insert",
        1 => "existing",
        _ => "overwrite",
    })
    .unwrap();
    let old_object = if action == 1 {
        assert_eq!(subtable(&owner, 1, &name), 0);
        unsafe { lua_settop(state, 1) };
        None
    } else if action == 2 {
        Some(
            owner
                .with_vm(|vm| {
                    let old = vm.allocate_byte_string(b"old value").unwrap();
                    vm.raw_set_byte_string_key(parent, name.as_bytes(), Value::Object(old))
                        .unwrap();
                    old
                })
                .unwrap(),
        )
    } else {
        None
    };
    // 保留原 A24 stack 邊界：callback 需要複製二十個 live slots。
    for value in 0..19 {
        unsafe { lua_pushinteger(state, value) };
    }
    assert_eq!(unsafe { lua_gettop(state) }, 20);
    (owner, parent, name, old_object)
}

fn ordinal_fault_matrix() {
    for action in 0..3 {
        let (probe, _, probe_name, _) = ordinal_case(action);
        let (attempts, _) = protected_subtable(&probe, 1, probe_name.as_ptr(), -1000);
        assert!(attempts > 0, "action={action}");
        let mut domains = Vec::new();
        for offset in 0..attempts {
            let (owner, parent, name, old_object) = ordinal_case(action);
            let state = owner.as_ptr();
            let original = named(&owner, parent, name.as_bytes());
            let before = snapshot(&owner);
            let (status, start) = protected_subtable(&owner, 1, name.as_ptr(), offset);
            assert_eq!(status, -4, "action={action};offset={offset}");
            assert_eq!(
                unsafe { lua_gettop(state) },
                20,
                "action={action};offset={offset}"
            );
            assert_eq!(
                snapshot(&owner).2,
                before.2,
                "action={action};offset={offset}: roots"
            );
            assert_eq!(named(&owner, parent, name.as_bytes()), original);
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.attempt.ordinal, start + offset as u64);
            domains.push(failure.attempt.domain);
            owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
            assert_eq!(
                snapshot(&owner).2,
                before.2,
                "action={action};offset={offset}: collected roots"
            );
            let returned = subtable(&owner, 1, &name);
            assert_eq!(returned, i32::from(action == 1));
            assert_eq!(unsafe { lua_gettop(state) }, 21);
            let child = only_added_host(&before.2, &snapshot(&owner).2);
            assert_eq!(named(&owner, parent, name.as_bytes()), Value::Object(child));
            unsafe { lua_settop(state, 20) };
            owner
                .with_vm(|vm| {
                    vm.collect().unwrap();
                    assert_eq!(vm.object_kind(child), Ok(ObjectKind::Table));
                    if let Some(old) = old_object {
                        assert_eq!(vm.object_kind(old), Err(VmError::StaleObject));
                    }
                })
                .unwrap();
        }
        assert!(
            domains.contains(&AllocationDomain::Host),
            "action={action}: Host 邊界"
        );
        assert!(
            domains.contains(&AllocationDomain::LuaHeap),
            "action={action}: Lua heap 邊界"
        );
    }
}

fn named_faults_and_retry() {
    for point in [
        FailPoint::RootReserve,
        FailPoint::StringBytesReserve,
        FailPoint::SlotReserve,
        FailPoint::ObjectReserve,
        FailPoint::TableArrayReserve,
        FailPoint::TableHashReserve,
        FailPoint::TableHashGrow,
        FailPoint::TableRehash,
        FailPoint::TableInsert,
        FailPoint::MarkReserve,
        FailPoint::RememberedReserve,
    ] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：先登錄夾具 callback，單次 failpoint 才只涵蓋 subtable 操作。
        unsafe { rivetlua_capi_test_prime_a4a(state) };
        let parent = add_table(&owner);
        owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_promotion_survivals(1).unwrap();
                vm.set_gc_mode(GcMode::Generational).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.gc_age(parent), Ok(GcAge::Old));
                for _ in 0..128 {
                    vm.incremental_step(1).unwrap();
                    if vm.gc_trace().phase != GcPhase::Pause
                        && vm.gc_color(parent) == Ok(GcColor::Black)
                    {
                        break;
                    }
                }
                assert_eq!(vm.gc_color(parent), Ok(GcColor::Black));
            })
            .unwrap();
        let before = snapshot(&owner);
        let name = CString::new("retry").unwrap();
        let code = match point {
            FailPoint::RootReserve => 3,
            FailPoint::StringBytesReserve => 6,
            FailPoint::SlotReserve => 0,
            FailPoint::ObjectReserve => 1,
            FailPoint::TableArrayReserve => 13,
            FailPoint::TableHashReserve => 14,
            FailPoint::TableHashGrow => 7,
            FailPoint::TableRehash => 8,
            FailPoint::TableInsert => 9,
            FailPoint::MarkReserve => 10,
            FailPoint::RememberedReserve => 12,
            _ => unreachable!(),
        };
        assert_eq!(
            protected_subtable(&owner, 1, name.as_ptr(), -code - 2).0,
            -4,
            "{point:?}"
        );
        assert_eq!(unsafe { lua_gettop(state) }, 1, "{point:?}");
        assert_eq!(snapshot(&owner).2, before.2, "{point:?}: roots");
        if let Some(failure) = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap()
        {
            assert_eq!(failure.attempt.point, Some(point), "{point:?}");
        }
        assert_eq!(named(&owner, parent, b"retry"), Value::Nil);
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(subtable(&owner, 1, &name), 0);
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        assert!(matches!(named(&owner, parent, b"retry"), Value::Object(_)));
    }
}

#[test]
fn aux_table_a24_matrix() {
    direct_table_registry_names_and_identity();
    overwrite_non_table_and_metamethod();
    invalid_states_and_indices();
    gc_barrier_and_weak_modes();
    ordinal_fault_matrix();
    named_faults_and_retry();
}
