use std::ffi::CString;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_pushinteger, lua_settop,
    luaL_newmetatable, luaL_setmetatable,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, FailPoint, FinalizerState, GcAge, GcColor, GcMode, GcPhase, GcTrace,
    LedgerSnapshot, ObjectKind, RootId, RootKind, Vm, VmError,
};

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

fn named(owner: &StateOwner, table: ObjectRef, name: &[u8]) -> Value {
    owner
        .with_vm(|vm| {
            vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
                .unwrap()
        })
        .unwrap()
}

fn call(owner: &StateOwner, name: &CString) -> i32 {
    // SAFETY：owner 在本次呼叫持有有效 state；C 字串可讀且 NUL 結尾。
    unsafe { luaL_newmetatable(owner.as_ptr(), name.as_ptr()) }
}

fn top(owner: &StateOwner) -> i32 {
    // SAFETY：owner 持有有效 state。
    unsafe { lua_gettop(owner.as_ptr()) }
}

fn pop_to(owner: &StateOwner, index: i32) {
    // SAFETY：owner 持有有效 state；index 在測試中的 stack 範圍內。
    unsafe { lua_settop(owner.as_ptr(), index) };
}

fn set_named(owner: &StateOwner, name: &CString) {
    // SAFETY：owner 與 C 字串在本次呼叫期間有效。
    unsafe { luaL_setmetatable(owner.as_ptr(), name.as_ptr()) };
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let before = snapshot(owner).2;
    // SAFETY：owner 在本次呼叫期間持有有效 state。
    unsafe { lua_createtable(owner.as_ptr(), 0, 0) };
    only_added_host(&before, &snapshot(owner).2)
}

fn create_named(owner: &StateOwner, name: &CString) -> ObjectRef {
    let before = snapshot(owner).2;
    assert_eq!(call(owner, name), 1);
    let table = only_added_host(&before, &snapshot(owner).2);
    pop_to(owner, -2);
    table
}

fn metatable(owner: &StateOwner, target: ObjectRef) -> Option<ObjectRef> {
    owner
        .with_vm(|vm| vm.get_metatable(target).unwrap())
        .unwrap()
}

fn assert_failed(owner: &StateOwner, old_top: i32, before: &Snapshot) {
    assert_eq!(top(owner), old_top);
    assert_eq!(&snapshot(owner), before);
}

fn identity_names_and_lifetime() {
    let owner = StateOwner::new().unwrap();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    assert_eq!(top(&owner), 0);
    for name in [
        b"named".as_slice(),
        b"",
        b"__name",
        b"long-name-long-name-long-name",
    ] {
        let c_name = CString::new(name).unwrap();
        let before = snapshot(&owner).2;
        assert_eq!(call(&owner, &c_name), 1);
        assert_eq!(top(&owner), 1);
        let table = only_added_host(&before, &snapshot(&owner).2);
        assert_eq!(named(&owner, reg, name), Value::Object(table));
        let Value::Object(stored_name) = named(&owner, table, b"__name") else {
            panic!("缺少 __name")
        };
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_byte_string(stored_name, |s| s.as_bytes().to_vec()))
                .unwrap(),
            Ok(name.to_vec())
        );
        let before_second = snapshot(&owner).2;
        assert_eq!(call(&owner, &c_name), 0);
        assert_eq!(top(&owner), 2);
        let second_root = only_added_host(&before_second, &snapshot(&owner).2);
        assert_eq!(second_root, table);
        pop_to(&owner, -2);
        assert_eq!(top(&owner), 1);
        pop_to(&owner, 0);
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
                assert_eq!(vm.object_kind(stored_name), Ok(ObjectKind::ByteString));
                vm.raw_set_byte_string_key(reg, name, Value::Nil).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
            })
            .unwrap();
    }
    let embedded = b"nul\0ignored\0";
    let before = snapshot(&owner).2;
    // SAFETY：靜態 buffer 在首個 NUL 前可讀，state 有效。
    assert_eq!(
        unsafe { luaL_newmetatable(owner.as_ptr(), embedded.as_ptr().cast()) },
        1
    );
    let table = only_added_host(&before, &snapshot(&owner).2);
    assert_eq!(named(&owner, reg, b"nul"), Value::Object(table));
    assert_eq!(named(&owner, reg, b"nul\0ignored"), Value::Nil);
    pop_to(&owner, 0);

    let sibling = owner.new_sibling().unwrap();
    assert_eq!(call(&owner, &CString::new("shared").unwrap()), 1);
    let Value::Object(shared) = named(&owner, reg, b"shared") else {
        panic!()
    };
    let before = snapshot(&owner).2;
    assert_eq!(call(&sibling, &CString::new("shared").unwrap()), 0);
    assert_eq!(only_added_host(&before, &snapshot(&owner).2), shared);
    pop_to(&sibling, 0);
    pop_to(&owner, 0);

    let other = StateOwner::new().unwrap();
    let other_reg = other.with_vm(|vm| registry(vm)).unwrap();
    assert_eq!(call(&other, &CString::new("shared").unwrap()), 1);
    assert_ne!(named(&other, other_reg, b"shared"), Value::Object(shared));
    pop_to(&other, 0);
}

fn existing_nonnil_and_fail_closed() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let string = owner
        .with_vm(|vm| vm.allocate_byte_string(b"old string").unwrap())
        .unwrap();
    let table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(table, b"__name", Value::Integer(7))
                .unwrap();
        })
        .unwrap();
    let builtin = owner
        .with_vm(|vm| {
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!()
            };
            vm.install_error_builtins(globals).unwrap();
            vm.with_temporary_byte_string(b"error", |vm, key| {
                vm.raw_get(globals, Value::Object(key))
            })
            .unwrap()
        })
        .unwrap();
    for (name, value) in [
        (b"integer".as_slice(), Value::Integer(42)),
        (b"false", Value::Boolean(false)),
        (b"string", Value::Object(string)),
        (b"table", Value::Object(table)),
        (b"function", builtin),
    ] {
        owner
            .with_vm(|vm| vm.raw_set_byte_string_key(reg, name, value).unwrap())
            .unwrap();
        let before = snapshot(&owner).2;
        assert_eq!(call(&owner, &CString::new(name).unwrap()), 0);
        assert_eq!(top(&owner), 1);
        assert_eq!(named(&owner, reg, name), value);
        if let Value::Object(object) = value {
            assert_eq!(only_added_host(&before, &snapshot(&owner).2), object);
        } else {
            assert_eq!(snapshot(&owner).2, before);
        }
        if name == b"table" {
            assert_eq!(named(&owner, table, b"__name"), Value::Integer(7));
        }
        pop_to(&owner, 0);
    }

    // SAFETY：null 不可解參；state 有效且 C 字串本身有效。
    let name = CString::new("invalid").unwrap();
    let before = snapshot(&owner);
    unsafe {
        assert_eq!(luaL_newmetatable(state, std::ptr::null()), -1);
        assert_eq!(luaL_newmetatable(std::ptr::null_mut(), name.as_ptr()), -1);
    }
    let pointer = state as usize;
    let name_pointer = name.as_ptr() as usize;
    std::thread::spawn(move || {
        // SAFETY：有效 state 指標由入口執行緒檢查拒絕，不解參 C 字串。
        unsafe {
            assert_eq!(
                luaL_newmetatable(pointer as *mut lua_State, name_pointer as *const i8),
                -1
            );
        }
    })
    .join()
    .unwrap();
    owner
        .with_vm(|_| {
            // SAFETY：有效 state 因 group 已借用而 fail-closed。
            assert_eq!(unsafe { luaL_newmetatable(state, name.as_ptr()) }, -1);
        })
        .unwrap();
    assert_failed(&owner, 0, &before);
    assert_eq!(named(&owner, reg, b"invalid"), Value::Nil);
}

fn active_gc_registry_barrier() {
    let owner = StateOwner::new().unwrap();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(reg) == Ok(GcColor::Black) {
                    break;
                }
            }
            assert_eq!(vm.gc_color(reg), Ok(GcColor::Black));
        })
        .unwrap();
    assert_eq!(call(&owner, &CString::new("incremental").unwrap()), 1);
    let Value::Object(table) = named(&owner, reg, b"incremental") else {
        panic!()
    };
    let Value::Object(name_value) = named(&owner, table, b"__name") else {
        panic!()
    };
    pop_to(&owner, 0);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(name_value), Ok(ObjectKind::ByteString));
        })
        .unwrap();

    let owner = StateOwner::new().unwrap();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(reg), Ok(GcAge::Old));
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause && vm.gc_color(reg) == Ok(GcColor::Black) {
                    break;
                }
            }
            assert_eq!(vm.gc_color(reg), Ok(GcColor::Black));
        })
        .unwrap();
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    let name = CString::new("young").unwrap();
    assert_eq!(call(&owner, &name), -1);
    assert_failed(&owner, 0, &before);
    assert_eq!(named(&owner, reg, b"young"), Value::Nil);
    assert_eq!(call(&owner, &name), 1);
    let Value::Object(table) = named(&owner, reg, b"young") else {
        panic!()
    };
    let Value::Object(name_value) = named(&owner, table, b"__name") else {
        panic!()
    };
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 1);
    pop_to(&owner, 0);
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(name_value), Ok(ObjectKind::ByteString));
        })
        .unwrap();
}

fn ordinal_and_named_failure_matrix() {
    type Event = (AllocationDomain, Option<FailPoint>, &'static str, usize);
    const HEAP: &str = "crates/rivetlua-runtime/src/heap.rs";
    const ROOTS: &str = "crates/rivetlua-runtime/src/roots.rs";
    const STRING: &str = "crates/rivetlua-runtime/src/string.rs";
    const TABLE: &str = "crates/rivetlua-runtime/src/table.rs";
    const LOOKUP: [Event; 7] = [
        (AllocationDomain::Host, None, HEAP, 8),
        (AllocationDomain::Host, None, HEAP, 216),
        (AllocationDomain::Host, None, ROOTS, 208),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::StringBytesReserve),
            STRING,
            7,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            HEAP,
            136,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            HEAP,
            312,
        ),
        (AllocationDomain::Host, None, ROOTS, 120),
    ];
    const CREATE: [Event; 15] = [
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::TableArrayReserve),
            TABLE,
            0,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::TableHashReserve),
            TABLE,
            208,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            HEAP,
            136,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            HEAP,
            312,
        ),
        (AllocationDomain::Host, None, ROOTS, 208),
        (AllocationDomain::Host, None, HEAP, 5760),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::StringBytesReserve),
            STRING,
            7,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            HEAP,
            136,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            HEAP,
            312,
        ),
        (AllocationDomain::Host, None, ROOTS, 208),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::StringBytesReserve),
            STRING,
            6,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::SlotReserve),
            HEAP,
            136,
        ),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::ObjectReserve),
            HEAP,
            312,
        ),
        (AllocationDomain::Host, None, ROOTS, 208),
        (
            AllocationDomain::LuaHeap,
            Some(FailPoint::TableHashGrow),
            TABLE,
            208,
        ),
    ];
    const EXISTING_TABLE: [Event; 2] = [
        (AllocationDomain::Host, None, ROOTS, 208),
        (AllocationDomain::Host, None, HEAP, 5760),
    ];
    const EXISTING_OTHER: [Event; 1] = [(AllocationDomain::Host, None, HEAP, 5760)];
    for action in 0..3 {
        let mut failed = Vec::new();
        let mut passed = Vec::new();
        let mut failure_sites = Vec::new();
        for offset in 0..48 {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            let reg = owner.with_vm(|vm| registry(vm)).unwrap();
            let name = CString::new("ordinal").unwrap();
            let existing = if action == 1 {
                let table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
                owner
                    .with_vm(|vm| {
                        vm.raw_set_byte_string_key(reg, name.as_bytes(), Value::Object(table))
                            .unwrap()
                    })
                    .unwrap();
                Value::Object(table)
            } else if action == 2 {
                owner
                    .with_vm(|vm| {
                        vm.raw_set_byte_string_key(reg, name.as_bytes(), Value::Integer(17))
                            .unwrap()
                    })
                    .unwrap();
                Value::Integer(17)
            } else {
                Value::Nil
            };
            // MIN_STACK 為 20；第 21 格須在 registry 發布前完成 Host preflight。
            for value in 0..20 {
                // SAFETY：state 有效，逐次增加一個 C stack slot。
                unsafe { lua_pushinteger(state, value) };
            }
            assert_eq!(top(&owner), 20);
            let before = snapshot(&owner);
            let next = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
                .unwrap();
            let returned = call(&owner, &name);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            if top(&owner) == 20 {
                assert_eq!(returned, -1);
                assert_failed(&owner, 20, &before);
                assert_eq!(named(&owner, reg, name.as_bytes()), existing);
                let failure = owner
                    .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                    .unwrap();
                assert_eq!(failure.attempt.ordinal, next + offset);
                failure_sites.push((
                    offset,
                    failure.attempt.domain,
                    failure.attempt.point,
                    failure.attempt.site.file,
                    failure.attempt.bytes,
                ));
                failed.push(offset);
            } else {
                assert_eq!(top(&owner), 21);
                assert_eq!(returned, i32::from(action == 0));
                if action == 0 {
                    let table = only_added_host(&before.2, &snapshot(&owner).2);
                    assert_eq!(named(&owner, reg, name.as_bytes()), Value::Object(table));
                    assert_ne!(named(&owner, table, b"__name"), Value::Nil);
                } else {
                    assert_eq!(named(&owner, reg, name.as_bytes()), existing);
                    if let Value::Object(table) = existing {
                        assert_eq!(only_added_host(&before.2, &snapshot(&owner).2), table);
                    } else {
                        assert_eq!(snapshot(&owner).2, before.2);
                    }
                }
                pop_to(&owner, 20);
                passed.push(offset);
            }
        }
        // B14 短字串鍵改為 inline：lookup 的 ordinal 與新建路徑兩次欄位寫入
        // 不再各複製一次 canonical key bytes；保留其餘配置事件與退款檢查。
        let suffix: &[Event] = match action {
            0 => &CREATE,
            1 => &EXISTING_TABLE,
            2 => &EXISTING_OTHER,
            _ => unreachable!(),
        };
        let expected: Vec<_> = LOOKUP.iter().chain(suffix).copied().collect();
        assert_eq!(failure_sites.len(), expected.len());
        for (offset, (actual, expected)) in failure_sites.iter().zip(&expected).enumerate() {
            assert_eq!(
                *actual,
                (
                    offset as u64,
                    expected.0,
                    expected.1,
                    expected.2,
                    expected.3
                )
            );
        }
        assert_eq!(failed.len(), [22, 9, 8][action]);
        assert_eq!(passed, (failed.len() as u64..48).collect::<Vec<_>>());
        assert_eq!(failed, (0..failed.len() as u64).collect::<Vec<_>>());
        // 三種路徑都在第 21 個 stack slot 的 Host 容量預備處真紅。
        let capacity_offset = [12, 8, 7][action];
        assert_eq!(failure_sites[capacity_offset].0, capacity_offset as u64);
        assert_eq!(failure_sites[capacity_offset].1, AllocationDomain::Host);
        assert!(
            failure_sites
                .iter()
                .any(|(_, domain, _, _, _)| *domain == AllocationDomain::Host)
        );
    }

    for point in [
        FailPoint::ObjectReserve,
        FailPoint::StringBytesReserve,
        FailPoint::TableHashReserve,
        FailPoint::TableInsert,
        FailPoint::RootReserve,
        FailPoint::HostLease,
    ] {
        let owner = StateOwner::new().unwrap();
        let reg = owner.with_vm(|vm| registry(vm)).unwrap();
        let before = snapshot(&owner);
        owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        let name = CString::new("named-failure").unwrap();
        assert_eq!(call(&owner, &name), -1, "{point:?}");
        assert_failed(&owner, 0, &before);
        assert_eq!(named(&owner, reg, name.as_bytes()), Value::Nil);
        assert_eq!(call(&owner, &name), 1);
        pop_to(&owner, 0);
    }
}

#[test]
fn aux_metatable_a25_matrix() {
    identity_names_and_lifetime();
    existing_nonnil_and_fail_closed();
    active_gc_registry_barrier();
    ordinal_and_named_failure_matrix();
}

#[test]
fn aux_metatable_a26_set_matrix() {
    set_named_basic_and_names();
    set_named_fail_closed();
    set_named_weak_and_finalizer();
    set_named_gc_barriers();
    set_named_failure_sweep();
}

fn set_named_basic_and_names() {
    let owner = StateOwner::new().unwrap();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let first = CString::new("first").unwrap();
    let second = CString::new("second").unwrap();
    let first_mt = create_named(&owner, &first);
    let second_mt = create_named(&owner, &second);
    let target = add_table(&owner);
    let before = snapshot(&owner).2;
    set_named(&owner, &first);
    assert_eq!(top(&owner), 1);
    assert_eq!(snapshot(&owner).2, before);
    assert_eq!(metatable(&owner, target), Some(first_mt));
    set_named(&owner, &first);
    assert_eq!(metatable(&owner, target), Some(first_mt));
    set_named(&owner, &second);
    assert_eq!(metatable(&owner, target), Some(second_mt));
    assert_eq!(snapshot(&owner).2, before);
    let missing = CString::new("missing").unwrap();
    set_named(&owner, &missing);
    assert_eq!(metatable(&owner, target), None);
    set_named(&owner, &first);
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(reg, first.as_bytes(), Value::Nil)
                .unwrap()
        })
        .unwrap();
    let before_clear = snapshot(&owner).2;
    set_named(&owner, &first);
    assert_eq!(metatable(&owner, target), None);
    assert_eq!(snapshot(&owner).2, before_clear);

    for name in [b"".as_slice(), b"__name", b"long-name-long-name-long-name"] {
        let name = CString::new(name).unwrap();
        let mt = create_named(&owner, &name);
        let before = snapshot(&owner).2;
        set_named(&owner, &name);
        assert_eq!(metatable(&owner, target), Some(mt));
        assert_eq!(snapshot(&owner).2, before);
        assert_eq!(top(&owner), 1);
    }
    let nul_mt = create_named(&owner, &CString::new("nul").unwrap());
    let before = snapshot(&owner).2;
    // SAFETY：靜態 buffer 在首個 NUL 前可讀，owner state 有效。
    unsafe { luaL_setmetatable(owner.as_ptr(), b"nul\0ignored\0".as_ptr().cast()) };
    assert_eq!(metatable(&owner, target), Some(nul_mt));
    assert_eq!(snapshot(&owner).2, before);
    assert_eq!(named(&owner, reg, b"nul\0ignored"), Value::Nil);

    let self_name = CString::new("self").unwrap();
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(reg, self_name.as_bytes(), Value::Object(target))
                .unwrap()
        })
        .unwrap();
    let before = snapshot(&owner).2;
    set_named(&owner, &self_name);
    assert_eq!(metatable(&owner, target), Some(target));
    assert_eq!(snapshot(&owner).2, before);
    set_named(&owner, &missing);

    let sibling = owner.new_sibling().unwrap();
    let sibling_target = add_table(&sibling);
    let before = snapshot(&owner).2;
    set_named(&sibling, &second);
    assert_eq!(metatable(&owner, sibling_target), Some(second_mt));
    assert_eq!(snapshot(&owner).2, before);
    let other = StateOwner::new().unwrap();
    let other_target = add_table(&other);
    set_named(&other, &second);
    assert_eq!(metatable(&other, other_target), None);
    assert_eq!(metatable(&owner, sibling_target), Some(second_mt));
}

fn set_named_fail_closed() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    let valid = CString::new("valid").unwrap();
    let old = create_named(&owner, &valid);
    let target = add_table(&owner);
    set_named(&owner, &valid);
    for (name, value) in [
        ("integer", Value::Integer(7)),
        ("false", Value::Boolean(false)),
    ] {
        let name = CString::new(name).unwrap();
        owner
            .with_vm(|vm| {
                vm.raw_set_byte_string_key(reg, name.as_bytes(), value)
                    .unwrap()
            })
            .unwrap();
        let before = snapshot(&owner);
        set_named(&owner, &name);
        assert_failed(&owner, 1, &before);
        assert_eq!(metatable(&owner, target), Some(old));
    }
    let before = snapshot(&owner);
    // SAFETY：state 有效，空指標在入口即被拒絕。
    unsafe {
        luaL_setmetatable(state, std::ptr::null());
        luaL_setmetatable(std::ptr::null_mut(), valid.as_ptr());
    }
    assert_failed(&owner, 1, &before);
    assert_eq!(metatable(&owner, target), Some(old));
    owner
        .with_vm(|_| {
            // SAFETY：有效 state 因 group 已借用而 fail-closed。
            unsafe { luaL_setmetatable(state, valid.as_ptr()) };
        })
        .unwrap();
    assert_failed(&owner, 1, &before);
    let pointer = state as usize;
    let name_pointer = valid.as_ptr() as usize;
    std::thread::spawn(move || {
        // SAFETY：入口會先檢查執行緒，不會解參跨執行緒的 state。
        unsafe {
            luaL_setmetatable(pointer as *mut lua_State, name_pointer as *const i8);
        }
    })
    .join()
    .unwrap();
    assert_failed(&owner, 1, &before);

    pop_to(&owner, 0);
    let before = snapshot(&owner);
    set_named(&owner, &valid);
    assert_failed(&owner, 0, &before);
    // SAFETY：owner 有效，測試 primitive top 不可作為 table target。
    unsafe { lua_pushinteger(state, 42) };
    let before = snapshot(&owner);
    set_named(&owner, &valid);
    assert_failed(&owner, 1, &before);
    assert_eq!(metatable(&owner, target), Some(old));
}

fn set_named_weak_and_finalizer() {
    let owner = StateOwner::new().unwrap();
    let mode_name = CString::new("weak-v").unwrap();
    let mode_mt = create_named(&owner, &mode_name);
    let table = add_table(&owner);
    let value = owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            let mode = vm.allocate_byte_string(b"v").unwrap();
            vm.raw_set_byte_string_key(mode_mt, b"__mode", Value::Object(mode))
                .unwrap();
            let value = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Object(value))
                .unwrap();
            value
        })
        .unwrap();
    set_named(&owner, &mode_name);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Nil));
            assert_eq!(vm.object_kind(value), Err(VmError::StaleObject));
        })
        .unwrap();
    set_named(&owner, &CString::new("missing-weak").unwrap());
    owner
        .with_vm(|vm| {
            let strong = vm.allocate_table().unwrap();
            vm.raw_set(table, Value::Integer(1), Value::Object(strong))
                .unwrap();
            vm.collect().unwrap();
            assert_eq!(
                vm.raw_get(table, Value::Integer(1)),
                Ok(Value::Object(strong))
            );
        })
        .unwrap();

    let gc_name = CString::new("with-gc").unwrap();
    let gc_mt = create_named(&owner, &gc_name);
    let finalizable = add_table(&owner);
    owner
        .with_vm(|vm| {
            let reg = registry(vm);
            let Value::Object(globals) = vm.raw_get(reg, Value::Integer(2)).unwrap() else {
                panic!("globals 缺席")
            };
            vm.install_error_builtins(globals).unwrap();
            let builtin = vm
                .with_temporary_byte_string(b"error", |vm, key| {
                    vm.raw_get(globals, Value::Object(key))
                })
                .unwrap();
            vm.raw_set_byte_string_key(gc_mt, b"__gc", builtin).unwrap();
        })
        .unwrap();
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(finalizable)).unwrap(),
        Ok(FinalizerState::Unregistered)
    );
    set_named(&owner, &gc_name);
    assert_eq!(metatable(&owner, finalizable), Some(gc_mt));
    assert_eq!(
        owner.with_vm(|vm| vm.finalizer_state(finalizable)).unwrap(),
        Ok(FinalizerState::Registered)
    );
}

fn set_named_gc_barriers() {
    let owner = StateOwner::new().unwrap();
    let target = add_table(&owner);
    let reg = owner.with_vm(|vm| registry(vm)).unwrap();
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(GcMode::Incremental).unwrap();
            vm.collect().unwrap();
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause
                    && vm.gc_color(target) == Ok(GcColor::Black)
                    && vm.gc_color(reg) == Ok(GcColor::Black)
                {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            assert_eq!(vm.gc_color(target), Ok(GcColor::Black));
            assert_eq!(vm.gc_color(reg), Ok(GcColor::Black));
        })
        .unwrap();
    let name = CString::new("incremental-set").unwrap();
    let mt = create_named(&owner, &name);
    let before = snapshot(&owner).2;
    set_named(&owner, &name);
    assert_eq!(snapshot(&owner).2, before);
    assert_eq!(metatable(&owner, target), Some(mt));
    owner
        .with_vm(|vm| {
            while vm.gc_trace().phase != GcPhase::Pause {
                vm.incremental_step(1024).unwrap();
            }
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();

    let owner = StateOwner::new().unwrap();
    let fillers: Vec<_> = (0..3).map(|_| add_table(&owner)).collect();
    let target = add_table(&owner);
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.set_gc_mode(GcMode::Generational).unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.gc_age(target), Ok(GcAge::Old));
        })
        .unwrap();
    let name = CString::new("young-set").unwrap();
    let mt = create_named(&owner, &name);
    assert_eq!(owner.with_vm(|vm| vm.gc_age(mt)).unwrap(), Ok(GcAge::Young));
    // registry 加上三個 filler old owner，讓 remembered 容量滿載；target 為下一個 edge。
    owner
        .with_vm(|vm| {
            for filler in fillers {
                let young = vm.allocate_table().unwrap();
                vm.set_metatable(filler, Some(young)).unwrap();
            }
            assert_eq!(vm.gc_trace().remembered_len, 4);
        })
        .unwrap();
    let before = snapshot(&owner);
    owner
        .with_vm(|vm| vm.inject_failure_once(FailPoint::RememberedReserve))
        .unwrap();
    set_named(&owner, &name);
    assert_failed(&owner, 4, &before);
    assert_eq!(metatable(&owner, target), None);
    assert_eq!(
        owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.point)
            .unwrap(),
        Some(FailPoint::RememberedReserve)
    );
    set_named(&owner, &name);
    assert_eq!(metatable(&owner, target), Some(mt));
    assert_eq!(owner.with_vm(|vm| vm.gc_trace().remembered_len).unwrap(), 5);
    owner
        .with_vm(|vm| {
            vm.collect_minor().unwrap();
            assert_eq!(vm.object_kind(mt), Ok(ObjectKind::Table));
        })
        .unwrap();
}

fn setup_set_sweep(
    action: usize,
) -> (
    StateOwner,
    CString,
    ObjectRef,
    Option<ObjectRef>,
    Option<ObjectRef>,
) {
    let owner = StateOwner::new().unwrap();
    owner
        .with_vm(|vm| vm.set_gc_debt_threshold(usize::MAX))
        .unwrap();
    let old_name = CString::new("sweep-old").unwrap();
    let old = create_named(&owner, &old_name);
    let target = add_table(&owner);
    if action == 1 {
        set_named(&owner, &old_name);
    }
    let name = if action == 0 {
        CString::new("sweep-old").unwrap()
    } else {
        CString::new("sweep-missing").unwrap()
    };
    (
        owner,
        name,
        target,
        (action == 1).then_some(old),
        (action == 0).then_some(old),
    )
}

fn set_named_failure_sweep() {
    for action in 0..2 {
        let (dry, name, target, old, desired) = setup_set_sweep(action);
        let start = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        set_named(&dry, &name);
        let end = dry
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        assert!(end > start, "A26 必須有可注入的配置點");
        assert_eq!(metatable(&dry, target), desired);
        for offset in 0..end - start {
            let (owner, name, target, original, desired) = setup_set_sweep(action);
            assert_eq!(original.is_some(), old.is_some());
            let before = snapshot(&owner);
            let next = owner
                .with_vm(|vm| vm.allocation_trace().next_ordinal)
                .unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(next + offset))
                .unwrap();
            set_named(&owner, &name);
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
                .unwrap();
            assert_failed(&owner, 1, &before);
            assert_eq!(metatable(&owner, target), original);
            let failure = owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
                .unwrap();
            assert_eq!(failure.attempt.ordinal, next + offset);
            set_named(&owner, &name);
            assert_eq!(metatable(&owner, target), desired);
        }
        println!("A26_ORDINAL_ACTION_{action} checked={}", end - start);
    }

    for point in [
        FailPoint::ObjectReserve,
        FailPoint::StringBytesReserve,
        FailPoint::RootReserve,
        FailPoint::HostLease,
    ] {
        let (owner, name, target, original, desired) = setup_set_sweep(0);
        let before = snapshot(&owner);
        owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        set_named(&owner, &name);
        assert_failed(&owner, 1, &before);
        assert_eq!(metatable(&owner, target), original);
        if matches!(
            point,
            FailPoint::ObjectReserve | FailPoint::StringBytesReserve
        ) {
            assert_eq!(
                owner
                    .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.point)
                    .unwrap(),
                Some(point)
            );
        }
        set_named(&owner, &name);
        assert_eq!(metatable(&owner, target), desired);
    }
}
