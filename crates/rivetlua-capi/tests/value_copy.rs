use std::ffi::{c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_copy, lua_createtable, lua_getglobal, lua_gettop, lua_isinteger,
    lua_pushboolean, lua_pushcclosure, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring,
    lua_pushnil, lua_pushnumber, lua_pushvalue, lua_rawequal, lua_rawgeti, lua_rawseti,
    lua_setglobal, lua_settop, lua_toboolean, lua_tocfunction, lua_tointegerx, lua_tolstring,
    lua_tonumberx, lua_touserdata, lua_type, luaL_ref, luaL_unref,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationFailureKind, AllocationTrace, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, Vm, VmError,
};

unsafe extern "C" {
    fn rivetlua_capi_test_protected_index_a4b(
        state: *mut lua_State,
        operation: c_int,
        index: c_int,
        argument: c_int,
        name: *const c_char,
        answer: *mut c_int,
    ) -> c_int;
}

fn protected_index(
    state: *mut lua_State,
    operation: c_int,
    index: c_int,
    argument: c_int,
) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：私有 C checkpoint 擷取 Lua error，並於返回前清除 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            operation,
            index,
            argument,
            std::ptr::null(),
            &mut answer,
        )
    };
    (status, answer)
}

fn protected_named(state: *mut lua_State, operation: c_int, name: *const c_char) -> (c_int, c_int) {
    let mut answer = 0;
    // SAFETY：私有 C checkpoint 擷取 Lua error，並於返回前清除 pending 狀態。
    let status = unsafe {
        rivetlua_capi_test_protected_index_a4b(state, operation, 0, 0, name, &mut answer)
    };
    (status, answer)
}

fn prime_checkpoint(state: *mut lua_State) {
    assert_eq!(protected_index(state, -1, 0, 0).0, 0);
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
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, Roots);
type Slot = (i32, i64, u64, i32, usize, Vec<u8>);
type StackSnapshot = (i32, Vec<Slot>, Vec<i32>, Vec<i32>);

fn vm_snapshot(owner: &StateOwner) -> VmSnapshot {
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

fn stack_snapshot(state: *mut lua_State) -> StackSnapshot {
    // SAFETY：StateOwner 在呼叫期間持有 state 與 top 範圍的 slots；所有查詢只讀值。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer = if tag == 3 && lua_isinteger(state, index) != 0 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let number_bits = if tag == 3 && lua_isinteger(state, index) == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let boolean = if tag == 1 {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                let pointer = if tag == 2 {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                let bytes = if tag == 4 {
                    let mut len = 0;
                    let value = lua_tolstring(state, index, &mut len);
                    assert!(!value.is_null());
                    std::slice::from_raw_parts(value.cast::<u8>(), len).to_vec()
                } else {
                    Vec::new()
                };
                (tag, integer, number_bits, boolean, pointer, bytes)
            })
            .collect();
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        let registry_matches = (1..=top)
            .map(|index| lua_rawequal(state, index, REGISTRY_INDEX))
            .collect();
        (top, slots, identities, registry_matches)
    }
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

fn host_roots(roots: &Roots) -> Vec<(RootId, ObjectRef)> {
    roots
        .iter()
        .filter_map(|(kind, id, object)| (*kind == RootKind::Host).then_some((*id, *object)))
        .collect()
}

fn add_table(owner: &StateOwner) -> ObjectRef {
    let table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(table)).unwrap();
    table
}

fn install_function_and_thread(owner: &StateOwner) {
    let (function_handle, coroutine_handle) = owner
        .with_vm(|vm| {
            let registry = registry(vm);
            let Value::Object(globals) = vm.raw_get(registry, Value::Integer(2)).unwrap() else {
                panic!("registry globals 必須是 table");
            };
            vm.install_basic_builtins(globals).unwrap();
            let key = vm.allocate_byte_string(b"type").unwrap();
            let function = vm.raw_get(globals, Value::Object(key)).unwrap();
            let Value::Object(function_object) = function else {
                panic!("basic type 必須是 function");
            };
            assert_eq!(vm.object_kind(function_object), Ok(ObjectKind::Builtin));
            (
                rivetlua_runtime::HostHandle::<Value>::new(vm, function_object).unwrap(),
                vm.new_coroutine(function).unwrap(),
            )
        })
        .unwrap();
    let (function, coroutine) = owner
        .with_vm(|vm| {
            (
                function_handle.as_value(vm).unwrap(),
                coroutine_handle.as_value(vm).unwrap(),
            )
        })
        .unwrap();
    owner.push_value(function).unwrap();
    owner.push_value(coroutine).unwrap();
    drop(function_handle);
    drop(coroutine_handle);
}

fn enter_active_gc(owner: &StateOwner) {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            for _ in 0..128 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            vm.set_collect_every_allocation(true);
        })
        .unwrap();
}

fn pushvalue_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let mut token = 12_u8;
    let pointer = (&mut token as *mut u8).cast::<c_void>();
    // SAFETY：owner 持有有效 state；lightuserdata 只傳遞 opaque pointer。
    unsafe {
        lua_pushnil(state);
        lua_pushboolean(state, -3);
        lua_pushinteger(state, i64::MIN);
        lua_pushnumber(state, -0.0);
        lua_pushlightuserdata(state, pointer);
        let bytes = b"a12\0\xff";
        assert!(!lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len()).is_null());
    }
    let table = add_table(&owner);
    install_function_and_thread(&owner);
    // SAFETY：先長到二十個 slots 再縮回九個，後續 pushvalue 不跨容量邊界。
    unsafe {
        assert_eq!(lua_gettop(state), 9);
        lua_settop(state, 20);
        lua_settop(state, 9);
    }
    enter_active_gc(&owner);

    for index in 1..=9 {
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        // SAFETY：1～9 都是仍有效的來源 slot；複製品只由新 slot 持有。
        unsafe {
            lua_pushvalue(state, index);
            assert_eq!(lua_gettop(state), 10);
            assert_eq!(lua_rawequal(state, index, -1), 1);
        }
        let after_vm = vm_snapshot(&owner);
        let before_host = host_roots(&before_vm.3);
        let after_host = host_roots(&after_vm.3);
        if index >= 6 {
            assert_eq!(after_host.len(), before_host.len() + 1, "slot {index}");
            let new_roots: Vec<_> = after_host
                .iter()
                .filter(|(id, _)| !before_host.iter().any(|(old, _)| old == id))
                .collect();
            assert_eq!(
                new_roots.len(),
                1,
                "slot {index}: collectable clone 須有獨立 root"
            );
        } else {
            assert_eq!(after_host, before_host, "slot {index}: scalar 不建立 root");
            assert_eq!(after_vm.1, before_vm.1, "slot {index}: 既有容量不配置");
            assert_eq!(after_vm.2, before_vm.2, "slot {index}: scalar 不推進 GC");
        }
        // SAFETY：只移除剛複製的最末 slot；原來源必須保留。
        unsafe { lua_settop(state, -2) };
        assert_eq!(stack_snapshot(state), before_stack);
        let after_pop = vm_snapshot(&owner);
        assert_eq!(after_pop.0, before_vm.0, "slot {index}: ledger 退還");
        assert_eq!(after_pop.3, before_vm.3, "slot {index}: 新 root 已釋放");
    }

    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(&owner);
    // SAFETY：registry 是合法來源 pseudo-index；複製後必有獨立 Host root。
    unsafe {
        lua_pushvalue(state, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), 10);
        assert_eq!(lua_type(state, -1), 5);
        assert_eq!(lua_rawequal(state, -1, REGISTRY_INDEX), 1);
    }
    assert_eq!(
        host_roots(&vm_snapshot(&owner).3).len(),
        host_roots(&before_vm.3).len() + 1
    );
    // SAFETY：移除 registry 的 stack 複本，不解除永久 Registry root。
    unsafe { lua_settop(state, -2) };
    assert_eq!(stack_snapshot(state), before_stack);
    assert_eq!(vm_snapshot(&owner).0, before_vm.0);
    assert_eq!(vm_snapshot(&owner).3, before_vm.3);

    let unchanged_stack = stack_snapshot(state);
    let unchanged_vm = vm_snapshot(&owner);
    // SAFETY：無效、他版 registry 與 upvalue pseudo-index 都須在建立 root 前拒絕。
    for index in [0, 10, -10, OTHER_REGISTRY_INDEX, REGISTRY_INDEX - 1] {
        assert!(protected_index(state, 11, index, 0).0 > 0, "index={index}");
        assert_eq!(stack_snapshot(state), unchanged_stack);
        assert_eq!(vm_snapshot(&owner).3, unchanged_vm.3);
    }
    assert_eq!(protected_index(std::ptr::null_mut(), 11, 1, 0).0, -1);
    owner
        .with_vm(|_| {
            // SAFETY：故意在 VM borrow 期間重入，入口應 fail-closed。
            assert_eq!(protected_index(state, 11, 1, 0).0, -1);
        })
        .unwrap();
    assert_eq!(stack_snapshot(state), unchanged_stack);
    assert_eq!(vm_snapshot(&owner).3, unchanged_vm.3);

    let rooted_objects: Vec<_> = host_roots(&vm_snapshot(&owner).3)
        .into_iter()
        .map(|(_, object)| {
            let kind = owner.with_vm(|vm| vm.object_kind(object)).unwrap().unwrap();
            (object, kind)
        })
        .collect();
    assert!(
        rooted_objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::ByteString)
    );
    assert!(
        rooted_objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::Table)
    );
    assert!(
        rooted_objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::Builtin)
    );
    assert!(
        rooted_objects
            .iter()
            .any(|(_, kind)| *kind == ObjectKind::Coroutine)
    );
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            for (object, kind) in &rooted_objects {
                assert_eq!(vm.object_kind(*object), Ok(*kind));
            }
        })
        .unwrap();
    // SAFETY：全部 C stack slots 移除後，只有永久 Registry root 保留。
    unsafe { lua_settop(state, 0) };
    assert!(host_roots(&vm_snapshot(&owner).3).is_empty());
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(table), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(registry(vm)), Ok(ObjectKind::Table));
        })
        .unwrap();
}

fn copy_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 有效；兩個 scalar 先占據真實目的 slots。
    unsafe {
        lua_pushinteger(state, 7);
        lua_pushboolean(state, 0);
    }
    let first = add_table(&owner);
    let replaced = add_table(&owner);
    assert_eq!(host_roots(&vm_snapshot(&owner).3).len(), 2);
    enter_active_gc(&owner);

    let scalar_vm = vm_snapshot(&owner);
    // SAFETY：real→real scalar copy 只替換 slot，不建立 root 或配置。
    unsafe {
        lua_copy(state, 1, 2);
        assert_eq!(lua_tointegerx(state, 2, std::ptr::null_mut()), 7);
    }
    assert_eq!(vm_snapshot(&owner), scalar_vm);
    let no_op_stack = stack_snapshot(state);
    let no_op_vm = vm_snapshot(&owner);
    // SAFETY：同一真實 slot 的 copy 必須是完全無配置 no-op。
    unsafe { lua_copy(state, 3, 3) };
    assert_eq!(stack_snapshot(state), no_op_stack);
    assert_eq!(vm_snapshot(&owner), no_op_vm);

    let old_roots = host_roots(&vm_snapshot(&owner).3);
    // SAFETY：負索引 -2/-1 對應兩個真實 table slots；新 root 先於舊目的 root 釋放。
    unsafe {
        assert_eq!(lua_rawequal(state, 3, 4), 0);
        lua_copy(state, -2, -1);
        assert_eq!(lua_rawequal(state, 3, 4), 1);
    }
    let after_roots = host_roots(&vm_snapshot(&owner).3);
    assert_eq!(after_roots.len(), 2);
    assert_eq!(
        after_roots
            .iter()
            .filter(|(_, object)| *object == first)
            .count(),
        2
    );
    assert!(after_roots.iter().all(|(_, object)| *object != replaced));
    assert_ne!(after_roots[0].0, after_roots[1].0);
    assert!(old_roots.iter().any(|(_, object)| *object == replaced));
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(replaced), Err(VmError::StaleObject));
        })
        .unwrap();

    let registry_object = owner.with_vm(|vm| registry(vm)).unwrap();
    // SAFETY：registry 可作 source；目的仍為第 4 個真實 slot。
    unsafe {
        lua_copy(state, REGISTRY_INDEX, 4);
        assert_eq!(lua_type(state, 4), 5);
        assert_eq!(lua_rawequal(state, 4, REGISTRY_INDEX), 1);
    }
    let after_registry = host_roots(&vm_snapshot(&owner).3);
    assert_eq!(after_registry.len(), 2);
    assert_eq!(
        after_registry
            .iter()
            .filter(|(_, object)| *object == first)
            .count(),
        1
    );
    assert_eq!(
        after_registry
            .iter()
            .filter(|(_, object)| *object == registry_object)
            .count(),
        1
    );
    // SAFETY：負索引 source -2 複製 object 到 scalar 目的，之後 scalar 覆寫 registry stack root。
    unsafe {
        lua_copy(state, -2, 2);
        assert_eq!(lua_rawequal(state, 2, 3), 1);
        lua_copy(state, 1, -1);
        assert_eq!(lua_tointegerx(state, 4, std::ptr::null_mut()), 7);
    }
    let final_roots = host_roots(&vm_snapshot(&owner).3);
    assert_eq!(final_roots.len(), 2);
    assert!(final_roots.iter().all(|(_, object)| *object == first));
    assert_ne!(final_roots[0].0, final_roots[1].0);

    let unchanged_stack = stack_snapshot(state);
    let unchanged_vm = vm_snapshot(&owner);
    // SAFETY：所有無效 source/destination 與 pseudo destination 均應在 mutation 前拒絕。
    for (source, destination) in [
        (0, 2),
        (5, 2),
        (-5, 2),
        (3, 0),
        (3, 5),
        (3, -5),
        (OTHER_REGISTRY_INDEX, 2),
        (3, OTHER_REGISTRY_INDEX),
        (REGISTRY_INDEX - 1, 2),
        (3, REGISTRY_INDEX - 1),
    ] {
        assert!(
            protected_index(state, 12, source, destination).0 > 0,
            "source={source} destination={destination}"
        );
        assert_eq!(stack_snapshot(state), unchanged_stack);
        assert_eq!(vm_snapshot(&owner).3, unchanged_vm.3);
    }
    assert_eq!(protected_index(std::ptr::null_mut(), 12, 1, 2).0, -1);
    owner
        .with_vm(|_| {
            // SAFETY：持有 VM borrow 時重入，同一 C state 必須 fail-closed。
            assert_eq!(protected_index(state, 12, 3, 2).0, -1);
        })
        .unwrap();
    assert_eq!(stack_snapshot(state), unchanged_stack);
    assert_eq!(vm_snapshot(&owner).3, unchanged_vm.3);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table));
            assert_eq!(vm.object_kind(registry_object), Ok(ObjectKind::Table));
        })
        .unwrap();
    // SAFETY：移除最後兩個 object slots，Host roots 應全部退還。
    unsafe { lua_settop(state, 0) };
    assert!(host_roots(&vm_snapshot(&owner).3).is_empty());
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
        })
        .unwrap();
}

fn replace_macro_cases() {
    let lua54 = include_str!("../../../include/rivetlua/lua54/lua.h");
    let lua55 = include_str!("../../../include/rivetlua/lua55/lua.h");
    for header in [lua54, lua55] {
        assert!(
            header.contains("#define lua_replace(L,idx)\t(lua_copy(L, -1, (idx)), lua_pop(L, 1))")
        );
    }
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：固定 header 的直接展開使用既有 copy 與 settop primitive。
    unsafe {
        lua_pushinteger(state, 10);
        lua_pushinteger(state, 20);
        lua_copy(state, -1, 1);
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_tointegerx(state, 1, std::ptr::null_mut()), 20);
        lua_settop(state, 0);
    }
    let old = add_table(&owner);
    let new = add_table(&owner);
    enter_active_gc(&owner);
    // SAFETY：先為 top object 建立目的 root，再依 lua_pop 展開移除舊 top root。
    unsafe {
        lua_copy(state, -1, 1);
        assert_eq!(lua_rawequal(state, 1, 2), 1);
        lua_settop(state, -2);
        assert_eq!(lua_gettop(state), 1);
    }
    let roots = host_roots(&vm_snapshot(&owner).3);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].1, new);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(old), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(new), Ok(ObjectKind::Table));
        })
        .unwrap();
    // SAFETY：最後一個 object slot 移除後，新物件亦可回收。
    unsafe { lua_settop(state, 0) };
    assert!(host_roots(&vm_snapshot(&owner).3).is_empty());
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(new), Err(VmError::StaleObject));
        })
        .unwrap();
}

#[derive(Clone, Copy, Debug)]
enum FaultOperation {
    PushScalarCapacity,
    PushObjectCapacity,
    CopyObjectReal,
    CopyRegistrySource,
}

fn check_fault_prefix(
    operation: FaultOperation,
    failures: &[(u64, AllocationDomain, &'static str, u32)],
    successes: &[(u64, u64)],
    end: u64,
) {
    let prefix = failures.len() as u64;
    assert!(prefix > 0, "{operation:?}: 必須命中實際配置點");
    assert!(
        end - prefix >= 8,
        "{operation:?}: 成功尾段至少八個連續 offsets"
    );
    assert_eq!(
        failures.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (0..prefix).collect::<Vec<_>>(),
        "{operation:?}: 每個失敗配置點都須在完整前綴"
    );
    assert_eq!(
        successes.iter().map(|entry| entry.0).collect::<Vec<_>>(),
        (prefix..end).collect::<Vec<_>>(),
        "{operation:?}: 成功必須是連續尾段"
    );
    for &(offset, domain, _site, line) in failures {
        assert_eq!(
            domain,
            AllocationDomain::Host,
            "{operation:?} offset {offset}"
        );
        assert!(line > 0, "{operation:?}: 配置點需有實際來源行");
    }
    let roots_site = ("crates/rivetlua-runtime/src/roots.rs", 151);
    let expected_sites: &[(&str, u32)] = match operation {
        FaultOperation::PushScalarCapacity => &[],
        FaultOperation::PushObjectCapacity => &[roots_site],
        FaultOperation::CopyObjectReal | FaultOperation::CopyRegistrySource => &[roots_site],
    };
    assert_eq!(
        failures
            .iter()
            .map(|entry| (entry.2, entry.3))
            .collect::<Vec<_>>(),
        expected_sites,
        "{operation:?}: trace 必須對應完整 root／capacity 配置前綴"
    );
    for &(offset, attempts) in successes {
        assert_eq!(
            attempts, prefix,
            "{operation:?} offset {offset}: 不得有隱藏後續配置"
        );
    }
    println!("A12_ALLOC\t{operation:?}\tfailures={failures:?}\tsuccesses={successes:?}");
}

fn fault_matrix() {
    const END: u64 = 20;
    // 第 21 格的 checkpoint 預留先獨立驗故障原子性與帳本退款。
    let preflight = StateOwner::new().unwrap();
    let preflight_state = preflight.as_ptr();
    unsafe {
        lua_pushinteger(preflight_state, 47);
        lua_settop(preflight_state, 20);
    }
    let before_stack = stack_snapshot(preflight_state);
    let before_vm = vm_snapshot(&preflight);
    preflight
        .with_vm(|vm| vm.inject_allocation_failure_at(before_vm.1.next_ordinal))
        .unwrap();
    assert_eq!(protected_index(preflight_state, -1, 0, 0).0, -1);
    assert_eq!(stack_snapshot(preflight_state), before_stack);
    let failed = vm_snapshot(&preflight);
    assert_eq!(failed.0, before_vm.0);
    assert_eq!(failed.2, before_vm.2);
    assert_eq!(failed.3, before_vm.3);
    let failure = failed.1.last_failure.unwrap();
    assert_eq!(failure.kind, AllocationFailureKind::Injection);
    assert_eq!(failure.attempt.ordinal, before_vm.1.next_ordinal);
    assert_eq!(failure.attempt.domain, AllocationDomain::Host);
    assert_eq!(
        failure.attempt.site.file,
        "crates/rivetlua-runtime/src/heap.rs"
    );
    assert_eq!(failure.attempt.site.line, 2308);
    assert_eq!(failure.attempt.bytes, 5760);
    assert_eq!(protected_index(preflight_state, -1, 0, 0).0, 0);
    let prepared = vm_snapshot(&preflight);
    assert_eq!(
        prepared.0.host_allocation_bytes - before_vm.0.host_allocation_bytes,
        2880
    );
    assert_eq!(protected_index(preflight_state, -1, 0, 0).0, 0);
    assert_eq!(vm_snapshot(&preflight).0, prepared.0);
    let probe = preflight.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(preflight);
    assert_eq!(probe.snapshot().committed, 0);

    for operation in [
        FaultOperation::PushScalarCapacity,
        FaultOperation::PushObjectCapacity,
        FaultOperation::CopyObjectReal,
        FaultOperation::CopyRegistrySource,
    ] {
        let mut failures = Vec::new();
        let mut successes = Vec::new();
        for offset in 0..END {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            let mut tables = Vec::new();
            match operation {
                FaultOperation::PushScalarCapacity => {
                    // SAFETY：將 stack 填滿最小容量；來源仍是第一格 scalar。
                    unsafe {
                        lua_pushinteger(state, 47);
                        lua_settop(state, 20);
                    }
                }
                FaultOperation::PushObjectCapacity => {
                    tables.push(add_table(&owner));
                    // SAFETY：將 stack 填滿最小容量，下一次複製需 root 與容量配置。
                    unsafe { lua_settop(state, 20) };
                }
                FaultOperation::CopyObjectReal => {
                    tables.push(add_table(&owner));
                    tables.push(add_table(&owner));
                    // SAFETY：兩個 table slots 是不同真實物件。
                    assert_eq!(unsafe { lua_rawequal(state, 1, 2) }, 0);
                }
                FaultOperation::CopyRegistrySource => {
                    tables.push(add_table(&owner));
                    // SAFETY：目的 table 與 permanent registry table 不同。
                    assert_eq!(unsafe { lua_rawequal(state, 1, REGISTRY_INDEX) }, 0);
                }
            }
            prime_checkpoint(state);
            enter_active_gc(&owner);
            let before_stack = stack_snapshot(state);
            let before_vm = vm_snapshot(&owner);
            let ordinal = owner
                .with_vm(|vm| {
                    let ordinal = vm.allocation_trace().next_ordinal + offset;
                    vm.inject_allocation_failure_at(ordinal);
                    ordinal
                })
                .unwrap();
            let (status, _) = match operation {
                FaultOperation::PushScalarCapacity | FaultOperation::PushObjectCapacity => {
                    protected_index(state, 11, 1, 0)
                }
                FaultOperation::CopyObjectReal => protected_index(state, 12, 1, 2),
                FaultOperation::CopyRegistrySource => protected_index(state, 12, REGISTRY_INDEX, 1),
            };
            // SAFETY：兩個 source/destination index 均由本測試建立；只讀取成功條件。
            let success = unsafe {
                match operation {
                    FaultOperation::PushScalarCapacity | FaultOperation::PushObjectCapacity => {
                        lua_gettop(state) == before_stack.0 + 1
                    }
                    FaultOperation::CopyObjectReal => lua_rawequal(state, 1, 2) == 1,
                    FaultOperation::CopyRegistrySource => {
                        lua_rawequal(state, 1, REGISTRY_INDEX) == 1
                    }
                }
            };
            let after_vm = vm_snapshot(&owner);
            assert_eq!(
                after_vm.2.phase, before_vm.2.phase,
                "{operation:?} offset {offset}"
            );
            assert_eq!(
                after_vm.2.transition_count, before_vm.2.transition_count,
                "{operation:?} offset {offset}: active GC 不可轉移"
            );
            if success {
                assert_eq!(status, 0);
                assert_eq!(
                    after_vm.1.last_failure, before_vm.1.last_failure,
                    "{operation:?} offset {offset}: 成功不可隱藏注入失敗"
                );
                successes.push((offset, after_vm.1.next_ordinal - before_vm.1.next_ordinal));
                let old_host = host_roots(&before_vm.3).len();
                let expected_host = match operation {
                    FaultOperation::PushScalarCapacity => old_host,
                    FaultOperation::PushObjectCapacity => old_host + 1,
                    FaultOperation::CopyObjectReal | FaultOperation::CopyRegistrySource => old_host,
                };
                assert_eq!(host_roots(&after_vm.3).len(), expected_host);
                owner
                    .with_vm(|vm| {
                        vm.inject_allocation_failure_at(u64::MAX);
                        vm.collect().unwrap();
                        vm.collect().unwrap();
                        if let Some(&first) = tables.first() {
                            match operation {
                                FaultOperation::CopyRegistrySource => {
                                    assert_eq!(vm.object_kind(first), Err(VmError::StaleObject));
                                }
                                _ => assert_eq!(vm.object_kind(first), Ok(ObjectKind::Table)),
                            }
                        }
                        if matches!(operation, FaultOperation::CopyObjectReal) {
                            assert_eq!(vm.object_kind(tables[1]), Err(VmError::StaleObject));
                        }
                        assert_eq!(vm.object_kind(registry(vm)), Ok(ObjectKind::Table));
                    })
                    .unwrap();
            } else {
                assert!(status > 0);
                assert_eq!(
                    stack_snapshot(state),
                    before_stack,
                    "{operation:?} offset {offset}"
                );
                assert_eq!(
                    after_vm.0, before_vm.0,
                    "{operation:?} offset {offset}: ledger"
                );
                assert_eq!(
                    after_vm.3, before_vm.3,
                    "{operation:?} offset {offset}: roots"
                );
                for object in tables {
                    assert_eq!(
                        owner.with_vm(|vm| vm.object_kind(object)).unwrap(),
                        Ok(ObjectKind::Table),
                        "{operation:?} offset {offset}: 失敗時 table 仍可達"
                    );
                }
                let failure = after_vm
                    .1
                    .last_failure
                    .expect("失敗必須有 allocation trace");
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt.ordinal, ordinal);
                failures.push((
                    offset,
                    failure.attempt.domain,
                    failure.attempt.site.file,
                    failure.attempt.site.line,
                ));
            }
        }
        if matches!(operation, FaultOperation::PushScalarCapacity) {
            assert!(failures.is_empty());
            assert_eq!(
                successes,
                (0..END).map(|offset| (offset, 0)).collect::<Vec<_>>()
            );
        } else {
            check_fault_prefix(operation, &failures, &successes, END);
        }
    }
}

fn existing_capacity_scalar_copy_is_allocation_free() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：先保留十格容量，再縮回一格 scalar；後續不跨容量邊界。
    unsafe {
        lua_pushinteger(state, 13);
        lua_settop(state, 10);
        lua_settop(state, 1);
    }
    enter_active_gc(&owner);
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(&owner);
    // SAFETY：scalar pushvalue、copy、same-slot copy 與 pop 均不需配置。
    unsafe {
        lua_pushvalue(state, 1);
        lua_copy(state, 1, 2);
        lua_copy(state, 2, 2);
        lua_copy(state, 1, 1);
        lua_settop(state, -2);
    }
    assert_eq!(stack_snapshot(state), before_stack);
    assert_eq!(vm_snapshot(&owner), before_vm);
}

#[cfg(feature = "lua55")]
const MAINTHREAD_INDEX_B12: i64 = 3;
#[cfg(feature = "lua54")]
const MAINTHREAD_INDEX_B12: i64 = 1;

unsafe extern "C" fn registry_function_b12(_state: *mut lua_State) -> i32 {
    0
}

fn registry_destination_value_cases_b12() {
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    let peer = sibling.as_ptr();
    let (old_registry, main_thread) = owner
        .with_vm(|vm| {
            let old = registry(vm);
            let Value::Object(main) = vm
                .raw_get(old, Value::Integer(MAINTHREAD_INDEX_B12))
                .unwrap()
            else {
                panic!("main coroutine 必須由初始 registry 可達");
            };
            (old, main)
        })
        .unwrap();

    // SAFETY：兩個 overlay 同屬存活 VM；registry 目的地不改 C stack top。
    unsafe {
        lua_pushinteger(state, 47);
        let top = lua_gettop(state);
        lua_copy(state, 1, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), top);
        assert_eq!(lua_type(peer, REGISTRY_INDEX), 3);
        assert_eq!(
            lua_tointegerx(peer, REGISTRY_INDEX, std::ptr::null_mut()),
            47
        );
        lua_copy(peer, REGISTRY_INDEX, REGISTRY_INDEX);
        assert_eq!(lua_gettop(peer), 0);
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(old_registry), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(main_thread), Ok(ObjectKind::Coroutine));
        })
        .unwrap();

    // SAFETY：public registry 已是 number；table consumers 均須 fail-closed 且不 pop。
    unsafe {
        lua_pushinteger(state, 99);
        let top = lua_gettop(state);
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 2), -1);
        assert!(protected_named(state, 19, c"b12".as_ptr()).0 > 0);
        lua_rawseti(state, REGISTRY_INDEX, 17);
        assert!(protected_named(state, 20, c"b12".as_ptr()).0 > 0);
        assert!(protected_index(state, 9, REGISTRY_INDEX, 0).0 > 0);
        assert!(protected_index(state, 10, REGISTRY_INDEX, 4).0 > 0);
        assert_eq!(lua_gettop(state), top);
        assert_eq!(lua_type(peer, REGISTRY_INDEX), 3);
    }

    // SAFETY：二進位字串 bytes 及 C function 身分由共享 registry 可見。
    unsafe {
        lua_pushnumber(state, 0.0);
        lua_copy(state, -1, REGISTRY_INDEX);
        lua_pushnumber(state, -0.0);
        lua_copy(state, -1, REGISTRY_INDEX);
        assert_eq!(
            lua_tonumberx(peer, REGISTRY_INDEX, std::ptr::null_mut()).to_bits(),
            (-0.0_f64).to_bits()
        );
        lua_pushlstring(state, b"a\0b".as_ptr().cast(), 3);
        lua_copy(state, -1, REGISTRY_INDEX);
        lua_pushvalue(peer, REGISTRY_INDEX);
        let mut len = 0;
        let pointer = lua_tolstring(peer, -1, &mut len);
        assert!(!pointer.is_null());
        assert_eq!(
            std::slice::from_raw_parts(pointer.cast::<u8>(), len),
            b"a\0b"
        );
        lua_settop(peer, 0);
        lua_pushcclosure(state, Some(registry_function_b12), 0);
        lua_copy(state, -1, REGISTRY_INDEX);
        assert_eq!(lua_type(peer, REGISTRY_INDEX), 6);
        assert!(lua_tocfunction(peer, REGISTRY_INDEX).is_some());
        assert_eq!(lua_rawequal(state, -1, REGISTRY_INDEX), 1);
        let snapshot = vm_snapshot(&owner);
        lua_copy(peer, REGISTRY_INDEX, REGISTRY_INDEX);
        assert_eq!(vm_snapshot(&owner), snapshot);
    }

    // SAFETY：寫回新 table 後，raw registry、globals 與 refs 均恢復使用新值。
    unsafe {
        lua_createtable(state, 0, 0);
        let table_index = lua_gettop(state);
        lua_copy(state, -1, REGISTRY_INDEX);
        assert_eq!(lua_gettop(state), table_index);
        assert_eq!(lua_rawequal(state, -1, REGISTRY_INDEX), 1);
        assert_eq!(lua_type(peer, REGISTRY_INDEX), 5);
        lua_pushinteger(peer, 88);
        lua_rawseti(peer, REGISTRY_INDEX, 44);
        assert_eq!(lua_rawgeti(state, REGISTRY_INDEX, 44), 3);
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 88);
        lua_createtable(state, 0, 0);
        lua_rawseti(state, REGISTRY_INDEX, 2);
        lua_pushinteger(state, 123);
        lua_setglobal(state, c"b12".as_ptr());
        assert_eq!(lua_getglobal(peer, c"b12".as_ptr()), 3);
        assert_eq!(lua_tointegerx(peer, -1, std::ptr::null_mut()), 123);
        lua_pushinteger(state, 55);
        let reference = luaL_ref(state, REGISTRY_INDEX);
        assert!(reference > 0);
        assert_eq!(lua_rawgeti(peer, REGISTRY_INDEX, i64::from(reference)), 3);
        assert_eq!(lua_tointegerx(peer, -1, std::ptr::null_mut()), 55);
        luaL_unref(state, REGISTRY_INDEX, reference);
        let before = stack_snapshot(state);
        assert!(protected_index(state, 12, 1, OTHER_REGISTRY_INDEX).0 > 0);
        assert!(protected_index(state, 12, 1, REGISTRY_INDEX - 1).0 > 0);
        assert_eq!(stack_snapshot(state), before);
    }
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    drop(sibling);
    drop(owner);
    assert_eq!(probe.snapshot().committed, 0);
    assert_eq!(probe.snapshot().reserved, 0);
}

fn registry_destination_failure_cases_b12() {
    for failpoint in [false, true] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let old_registry = owner.with_vm(|vm| registry(vm)).unwrap();
        let table = add_table(&owner);
        prime_checkpoint(state);
        enter_active_gc(&owner);
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        owner
            .with_vm(|vm| {
                if failpoint {
                    vm.inject_failure_once(rivetlua_runtime::FailPoint::RootReserve);
                } else {
                    vm.inject_allocation_failure_at(vm.allocation_trace().next_ordinal);
                }
            })
            .unwrap();
        // SAFETY：注入的新 registry root 準備失敗；原值、stack 與 GC 不可變。
        assert!(protected_index(state, 12, 1, REGISTRY_INDEX).0 > 0);
        assert_eq!(stack_snapshot(state), before_stack);
        let after_vm = vm_snapshot(&owner);
        assert_eq!(after_vm.0, before_vm.0);
        assert_eq!(after_vm.3, before_vm.3);
        assert_eq!(after_vm.2.phase, before_vm.2.phase);
        assert_eq!(after_vm.2.transition_count, before_vm.2.transition_count);
        assert_eq!(unsafe { lua_rawequal(state, 1, REGISTRY_INDEX) }, 0);
        // SAFETY：同一 state 立即重試，成功後只有新 table 的 registry root 存活。
        unsafe {
            lua_copy(state, 1, REGISTRY_INDEX);
            assert_eq!(lua_rawequal(state, 1, REGISTRY_INDEX), 1);
            lua_settop(state, 0);
        }
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
                assert_eq!(vm.object_kind(old_registry), Err(VmError::StaleObject));
            })
            .unwrap();
        let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        drop(owner);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}

#[test]
fn registry_destination_b12_matrix() {
    registry_destination_value_cases_b12();
    registry_destination_failure_cases_b12();
}

#[test]
fn value_copy_a12_matrix() {
    {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：owner 持有有效 state；registry 是固定 header 的合法來源 pseudo-index。
        unsafe {
            lua_pushnil(state);
            assert_eq!(lua_type(state, 1), 0);
            lua_copy(state, REGISTRY_INDEX, 1);
            assert_eq!(
                lua_type(state, 1),
                5,
                "registry source 必須複製 table 至真實 slot"
            );
        }
    }
    pushvalue_cases();
    copy_cases();
    replace_macro_cases();
    fault_matrix();
    existing_capacity_scalar_copy_is_allocation_free();
}
