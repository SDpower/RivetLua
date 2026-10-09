use std::ffi::{c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_isinteger, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber,
    lua_pushvalue, lua_rawequal, lua_settop, lua_tointegerx, lua_tolstring, lua_tonumberx,
    lua_touserdata, lua_type, lua_xmove, luaL_checklstring, luaL_optlstring,
};
use rivetlua_core::{ObjectRef, SlotId, Value};
use rivetlua_runtime::{
    AllocationDomain, AllocationTrace, FailPoint, GcMode, GcPhase, GcTrace, LedgerSnapshot,
    ObjectKind, RootId, RootKind, SlotState, Vm, VmError,
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

fn protected_string(state: *mut lua_State, operation: c_int, index: c_int) -> c_int {
    // SAFETY：私有純 C checkpoint 捕捉 Lua 錯誤並消費 pending 狀態。
    unsafe {
        rivetlua_capi_test_protected_index_a4b(
            state,
            operation,
            index,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
        )
    }
}

#[cfg(feature = "lua55")]
const REGISTRY_INDEX: c_int = -(c_int::MAX / 2 + 1000);
#[cfg(feature = "lua54")]
const REGISTRY_INDEX: c_int = -1_001_000;
#[cfg(feature = "lua55")]
const OTHER_PROFILE_REGISTRY_INDEX: c_int = -1_001_000;
#[cfg(feature = "lua54")]
const OTHER_PROFILE_REGISTRY_INDEX: c_int = -(c_int::MAX / 2 + 1000);

const TOP: c_int = 13;
const LUA_TNONE: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TNUMBER: c_int = 3;
const LUA_TSTRING: c_int = 4;
const LUA_TTABLE: c_int = 5;
const LUA_TFUNCTION: c_int = 6;
const LUA_TTHREAD: c_int = 8;

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, RootSnapshot);
type StackSnapshot = (c_int, Vec<(c_int, c_int, i64, u64, usize)>, Vec<c_int>);

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
    // SAFETY：呼叫端持有有效 StateOwner；只讀取目前 top 範圍內的值與身份。
    unsafe {
        let top = lua_gettop(state);
        let slots = (1..=top)
            .map(|index| {
                let tag = lua_type(state, index);
                let integer_tag = if tag == LUA_TNUMBER {
                    lua_isinteger(state, index)
                } else {
                    0
                };
                let integer = if integer_tag != 0 {
                    lua_tointegerx(state, index, std::ptr::null_mut())
                } else {
                    0
                };
                let number_bits = if tag == LUA_TNUMBER && integer_tag == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let pointer = if tag == 2 {
                    lua_touserdata(state, index).expose_provenance()
                } else {
                    0
                };
                (tag, integer_tag, integer, number_bits, pointer)
            })
            .collect();
        let mut identities = Vec::new();
        for left in 1..=top {
            for right in 1..=top {
                identities.push(lua_rawequal(state, left, right));
            }
        }
        (top, slots, identities)
    }
}

fn assert_unchanged(
    owner: &StateOwner,
    state: *mut lua_State,
    stack: &StackSnapshot,
    vm: &VmSnapshot,
) {
    assert_eq!(&stack_snapshot(state), stack);
    assert_eq!(&vm_snapshot(owner), vm);
}

fn returned_bytes(pointer: *const c_char, len: usize) -> Vec<u8> {
    assert!(!pointer.is_null());
    // SAFETY：pointer 對應仍在 stack root 內的 Lua string；只讀取已回報的 len bytes。
    unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len).to_vec() }
}

fn push_bytes(state: *mut lua_State, bytes: &[u8]) -> *const c_char {
    // SAFETY：state 由存活 StateOwner 持有，bytes 在呼叫期間有效。
    let string = unsafe { lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len()) };
    assert!(!string.is_null());
    string
}

fn host_objects(owner: &StateOwner) -> Vec<(ObjectRef, ObjectKind)> {
    owner
        .with_vm(|vm| {
            let mut objects = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host {
                    objects.push((object, vm.object_kind(object).unwrap()));
                }
            });
            objects
        })
        .unwrap()
}

fn rooted_state() -> (
    StateOwner,
    *mut lua_State,
    Vec<(ObjectRef, ObjectKind)>,
    *const c_char,
    *const c_char,
    *const c_char,
) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 持有有效 state；lightuserdata 只保存 opaque 位址，不解參照。
    unsafe {
        lua_pushinteger(state, 17);
        lua_pushnumber(state, -0.0);
        lua_pushnil(state);
        lua_pushboolean(state, 1);
        lua_pushlightuserdata(state, std::ptr::dangling_mut::<c_void>());
    }
    let binary = push_bytes(state, b"A\0B");
    let empty = push_bytes(state, b"");
    let present = push_bytes(state, b"present");
    // SAFETY：owner 持有有效 state；建立 number、table roots。
    unsafe {
        lua_pushinteger(state, 7);
        lua_pushnumber(state, -0.0);
        lua_createtable(state, 0, 0);
    }

    let (function, thread_root) = owner
        .with_vm(|vm| -> Result<_, VmError> {
            let mut registry = None;
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Registry && vm.object_kind(object) == Ok(ObjectKind::Table) {
                    registry = Some(object);
                }
            });
            let registry = registry.ok_or(VmError::LedgerInvariant)?;
            let globals = match vm.raw_get(registry, Value::Integer(2))? {
                Value::Object(globals) => globals,
                _ => return Err(VmError::WrongObjectType),
            };
            vm.install_basic_builtins(globals)?;
            let type_key = vm.allocate_byte_string(b"type")?;
            let function = vm.raw_get(globals, Value::Object(type_key))?;
            let Value::Object(function) = function else {
                return Err(VmError::WrongObjectType);
            };
            if vm.object_kind(function)? != ObjectKind::Builtin {
                return Err(VmError::WrongObjectType);
            }
            let thread = vm.new_coroutine(Value::Object(function))?;
            Ok((Value::Object(function), thread))
        })
        .unwrap()
        .unwrap();
    owner.push_value(function).unwrap();
    let thread = owner
        .with_vm(|vm| thread_root.as_value(vm))
        .unwrap()
        .unwrap();
    owner.push_value(thread).unwrap();
    drop(thread_root);

    assert_eq!(unsafe { lua_gettop(state) }, TOP);
    let objects = host_objects(&owner);
    for expected in [
        ObjectKind::ByteString,
        ObjectKind::Table,
        ObjectKind::Builtin,
        ObjectKind::Coroutine,
    ] {
        assert!(objects.iter().any(|(_, kind)| *kind == expected));
    }
    (owner, state, objects, binary, empty, present)
}

fn collect_and_verify_roots(owner: &StateOwner, rooted: &[(ObjectRef, ObjectKind)]) {
    owner
        .with_vm(|vm| -> Result<(), VmError> {
            vm.collect()?;
            vm.collect()?;
            for (object, kind) in rooted {
                assert_eq!(vm.object_kind(*object)?, *kind);
            }
            Ok(())
        })
        .unwrap()
        .unwrap();
}

fn enter_active_gc(owner: &StateOwner, mode: GcMode) {
    owner
        .with_vm(|vm| -> Result<(), VmError> {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(mode)?;
            vm.set_gc_promotion_survivals(1)?;
            vm.collect()?;
            for _ in 0..256 {
                vm.incremental_step(1)?;
                if vm.gc_trace().phase != GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
            Ok(())
        })
        .unwrap()
        .unwrap();
}

fn assert_string(pointer: *const c_char, len: usize, expected: &[u8]) {
    assert!(!pointer.is_null());
    assert_eq!(len, expected.len());
    assert_eq!(returned_bytes(pointer, len), expected);
}

fn exercise_pure_paths(
    state: *mut lua_State,
    binary: *const c_char,
    empty: *const c_char,
    present: *const c_char,
) {
    let default = b"fallback\0ignored";
    let default_pointer = default.as_ptr().cast::<c_char>();
    // SAFETY：state 與 all returned slots 存活；default 的第一個 NUL 在陣列內。
    unsafe {
        let mut len = usize::MAX;
        let checked = luaL_checklstring(state, 6, &mut len);
        assert_eq!(checked, binary);
        assert_string(checked, len, b"A\0B");

        len = usize::MAX;
        let checked_negative = luaL_checklstring(state, -8, &mut len);
        assert_eq!(checked_negative, binary);
        assert_string(checked_negative, len, b"A\0B");

        len = usize::MAX;
        let checked_empty = luaL_checklstring(state, 7, &mut len);
        assert_eq!(checked_empty, empty);
        assert_string(checked_empty, len, b"");

        len = usize::MAX;
        let checked_present = luaL_checklstring(state, 8, &mut len);
        assert_eq!(checked_present, present);
        assert_string(checked_present, len, b"present");

        len = usize::MAX;
        let opt_present = luaL_optlstring(state, 8, default_pointer, &mut len);
        assert_eq!(opt_present, present);
        assert_string(opt_present, len, b"present");

        len = usize::MAX;
        let opt_binary = luaL_optlstring(state, -8, default_pointer, &mut len);
        assert_eq!(opt_binary, binary);
        assert_string(opt_binary, len, b"A\0B");

        for index in [3, 0, TOP + 1, -TOP - 1] {
            len = usize::MAX;
            let result = luaL_optlstring(state, index, default_pointer, &mut len);
            assert_eq!(result, default_pointer, "index {index}");
            assert_string(result, len, b"fallback");
        }
        len = usize::MAX;
        let null_default = luaL_optlstring(state, TOP + 1, std::ptr::null(), &mut len);
        assert!(null_default.is_null());
        assert_eq!(len, 0);
        len = usize::MAX;
        let null_default_nil = luaL_optlstring(state, 3, std::ptr::null(), &mut len);
        assert!(null_default_nil.is_null());
        assert_eq!(len, 0);

        assert_eq!(
            luaL_optlstring(state, 0, default_pointer, std::ptr::null_mut()),
            default_pointer
        );
        assert_eq!(luaL_checklstring(state, 6, std::ptr::null_mut()), binary);
    }
}

fn exercise_string_errors(state: *mut lua_State) {
    for index in [
        3,
        TOP + 1,
        4,
        5,
        11,
        12,
        13,
        REGISTRY_INDEX,
        OTHER_PROFILE_REGISTRY_INDEX,
        REGISTRY_INDEX - 1,
    ] {
        assert!(
            protected_string(state, 17, index) > 0,
            "check index {index}"
        );
        if index != 3 && index != TOP + 1 {
            assert!(protected_string(state, 18, index) > 0, "opt index {index}");
        }
    }
    // SAFETY：state 存活；index 11/12/13 分別是 table、builtin function、coroutine。
    unsafe {
        assert_eq!(lua_type(state, 11), LUA_TTABLE);
        assert_eq!(lua_type(state, 12), LUA_TFUNCTION);
        assert_eq!(lua_type(state, 13), LUA_TTHREAD);
        assert_eq!(lua_type(state, REGISTRY_INDEX), LUA_TTABLE);
        assert_eq!(lua_type(state, OTHER_PROFILE_REGISTRY_INDEX), LUA_TNONE);
        assert_eq!(lua_type(state, REGISTRY_INDEX - 1), LUA_TNONE);
        assert_eq!(lua_type(state, 3), LUA_TNIL);
    }
}

fn assert_zero_allocation_pure_paths(
    owner: &StateOwner,
    state: *mut lua_State,
    binary: *const c_char,
    empty: *const c_char,
    present: *const c_char,
) {
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(owner);
    let target = before_vm.1.next_ordinal;
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(target))
        .unwrap();
    assert_eq!(vm_snapshot(owner), before_vm);

    exercise_pure_paths(state, binary, empty, present);

    assert_unchanged(owner, state, &before_stack, &before_vm);
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
        .unwrap();
}

fn assert_invalid_state_fallbacks(state: *mut lua_State) {
    for operation in 17..=18 {
        assert_eq!(protected_string(std::ptr::null_mut(), operation, 1), -1);
    }

    let address = state as usize;
    let wrong_thread = std::thread::spawn(move || {
        let state = address as *mut lua_State;
        (17..=18)
            .map(|operation| protected_string(state, operation, 1))
            .collect::<Vec<_>>()
    })
    .join()
    .unwrap();
    assert_eq!(wrong_thread, vec![-1; 2]);
}

fn assert_busy_fallbacks(owner: &StateOwner, state: *mut lua_State) {
    owner
        .with_vm(|_| {
            for operation in 17..=18 {
                assert_eq!(protected_string(state, operation, 1), -1);
            }
        })
        .unwrap();
}

fn exercise_numeric_conversions(state: *mut lua_State) -> (*const c_char, *const c_char) {
    let default = b"not used\0";
    // SAFETY：state 存活；轉換成功後 pointer 由替換後的 stack slot root 保活。
    unsafe {
        let mut int_len = usize::MAX;
        let integer = luaL_checklstring(state, 9, &mut int_len);
        assert_string(integer, int_len, b"7");
        assert_eq!(lua_type(state, 9), LUA_TSTRING);

        let mut float_len = usize::MAX;
        let float = luaL_optlstring(state, 10, default.as_ptr().cast::<c_char>(), &mut float_len);
        assert_string(float, float_len, b"-0.0");
        assert_eq!(lua_type(state, 10), LUA_TSTRING);
        (integer, float)
    }
}

fn settle_gc(owner: &StateOwner) {
    owner
        .with_vm(|vm| {
            for _ in 0..3 {
                while vm.gc_trace().phase != GcPhase::Pause {
                    vm.incremental_step(1024).unwrap();
                }
                vm.collect().unwrap();
            }
        })
        .unwrap();
}

fn slot_census(vm: &Vm) -> (usize, usize, usize) {
    let mut occupied = 0;
    let mut free = 0;
    let mut retired = 0;
    let mut index = 0;
    while let Some(state) = vm.slot_state(SlotId::new(index)) {
        match state {
            SlotState::Occupied => occupied += 1,
            SlotState::Free => free += 1,
            SlotState::Retired => retired += 1,
        }
        index += 1;
    }
    (occupied, free, retired)
}

fn scan_numeric_allocation_failures(use_opt: bool) -> Vec<usize> {
    let mut failures = Vec::new();
    let mut successes = Vec::new();
    for offset in 0..24 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：state 存活；整數 slot 將只在整個字串成功發布時被替換。
        unsafe { lua_pushinteger(state, 7) };
        assert_eq!(protected_string(state, -1, 0), 0);
        settle_gc(&owner);
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        let before_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
        let start = before_vm.1.next_ordinal;
        let target = start + offset as u64;
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(target))
            .unwrap();
        assert_eq!(vm_snapshot(&owner), before_vm);

        let status = protected_string(state, if use_opt { 18 } else { 17 }, 1);
        if status > 0 {
            failures.push(offset);
            let after_stack = stack_snapshot(state);
            let after_vm = vm_snapshot(&owner);
            assert_eq!(after_stack, before_stack, "offset {offset}, opt={use_opt}");
            assert_eq!(
                after_vm.3, before_vm.3,
                "roots offset {offset}, opt={use_opt}"
            );
            assert!(after_vm.1.next_ordinal >= target + 1);
            assert!(
                after_vm.1.last_failure.is_some(),
                "missing recorded fault at {offset}, opt={use_opt}"
            );
            settle_gc(&owner);
            let settled = vm_snapshot(&owner);
            let settled_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
            assert_eq!(settled_slots.0, before_slots.0);
            assert_eq!(settled_slots.2, before_slots.2);
            assert_eq!(
                settled.0.lua_heap_bytes - before_vm.0.lua_heap_bytes,
                (settled_slots.1 - before_slots.1) * 136
            );
            assert_eq!(settled.3, before_vm.3);
        } else {
            assert_eq!(status, 0, "offset {offset}, opt={use_opt}");
            successes.push(offset);
            let mut len = usize::MAX;
            // SAFETY：checkpoint 成功後，替換的字串由 stack slot root 保活。
            let pointer = unsafe { lua_tolstring(state, 1, &mut len) };
            assert_string(pointer, len, b"7");
            assert_eq!(unsafe { lua_type(state, 1) }, LUA_TSTRING);
        }
    }
    assert!(
        !failures.is_empty(),
        "numeric coercion did not hit any injected allocation"
    );
    assert!(
        !successes.is_empty(),
        "fault scan did not reach an allocation-free success offset"
    );
    assert_eq!(
        failures,
        (0..failures.len()).collect::<Vec<_>>(),
        "opt={use_opt}"
    );
    assert_eq!(
        successes,
        (failures.len()..24).collect::<Vec<_>>(),
        "opt={use_opt}"
    );
    failures
}

#[test]
fn aux_string_a18_matrix() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let (owner, state, initial_roots, binary, empty, present) = rooted_state();
        collect_and_verify_roots(&owner, &initial_roots);
        enter_active_gc(&owner, mode);

        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        exercise_pure_paths(state, binary, empty, present);
        assert_unchanged(&owner, state, &before_stack, &before_vm);

        assert_zero_allocation_pure_paths(&owner, state, binary, empty, present);
        settle_gc(&owner);
        let before_errors = vm_snapshot(&owner);
        let before_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
        let error_stack = stack_snapshot(state);
        exercise_string_errors(state);
        assert_eq!(stack_snapshot(state), error_stack);
        assert_eq!(vm_snapshot(&owner).3, before_errors.3);
        settle_gc(&owner);
        let settled = vm_snapshot(&owner);
        let settled_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
        assert_eq!(settled_slots.0, before_slots.0);
        assert_eq!(settled_slots.2, before_slots.2);
        assert_eq!(
            settled.0.lua_heap_bytes - before_errors.0.lua_heap_bytes,
            (settled_slots.1 - before_slots.1) * 136
        );
        assert_eq!(settled.3, before_errors.3);
        assert_eq!(settled.2.worklist_len, 0);
        assert_eq!(stack_snapshot(state), error_stack);
        for index in TOP + 1..=TOP + 10 {
            assert!(protected_string(state, 17, index) > 0);
            settle_gc(&owner);
            assert_eq!(owner.with_vm(|vm| slot_census(vm)).unwrap(), settled_slots);
            assert_eq!(vm_snapshot(&owner).0, settled.0);
            assert_eq!(stack_snapshot(state), error_stack);
        }
        let (integer_string, float_string) = exercise_numeric_conversions(state);
        let current_roots = host_objects(&owner);
        collect_and_verify_roots(&owner, &current_roots);
        assert_string(integer_string, 1, b"7");
        assert_string(float_string, 4, b"-0.0");
        // SAFETY：owner 仍存活，slot roots 經 collect/major 後仍保活兩個 coercion views。
        unsafe {
            assert_eq!(lua_type(state, 9), LUA_TSTRING);
            assert_eq!(lua_type(state, 10), LUA_TSTRING);
        }

        let before_invalid = stack_snapshot(state);
        let before_invalid_vm = vm_snapshot(&owner);
        assert_invalid_state_fallbacks(state);
        assert_busy_fallbacks(&owner, state);
        assert_unchanged(&owner, state, &before_invalid, &before_invalid_vm);
    }

    let check_failures = scan_numeric_allocation_failures(false);
    let opt_failures = scan_numeric_allocation_failures(true);
    assert_eq!(
        check_failures, opt_failures,
        "check/opt conversion paths diverged"
    );
}

#[test]
fn aux_gsub_a45_matrix() {
    let run_case = |source: &[u8], pattern: &[u8], replacement: &[u8], expected: &[u8]| {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let source = std::ffi::CString::new(source).unwrap();
        let pattern = std::ffi::CString::new(pattern).unwrap();
        let replacement = std::ffi::CString::new(replacement).unwrap();
        let before_top = unsafe { lua_gettop(state) };
        // SAFETY：state 有效；三個 CString 都在呼叫期間維持 NUL 結尾且可讀。
        let result = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        assert!(!result.is_null());
        // SAFETY：成功結果由 top slot 的 root 保活，且 Lua 字串有結尾 NUL。
        unsafe {
            assert_eq!(lua_gettop(state), before_top + 1);
            let mut len = usize::MAX;
            assert_eq!(lua_tolstring(state, -1, &mut len), result);
            assert_string(result, len, expected);
            assert_eq!(*result.add(len), 0);
            assert_eq!(std::ffi::CStr::from_ptr(result).to_bytes(), expected);
            lua_pushvalue(state, -1);
            assert_eq!(lua_tolstring(state, -1, std::ptr::null_mut()), result);
            assert_eq!(lua_rawequal(state, -1, -2), 1);
        }
        let rooted = host_objects(&owner);
        collect_and_verify_roots(&owner, &rooted);
        // SAFETY：兩個 stack slot 仍保有輸出與 clone 的 root。
        unsafe {
            assert_eq!(returned_bytes(result, expected.len()), expected);
            lua_settop(state, 0);
        }
        owner
            .with_vm(|vm| -> Result<(), VmError> {
                vm.collect()?;
                vm.collect()?;
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                Ok(())
            })
            .unwrap()
            .unwrap();
    };

    let cases: &[(&[u8], &[u8], &[u8], &[u8])] = &[
        (
            b"alo.alo.uhuh.".as_slice(),
            b".",
            b"//",
            b"alo//alo//uhuh//",
        ),
        (b"alo.alo.uhuh.", b"alo", b"//", b"//.//.uhuh."),
        (b"", b"alo", b"//", b""),
        (b"...", b".", b"/.", b"/././."),
        (b"...", b"...", b"", b""),
        (b"aaaaa", b"aa", b"X", b"XXa"),
        (b"aaa", b"aa", b"X", b"Xa"),
        (b"ababa", b"a", b"aa", b"aabaabaa"),
        (b"xy", b"xyz", b"!", b"xy"),
        (b"xyz", b"q", b"!", b"xyz"),
        (b"abcabc", b"b", b"", b"acac"),
        (&[0xff, b'/', 0xff], &[0xff], &[0xfe], &[0xfe, b'/', 0xfe]),
    ];
    for (source, pattern, replacement, expected) in cases {
        run_case(source, pattern, replacement, expected);
    }

    let long_source = vec![b'a'; 1536];
    run_case(&long_source, b"a", b"bb", &vec![b'b'; 3072]);

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let source_with_suffix = b"a.a\0ignored source";
    let pattern_with_suffix = b".\0ignored pattern";
    let replacement_with_suffix = b"/\0ignored replacement";
    // SAFETY：三個陣列各自包含可讀的第一個 NUL 與尾端 NUL。
    let result = unsafe {
        rivetlua_capi::stack::luaL_gsub(
            state,
            source_with_suffix.as_ptr().cast(),
            pattern_with_suffix.as_ptr().cast(),
            replacement_with_suffix.as_ptr().cast(),
        )
    };
    assert_string(result, 3, b"a/a");
    // SAFETY：輸出仍由 top slot 保活。
    unsafe {
        let mut len = 0;
        assert_eq!(lua_tolstring(state, -1, &mut len), result);
        assert_eq!(len, 3);
        lua_settop(state, 0);
    }

    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let state = owner.as_ptr();
    let sibling_state = sibling.as_ptr();
    let (source, pattern, replacement) = (
        push_bytes(state, b"prefix--middle--suffix"),
        push_bytes(state, b"--"),
        push_bytes(state, b"<>"),
    );
    let before_top = unsafe { lua_gettop(state) };
    // SAFETY：輸入 views 在其原始 stack slots 存活期間可讀。
    let result = unsafe { rivetlua_capi::stack::luaL_gsub(state, source, pattern, replacement) };
    assert_string(result, 22, b"prefix<>middle<>suffix");
    // SAFETY：函式新推一個結果；clone 跨 sibling xmove 保持 view root。
    unsafe {
        assert_eq!(lua_gettop(state), before_top + 1);
        let mut len = 0;
        assert_eq!(lua_tolstring(state, -1, &mut len), result);
        assert_eq!(len, 22);
        assert_eq!(lua_tolstring(state, 1, std::ptr::null_mut()), source);
        assert_eq!(lua_tolstring(state, 2, std::ptr::null_mut()), pattern);
        assert_eq!(lua_tolstring(state, 3, std::ptr::null_mut()), replacement);
        lua_pushvalue(state, -1);
        lua_xmove(state, sibling_state, 1);
        lua_xmove(state, sibling_state, 1);
        assert_eq!(lua_gettop(state), 3);
        assert_eq!(lua_gettop(sibling_state), 2);
        lua_settop(sibling_state, 1);
        assert_eq!(
            lua_tolstring(sibling_state, -1, std::ptr::null_mut()),
            result
        );
    }
    collect_and_verify_roots(&owner, &host_objects(&owner));
    // SAFETY：gsub 的原 slot 已移至 sibling 並 pop；唯一輸出 clone 仍有效。
    unsafe {
        assert_eq!(returned_bytes(result, 22), b"prefix<>middle<>suffix");
        lua_settop(sibling_state, 0);
    }
    owner
        .with_vm(|vm| -> Result<(), VmError> {
            vm.collect()?;
            vm.collect()?;
            assert_eq!(vm.roots().count(RootKind::Host), 3);
            Ok(())
        })
        .unwrap()
        .unwrap();
    // SAFETY：原輸入 views 仍由 source slots 保活；移除後只檢查 root 數量。
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| -> Result<(), VmError> {
            vm.collect()?;
            vm.collect()?;
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            Ok(())
        })
        .unwrap()
        .unwrap();

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let source = std::ffi::CString::new("alpha beta").unwrap();
    let pattern = std::ffi::CString::new("a").unwrap();
    let replacement = std::ffi::CString::new("A").unwrap();
    let baseline_stack = stack_snapshot(state);
    let baseline_vm = vm_snapshot(&owner);
    let invalid = [
        (std::ptr::null(), pattern.as_ptr(), replacement.as_ptr()),
        (source.as_ptr(), std::ptr::null(), replacement.as_ptr()),
        (source.as_ptr(), pattern.as_ptr(), std::ptr::null()),
    ];
    for (source, pattern, replacement) in invalid {
        // SAFETY：只有一個輸入故意為 null；另外兩個 CString 在呼叫期間有效。
        assert!(
            unsafe { rivetlua_capi::stack::luaL_gsub(state, source, pattern, replacement) }
                .is_null()
        );
        assert_unchanged(&owner, state, &baseline_stack, &baseline_vm);
    }
    let empty_pattern = std::ffi::CString::new("").unwrap();
    // SAFETY：state 與三個 C 字串都有效；空 pattern 由 API fail-closed。
    assert!(
        unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                empty_pattern.as_ptr(),
                replacement.as_ptr(),
            )
        }
        .is_null()
    );
    assert_unchanged(&owner, state, &baseline_stack, &baseline_vm);
    // SAFETY：null state 先被 with_state 拒絕；不讀取其餘有效輸入。
    assert!(
        unsafe {
            rivetlua_capi::stack::luaL_gsub(
                std::ptr::null_mut(),
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        }
        .is_null()
    );
    assert_unchanged(&owner, state, &baseline_stack, &baseline_vm);
    owner
        .with_vm(|_| {
            // SAFETY：with_vm 正借用同一 VM，gsub 必須在 busy 時 fail-closed。
            assert!(
                unsafe {
                    rivetlua_capi::stack::luaL_gsub(
                        state,
                        source.as_ptr(),
                        pattern.as_ptr(),
                        replacement.as_ptr(),
                    )
                }
                .is_null()
            );
        })
        .unwrap();
    assert_unchanged(&owner, state, &baseline_stack, &baseline_vm);
    let state_address = state as usize;
    let source_address = source.as_ptr() as usize;
    let pattern_address = pattern.as_ptr() as usize;
    let replacement_address = replacement.as_ptr() as usize;
    let wrong_thread = std::thread::spawn(move || {
        // SAFETY：owner/CStrings 在 join 前仍存活；跨 thread 的 state 由入口拒絕。
        unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state_address as *mut lua_State,
                source_address as *const c_char,
                pattern_address as *const c_char,
                replacement_address as *const c_char,
            )
        }
        .is_null()
    })
    .join()
    .unwrap();
    assert!(wrong_thread);
    assert_unchanged(&owner, state, &baseline_stack, &baseline_vm);
    // SAFETY：前述失敗不損壞 state；這次有效呼叫須成功。
    let recovered = unsafe {
        rivetlua_capi::stack::luaL_gsub(
            state,
            source.as_ptr(),
            pattern.as_ptr(),
            replacement.as_ptr(),
        )
    };
    assert_string(recovered, 10, b"AlphA betA");

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let source = std::ffi::CString::new("a").unwrap();
    let pattern = std::ffi::CString::new("a").unwrap();
    let replacement = std::ffi::CString::new("b").unwrap();
    let full_top = 1_000_000;
    // SAFETY：top 受固定 MAX_STACK 限制且以 c_int 表示。
    unsafe { lua_settop(state, full_top) };
    let before_top = unsafe { lua_gettop(state) };
    let before_vm = vm_snapshot(&owner);
    // SAFETY：三個 C 字串有效；stack 已達 MAX_STACK，操作應在配置前拒絕。
    assert!(
        unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        }
        .is_null()
    );
    assert_eq!(unsafe { lua_gettop(state) }, before_top);
    assert_eq!(unsafe { lua_type(state, 1) }, LUA_TNIL);
    assert_eq!(unsafe { lua_type(state, full_top) }, LUA_TNIL);
    assert_eq!(vm_snapshot(&owner), before_vm);
    // SAFETY：清空已填滿的 stack 以釋放測試配置。
    unsafe { lua_settop(state, 0) };

    let mut failure_offsets = Vec::new();
    let mut failure_domains = Vec::new();
    let mut successful_offsets = Vec::new();
    for offset in 0..24 {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        // SAFETY：填滿初始 stack capacity，讓本次發布包含 stack 擴容路徑。
        unsafe { lua_settop(state, 128) };
        let source = std::ffi::CString::new("one two one").unwrap();
        let pattern = std::ffi::CString::new("one").unwrap();
        let replacement = std::ffi::CString::new("1").unwrap();
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        owner
            .with_vm(|vm| {
                vm.inject_allocation_failure_at(
                    before_vm.1.next_ordinal + u64::try_from(offset).unwrap(),
                );
            })
            .unwrap();
        // SAFETY：輸入 CString 有效；故障注入後由 C API 轉成 null。
        let result = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        if result.is_null() {
            let after = vm_snapshot(&owner);
            assert_eq!(stack_snapshot(state), before_stack, "offset {offset}");
            assert_eq!(after.0, before_vm.0, "ledger offset {offset}");
            assert_eq!(after.2, before_vm.2, "GC offset {offset}");
            assert_eq!(after.3, before_vm.3, "roots offset {offset}");
            assert!(after.1.last_failure.is_some(), "offset {offset}");
            failure_offsets.push(offset);
            failure_domains.push(after.1.last_failure.unwrap().attempt.domain);
            // SAFETY：單次注入點已消耗；同一 state 必須能立即重試成功。
            let retry = unsafe {
                rivetlua_capi::stack::luaL_gsub(
                    state,
                    source.as_ptr(),
                    pattern.as_ptr(),
                    replacement.as_ptr(),
                )
            };
            assert_string(retry, 7, b"1 two 1");
            unsafe { lua_settop(state, 128) };
        } else {
            assert_string(result, 7, b"1 two 1");
            successful_offsets.push(offset);
        }
    }
    assert_eq!(failure_offsets.len(), 7, "unexpected gsub allocation count");
    assert_eq!(
        failure_offsets,
        (0..failure_offsets.len()).collect::<Vec<_>>()
    );
    assert_eq!(
        successful_offsets,
        (failure_offsets.len()..24).collect::<Vec<_>>()
    );
    assert_eq!(
        failure_domains,
        [
            AllocationDomain::Host,
            AllocationDomain::Host,
            AllocationDomain::Host,
            AllocationDomain::LuaHeap,
            AllocationDomain::LuaHeap,
            AllocationDomain::LuaHeap,
            AllocationDomain::Host,
        ]
    );

    for point in [
        FailPoint::StringBytesReserve,
        FailPoint::SlotReserve,
        FailPoint::ObjectReserve,
        FailPoint::ObjectInitialize,
        FailPoint::RootReserve,
        FailPoint::HostLease,
    ] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let source = std::ffi::CString::new("abc").unwrap();
        let pattern = std::ffi::CString::new("b").unwrap();
        let replacement = std::ffi::CString::new("X").unwrap();
        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
        // SAFETY：三個 CString 有效；指定的配置失敗由 FFI 邊界轉為 null。
        let result = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        assert!(result.is_null(), "{point:?} must be reachable");
        let after = vm_snapshot(&owner);
        assert_eq!(stack_snapshot(state), before_stack, "{point:?}");
        assert_eq!(after.0, before_vm.0, "ledger {point:?}");
        assert_eq!(after.2, before_vm.2, "GC {point:?}");
        assert_eq!(after.3, before_vm.3, "roots {point:?}");
        // SAFETY：單次命名失敗已消耗；state 可重用。
        let retry = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        assert_string(retry, 3, b"aXc");
    }

    for mode in [GcMode::Incremental, GcMode::Generational] {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        enter_active_gc(&owner, mode);
        let source = std::ffi::CString::new("before after before").unwrap();
        let pattern = std::ffi::CString::new("before").unwrap();
        let replacement = std::ffi::CString::new("during").unwrap();
        let before_vm = vm_snapshot(&owner);
        // SAFETY：輸入於呼叫期間有效；byte string 發布時必須成為 Host root。
        let result = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        assert_string(result, 19, b"during after during");
        let rooted = host_objects(&owner);
        collect_and_verify_roots(&owner, &rooted);
        // SAFETY：收集期間結果仍由 stack root 保活。
        unsafe {
            assert_eq!(returned_bytes(result, 19), b"during after during");
            lua_settop(state, 0);
        }
        owner
            .with_vm(|vm| -> Result<(), VmError> {
                vm.collect()?;
                vm.collect()?;
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                Ok(())
            })
            .unwrap()
            .unwrap();
        assert_ne!(before_vm.2.phase, GcPhase::Pause);

        for point in [FailPoint::MarkReserve, FailPoint::WorkReserve] {
            let owner = StateOwner::new().unwrap();
            let state = owner.as_ptr();
            enter_active_gc(&owner, mode);
            let source = std::ffi::CString::new("x").unwrap();
            let pattern = std::ffi::CString::new("x").unwrap();
            let replacement = std::ffi::CString::new("y").unwrap();
            let active_before = vm_snapshot(&owner);
            owner.with_vm(|vm| vm.inject_failure_once(point)).unwrap();
            // SAFETY：此模式與 phase 由 enter_active_gc 準備；輸入 C 字串有效。
            let result = unsafe {
                rivetlua_capi::stack::luaL_gsub(
                    state,
                    source.as_ptr(),
                    pattern.as_ptr(),
                    replacement.as_ptr(),
                )
            };
            assert!(
                result.is_null(),
                "active {mode:?}/{point:?} must be reached"
            );
            if result.is_null() {
                let after = vm_snapshot(&owner);
                assert_eq!(after.0, active_before.0, "active ledger {mode:?}/{point:?}");
                assert_eq!(after.2, active_before.2, "active GC {mode:?}/{point:?}");
                assert_eq!(after.3, active_before.3, "active roots {mode:?}/{point:?}");
                // SAFETY：命名故障已消耗，重試必須可以完成發布。
                let retry = unsafe {
                    rivetlua_capi::stack::luaL_gsub(
                        state,
                        source.as_ptr(),
                        pattern.as_ptr(),
                        replacement.as_ptr(),
                    )
                };
                assert_string(retry, 1, b"y");
            } else {
                assert_string(result, 1, b"y");
            }
        }

        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        owner
            .with_vm(|vm| -> Result<(), VmError> {
                vm.set_gc_debt_threshold(0);
                vm.set_gc_mode(mode)?;
                vm.set_gc_promotion_survivals(1)?;
                Ok(())
            })
            .unwrap()
            .unwrap();
        let source = std::ffi::CString::new("every allocation").unwrap();
        let pattern = std::ffi::CString::new(" ").unwrap();
        let replacement = std::ffi::CString::new("-").unwrap();
        // SAFETY：collect-every 設定下輸入仍有效，發布後 byte string 必須受 root 保護。
        let result = unsafe {
            rivetlua_capi::stack::luaL_gsub(
                state,
                source.as_ptr(),
                pattern.as_ptr(),
                replacement.as_ptr(),
            )
        };
        assert_string(result, 16, b"every-allocation");
        collect_and_verify_roots(&owner, &host_objects(&owner));
        // SAFETY：顯式收集後輸出仍 rooted；pop 後可以回收。
        unsafe {
            assert_eq!(returned_bytes(result, 16), b"every-allocation");
            lua_settop(state, 0);
        }
        owner
            .with_vm(|vm| -> Result<(), VmError> {
                vm.collect()?;
                vm.collect()?;
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                Ok(())
            })
            .unwrap()
            .unwrap();
    }
}
