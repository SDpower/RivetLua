use std::ffi::{c_char, c_int, c_void};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_createtable, lua_gettop, lua_isinteger, lua_pushboolean,
    lua_pushinteger, lua_pushlightuserdata, lua_pushlstring, lua_pushnil, lua_pushnumber,
    lua_rawequal, lua_tointegerx, lua_tonumberx, lua_touserdata, lua_type, luaL_checkinteger,
    luaL_checknumber, luaL_optinteger, luaL_optnumber,
};
use rivetlua_core::{ObjectRef, SlotId, Value};
use rivetlua_runtime::{
    AllocationTrace, GcMode, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind,
    SlotState, Vm, VmError,
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

fn protected_numeric(state: *mut lua_State, operation: c_int, index: c_int) -> c_int {
    // SAFETY：私有純 C checkpoint 執行 Lua API，錯誤在 C frame 捕捉並 consume。
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

const TOP: c_int = 33;
const DEFAULT_NUMBER: f64 = 987.25;
const DEFAULT_INTEGER: i64 = -987;
const LUA_TNONE: c_int = -1;
const LUA_TNIL: c_int = 0;
const LUA_TBOOLEAN: c_int = 1;
const LUA_TLIGHTUSERDATA: c_int = 2;
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
                let pointer = if tag == LUA_TLIGHTUSERDATA {
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

fn push_bytes(state: *mut lua_State, bytes: &[u8]) {
    // SAFETY：state 由存活的 StateOwner 持有，bytes 在呼叫期間有效。
    let string = unsafe { lua_pushlstring(state, bytes.as_ptr().cast::<c_char>(), bytes.len()) };
    assert!(!string.is_null());
}

fn rooted_state() -> (StateOwner, *mut lua_State, Vec<(ObjectRef, ObjectKind)>) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 持有有效 state；lightuserdata 只保存 opaque 位址，不解參照。
    unsafe {
        lua_pushinteger(state, i64::MIN);
        lua_pushinteger(state, i64::MAX);
        lua_pushnumber(state, 0.0);
        lua_pushnumber(state, -0.0);
        lua_pushnumber(state, f64::MIN_POSITIVE);
        lua_pushnumber(state, f64::MAX);
        lua_pushnumber(state, f64::from_bits(1));
        lua_pushnumber(state, f64::MIN);
        lua_pushnumber(state, f64::INFINITY);
        lua_pushnumber(state, f64::NEG_INFINITY);
        lua_pushnumber(state, f64::NAN);
        lua_pushnumber(state, i64::MIN as f64);
        lua_pushnumber(state, i64::MAX as f64);
        lua_pushnumber(state, 42.0);
        lua_pushnumber(state, 42.5);
        lua_pushnumber(state, -9.0);
        lua_pushnil(state);
        lua_pushboolean(state, 0);
        lua_pushlightuserdata(state, std::ptr::null_mut());
        lua_pushlightuserdata(state, std::ptr::dangling_mut::<c_void>());
    }
    push_bytes(state, b" \t+42.5\n");
    push_bytes(state, b"0x2a");
    push_bytes(state, b"0x1.8p1");
    push_bytes(state, b"9223372036854775807");
    push_bytes(state, b"9223372036854775808");
    push_bytes(state, b" \t\n");
    push_bytes(state, b"12\0x");
    push_bytes(state, b"not-a-number");
    push_bytes(state, b"nan");
    push_bytes(state, &[0xff]);
    // SAFETY：owner 持有有效 state；建立一個由 stack root 保活的 table。
    unsafe { lua_createtable(state, 0, 0) };

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
    assert_eq!(
        unsafe {
            (1..=TOP)
                .map(|index| lua_type(state, index))
                .collect::<Vec<_>>()
        },
        [
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNUMBER,
            LUA_TNIL,
            LUA_TBOOLEAN,
            LUA_TLIGHTUSERDATA,
            LUA_TLIGHTUSERDATA,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TSTRING,
            LUA_TTABLE,
            LUA_TFUNCTION,
            LUA_TTHREAD,
        ]
    );

    let rooted_objects = owner
        .with_vm(|vm| {
            let mut objects = Vec::new();
            vm.visit_roots(|kind, _, object| {
                if kind == RootKind::Host {
                    objects.push((object, vm.object_kind(object).unwrap()));
                }
            });
            objects
        })
        .unwrap();
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
    (owner, state, rooted_objects)
}

fn collect_and_verify_roots(owner: &StateOwner, rooted_objects: &[(ObjectRef, ObjectKind)]) {
    owner
        .with_vm(|vm| -> Result<(), VmError> {
            vm.collect()?;
            vm.collect()?;
            for (object, kind) in rooted_objects {
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

fn assert_float(actual: f64, expected: f64, label: &str) {
    if expected.is_nan() {
        assert!(actual.is_nan(), "{label}: 預期 NaN，得到 {actual:?}");
    } else {
        assert_eq!(actual.to_bits(), expected.to_bits(), "{label}");
    }
}

fn assert_number(state: *mut lua_State, index: c_int, expected: f64) {
    // SAFETY：state 由存活的 StateOwner 持有；測試只讀取既有 stack 值。
    assert_float(
        unsafe { luaL_checknumber(state, index) },
        expected,
        "checknumber",
    );
    assert_float(
        unsafe { luaL_optnumber(state, index, DEFAULT_NUMBER) },
        expected,
        "optnumber override",
    );
}

fn assert_integer(state: *mut lua_State, index: c_int, expected: i64) {
    // SAFETY：state 由存活的 StateOwner 持有；測試只讀取既有 stack 值。
    assert_eq!(unsafe { luaL_checkinteger(state, index) }, expected);
    assert_eq!(
        unsafe { luaL_optinteger(state, index, DEFAULT_INTEGER) },
        expected
    );
}

fn exercise_valid_read_collection(state: *mut lua_State) {
    let number_cases = [
        (1, i64::MIN as f64),
        (2, i64::MAX as f64),
        (3, 0.0),
        (4, -0.0),
        (5, f64::MIN_POSITIVE),
        (6, f64::MAX),
        (7, f64::from_bits(1)),
        (8, f64::MIN),
        (9, f64::INFINITY),
        (10, f64::NEG_INFINITY),
        (11, f64::NAN),
        (12, i64::MIN as f64),
        (13, i64::MAX as f64),
        (14, 42.0),
        (15, 42.5),
        (16, -9.0),
        (21, 42.5),
        (22, 42.0),
        (23, 3.0),
        (24, i64::MAX as f64),
        (25, i64::MAX as f64),
    ];
    for (index, expected) in number_cases {
        assert_number(state, index, expected);
    }

    let integer_cases = [
        (1, i64::MIN),
        (2, i64::MAX),
        (3, 0),
        (4, 0),
        (12, i64::MIN),
        (14, 42),
        (16, -9),
        (22, 42),
        (23, 3),
        (24, i64::MAX),
    ];
    for (index, expected) in integer_cases {
        assert_integer(state, index, expected);
    }

    for index in [0, TOP + 1, -TOP - 1] {
        assert_float(
            unsafe { luaL_optnumber(state, index, -0.0) },
            -0.0,
            "none optnumber default preserves negative-zero bits",
        );
        assert_eq!(
            unsafe { luaL_optinteger(state, index, DEFAULT_INTEGER) },
            DEFAULT_INTEGER
        );
    }
    assert_float(
        unsafe { luaL_optnumber(state, 17, -0.0) },
        -0.0,
        "nil optnumber default preserves negative-zero bits",
    );
    assert_eq!(
        unsafe { luaL_optinteger(state, 17, DEFAULT_INTEGER) },
        DEFAULT_INTEGER
    );

    assert_number(state, -TOP, i64::MIN as f64);
    assert_integer(state, -TOP + 1, i64::MAX);
    assert_eq!(unsafe { lua_type(state, 31) }, LUA_TTABLE);
    assert_eq!(unsafe { lua_type(state, 32) }, LUA_TFUNCTION);
    assert_eq!(unsafe { lua_type(state, 33) }, LUA_TTHREAD);
    assert_eq!(unsafe { lua_type(state, REGISTRY_INDEX) }, LUA_TTABLE);
    assert_eq!(
        unsafe { lua_type(state, OTHER_PROFILE_REGISTRY_INDEX) },
        LUA_TNONE
    );
    assert_eq!(unsafe { lua_type(state, REGISTRY_INDEX - 1) }, LUA_TNONE);
}

fn exercise_numeric_errors(state: *mut lua_State) {
    for index in [5, 6, 7, 8, 9, 10, 11, 13, 15, 21, 25] {
        assert!(
            protected_numeric(state, 15, index) > 0,
            "checkinteger {index}"
        );
        assert!(
            protected_numeric(state, 16, index) > 0,
            "optinteger {index}"
        );
    }
    for index in [18, 19, 20, 26, 27, 28, 29, 30, 31, 32, 33, REGISTRY_INDEX] {
        for operation in 13..=16 {
            assert!(
                protected_numeric(state, operation, index) > 0,
                "op={operation} index={index}"
            );
        }
    }
    for index in [
        0,
        TOP + 1,
        -TOP - 1,
        17,
        OTHER_PROFILE_REGISTRY_INDEX,
        REGISTRY_INDEX - 1,
    ] {
        assert!(
            protected_numeric(state, 13, index) > 0,
            "checknumber {index}"
        );
        assert!(
            protected_numeric(state, 15, index) > 0,
            "checkinteger {index}"
        );
    }
}

fn assert_invalid_state_fallbacks(state: *mut lua_State) {
    for operation in 13..=16 {
        assert_eq!(protected_numeric(std::ptr::null_mut(), operation, 1), -1);
    }

    let address = state as usize;
    let wrong_thread = std::thread::spawn(move || {
        let state = address as *mut lua_State;
        (13..=16)
            .map(|operation| protected_numeric(state, operation, 1))
            .collect::<Vec<_>>()
    })
    .join()
    .unwrap();
    assert_eq!(wrong_thread, vec![-1; 4]);
}

fn assert_busy_fallbacks(owner: &StateOwner, state: *mut lua_State) {
    owner
        .with_vm(|_| {
            for operation in 13..=16 {
                assert_eq!(protected_numeric(state, operation, 1), -1);
            }
        })
        .unwrap();
}

fn assert_zero_allocation_under_fault(owner: &StateOwner, state: *mut lua_State) {
    let before_stack = stack_snapshot(state);
    let before_vm = vm_snapshot(owner);
    let target = before_vm.1.next_ordinal;
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(target))
        .unwrap();
    let armed_vm = vm_snapshot(owner);
    assert_eq!(armed_vm, before_vm);

    exercise_valid_read_collection(state);

    let after_stack = stack_snapshot(state);
    let after_vm = vm_snapshot(owner);
    assert_eq!(after_stack, before_stack);
    assert_eq!(after_vm.0, before_vm.0);
    assert_eq!(after_vm.1, armed_vm.1);
    assert_eq!(after_vm.1.next_ordinal, target);
    assert_eq!(after_vm.1.last_failure, before_vm.1.last_failure);
    assert_eq!(after_vm.2, before_vm.2);
    assert_eq!(after_vm.3, before_vm.3);

    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
        .unwrap();
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

#[test]
fn aux_numeric_a16_matrix() {
    for mode in [GcMode::Incremental, GcMode::Generational] {
        let (owner, state, rooted_objects) = rooted_state();
        let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        collect_and_verify_roots(&owner, &rooted_objects);
        enter_active_gc(&owner, mode);

        let before_stack = stack_snapshot(state);
        let before_vm = vm_snapshot(&owner);
        exercise_valid_read_collection(state);
        assert_unchanged(&owner, state, &before_stack, &before_vm);

        assert_invalid_state_fallbacks(state);
        assert_busy_fallbacks(&owner, state);
        assert_unchanged(&owner, state, &before_stack, &before_vm);

        assert_zero_allocation_under_fault(&owner, state);
        assert_unchanged(&owner, state, &before_stack, &before_vm);

        settle_gc(&owner);
        let before_errors = vm_snapshot(&owner);
        let before_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
        let error_stack = stack_snapshot(state);
        exercise_numeric_errors(state);
        assert_eq!(stack_snapshot(state), error_stack);
        assert_eq!(
            vm_snapshot(&owner).3,
            before_errors.3,
            "錯誤傳輸不得殘留 root"
        );
        settle_gc(&owner);
        let settled = vm_snapshot(&owner);
        let settled_slots = owner.with_vm(|vm| slot_census(vm)).unwrap();
        assert_eq!(
            settled_slots.0, before_slots.0,
            "錯誤物件須在 major 後全數回收"
        );
        assert_eq!(settled_slots.2, before_slots.2);
        assert_eq!(
            settled.0.lua_heap_bytes - before_errors.0.lua_heap_bytes,
            (settled_slots.1 - before_slots.1) * 136,
            "剩餘 LuaHeap 帳款只可屬於可重用的 free slot backing"
        );
        assert_eq!(settled.3, before_errors.3);
        assert_eq!(settled.2.phase, GcPhase::Pause);
        assert_eq!(settled.2.worklist_len, 0);
        assert_eq!(stack_snapshot(state), error_stack);
        for index in TOP + 1..=TOP + 10 {
            assert!(protected_numeric(state, 13, index) > 0);
            settle_gc(&owner);
            assert_eq!(owner.with_vm(|vm| slot_census(vm)).unwrap(), settled_slots);
            assert_eq!(
                vm_snapshot(&owner).0,
                settled.0,
                "不同訊息須重用 free slots"
            );
            assert_eq!(stack_snapshot(state), error_stack);
        }
        drop(owner);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
