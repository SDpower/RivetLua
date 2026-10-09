use std::ffi::CString;

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_gettop, lua_isinteger, lua_rawequal, lua_settop, lua_toboolean,
    lua_tointegerx, lua_tonumberx, lua_type, luaL_checkstack,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    AllocationAttempt, AllocationDomain, AllocationFailureKind, AllocationTrace, GcMode, GcTrace,
    LedgerSnapshot, ObjectKind, RootId, RootKind, VmError,
};

const MAX_STACK: i32 = 1_000_000;
const GROWTH_SPACE: i32 = 128;
const FAULT_SCAN_LIMIT: u64 = 64;

type RootSnapshot = Vec<(RootKind, RootId, ObjectRef)>;
type VmSnapshot = (LedgerSnapshot, AllocationTrace, GcTrace, RootSnapshot);
type StackSnapshot = (i32, Vec<(i32, i64, u64, i32)>, Vec<i32>);

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
    // SAFETY：呼叫端持有有效 StateOwner；只讀取目前 top 內的 slot。
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
                let number = if tag == 3 && lua_isinteger(state, index) == 0 {
                    lua_tonumberx(state, index, std::ptr::null_mut()).to_bits()
                } else {
                    0
                };
                let boolean = if tag == 1 {
                    lua_toboolean(state, index)
                } else {
                    0
                };
                (tag, integer, number, boolean)
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

fn rooted_state() -> (StateOwner, *mut lua_State) {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let (string, table, function, thread, thread_root) = owner
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
            let Value::Object(function_object) = function else {
                return Err(VmError::WrongObjectType);
            };
            if vm.object_kind(function_object)? != ObjectKind::Builtin {
                return Err(VmError::WrongObjectType);
            }
            let thread_root = vm.new_coroutine(function)?;
            let thread = thread_root.as_value(vm)?;
            let string = Value::Object(vm.allocate_byte_string(b"a15 rooted string")?);
            let table = Value::Object(vm.allocate_table()?);
            Ok((string, table, function, thread, thread_root))
        })
        .unwrap()
        .unwrap();

    // SAFETY：owner 保持 state 有效；物件值由下方 capi slots 取得 HostHandle roots。
    unsafe { rivetlua_capi::stack::lua_pushinteger(state, 73) };
    for value in [string, table, function, thread] {
        owner.push_value(value).unwrap();
    }
    drop(thread_root);
    assert_eq!(
        unsafe {
            (1..=lua_gettop(state))
                .map(|i| lua_type(state, i))
                .collect::<Vec<_>>()
        },
        [3, 4, 5, 6, 8]
    );
    owner
        .with_vm(|vm| {
            // registry table、emergency error 與 B10 hidden hook bridge。
            assert_eq!(vm.roots().count(RootKind::Registry), 3);
            assert_eq!(vm.roots().count(RootKind::Host), 4);
        })
        .unwrap();
    (owner, state)
}

fn enter_active_gc(owner: &StateOwner, mode: GcMode) {
    owner
        .with_vm(|vm| {
            vm.set_gc_debt_threshold(usize::MAX);
            vm.set_gc_mode(mode).unwrap();
            vm.set_gc_promotion_survivals(1).unwrap();
            vm.collect().unwrap();
            for _ in 0..256 {
                vm.incremental_step(1).unwrap();
                if vm.gc_trace().phase != rivetlua_runtime::GcPhase::Pause {
                    break;
                }
            }
            assert_ne!(vm.gc_trace().phase, rivetlua_runtime::GcPhase::Pause);
        })
        .unwrap();
}

fn assert_capacity_attempt(attempt: AllocationAttempt) {
    assert_eq!(attempt.domain, AllocationDomain::Host);
    assert!(attempt.bytes > 0);
    assert_eq!(attempt.point, None);
    assert_eq!(attempt.site.file, "crates/rivetlua-runtime/src/heap.rs");
    assert_eq!(attempt.site.line, 2308, "{attempt:?}");
    assert_eq!(attempt.site.column, 33, "{attempt:?}");
}

fn allocation_fault_matrix(mode: GcMode) {
    let mut failures = Vec::new();
    let (success_owner, success_state, success_before, success_after, success_offset) = 'scan: loop {
        for offset in 0..FAULT_SCAN_LIMIT {
            let (owner, state) = rooted_state();
            enter_active_gc(&owner, mode);
            let before_stack = stack_snapshot(state);
            let before_vm = vm_snapshot(&owner);
            assert!(before_vm.1.last_failure.is_none());
            let start = before_vm.1.next_ordinal;
            let target = start.checked_add(offset).unwrap();
            owner
                .with_vm(|vm| vm.inject_allocation_failure_at(target))
                .unwrap();
            let message = CString::new("A15 capacity request").unwrap();
            let message_before = message.as_bytes_with_nul().to_vec();
            // SAFETY：state 與有效 message 均存活；注入的配置失敗須 fail-closed。
            unsafe { luaL_checkstack(state, GROWTH_SPACE, message.as_ptr()) };
            assert_eq!(message.as_bytes_with_nul(), message_before);
            let after_stack = stack_snapshot(state);
            let after_vm = vm_snapshot(&owner);

            if let Some(failure) = after_vm.1.last_failure {
                assert_eq!(failure.kind, AllocationFailureKind::Injection);
                assert_eq!(failure.attempt.ordinal, target);
                assert_eq!(after_vm.1.next_ordinal, target + 1);
                assert_eq!(after_vm.1.last_attempt, Some(failure.attempt));
                assert_capacity_attempt(failure.attempt);
                assert_eq!(after_stack, before_stack, "{mode:?} offset {offset}");
                assert_eq!(after_vm.0, before_vm.0, "{mode:?} offset {offset}");
                assert_eq!(after_vm.2, before_vm.2, "{mode:?} offset {offset}");
                assert_eq!(after_vm.3, before_vm.3, "{mode:?} offset {offset}");
                failures.push((offset, failure.attempt));
                continue;
            }

            assert_eq!(
                after_stack, before_stack,
                "{mode:?} success offset {offset}"
            );
            assert_eq!(after_vm.2, before_vm.2, "{mode:?} success offset {offset}");
            assert_eq!(after_vm.3, before_vm.3, "{mode:?} success offset {offset}");
            assert_eq!(after_vm.0.lua_heap_bytes, before_vm.0.lua_heap_bytes);
            assert!(after_vm.0.host_allocation_bytes > before_vm.0.host_allocation_bytes);
            assert_eq!(after_vm.1.next_ordinal, start + offset);
            assert_eq!(after_vm.1.last_failure, before_vm.1.last_failure);
            let last = after_vm
                .1
                .last_attempt
                .expect("成功成長必須留下實際 host reserve attempt");
            assert_eq!(last.ordinal, start + offset - 1);
            assert_capacity_attempt(last);
            assert!(!failures.is_empty(), "offset 0 必須命中容量預留配置");
            break 'scan (owner, state, before_vm, after_vm, offset);
        }
        panic!("offset scan reached guard {FAULT_SCAN_LIMIT} without an unhit offset");
    };

    let observed_offsets: Vec<u64> = failures.iter().map(|(offset, _)| *offset).collect();
    assert_eq!(
        observed_offsets,
        (0..success_offset).collect::<Vec<_>>(),
        "{mode:?} 必須逐一命中所有實際 reserve attempt，直到首個未命中 offset"
    );
    assert_eq!(
        observed_offsets,
        vec![0_u64],
        "{mode:?} 實測 StackCapacity 只有 offset 0 一筆 host reserve attempt"
    );
    assert_eq!(success_offset, 1, "{mode:?} 首個未命中 offset 應為 1");
    assert_eq!(failures[0].1.bytes, 19_152);
    assert_eq!(
        success_after.1.next_ordinal,
        success_before.1.next_ordinal + success_offset
    );
    assert_eq!(success_after.1.last_failure, success_before.1.last_failure);
    assert_eq!(
        success_after.0.reserved, success_before.0.reserved,
        "成功 reserve 後不應遺留 live reservations"
    );
    drop((success_owner, success_state));
}

fn success_push_and_refund() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let baseline = vm_snapshot(&owner);
    assert_eq!(stack_snapshot(state).0, 0);
    let message = CString::new("message remains untouched").unwrap();
    let message_bytes = message.as_bytes_with_nul().to_vec();
    // SAFETY：owner 與非空 C string 均有效；成功路徑只預留空 stack 容量。
    unsafe { luaL_checkstack(state, GROWTH_SPACE, message.as_ptr()) };
    assert_eq!(message.as_bytes_with_nul(), message_bytes);
    let reserved = vm_snapshot(&owner);
    assert_eq!(reserved.2, baseline.2);
    assert_eq!(reserved.3, baseline.3);
    assert_eq!(reserved.0.lua_heap_bytes, baseline.0.lua_heap_bytes);
    assert!(reserved.0.host_allocation_bytes > baseline.0.host_allocation_bytes);
    assert_eq!(reserved.1.next_ordinal, baseline.1.next_ordinal + 1);
    assert_capacity_attempt(reserved.1.last_attempt.unwrap());

    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(u64::MAX))
        .unwrap();
    // SAFETY：已預留足量容量，以下 scalar push 不需建立 heap object 或擴容。
    unsafe {
        for value in 0..GROWTH_SPACE {
            rivetlua_capi::stack::lua_pushinteger(state, i64::from(value));
        }
        assert_eq!(lua_gettop(state), GROWTH_SPACE);
    }
    let pushed = vm_snapshot(&owner);
    assert_eq!(pushed.1, reserved.1);
    assert_eq!(pushed.2, reserved.2);
    assert_eq!(pushed.3, reserved.3);
    assert_eq!(pushed.0.lua_heap_bytes, reserved.0.lua_heap_bytes);

    // SAFETY：將 stack 清空會釋放容量 charge 並回到建立 owner 時的帳本基線。
    unsafe { lua_settop(state, 0) };
    let cleaned = vm_snapshot(&owner);
    assert_eq!(cleaned.0, baseline.0);
    assert_eq!(cleaned.2, baseline.2);
    assert_eq!(cleaned.3, baseline.3);
    assert_eq!(cleaned.1.next_ordinal, reserved.1.next_ordinal);
}

#[test]
fn aux_stack_a15_matrix() {
    let empty = StateOwner::new().unwrap();
    let empty_state = empty.as_ptr();
    let empty_stack = stack_snapshot(empty_state);
    let empty_vm = vm_snapshot(&empty);
    // SAFETY：null state is rejected before any dereference; valid empty stack accepts zero.
    unsafe {
        luaL_checkstack(empty_state, 0, std::ptr::null());
        luaL_checkstack(std::ptr::null_mut(), 0, std::ptr::null());
    }
    assert_unchanged(&empty, empty_state, &empty_stack, &empty_vm);

    let (owner, state) = rooted_state();
    let message = CString::new("valid nonempty message").unwrap();
    let message_bytes = message.as_bytes_with_nul().to_vec();
    let initial_stack = stack_snapshot(state);
    let initial_vm = vm_snapshot(&owner);
    assert_eq!(initial_stack.0, 5);
    assert_eq!(
        initial_vm
            .3
            .iter()
            .filter(|(kind, _, _)| *kind == RootKind::Host)
            .count(),
        4
    );
    assert_eq!(
        initial_vm
            .3
            .iter()
            .filter(|(kind, _, _)| *kind == RootKind::Registry)
            .count(),
        3
    );

    // SAFETY：有效 state；space=0 不需要成長，msg 為可讀 C string 但入口不得讀取。
    unsafe {
        luaL_checkstack(state, 0, message.as_ptr());
        luaL_checkstack(std::ptr::null_mut(), GROWTH_SPACE, std::ptr::null());
        luaL_checkstack(state, -1, std::ptr::null());
        luaL_checkstack(state, MAX_STACK + 1, message.as_ptr());
    }
    assert_eq!(message.as_bytes_with_nul(), message_bytes);
    assert_unchanged(&owner, state, &initial_stack, &initial_vm);

    let address = state as usize;
    std::thread::spawn(move || {
        // SAFETY：owner 留在呼叫執行緒存活，worker 僅把有效指標交給 thread-owner 驗證。
        unsafe { luaL_checkstack(address as *mut lua_State, 1, std::ptr::null()) };
    })
    .join()
    .unwrap();
    assert_unchanged(&owner, state, &initial_stack, &initial_vm);

    owner
        .with_vm(|_| {
            // SAFETY：同一 group 正由 with_vm 借用；入口須 fail-closed 為 Busy。
            unsafe { luaL_checkstack(state, GROWTH_SPACE, std::ptr::null()) };
        })
        .unwrap();
    assert_unchanged(&owner, state, &initial_stack, &initial_vm);

    for mode in [GcMode::Incremental, GcMode::Generational] {
        let (active_owner, active_state) = rooted_state();
        enter_active_gc(&active_owner, mode);
        let before_stack = stack_snapshot(active_state);
        let before_vm = vm_snapshot(&active_owner);
        let message = CString::new("active GC reserve").unwrap();
        // SAFETY：有效 state 與 message；擴容只觸及 C-owned slot capacity。
        unsafe { luaL_checkstack(active_state, GROWTH_SPACE, message.as_ptr()) };
        assert_eq!(message.as_bytes(), b"active GC reserve");
        let after_vm = vm_snapshot(&active_owner);
        assert_eq!(stack_snapshot(active_state), before_stack);
        assert_eq!(after_vm.2, before_vm.2);
        assert_eq!(after_vm.3, before_vm.3);
        assert_eq!(after_vm.0.lua_heap_bytes, before_vm.0.lua_heap_bytes);
        assert!(after_vm.0.host_allocation_bytes > before_vm.0.host_allocation_bytes);
        assert_eq!(after_vm.1.next_ordinal, before_vm.1.next_ordinal + 1);
        let attempt = after_vm.1.last_attempt.unwrap();
        assert_capacity_attempt(attempt);
        assert_eq!(attempt.bytes, 19_152);
        allocation_fault_matrix(mode);
    }

    success_push_and_refund();
}
