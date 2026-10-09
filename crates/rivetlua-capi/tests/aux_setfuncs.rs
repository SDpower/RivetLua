use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicUsize, Ordering};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_getfield, lua_gettop, lua_pushinteger, lua_settop, lua_toboolean,
    lua_tointegerx, lua_type,
};
use rivetlua_core::{ObjectRef, Value};
use rivetlua_runtime::{
    FailPoint, GcAge, GcMode, GcPhase, GcTrace, LedgerSnapshot, ObjectKind, RootId, RootKind,
    VmError,
};

type LuaCFunction = unsafe extern "C" fn(*mut lua_State) -> c_int;

#[repr(C)]
struct LuaLReg {
    name: *const c_char,
    func: Option<LuaCFunction>,
}

static CALLBACKS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn callback(_state: *mut lua_State) -> c_int {
    CALLBACKS.fetch_add(1, Ordering::SeqCst);
    0
}

unsafe extern "C" {
    fn rivetlua_capi_test_prime_a4a(state: *mut lua_State);
    fn luaL_setfuncs(state: *mut lua_State, entries: *const LuaLReg, nup: c_int);
    fn rivetlua_capi_test_public_protected_a4a(
        state: *mut lua_State,
        operation: c_int,
        index: c_int,
        name: *const c_char,
        key: i64,
        entries: *const LuaLReg,
        nup: c_int,
        inject_offset: c_int,
        injection_start: *mut u64,
    ) -> c_int;
    fn lua_getupvalue(state: *mut lua_State, index: c_int, n: c_int) -> *const c_char;
    fn lua_tocfunction(state: *mut lua_State, index: c_int) -> Option<LuaCFunction>;
    fn lua_upvalueid(state: *mut lua_State, index: c_int, n: c_int) -> *mut c_void;
}

fn reg(name: *const c_char, func: Option<LuaCFunction>) -> LuaLReg {
    LuaLReg { name, func }
}

fn sentinel() -> LuaLReg {
    reg(std::ptr::null(), None)
}

fn setfuncs(owner: &StateOwner, entries: &[LuaLReg], nup: c_int) {
    // SAFETY：owner 保活 state；entries 於呼叫期間有效且以 null name 終止；
    // 所有非空 name 均使用靜態 NUL 結尾 C 字串。
    unsafe { luaL_setfuncs(owner.as_ptr(), entries.as_ptr(), nup) };
}

fn protected_setfuncs(
    owner: &StateOwner,
    entries: *const LuaLReg,
    nup: c_int,
    inject: c_int,
) -> (c_int, u64) {
    let mut start = 0;
    // SAFETY：helper 在純 C lua_pcall callback 內執行公開 setfuncs，錯誤在返回 Rust 前被捕獲。
    let status = unsafe {
        rivetlua_capi_test_public_protected_a4a(
            owner.as_ptr(),
            9,
            0,
            std::ptr::null(),
            0,
            entries,
            nup,
            inject,
            &mut start,
        )
    };
    (status, start)
}

fn protected_setfuncs_at_point(
    owner: &StateOwner,
    entries: *const LuaLReg,
    nup: c_int,
    point: FailPoint,
) -> c_int {
    let code = match point {
        FailPoint::SlotReserve => 0,
        FailPoint::ObjectReserve => 1,
        FailPoint::ObjectInitialize => 2,
        FailPoint::RootReserve => 3,
        FailPoint::HostLease => 4,
        FailPoint::ClosureCapturesReserve => 5,
        FailPoint::StringBytesReserve => 6,
        FailPoint::TableHashGrow => 7,
        FailPoint::TableRehash => 8,
        FailPoint::TableInsert => 9,
        FailPoint::MarkReserve => 10,
        FailPoint::WorkReserve => 11,
        FailPoint::RememberedReserve => 12,
        _ => panic!("A4a 夾具未定義此配置點：{point:?}"),
    };
    protected_setfuncs(owner, entries, nup, -code - 2).0
}

fn table_on_stack(owner: &StateOwner) -> ObjectRef {
    let table = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner.push_value(Value::Object(table)).unwrap();
    table
}

type Snapshot = (LedgerSnapshot, GcTrace, Vec<(RootKind, RootId, ObjectRef)>);

fn snapshot(owner: &StateOwner) -> Snapshot {
    owner
        .with_vm(|vm| {
            let mut roots = Vec::new();
            vm.visit_roots(|kind, id, object| roots.push((kind, id, object)));
            (vm.ledger_snapshot(), vm.gc_trace(), roots)
        })
        .unwrap()
}

fn raw_name(owner: &StateOwner, table: ObjectRef, name: &[u8]) -> Value {
    owner
        .with_vm(|vm| {
            vm.with_temporary_byte_string(name, |vm, key| vm.raw_get(table, Value::Object(key)))
                .unwrap()
        })
        .unwrap()
}

fn normal_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let entries = [
        reg(c"answer".as_ptr(), Some(callback)),
        reg(c"missing".as_ptr(), None),
        sentinel(),
        reg(1usize as *const c_char, Some(callback)),
    ];
    CALLBACKS.store(0, Ordering::SeqCst);
    let table = table_on_stack(&owner);
    // SAFETY：state 由 owner 保活。
    unsafe {
        lua_pushinteger(state, 42);
    }
    setfuncs(&owner, &entries, 1);
    // SAFETY：state 由 owner 保活；欄位名稱為靜態 C 字串。
    unsafe {
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_getfield(state, 1, c"answer".as_ptr()), 6);
        assert_eq!(lua_type(state, -1), 6);
        assert!(!lua_getupvalue(state, -1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 42);
        lua_settop(state, 1);
        assert_eq!(lua_getfield(state, 1, c"missing".as_ptr()), 1);
        assert_eq!(lua_toboolean(state, -1), 0);
        lua_settop(state, 1);
    }
    assert!(matches!(
        raw_name(&owner, table, b"answer"),
        Value::Object(_)
    ));
    assert_eq!(CALLBACKS.load(Ordering::SeqCst), 0);

    let duplicate = [
        reg(c"same".as_ptr(), Some(callback)),
        reg(c"same".as_ptr(), Some(other_callback)),
        sentinel(),
    ];
    setfuncs(&owner, &duplicate, 0);
    // SAFETY：兩個 callback 指標只比較、不執行。
    unsafe {
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_getfield(state, 1, c"same".as_ptr()), 6);
        assert!(
            lua_tocfunction(state, -1)
                .is_some_and(|value| std::ptr::fn_addr_eq(value, other_callback as LuaCFunction))
        );
        lua_settop(state, 1);
    }

    let empty = [sentinel()];
    // SAFETY：state 有效，原始 capture 應於空清單後移除。
    unsafe { lua_pushinteger(state, 71) };
    setfuncs(&owner, &empty, 1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    setfuncs(&owner, &empty, 0);
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    let pair = [
        reg(c"left".as_ptr(), Some(callback)),
        reg(c"right".as_ptr(), Some(callback)),
        sentinel(),
    ];
    // SAFETY：state 有效；兩筆必須各自複製同順序 captures。
    unsafe {
        lua_pushinteger(state, 11);
        lua_pushinteger(state, 22);
    }
    setfuncs(&owner, &pair, 2);
    // SAFETY：所有 index 都位於有效 stack，靜態名稱有效。
    unsafe {
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_getfield(state, 1, c"left".as_ptr()), 6);
        let left_first = lua_upvalueid(state, -1, 1);
        let left_second = lua_upvalueid(state, -1, 2);
        assert!(!left_first.is_null());
        assert_ne!(left_first, left_second);
        assert!(!lua_getupvalue(state, -1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 11);
        lua_settop(state, 2);
        assert!(!lua_getupvalue(state, -1, 2).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 22);
        lua_settop(state, 1);
        assert_eq!(lua_getfield(state, 1, c"right".as_ptr()), 6);
        assert_ne!(lua_upvalueid(state, -1, 1), left_first);
        assert_ne!(lua_upvalueid(state, -1, 2), left_second);
        assert!(!lua_getupvalue(state, -1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 11);
        lua_settop(state, 1);
    }

    let old_left = match raw_name(&owner, table, b"left") {
        Value::Object(object) => object,
        value => panic!("原欄位應是 closure：{value:?}"),
    };
    // SAFETY：成功覆寫後，舊 closure 不再由 table 保活。
    unsafe { lua_pushinteger(state, 33) };
    setfuncs(
        &owner,
        &[reg(c"left".as_ptr(), Some(callback)), sentinel()],
        1,
    );
    let new_left = match raw_name(&owner, table, b"left") {
        Value::Object(object) => object,
        value => panic!("新欄位應是 closure：{value:?}"),
    };
    assert_ne!(old_left, new_left);
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.object_kind(old_left), Err(VmError::StaleObject));
            assert_eq!(vm.object_kind(new_left), Ok(ObjectKind::CClosure));
        })
        .unwrap();

    let boundary = StateOwner::new().unwrap();
    table_on_stack(&boundary);
    for number in 1..=255 {
        // SAFETY：boundary state 有效且 stack 仍在上限內。
        unsafe { lua_pushinteger(boundary.as_ptr(), number) };
    }
    setfuncs(
        &boundary,
        &[reg(c"boundary".as_ptr(), Some(callback)), sentinel()],
        255,
    );
    // SAFETY：成功後 stack 僅餘 table；兩端 capture index 有效。
    unsafe {
        let state = boundary.as_ptr();
        assert_eq!(lua_gettop(state), 1);
        assert_eq!(lua_getfield(state, 1, c"boundary".as_ptr()), 6);
        assert!(!lua_getupvalue(state, -1, 1).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 1);
        lua_settop(state, 2);
        assert!(!lua_getupvalue(state, -1, 255).is_null());
        assert_eq!(lua_tointegerx(state, -1, std::ptr::null_mut()), 255);
    }
    assert_eq!(CALLBACKS.load(Ordering::SeqCst), 0);
}

unsafe extern "C" fn other_callback(_state: *mut lua_State) -> c_int {
    CALLBACKS.fetch_add(1, Ordering::SeqCst);
    1
}

fn invalid_cases() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let table = table_on_stack(&owner);
    // SAFETY：state 有效；公開 Lua 錯誤由純 C protected callback 接住。
    unsafe { lua_pushinteger(state, 23) };
    let entries = [reg(c"safe".as_ptr(), Some(callback)), sentinel()];
    let before_roots = snapshot(&owner).2;
    for nup in [-1, 256, 3] {
        assert!(protected_setfuncs(&owner, entries.as_ptr(), nup, -1).0 < 0);
        assert_eq!(unsafe { lua_gettop(state) }, 2);
        let after = snapshot(&owner);
        assert_eq!(after.0.reserved, 0);
        assert_eq!(after.2, before_roots);
    }
    assert!(protected_setfuncs(&owner, std::ptr::null(), 1, -1).0 < 0);
    assert_eq!(unsafe { lua_gettop(state) }, 2);
    assert_eq!(snapshot(&owner).2, before_roots);
    assert_eq!(raw_name(&owner, table, b"safe"), Value::Nil);

    let meta = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
    owner
        .with_vm(|vm| vm.set_metatable(table, Some(meta)).unwrap())
        .unwrap();
    setfuncs(&owner, &entries, 1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert!(matches!(raw_name(&owner, table, b"safe"), Value::Object(_)));
    unsafe { lua_pushinteger(state, 23) };
    setfuncs(&owner, &[sentinel()], 1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    // SAFETY：空清單只移除 capture；重新建立測試後續可重試性。
    unsafe { lua_pushinteger(state, 23) };
    owner
        .with_vm(|vm| vm.set_metatable(table, None).unwrap())
        .unwrap();
    setfuncs(&owner, &entries, 1);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert!(matches!(raw_name(&owner, table, b"safe"), Value::Object(_)));

    let wrong = StateOwner::new().unwrap();
    assert!(protected_setfuncs(&wrong, entries.as_ptr(), 0, -1).0 < 0);
    assert_eq!(unsafe { lua_gettop(wrong.as_ptr()) }, 0);
    unsafe { lua_pushinteger(wrong.as_ptr(), 7) };
    assert!(protected_setfuncs(&wrong, entries.as_ptr(), 0, -1).0 < 0);
    assert_eq!(unsafe { lua_gettop(wrong.as_ptr()) }, 1);
}

fn gc_survival_cases() {
    for (mode, stress) in [
        (GcMode::Incremental, false),
        (GcMode::Incremental, true),
        (GcMode::Generational, false),
        (GcMode::Generational, true),
    ] {
        let owner = StateOwner::new().unwrap();
        let table = table_on_stack(&owner);
        let captured = owner.with_vm(|vm| vm.allocate_table().unwrap()).unwrap();
        owner.push_value(Value::Object(captured)).unwrap();
        owner
            .with_vm(|vm| {
                vm.set_gc_mode(mode).unwrap();
                vm.set_collect_every_allocation(stress);
                vm.incremental_step(1).unwrap();
            })
            .unwrap();
        setfuncs(
            &owner,
            &[reg(c"keep".as_ptr(), Some(callback)), sentinel()],
            1,
        );
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        let closure = match raw_name(&owner, table, b"keep") {
            Value::Object(closure) => closure,
            value => panic!("mode={mode:?};stress={stress}; value={value:?}"),
        };
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(closure), Ok(ObjectKind::CClosure));
                assert_eq!(vm.object_kind(captured), Ok(ObjectKind::Table));
            })
            .unwrap();
        // SAFETY：移除 table 唯一 stack root 後 closure/capture 均應可回收。
        unsafe { lua_settop(owner.as_ptr(), 0) };
        owner
            .with_vm(|vm| {
                vm.collect().unwrap();
                assert_eq!(vm.object_kind(closure), Err(VmError::StaleObject));
                assert_eq!(vm.object_kind(captured), Err(VmError::StaleObject));
            })
            .unwrap();
    }
}

fn failure_owner() -> (StateOwner, ObjectRef) {
    let owner = StateOwner::new().unwrap();
    // SAFETY：測試 callback 只於此 state 登錄一次，避免夾具本身的 registry
    // 容量配置混入後續 failpoint ledger 比較。
    unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
    let table = table_on_stack(&owner);
    // SAFETY：有效 state；原始 captures 直到整筆成功都必須保留。
    unsafe {
        lua_pushinteger(owner.as_ptr(), 11);
        lua_pushinteger(owner.as_ptr(), 22);
    }
    owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
    (owner, table)
}

fn ordinal_failures() {
    let entries = [reg(c"ordinal".as_ptr(), Some(callback)), sentinel()];
    let (probe, _) = failure_owner();
    let start = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    setfuncs(&probe, &entries, 2);
    assert_eq!(unsafe { lua_gettop(probe.as_ptr()) }, 1);
    let end = probe
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    let attempts = end - start;
    assert!(attempts >= 10, "須涵蓋 registry、cells、key 與 table");
    for offset in 0..attempts {
        let (owner, table) = failure_owner();
        let before = snapshot(&owner);
        let (status, next) = protected_setfuncs(&owner, entries.as_ptr(), 2, offset as c_int);
        assert_eq!(status, -4, "offset={offset}");
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 3, "offset={offset}");
        let after = snapshot(&owner);
        assert_eq!(after.2, before.2, "offset={offset}: roots");
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        let collected = snapshot(&owner);
        assert_eq!(collected.2, before.2, "offset={offset}: collected roots");
        assert_eq!(
            collected.1.white + collected.1.gray + collected.1.black,
            before.1.white + before.1.gray + before.1.black,
            "offset={offset}: unreachable heap objects after GC"
        );
        // 已建立的暫存物件全數回收；arena 容量可留給同 state 重試，
        // 第二輪 GC 不應使 ledger 繼續增長。
        assert_eq!(collected.0.reserved, 0, "offset={offset}");
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            snapshot(&owner).0,
            collected.0,
            "offset={offset}: steady ledger"
        );
        assert!(
            collected.0.host_allocation_bytes == before.0.host_allocation_bytes
                || collected.0.host_allocation_bytes == before.0.host_allocation_bytes + 24,
            "offset={offset}: host registry capacity: {collected:?} vs {before:?}"
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_table(table, |table| table.is_empty()))
                .unwrap(),
            Ok(true),
            "offset={offset}"
        );
        let failed = owner
            .with_vm(|vm| vm.allocation_trace().last_failure.unwrap())
            .unwrap();
        assert_eq!(failed.attempt.ordinal, next + offset);
        setfuncs(&owner, &entries, 2);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert!(matches!(
            raw_name(&owner, table, b"ordinal"),
            Value::Object(_)
        ));
    }
}

fn light_and_partial_entry_failures() {
    let light = [reg(c"light".as_ptr(), Some(callback)), sentinel()];
    let light_probe = StateOwner::new().unwrap();
    // SAFETY：先登錄夾具 callback，避免量測時混入其固定 registry 配置。
    unsafe { rivetlua_capi_test_prime_a4a(light_probe.as_ptr()) };
    table_on_stack(&light_probe);
    let (attempts, _) = protected_setfuncs(&light_probe, light.as_ptr(), 0, -1000);
    assert!(attempts >= 4);
    for offset in 0..attempts as u64 {
        let owner = StateOwner::new().unwrap();
        // SAFETY：owner 保活 state；夾具 callback 只登錄一次。
        unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
        let table = table_on_stack(&owner);
        let before = snapshot(&owner);
        let (status, next) = protected_setfuncs(&owner, light.as_ptr(), 0, offset as c_int);
        assert_eq!(status, -4, "light offset={offset}");
        assert_eq!(
            unsafe { lua_gettop(owner.as_ptr()) },
            1,
            "light offset={offset}"
        );
        assert_eq!(snapshot(&owner).2, before.2, "light offset={offset}: roots");
        assert_eq!(
            owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
                .unwrap(),
            next + offset as u64
        );
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_table(table, |table| table.is_empty()))
                .unwrap(),
            Ok(true)
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(
            snapshot(&owner).2,
            before.2,
            "light offset={offset}: collected roots"
        );
        setfuncs(&owner, &light, 0);
        assert!(matches!(
            raw_name(&owner, table, b"light"),
            Value::CFunction(_)
        ));
    }

    let first = [reg(c"first".as_ptr(), Some(callback)), sentinel()];
    let both = [
        reg(c"first".as_ptr(), Some(callback)),
        reg(c"second".as_ptr(), Some(callback)),
        sentinel(),
    ];
    let (first_probe, _) = failure_owner();
    let (first_attempts, _) = protected_setfuncs(&first_probe, first.as_ptr(), 2, -1000);
    assert!(first_attempts > 0);
    let (both_probe, _) = failure_owner();
    let (all_attempts, _) = protected_setfuncs(&both_probe, both.as_ptr(), 2, -1000);
    assert!(all_attempts > first_attempts);
    for offset in first_attempts..all_attempts {
        let (owner, table) = failure_owner();
        let before = snapshot(&owner);
        let (status, next) = protected_setfuncs(&owner, both.as_ptr(), 2, offset as c_int);
        assert_eq!(status, -4, "partial offset={offset}");
        assert_eq!(
            owner
                .with_vm(|vm| vm.allocation_trace().last_failure.unwrap().attempt.ordinal)
                .unwrap(),
            next + offset as u64
        );
        assert_eq!(
            unsafe { lua_gettop(owner.as_ptr()) },
            3,
            "partial offset={offset}"
        );
        assert_eq!(
            snapshot(&owner).2,
            before.2,
            "partial offset={offset}: roots"
        );
        assert!(matches!(
            raw_name(&owner, table, b"first"),
            Value::Object(_)
        ));
        assert_eq!(raw_name(&owner, table, b"second"), Value::Nil);
        assert_eq!(
            unsafe { lua_tointegerx(owner.as_ptr(), 2, std::ptr::null_mut()) },
            11
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert!(matches!(
            raw_name(&owner, table, b"first"),
            Value::Object(_)
        ));
        setfuncs(&owner, &both, 2);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
        assert!(matches!(
            raw_name(&owner, table, b"second"),
            Value::Object(_)
        ));
    }
}

fn overwrite_failure_keeps_previous_value() {
    let owner = StateOwner::new().unwrap();
    // SAFETY：只登錄夾具 callback；後續 named failpoint 在 callback 內啟用。
    unsafe { rivetlua_capi_test_prime_a4a(owner.as_ptr()) };
    let table = table_on_stack(&owner);
    owner
        .with_vm(|vm| {
            vm.raw_set_byte_string_key(table, b"existing", Value::Integer(7))
                .unwrap()
        })
        .unwrap();
    // SAFETY：state 有效；原始 capture 須在失敗後保留。
    unsafe { lua_pushinteger(owner.as_ptr(), 41) };
    let entries = [reg(c"existing".as_ptr(), Some(callback)), sentinel()];
    let before = snapshot(&owner);
    assert_eq!(
        protected_setfuncs_at_point(&owner, entries.as_ptr(), 1, FailPoint::StringBytesReserve),
        -4
    );
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 2);
    assert_eq!(snapshot(&owner).2, before.2);
    assert_eq!(raw_name(&owner, table, b"existing"), Value::Integer(7));
    setfuncs(&owner, &entries, 1);
    assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1);
    assert!(matches!(
        raw_name(&owner, table, b"existing"),
        Value::Object(_)
    ));
}

fn named_failures() {
    let entries = [reg(c"named".as_ptr(), Some(callback)), sentinel()];
    for (point, mode) in [
        (FailPoint::SlotReserve, GcMode::Incremental),
        (FailPoint::ObjectReserve, GcMode::Incremental),
        (FailPoint::ObjectInitialize, GcMode::Incremental),
        (FailPoint::RootReserve, GcMode::Incremental),
        (FailPoint::HostLease, GcMode::Incremental),
        (FailPoint::ClosureCapturesReserve, GcMode::Incremental),
        (FailPoint::StringBytesReserve, GcMode::Incremental),
        (FailPoint::TableHashGrow, GcMode::Incremental),
        (FailPoint::TableRehash, GcMode::Incremental),
        (FailPoint::TableInsert, GcMode::Incremental),
        (FailPoint::MarkReserve, GcMode::Incremental),
        (FailPoint::WorkReserve, GcMode::Incremental),
        (FailPoint::RememberedReserve, GcMode::Generational),
    ] {
        let (owner, table) = failure_owner();
        owner
            .with_vm(|vm| {
                vm.set_gc_debt_threshold(usize::MAX);
                vm.set_gc_mode(mode).unwrap();
                if mode == GcMode::Generational {
                    vm.set_gc_promotion_survivals(1).unwrap();
                    vm.collect().unwrap();
                    assert_eq!(vm.gc_age(table), Ok(GcAge::Old));
                } else if matches!(point, FailPoint::MarkReserve | FailPoint::WorkReserve) {
                    vm.incremental_step(1).unwrap();
                    assert_ne!(vm.gc_trace().phase, GcPhase::Pause);
                }
            })
            .unwrap();
        let before = snapshot(&owner);
        let status = protected_setfuncs_at_point(&owner, entries.as_ptr(), 2, point);
        assert_eq!(status, -4, "{point:?}");
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap();
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 3, "{point:?}");
        if let Some(failure) = failure {
            assert_eq!(failure.attempt.point, Some(point), "{point:?}");
        }
        assert_eq!(snapshot(&owner).2, before.2, "{point:?}: roots");
        assert_eq!(
            owner
                .with_vm(|vm| vm.with_table(table, |table| table.is_empty()))
                .unwrap(),
            Ok(true)
        );
        owner.with_vm(|vm| vm.collect().unwrap()).unwrap();
        assert_eq!(snapshot(&owner).2, before.2, "{point:?}: collected roots");
        setfuncs(&owner, &entries, 2);
        assert_eq!(unsafe { lua_gettop(owner.as_ptr()) }, 1, "{point:?}");
        assert!(matches!(
            raw_name(&owner, table, b"named"),
            Value::Object(_)
        ));
    }
}

#[test]
fn aux_setfuncs_a44_matrix() {
    normal_cases();
    invalid_cases();
    gc_survival_cases();
    ordinal_failures();
    light_and_partial_entry_failures();
    overwrite_failure_keeps_previous_value();
    named_failures();
}
