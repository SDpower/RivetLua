use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{Value, VerifyLimits};
use rivetlua_runtime::{ByteString, HostHandle, RootKind, Vm, VmError};
use rivetlua_runtime::{CanonicalKeyClass, ObjectKind, RunOutcome, Table};

#[test]
fn p08_1_byte_string_public_bytes_and_handle_lifetime() {
    let profile =
        std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
    let mut vm = Vm::new().unwrap();
    let bytes = [0x00, 0x41, 0x80, 0xff];
    let object = vm.allocate_byte_string(&bytes).unwrap();
    let handle = HostHandle::<ByteString>::new(&mut vm, object).unwrap();
    assert_eq!(handle.object_id(), object.identity().unwrap());
    assert_eq!(vm.roots().count(RootKind::Host), 1);
    vm.with_byte_string(object, |value| {
        assert_eq!(value.len(), 4);
        for (index, byte) in bytes.iter().enumerate() {
            assert_eq!(value.as_bytes()[index], *byte);
        }
    })
    .unwrap();
    assert_eq!(vm.collect().unwrap(), 0);
    assert_eq!(
        vm.with_byte_string(object, |value| value.as_bytes()[3]),
        Ok(0xff)
    );
    drop(handle);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.collect().unwrap(), 1);
    assert_eq!(
        vm.with_byte_string(object, |value| value.len()),
        Err(VmError::StaleObject)
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p08_2_canonical_key_public_table_and_normalization() {
    let profile =
        std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
    let mut vm = Vm::new().unwrap();
    let table = vm.allocate_table().unwrap();
    let handle = HostHandle::<Table>::new(&mut vm, table).unwrap();
    assert_eq!(vm.object_kind(table), Ok(ObjectKind::Table));
    assert_eq!(handle.object_id(), table.identity().unwrap());
    vm.with_table(table, |value| assert!(value.is_empty()))
        .unwrap();
    let integer = vm.canonical_key(Value::Integer(1)).unwrap().unwrap();
    let float = vm.canonical_key(Value::Float(1.0)).unwrap().unwrap();
    assert_eq!(integer.class(), CanonicalKeyClass::Integer);
    assert!(integer == float);
    assert!(vm.canonical_key(Value::Nil).unwrap().is_none());
    assert!(vm.canonical_key(Value::Float(f64::NAN)).unwrap().is_none());
    let a = vm.allocate_byte_string(&[0, 0x80]).unwrap();
    let b = vm.allocate_byte_string(&[0, 0x80]).unwrap();
    let ak = vm.canonical_key(Value::Object(a)).unwrap().unwrap();
    let bk = vm.canonical_key(Value::Object(b)).unwrap().unwrap();
    assert_eq!(ak.class(), CanonicalKeyClass::ByteString);
    assert!(ak == bk);
    let object = vm.allocate(Value::Boolean(true)).unwrap();
    let object_key = vm.canonical_key(Value::Object(object)).unwrap().unwrap();
    assert_eq!(object_key.class(), CanonicalKeyClass::Object);
    assert!(object_key != ak);
    assert_eq!(vm.collect().unwrap(), 3);
    drop(handle);
    assert_eq!(vm.collect().unwrap(), 1);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn p08_3_raw_vm_cases() {
    fn compiled(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    }

    let profile_name =
        std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match profile_name.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P08 profile 無效"),
    };
    for (case, source, expected) in [
        (
            "TAB-002",
            b"local t={}; t[1]=7; return t[1.0]".as_slice(),
            Value::Integer(7),
        ),
        (
            "TAB-003",
            b"local t={x=false}; return t.x".as_slice(),
            Value::Boolean(false),
        ),
        (
            "TAB-006",
            b"local t={x=1}; t.x=nil; return t.x".as_slice(),
            Value::Nil,
        ),
    ] {
        let mut vm = Vm::new().unwrap();
        let verified = compiled(source, profile);
        let mut execution = vm.load(verified).unwrap();
        let actual = execution.run();
        assert_eq!(actual, Ok(RunOutcome::Returned(vec![expected])));
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        println!(
            "P08_CASE\t{case}\t{profile_name}\tinput={source:?}\texpected=Returned({expected:?})\tactual={actual:?}"
        );
    }

    let mut vm = Vm::new().unwrap();
    let verified = compiled(b"return \"\\0\\x80\\xff\"", profile);
    let mut execution = vm.load(verified).unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("字串常數須正常回傳")
    };
    drop(execution);
    let [Value::Object(string)] = values.as_slice() else {
        panic!("字串常數須進入 heap")
    };
    vm.with_byte_string(*string, |value| {
        assert_eq!(value.as_bytes(), [0, 0x80, 0xff])
    })
    .unwrap();
    assert_eq!(vm.roots().total_count(), 0);

    let mut vm = Vm::new().unwrap();
    let table = vm.allocate_table().unwrap();
    let before = vm.ledger_snapshot();
    for (case, key, expected) in [
        ("TAB-004", Value::Nil, VmError::NilTableKey),
        ("TAB-005", Value::Float(f64::NAN), VmError::NaNTableKey),
    ] {
        let actual = vm.raw_set(table, key, Value::Integer(1));
        assert_eq!(actual, Err(expected));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
        println!(
            "P08_CASE\t{case}\t{profile_name}\tinput=raw_set({key:?},1)\texpected={expected:?}\tactual={actual:?}\tdiagnostic={}",
            expected.code()
        );
    }
    for (case, key) in [("TAB-011", Value::Nil), ("TAB-012", Value::Float(f64::NAN))] {
        let actual = vm.raw_get(table, key);
        assert_eq!(actual, Ok(Value::Nil));
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
        println!(
            "P08_CASE\t{case}\t{profile_name}\tinput=raw_get({key:?})\texpected=Nil\tactual={actual:?}"
        );
    }
    assert!(vm.with_table(table, |value| value.is_empty()).unwrap());
}

#[test]
fn p08_4_length_vm_cases() {
    fn compiled(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    }

    let profile_name =
        std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    let profile = match profile_name.as_str() {
        "lua55-i64f64" => LanguageProfile::Lua55,
        "lua54-i64f64" => LanguageProfile::Lua54,
        _ => panic!("P08 profile 無效"),
    };

    let source = b"return #\"\\0A\"";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compiled(source, profile)).unwrap();
    let actual = execution.run();
    assert_eq!(actual, Ok(RunOutcome::Returned(vec![Value::Integer(2)])));
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    println!(
        "P08_CASE\tTAB-001\t{profile_name}\tinput={source:?}\texpected=Returned(2)\tactual={actual:?}"
    );

    let source = b"local t={}; t[1]=7; t[3]=9; return #t";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compiled(source, profile)).unwrap();
    let actual = execution.run();
    let Ok(RunOutcome::Returned(values)) = &actual else {
        panic!("TAB-007 須正常回傳邊界")
    };
    let [Value::Integer(border)] = values.as_slice() else {
        panic!("TAB-007 須回傳整數邊界")
    };
    let border = *border;
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
    let table = vm.allocate_table().unwrap();
    vm.raw_set(table, Value::Integer(1), Value::Integer(7))
        .unwrap();
    vm.raw_set(table, Value::Integer(3), Value::Integer(9))
        .unwrap();
    assert!(border >= 1);
    assert_ne!(vm.raw_get(table, Value::Integer(border)), Ok(Value::Nil));
    assert_eq!(
        vm.raw_get(table, Value::Integer(border + 1)),
        Ok(Value::Nil)
    );
    println!(
        "P08_CASE\tTAB-007\t{profile_name}\tinput={source:?}\texpected=valid_border\tactual={actual:?}"
    );

    let source = b"return #7";
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(compiled(source, profile)).unwrap();
    let error = execution
        .run()
        .err()
        .expect("number 的 Length 須回結構化錯誤");
    assert_eq!(
        error.kind,
        rivetlua_runtime::RuntimeErrorKind::UnsupportedUnaryOperation(
            rivetlua_core::UnaryOperation::Length
        )
    );
    drop(execution);
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn p08_5_gc_and_failure_cases() {
    fn compiled(source: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
        let limits = CompileLimits::default();
        let chunk = lex(source, profile, &limits).unwrap();
        let parsed = parse(&chunk, profile, &limits).unwrap();
        let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
        let ir = lower(&resolved, &IrLimits::default()).unwrap();
        emit(&ir, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone()
    }

    let profile =
        std::env::var("RIVETLUA_P08_PROFILE").unwrap_or_else(|_| "lua55-i64f64".to_owned());
    assert!(matches!(profile.as_str(), "lua55-i64f64" | "lua54-i64f64"));
    let language_profile = if profile == "lua55-i64f64" {
        LanguageProfile::Lua55
    } else {
        LanguageProfile::Lua54
    };

    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let source = b"local s=\"\\0\\x80\"; local t={}; t[s]=s; return t[s]";
    let mut execution = vm.load(compiled(source, language_profile)).unwrap();
    let RunOutcome::Returned(values) = execution.run().unwrap() else {
        panic!("強制收集下 VM table/string 須正常回傳")
    };
    drop(execution);
    let [Value::Object(string)] = values.as_slice() else {
        panic!("VM 須回傳 byte string object")
    };
    assert_eq!(
        vm.with_byte_string(*string, |value| value.as_bytes().to_vec()),
        Ok(vec![0, 0x80])
    );
    assert_eq!(vm.roots().total_count(), 0);
    let stack_reclaimed = vm.collect().unwrap();
    assert_eq!(stack_reclaimed, 2);
    assert_eq!(vm.ledger_snapshot().reserved, 0);

    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let table = vm.allocate_table().unwrap();
    let table_handle = HostHandle::<Table>::new(&mut vm, table).unwrap();
    let string_key = vm.allocate_byte_string(&[0, 0x80, 0xff]).unwrap();
    let string_key_root = vm.add_root(RootKind::Host, string_key).unwrap();
    let string_value = vm.allocate_byte_string(&[0, 0x41]).unwrap();
    let string_value_root = vm.add_root(RootKind::Host, string_value).unwrap();
    vm.raw_set(
        table,
        Value::Object(string_key),
        Value::Object(string_value),
    )
    .unwrap();
    vm.remove_root(string_key_root).unwrap();
    vm.remove_root(string_value_root).unwrap();
    let object_key = vm.allocate(Value::Integer(41)).unwrap();
    let object_key_root = vm.add_root(RootKind::Host, object_key).unwrap();
    let object_value = vm.allocate(Value::Integer(42)).unwrap();
    let object_value_root = vm.add_root(RootKind::Host, object_value).unwrap();
    vm.raw_set(
        table,
        Value::Object(object_key),
        Value::Object(object_value),
    )
    .unwrap();
    vm.remove_root(object_key_root).unwrap();
    vm.remove_root(object_value_root).unwrap();
    let array_value = vm.allocate_byte_string(&[0, 0xfe]).unwrap();
    vm.raw_set(table, Value::Integer(1), Value::Object(array_value))
        .unwrap();
    for key in 2..=8 {
        vm.raw_set(table, Value::Integer(key), Value::Integer(key))
            .unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    for key in 100..112 {
        vm.raw_set(table, Value::Integer(key), Value::Integer(key))
            .unwrap();
        assert_eq!(vm.collect().unwrap(), 0);
        assert_eq!(vm.roots().count(RootKind::Temporary), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(table_handle.object_id(), table.identity().unwrap());
    assert_eq!(
        vm.raw_get(table, Value::Object(string_key)),
        Ok(Value::Object(string_value))
    );
    assert_eq!(
        vm.raw_get(table, Value::Object(object_key)),
        Ok(Value::Object(object_value))
    );
    assert_eq!(
        vm.raw_get(table, Value::Integer(1)),
        Ok(Value::Object(array_value))
    );
    assert_eq!(
        vm.with_byte_string(string_key, |string| string.as_bytes().to_vec()),
        Ok(vec![0, 0x80, 0xff])
    );
    assert_eq!(vm.read(object_value), Ok(Value::Integer(42)));
    let transient = vm.allocate_byte_string(&[0x55]).unwrap();
    assert_eq!(vm.collect().unwrap(), 1);
    assert_eq!(
        vm.with_byte_string(transient, |string| string.len()),
        Err(VmError::StaleObject)
    );
    assert_eq!(vm.collect().unwrap(), 0);

    let before_removal = vm.ledger_snapshot();
    vm.raw_set(table, Value::Object(string_key), Value::Nil)
        .unwrap();
    vm.raw_set(table, Value::Object(object_key), Value::Nil)
        .unwrap();
    vm.raw_set(table, Value::Integer(1), Value::Nil).unwrap();
    let removed = vm.collect().unwrap();
    assert_eq!(removed, 5);
    assert_eq!(
        vm.with_byte_string(string_key, |string| string.len()),
        Err(VmError::StaleObject)
    );
    assert_eq!(vm.read(object_value), Err(VmError::StaleObject));
    assert!(vm.ledger_snapshot().committed < before_removal.committed);
    assert_eq!(vm.roots().total_count(), 1);
    drop(table_handle);
    let table_reclaimed = vm.collect().unwrap();
    assert_eq!(table_reclaimed, 1);
    assert_eq!(vm.roots().total_count(), 0);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    println!(
        "P08_CASE\tTAB-008\t{profile}\tinput=forced_gc_vm_stack_and_table_fields\texpected=stack_2_live_then_removed_5_table_1\tactual=stack_reclaimed,{stack_reclaimed};live,true;removed,{removed};table_reclaimed,{table_reclaimed};reserved,{}",
        vm.ledger_snapshot().reserved
    );

    let mut vm = Vm::new().unwrap();
    vm.set_collect_every_allocation(true);
    let table = vm.allocate_table().unwrap();
    let table_handle = HostHandle::<Table>::new(&mut vm, table).unwrap();
    vm.raw_set(table, Value::Integer(1), Value::Integer(7))
        .unwrap();
    for key in 100..=102 {
        vm.raw_set(table, Value::Integer(key), Value::Integer(key))
            .unwrap();
    }
    let capacities = vm
        .with_table(table, |stored| {
            (stored.array_capacity(), stored.hash_capacity())
        })
        .unwrap();
    let before = vm.ledger_snapshot();
    vm.inject_failure_once(rivetlua_runtime::FailPoint::TableRehash);
    assert_eq!(
        vm.raw_set(table, Value::Integer(103), Value::Integer(999)),
        Err(VmError::InjectedFailure(
            rivetlua_runtime::FailPoint::TableRehash
        ))
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(
        vm.with_table(table, |stored| (
            stored.array_capacity(),
            stored.hash_capacity()
        ))
        .unwrap(),
        capacities
    );
    let probe = vm.add_root(RootKind::Temporary, table).unwrap();
    let root_charge = vm.ledger_snapshot().committed - before.committed;
    vm.remove_root(probe).unwrap();
    vm.set_allocation_limit(before.committed + root_charge);
    assert_eq!(
        vm.raw_set(table, Value::Integer(103), Value::Integer(999)),
        Err(VmError::AllocationFailed)
    );
    vm.set_allocation_limit(before.limit);
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(
        vm.allocate_table_with_capacity(usize::MAX, 0),
        Err(VmError::ArithmeticOverflow)
    );
    vm.inject_failure_once(rivetlua_runtime::FailPoint::ObjectInitialize);
    assert_eq!(
        vm.allocate_table_with_capacity(2, 3),
        Err(VmError::InjectedFailure(
            rivetlua_runtime::FailPoint::ObjectInitialize
        ))
    );
    vm.inject_failure_once(rivetlua_runtime::FailPoint::StringBytesReserve);
    assert_eq!(
        vm.allocate_byte_string(&[0, 0x80]),
        Err(VmError::InjectedFailure(
            rivetlua_runtime::FailPoint::StringBytesReserve
        ))
    );
    assert_eq!(vm.raw_get(table, Value::Integer(1)), Ok(Value::Integer(7)));
    for key in 100..=102 {
        assert_eq!(
            vm.raw_get(table, Value::Integer(key)),
            Ok(Value::Integer(key))
        );
    }
    assert_eq!(vm.raw_get(table, Value::Integer(103)), Ok(Value::Nil));
    assert_eq!(
        vm.with_table(table, |stored| (
            stored.array_capacity(),
            stored.hash_capacity()
        ))
        .unwrap(),
        capacities
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), 1);
    assert_eq!(vm.roots().count(RootKind::Temporary), 0);
    assert_eq!(vm.collect().unwrap(), 0);
    println!(
        "P08_CASE\tTAB-009\t{profile}\tinput=rehash_failpoint,quota,overflow,init,string_reserve\texpected=fields_and_ledger_unchanged\tactual=fields_unchanged,true;roots,{};reserved,{};capacity,{capacities:?}",
        vm.roots().total_count(),
        vm.ledger_snapshot().reserved
    );
    drop(table_handle);
    assert_eq!(vm.collect().unwrap(), 1);
}
