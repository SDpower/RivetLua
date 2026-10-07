use std::cell::{Cell, RefCell};
use std::process::Command;
use std::rc::Rc;

use rivetlua::{
    AbortReason, CallbackContinuation, CallbackResult, ContainerErrorKind, ContainerLimits, Engine,
    HostOutput, HostOutputError, HostServices, LuaProfile, RunOutcome, SdkError, TransportBudget,
    Value, Vm,
};

fn profiles() -> Vec<(LuaProfile, &'static str)> {
    match std::env::var("RIVETLUA_P14_PROFILE").ok().as_deref() {
        Some("lua55-i64f64") => vec![(LuaProfile::Lua55, "lua55-i64f64")],
        Some("lua54-i64f64") => vec![(LuaProfile::Lua54, "lua54-i64f64")],
        None => vec![
            (LuaProfile::Lua55, "lua55-i64f64"),
            (LuaProfile::Lua54, "lua54-i64f64"),
        ],
        Some(other) => panic!("未知 P14 profile：{other}"),
    }
}

fn budget() -> TransportBudget {
    TransportBudget::new(ContainerLimits::default())
}

fn emit(id: &str, profile: &str, actual: &str, allocation: &str, resource: &str, vm: &str) {
    assert!(!allocation.is_empty() && !resource.is_empty() && !vm.is_empty());
    println!(
        "P14_CASE\t{id}\t{profile}\tstatus=PASS;actual={actual};diagnostic=asserted\tallocation={allocation}\tresource={resource}\tvm={vm}\tcli=not-applicable"
    );
}

fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    for part in parts {
        for &byte in *part {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb8_8320 & (0u32.wrapping_sub(crc & 1)));
            }
        }
    }
    !crc
}

fn refresh_crc(bytes: &mut [u8]) {
    let crc = crc32(&[&bytes[..32], &bytes[36..]]);
    bytes[32..36].copy_from_slice(&crc.to_le_bytes());
}

fn saved(engine: &Engine, source: &[u8]) -> Vec<u8> {
    let module = engine.compile(source).unwrap();
    engine.save_module(&module, &budget()).unwrap()
}

fn returned(vm: &mut Vm, module: &rivetlua::Module) -> Vec<Value> {
    match vm.load_module(module).unwrap().run().unwrap() {
        RunOutcome::Returned(values) => values,
        other => panic!("預期正常回傳：{other:?}"),
    }
}

fn table_field(vm: &mut Vm, table: &rivetlua::Root, name: &[u8]) -> rivetlua::Root {
    let key = vm.new_string(name).unwrap();
    let value = vm.table_raw_get(table, key.value(vm).unwrap()).unwrap();
    vm.root(value).unwrap()
}

struct CapturedOutput(Rc<RefCell<Vec<u8>>>);

impl HostOutput for CapturedOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
}

#[test]
fn sdk_case_001() {
    for (profile, label) in profiles() {
        let original = Engine::new(profile);
        let module = original
            .compile(b"return function(x) return x + 2 end")
            .unwrap();
        let mut first_vm = original.new_vm().unwrap();
        let first_function_value = returned(&mut first_vm, &module)[0];
        let first_function = first_vm.root(first_function_value).unwrap();
        let first = first_vm
            .call(&first_function, &[Value::Integer(40)])
            .unwrap()
            .run()
            .unwrap();
        let bytes = original.save_module(&module, &budget()).unwrap();
        drop(first_vm);
        drop(module);
        drop(original);
        let restarted = Engine::new(profile);
        let restored = restarted.load_module(&bytes, &budget()).unwrap();
        let mut vm = restarted.new_vm().unwrap();
        let function_value = returned(&mut vm, &restored)[0];
        let function = vm.root(function_value).unwrap();
        let second = vm
            .call(&function, &[Value::Integer(40)])
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(first, RunOutcome::Returned(vec![Value::Integer(42)]));
        assert_eq!(second, first);
        assert_eq!(vm.allocation_snapshot().reserved, 0);
        emit(
            "SDK-001",
            label,
            "int:42",
            "reserved=0",
            "module=restored",
            "fresh-vm",
        );
    }
}

#[test]
fn sdk_case_002() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let good = saved(&engine, b"return 42");
        let mut length = good.clone();
        length[8..16].copy_from_slice(&((good.len() as u64) + 1).to_le_bytes());
        refresh_crc(&mut length);
        let mut checksum = good.clone();
        *checksum.last_mut().unwrap() ^= 1;
        for (bytes, expected) in [
            (length, ContainerErrorKind::InvalidFormat),
            (checksum, ContainerErrorKind::IntegrityMismatch),
        ] {
            let ledger = budget();
            assert_eq!(
                engine.load_module(&bytes, &ledger).unwrap_err().kind,
                expected
            );
            assert_eq!(ledger.allocation_trace().next_ordinal, 1);
            assert_eq!(ledger.allocation_snapshot().reserved, 0);
        }
        emit(
            "SDK-002",
            label,
            "length+crc:preallocation",
            "next=1,reserved=0",
            "no-module",
            "none",
        );
    }
}

#[test]
fn sdk_case_003() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let good = saved(&engine, b"return 42");
        for (offset, value) in [(44, 3), (47, 2), (46, 9)] {
            let mut malformed = good.clone();
            malformed[offset] = value;
            refresh_crc(&mut malformed);
            let ledger = budget();
            let error = engine.load_module(&malformed, &ledger).unwrap_err();
            assert_eq!(error.kind, ContainerErrorKind::Payload);
            assert_eq!(
                error.payload_kind,
                Some(rivetlua::TransportErrorKind::InvalidFormat)
            );
            assert_eq!(error.offset, offset - 40);
            assert_eq!(error.detail, "P05 transport verifier 拒絕 payload");
            assert_eq!(ledger.allocation_snapshot().reserved, 0);
        }
        let other = Engine::new(match profile {
            LuaProfile::Lua55 => LuaProfile::Lua54,
            LuaProfile::Lua54 => LuaProfile::Lua55,
        });
        let error = other.load_module(&good, &budget()).unwrap_err();
        assert_eq!(error.kind, ContainerErrorKind::Payload);
        assert_eq!(
            error.payload_kind,
            Some(rivetlua::TransportErrorKind::InvalidFormat)
        );
        assert_eq!(error.offset, 6);
        emit(
            "SDK-003",
            label,
            "version+numeric+profile:payload",
            "reserved=0",
            "p05-InvalidFormat-offsets=4,7,6",
            "none",
        );
    }
}

#[test]
fn sdk_case_004() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(b"counter=(counter or 0)+1; local loaded=require('p14-shared'); print(marker); return counter,loaded,coroutine.create(function() coroutine.yield(marker); return vm_callback() end)").unwrap();
        let clone = module.clone();
        let left_output = Rc::new(RefCell::new(Vec::new()));
        let right_output = Rc::new(RefCell::new(Vec::new()));
        let (mut left, mut right) = (
            engine
                .new_vm_with_services(HostServices::with_output(CapturedOutput(Rc::clone(
                    &left_output,
                ))))
                .unwrap(),
            engine
                .new_vm_with_services(HostServices::with_output(CapturedOutput(Rc::clone(
                    &right_output,
                ))))
                .unwrap(),
        );
        left.set_global(b"marker", Value::Integer(11)).unwrap();
        right.set_global(b"marker", Value::Integer(22)).unwrap();
        let left_callback = left
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(31)])),
            )
            .unwrap();
        let right_callback = right
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(42)])),
            )
            .unwrap();
        left.set_global(b"vm_callback", left_callback.value(&left).unwrap())
            .unwrap();
        right
            .set_global(b"vm_callback", right_callback.value(&right).unwrap())
            .unwrap();
        let left_calls = Rc::new(Cell::new(0));
        let right_calls = Rc::new(Cell::new(0));
        for (vm, value, calls) in [
            (&mut left, 51, Rc::clone(&left_calls)),
            (&mut right, 62, Rc::clone(&right_calls)),
        ] {
            let package_value = vm.get_global(b"package").unwrap();
            let package = vm.root(package_value).unwrap();
            let preload = table_field(vm, &package, b"preload");
            let loader = vm
                .register_callback(
                    &[],
                    Rc::new(move |_, _| {
                        calls.set(calls.get() + 1);
                        CallbackResult::Return(vec![Value::Integer(value)])
                    }),
                )
                .unwrap();
            let key = vm.new_string(b"p14-shared").unwrap();
            vm.table_raw_set(&preload, key.value(vm).unwrap(), loader.value(vm).unwrap())
                .unwrap();
        }
        let left_values = returned(&mut left, &module);
        let right_values = returned(&mut right, &clone);
        assert_eq!(&left_values[..2], &[Value::Integer(1), Value::Integer(51)]);
        assert_eq!(&right_values[..2], &[Value::Integer(1), Value::Integer(62)]);
        assert_eq!(&*left_output.borrow(), b"11\n");
        assert_eq!(&*right_output.borrow(), b"22\n");
        let left_thread = left.root(left_values[2]).unwrap();
        let right_thread = right.root(right_values[2]).unwrap();
        assert_eq!(
            left.resume(&left_thread, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(11)])
        );
        assert_eq!(
            right.resume(&right_thread, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(22)])
        );
        assert_eq!(
            left.resume(&left_thread, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(31)])
        );
        assert_eq!(
            right.resume(&right_thread, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(42)])
        );
        assert!(left.resume(&right_thread, &[]).is_err());
        left.set_global(b"package", Value::Nil).unwrap();
        right.set_global(b"package", Value::Nil).unwrap();
        assert_eq!(
            &returned(&mut left, &module)[..2],
            &[Value::Integer(2), Value::Integer(51)]
        );
        assert_eq!(
            &returned(&mut right, &clone)[..2],
            &[Value::Integer(2), Value::Integer(62)]
        );
        assert_eq!(left_calls.get(), 1);
        assert_eq!(right_calls.get(), 1);
        let foreign = left.new_table().unwrap();
        assert!(
            right
                .set_global(b"foreign", foreign.value(&left).unwrap())
                .is_err()
        );
        assert!(foreign.value(&right).is_err());
        assert_eq!(left.allocation_snapshot().reserved, 0);
        assert_eq!(right.allocation_snapshot().reserved, 0);
        emit(
            "SDK-004",
            label,
            "vm:isolated",
            "reserved=0",
            "registry+package+foreign-root=rejected",
            "globals=1,2|1,2;callbacks=31|42;coroutines=11|22;outputs=11|22",
        );
    }
}

#[test]
fn sdk_case_005() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let mut vm = engine.new_vm().unwrap();
        let table = vm.new_table().unwrap();
        let copied = table.try_clone(&mut vm).unwrap();
        vm.collect().unwrap();
        drop(table);
        assert!(matches!(copied.value(&vm), Ok(Value::Object(_))));
        let callback = vm
            .register_callback(
                &[],
                Rc::new(|_, _| {
                    CallbackResult::Return(vec![Value::Integer(42), Value::Nil, Value::Integer(7)])
                }),
            )
            .unwrap();
        assert_eq!(
            vm.call(&callback, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42), Value::Nil, Value::Integer(7)])
        );
        let throwing = vm
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Throw(Value::Integer(7))),
            )
            .unwrap();
        assert!(matches!(
            vm.call(&throwing, &[]).unwrap().run().unwrap(),
            RunOutcome::LuaError(_)
        ));
        let module = engine.compile(b"return function() return 42 end").unwrap();
        let function_value = returned(&mut vm, &module)[0];
        let function = vm.root(function_value).unwrap();
        let coroutine = vm.new_coroutine(&function).unwrap();
        assert_eq!(
            vm.resume(&coroutine, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(42)])
        );
        let marker = vm.new_table().unwrap();
        let marker_value = marker.value(&vm).unwrap();
        let yielding = vm
            .register_callback(
                &[marker_value],
                Rc::new(|context, _| {
                    context.yield_with(
                        vec![Value::Integer(7)],
                        CallbackContinuation::new(
                            vec![context.capture(0).unwrap()],
                            Rc::new(|context, args| {
                                let mut values = vec![context.capture(0).unwrap()];
                                values.extend_from_slice(args);
                                CallbackResult::Return(values)
                            }),
                        ),
                    )
                }),
            )
            .unwrap();
        vm.set_global(b"host_yield", yielding.value(&vm).unwrap())
            .unwrap();
        let yield_module = engine
            .compile(b"return coroutine.create(function() return host_yield() end)")
            .unwrap();
        let yielding_coroutine_value = returned(&mut vm, &yield_module)[0];
        let yielding_coroutine = vm.root(yielding_coroutine_value).unwrap();
        assert_eq!(
            vm.resume(&yielding_coroutine, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(7)])
        );
        vm.collect().unwrap();
        assert_eq!(
            vm.resume(&yielding_coroutine, &[Value::Nil, Value::Integer(42)])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                marker_value,
                Value::Nil,
                Value::Integer(42)
            ])
        );
        assert_eq!(marker.value(&vm).unwrap(), marker_value);
        let aborted = engine.compile(b"return 10").unwrap();
        let mut execution = vm.load_module(&aborted).unwrap();
        execution.set_fuel(0).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted)
        );
        drop(execution);
        assert_eq!(
            vm.call(&callback, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42), Value::Nil, Value::Integer(7)])
        );
        assert_eq!(vm.allocation_snapshot().reserved, 0);
        emit(
            "SDK-005",
            label,
            "public-api:root+callback+resume",
            "reserved=0",
            "root+gc+error+fuel+nil-gap",
            "yield=7,resume=table|nil|42",
        );
    }
}

#[test]
fn sdk_case_008() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let good = saved(&engine, b"return 42");
        let mut overflow = good.clone();
        overflow[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
        overflow[24..32].copy_from_slice(&1u64.to_le_bytes());
        refresh_crc(&mut overflow);
        let ledger = budget();
        assert_eq!(
            engine.load_module(&overflow, &ledger).unwrap_err().kind,
            ContainerErrorKind::LimitExceeded
        );
        assert_eq!(ledger.allocation_trace().next_ordinal, 1);
        let rvlu_len = u64::from_le_bytes(good[16..24].try_into().unwrap()) as usize;
        let mut opcode = good.clone();
        let rvlu = &good[40..40 + rvlu_len];
        let constants_len = u32::from_le_bytes(rvlu[89..93].try_into().unwrap()) as usize;
        let opcode_at = 40 + 89 + 4 + constants_len + 4 + 4;
        opcode[opcode_at] = 0xff;
        refresh_crc(&mut opcode);
        let error = engine.load_module(&opcode, &budget()).unwrap_err();
        assert_eq!(error.kind, ContainerErrorKind::Payload);
        assert_eq!(
            error.payload_kind,
            Some(rivetlua::TransportErrorKind::InvalidFormat)
        );
        assert_eq!(error.offset, 4);
        let core_opcode = rivetlua_core::decode_module(
            &opcode[40..40 + rvlu_len],
            profile,
            &rivetlua_core::VerifyLimits::default(),
        )
        .unwrap_err();
        assert_eq!(core_opcode.message, "RVLU opcode 無效");
        assert_eq!(core_opcode.offset, opcode_at - 40);
        let mut boundary = good.clone();
        let record_len = u32::from_le_bytes(boundary[72..76].try_into().unwrap());
        boundary[72..76].copy_from_slice(&(record_len + 1).to_le_bytes());
        refresh_crc(&mut boundary);
        let boundary_budget = budget();
        let boundary_error = engine.load_module(&boundary, &boundary_budget).unwrap_err();
        assert_eq!(boundary_error.kind, ContainerErrorKind::Payload);
        assert_eq!(
            boundary_error.payload_kind,
            Some(rivetlua::TransportErrorKind::InvalidFormat)
        );
        assert_eq!(boundary_error.offset, 8);
        let core_boundary = rivetlua_core::decode_module(
            &boundary[40..40 + rvlu_len],
            profile,
            &rivetlua_core::VerifyLimits::default(),
        )
        .unwrap_err();
        assert_eq!(core_boundary.message, "RVLU bytes 截斷");
        assert_eq!(core_boundary.offset, 36);
        assert_eq!(boundary_budget.allocation_snapshot().reserved, 0);
        let multi = saved(
            &engine,
            b"local function nested() return 42 end; return nested()",
        );
        let mut sibling = multi.clone();
        let rvlu_start = 40;
        let first_record_start = 76;
        let first_record_len = u32::from_le_bytes(sibling[72..76].try_into().unwrap());
        let multi_rvlu_len = u64::from_le_bytes(multi[16..24].try_into().unwrap()) as usize;
        let section_len = u32::from_le_bytes(multi[64..68].try_into().unwrap()) as usize;
        let prototype_count = u32::from_le_bytes(multi[68..72].try_into().unwrap());
        assert_eq!(prototype_count, 2);
        let section_end = 68 + section_len;
        assert_eq!(section_end, rvlu_start + multi_rvlu_len);
        let second_record_len_at = first_record_start + first_record_len as usize;
        let second_record_at = second_record_len_at + 4;
        assert!(second_record_at < section_end);
        let second_record_len = u32::from_le_bytes(
            multi[second_record_len_at..second_record_at]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(second_record_at + second_record_len, section_end);
        sibling[72..76].copy_from_slice(&(first_record_len + 4).to_le_bytes());
        refresh_crc(&mut sibling);
        let sibling_budget = budget();
        let sibling_error = engine.load_module(&sibling, &sibling_budget).unwrap_err();
        assert_eq!(sibling_error.kind, ContainerErrorKind::Payload);
        assert_eq!(
            sibling_error.payload_kind,
            Some(rivetlua::TransportErrorKind::InvalidFormat)
        );
        assert_eq!(
            sibling_error.offset,
            second_record_len_at - first_record_start
        );
        let core_sibling = rivetlua_core::decode_module(
            &sibling[rvlu_start..rvlu_start + multi_rvlu_len],
            profile,
            &rivetlua_core::VerifyLimits::default(),
        )
        .unwrap_err();
        assert_eq!(
            core_sibling.message,
            "RVLU prototype record 尾端 bytes 無效"
        );
        assert_eq!(core_sibling.offset, second_record_len_at - rvlu_start);
        assert_eq!(sibling_budget.allocation_snapshot().reserved, 0);
        let baseline = budget();
        engine.load_module(&good, &baseline).unwrap();
        let ordinal_end = baseline.allocation_trace().next_ordinal;
        assert!(ordinal_end > 1);
        for ordinal in 1..ordinal_end {
            let retry = budget();
            retry.fail_once_at_ordinal(ordinal);
            assert_eq!(
                engine.load_module(&good, &retry).unwrap_err().kind,
                ContainerErrorKind::AllocationFailed
            );
            assert_eq!(retry.allocation_snapshot().reserved, 0);
            let restored = engine.load_module(&good, &retry).unwrap();
            assert_eq!(
                returned(&mut engine.new_vm().unwrap(), &restored),
                vec![Value::Integer(42)]
            );
            assert_eq!(retry.allocation_snapshot().reserved, 0);
        }
        emit(
            "SDK-008",
            label,
            "overflow+section-boundary+opcode+injection:retry",
            &format!("ordinals=1..{},reserved=0", ordinal_end - 1),
            &format!(
                "p05-boundary=InvalidFormat@{},p05-opcode=InvalidFormat@{},core-opcode@{},p05-sibling={:?}@{},retry=42",
                boundary_error.offset,
                error.offset,
                core_opcode.offset,
                sibling_error.payload_kind.unwrap(),
                sibling_error.offset
            ),
            "fresh-vm",
        );
    }
}

#[test]
fn sdk_case_neg_001() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let mut payload = saved(&engine, b"return 42");
        payload[44] = 3;
        refresh_crc(&mut payload);
        let ledger = budget();
        let error = engine.load_module(&payload, &ledger).unwrap_err();
        assert_eq!(error.kind, ContainerErrorKind::Payload);
        assert_eq!(
            error.payload_kind,
            Some(rivetlua::TransportErrorKind::InvalidFormat)
        );
        assert_eq!(error.offset, 4);
        assert_eq!(error.detail, "P05 transport verifier 拒絕 payload");
        assert_eq!(ledger.allocation_snapshot().reserved, 0);
        emit(
            "SDK-NEG-001",
            label,
            "payload:delegated",
            "reserved=0",
            "p05-InvalidFormat@4",
            "none",
        );
    }
}

#[test]
fn sdk_case_neg_002() {
    for (_, label) in profiles() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let scratch = std::env::temp_dir().join(format!(
            "rivetlua-p14-private-{}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(scratch.join("src")).unwrap();
        std::fs::write(scratch.join("Cargo.toml"), format!("[package]\nname=\"p14_private_probe\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[dependencies]\nrivetlua={{path=\"{}\"}}\n", root.join("crates/rivetlua").display())).unwrap();
        std::fs::write(
            scratch.join("src/lib.rs"),
            "pub fn unchecked() { let _ = rivetlua::Module { verified: unimplemented!() }; }\n",
        )
        .unwrap();
        let output = Command::new("cargo")
            .args(["check", "--offline", "--quiet"])
            .current_dir(&scratch)
            .env(
                "CARGO_TARGET_DIR",
                std::env::var("CARGO_TARGET_DIR")
                    .unwrap_or_else(|_| root.join("target").display().to_string()),
            )
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "未驗證 Module 竟可公開建構");
        assert!(
            stderr.contains("error[E0451]")
                && stderr.contains("field `verified` of struct `Module` is private"),
            "預期 E0451 欄位私有診斷：{stderr}"
        );
        std::fs::remove_dir_all(scratch).unwrap();
        emit(
            "SDK-NEG-002",
            label,
            "private-module:compile-rejected",
            "none",
            "rustc=privacy",
            "none",
        );
    }
}

#[test]
fn sdk_case_neg_003() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let module = engine
            .compile(b"local captured=runtime_secret; return function() return captured end")
            .unwrap();
        let mut first = engine.new_vm().unwrap();
        first
            .set_global(b"runtime_secret", Value::Integer(91))
            .unwrap();
        let captured = returned(&mut first, &module)[0];
        let captured = first.root(captured).unwrap();
        assert_eq!(
            first.call(&captured, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(91)])
        );
        let bytes = engine.save_module(&module, &budget()).unwrap();
        let restarted = Engine::new(profile);
        let restored = restarted.load_module(&bytes, &budget()).unwrap();
        let mut fresh = restarted.new_vm().unwrap();
        let fresh_function = returned(&mut fresh, &restored)[0];
        let fresh_function = fresh.root(fresh_function).unwrap();
        assert_eq!(
            fresh.call(&fresh_function, &[]).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Nil])
        );

        let privileged_output = Rc::new(RefCell::new(Vec::new()));
        let mut privileged = engine
            .new_vm_with_services(HostServices::with_output(CapturedOutput(Rc::clone(
                &privileged_output,
            ))))
            .unwrap();
        let print_module = engine.compile(b"print('authorized')").unwrap();
        assert_eq!(
            privileged
                .load_module(&print_module)
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![])
        );
        assert_eq!(&*privileged_output.borrow(), b"authorized\n");
        let print_bytes = engine.save_module(&print_module, &budget()).unwrap();
        let restored_print = restarted.load_module(&print_bytes, &budget()).unwrap();
        assert!(matches!(
            fresh.load_module(&restored_print).unwrap().run().unwrap(),
            RunOutcome::LuaError(_)
        ));
        assert_eq!(&*privileged_output.borrow(), b"authorized\n");

        let callback_module = engine.compile(b"return host_callback()").unwrap();
        let callback = privileged
            .register_callback(
                &[],
                Rc::new(|_, _| CallbackResult::Return(vec![Value::Integer(17)])),
            )
            .unwrap();
        privileged
            .set_global(b"host_callback", callback.value(&privileged).unwrap())
            .unwrap();
        assert_eq!(
            privileged
                .load_module(&callback_module)
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(17)])
        );
        let callback_bytes = engine.save_module(&callback_module, &budget()).unwrap();
        let restored_callback = restarted.load_module(&callback_bytes, &budget()).unwrap();
        assert!(matches!(
            fresh
                .load_module(&restored_callback)
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::LuaError(_)
        ));
        assert_eq!(fresh.allocation_snapshot().reserved, 0);
        emit(
            "SDK-NEG-003",
            label,
            "runtime:absent-after-restart",
            "reserved=0",
            "closure-capture=nil,output-denied,callback-absent",
            "fresh-vm",
        );
    }
}

#[test]
fn sdk_case_neg_004() {
    for (profile, label) in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(b"return 42").unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        let object = first.new_table().unwrap();
        assert!(matches!(object.value(&second), Err(SdkError::RuntimeVm(_))));
        assert!(
            second
                .set_global(b"foreign", object.value(&first).unwrap())
                .is_err()
        );
        assert_eq!(returned(&mut first, &module), vec![Value::Integer(42)]);
        assert_eq!(returned(&mut second, &module), vec![Value::Integer(42)]);
        assert_eq!(first.allocation_snapshot().reserved, 0);
        assert_eq!(second.allocation_snapshot().reserved, 0);
        emit(
            "SDK-NEG-004",
            label,
            "cross-vm:rejected",
            "reserved=0",
            "foreign-root=rejected",
            "both-retry=42",
        );
    }
}
