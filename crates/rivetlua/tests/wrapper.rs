use rivetlua::{
    ContainerErrorKind, ContainerLimits, Engine, LuaProfile, ModuleOrigin, RunOutcome,
    TransportBudget, TransportLimits, Value, Vm,
};
use rivetlua_core::{
    OfficialChunkLimits, OfficialWorkBudget, decode_official_chunk, encode_module,
    encode_transport_module, preflight_transport_decode, translate_official_chunk,
    transport_scan_admission, verify_module,
};
use rivetlua_runtime::{HostHandle, HostServices, ObjectKind, Vm as CoreVm};

fn profiles() -> [LuaProfile; 2] {
    [LuaProfile::Lua54, LuaProfile::Lua55]
}

fn crc32_parts(parts: &[&[u8]]) -> u32 {
    let mut crc = 0xffff_ffffu32;
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

fn budget(limits: ContainerLimits) -> TransportBudget {
    TransportBudget::new(limits)
}

fn core_vm_with_sdk_standard_library(profile: LuaProfile) -> (CoreVm, HostHandle<Value>) {
    let mut vm = CoreVm::new_with_services(profile, HostServices::deny_all()).unwrap();
    let globals = vm.allocate_table().unwrap();
    let globals_root = HostHandle::<Value>::new(&mut vm, globals).unwrap();
    vm.install_error_builtins(globals).unwrap();
    vm.install_basic_builtins(globals).unwrap();
    vm.install_coroutine_builtins(globals).unwrap();
    vm.install_string_builtins(globals).unwrap();
    vm.install_table_builtins(globals).unwrap();
    vm.install_math_builtins(globals).unwrap();
    vm.install_utf8_builtins(globals).unwrap();
    vm.install_package_builtins(globals).unwrap();
    vm.install_io_os_builtins(globals).unwrap();
    vm.install_debug_builtins(globals).unwrap();
    (vm, globals_root)
}

fn run_core_with_sdk_environment(
    vm: &mut CoreVm,
    globals: &HostHandle<Value>,
    verified: rivetlua_core::VerifiedModule,
) -> RunOutcome {
    let environment = globals.as_value(vm).unwrap();
    vm.load_with_environment(verified, environment)
        .unwrap()
        .run()
        .unwrap()
}

fn outer_container(rvlu: &[u8], sidecar: &[u8]) -> Vec<u8> {
    let total = 40 + rvlu.len() + sidecar.len();
    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(b"RVCT");
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(total as u64).to_le_bytes());
    bytes.extend_from_slice(&(rvlu.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&(sidecar.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(&[0; 4]);
    bytes.extend_from_slice(rvlu);
    bytes.extend_from_slice(sidecar);
    let crc = crc32_parts(&[&bytes[..32], &bytes[36..]]);
    bytes[32..36].copy_from_slice(&crc.to_le_bytes());
    bytes
}

fn refresh_outer_crc(bytes: &mut [u8]) {
    let crc = crc32_parts(&[&bytes[..32], &bytes[36..]]);
    bytes[32..36].copy_from_slice(&crc.to_le_bytes());
}

fn first_rvlu_opcode_offset(rvlu: &[u8]) -> usize {
    let constants_len_at = 36 + 53;
    let constants_count_at = constants_len_at + 4;
    let constants_len = u32::from_le_bytes(
        rvlu[constants_len_at..constants_len_at + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let instructions_len_at = constants_count_at + 4 + constants_len;
    let instructions_count_at = instructions_len_at + 4;
    instructions_count_at + 4
}

fn official_fixture(profile: LuaProfile, name: &str) -> &'static [u8] {
    match (profile, name) {
        (LuaProfile::Lua54, "debug") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac")
        }
        (LuaProfile::Lua54, "strip") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-strip.luac")
        }
        (LuaProfile::Lua54, "closure") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua54-closure.luac")
        }
        (LuaProfile::Lua55, "debug") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac")
        }
        (LuaProfile::Lua55, "strip") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-strip.luac")
        }
        (LuaProfile::Lua55, "closure") => {
            include_bytes!("../../rivetlua-core/tests/official_chunk_fixtures/lua55-closure.luac")
        }
        (LuaProfile::Lua55, "helpers") => {
            include_bytes!(
                "../../rivetlua-core/tests/official_chunk_fixtures/lua55-many-helpers.luac"
            )
        }
        _ => panic!("沒有這個受測官方 fixture"),
    }
}

fn p05_transport(profile: LuaProfile, bytes: &[u8]) -> (rivetlua_core::VerifiedModule, Vec<u8>) {
    let limits = TransportLimits::default();
    let chunk = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
    let verified = translate_official_chunk(&chunk, &limits.verify)
        .unwrap()
        .verified()
        .clone();
    let encoded = encode_transport_module(
        &verified,
        &limits,
        &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
    )
    .unwrap();
    let (rvlu, sidecar) = encoded.into_parts();
    (verified, outer_container(&rvlu, &sidecar))
}

fn p05_native_without_debug_transport(
    profile: LuaProfile,
    bytes: &[u8],
) -> (rivetlua_core::VerifiedModule, Vec<u8>) {
    let limits = TransportLimits::default();
    let chunk = decode_official_chunk(bytes, profile, &OfficialChunkLimits::default()).unwrap();
    let official = translate_official_chunk(&chunk, &limits.verify)
        .unwrap()
        .verified()
        .clone();
    let native = verify_module(official.module().clone(), profile, &limits.verify).unwrap();
    assert!(native.native_debug().is_none());
    let encoded = encode_transport_module(
        &native,
        &limits,
        &mut OfficialWorkBudget::for_limits(&limits.verify).unwrap(),
    )
    .unwrap();
    let (rvlu, sidecar) = encoded.into_parts();
    (native, outer_container(&rvlu, &sidecar))
}

fn assert_sdk_value_matches_core(sdk_vm: &mut Vm, core_vm: &CoreVm, sdk: Value, core: Value) {
    match (sdk, core) {
        (Value::Nil, Value::Nil) => {}
        (Value::Boolean(left), Value::Boolean(right)) => assert_eq!(left, right),
        (Value::Integer(left), Value::Integer(right)) => assert_eq!(left, right),
        (Value::Float(left), Value::Float(right)) => assert_eq!(left.to_bits(), right.to_bits()),
        (Value::Object(sdk_object), Value::Object(core_object)) => {
            let core_kind = core_vm.object_kind(core_object).unwrap();
            assert_eq!(core_kind, ObjectKind::ByteString);
            let expected = core_vm
                .with_byte_string(core_object, |text| text.as_bytes().to_vec())
                .unwrap();
            let root = sdk_vm.root(Value::Object(sdk_object)).unwrap();
            assert_eq!(sdk_vm.read_byte_string(&root).unwrap(), expected);
        }
        (sdk, core) => panic!("SDK value {sdk:?} 與 P05 value {core:?} 不同"),
    }
}

fn assert_sdk_error_value_matches_core(sdk_vm: &mut Vm, core_vm: &CoreVm, sdk: Value, core: Value) {
    match (sdk, core) {
        (Value::Object(sdk_object), Value::Object(core_object)) => {
            let root = sdk_vm.root(Value::Object(sdk_object)).unwrap();
            if core_vm.object_kind(core_object).unwrap() == ObjectKind::ByteString {
                let expected = core_vm
                    .with_byte_string(core_object, |text| text.as_bytes().to_vec())
                    .unwrap();
                assert_eq!(sdk_vm.read_byte_string(&root).unwrap(), expected);
            } else {
                // 非字串錯誤值的物件身分是 VM-local；error.kind 已精確核對 operand kind。
                assert!(sdk_vm.read_byte_string(&root).is_err());
            }
        }
        (sdk, core) => assert_sdk_value_matches_core(sdk_vm, core_vm, sdk, core),
    }
}

#[derive(Clone, Copy)]
enum ReturnedClosureCheck {
    SeededNumeric,
    DebugCapture,
}

fn assert_sdk_outcome_matches_core(
    sdk_vm: &mut Vm,
    sdk: RunOutcome,
    core_vm: &mut CoreVm,
    core: RunOutcome,
    closure_check: Option<ReturnedClosureCheck>,
) {
    match (sdk, core) {
        (RunOutcome::Returned(sdk_values), RunOutcome::Returned(core_values)) => {
            assert_eq!(sdk_values.len(), core_values.len());
            for (sdk_value, core_value) in sdk_values.into_iter().zip(core_values) {
                if let (Value::Object(sdk_object), Value::Object(core_object)) =
                    (sdk_value, core_value)
                    && core_vm.object_kind(core_object).unwrap() == ObjectKind::Closure
                {
                    let check = closure_check.expect("fixture 回傳 closure 時需指定語意呼叫");
                    let sdk_function = sdk_vm.root(Value::Object(sdk_object)).unwrap();
                    let core_function = HostHandle::<Value>::new(core_vm, core_object).unwrap();
                    let (sdk_args, core_args) = match check {
                        ReturnedClosureCheck::SeededNumeric => {
                            (vec![Value::Integer(35)], vec![Value::Integer(35)])
                        }
                        ReturnedClosureCheck::DebugCapture => (
                            vec![Value::Boolean(true), Value::Integer(9)],
                            vec![Value::Boolean(true), Value::Integer(9)],
                        ),
                    };
                    let sdk_result = sdk_vm
                        .call(&sdk_function, &sdk_args)
                        .unwrap()
                        .run()
                        .unwrap();
                    let core_function_value = core_function.as_value(core_vm).unwrap();
                    let core_result = core_vm
                        .call(core_function_value, &core_args)
                        .unwrap()
                        .run()
                        .unwrap();
                    assert_sdk_outcome_matches_core(sdk_vm, sdk_result, core_vm, core_result, None);
                } else {
                    assert_sdk_value_matches_core(sdk_vm, core_vm, sdk_value, core_value);
                }
            }
        }
        (RunOutcome::LuaError(sdk_error), RunOutcome::LuaError(core_error)) => {
            assert_eq!(sdk_error.kind, core_error.kind);
            assert_eq!(sdk_error.diagnostic_id, core_error.diagnostic_id);
            assert_eq!(sdk_error.source_pc, core_error.source_pc);
            assert_eq!(sdk_error.source_prototype, core_error.source_prototype);
            assert_eq!(sdk_error.source_depth, core_error.source_depth);
            assert_sdk_error_value_matches_core(sdk_vm, core_vm, sdk_error.value, core_error.value);
        }
        (RunOutcome::Aborted(sdk_reason), RunOutcome::Aborted(core_reason)) => {
            assert_eq!(sdk_reason, core_reason);
        }
        (RunOutcome::PendingClose(sdk_snapshot), RunOutcome::PendingClose(core_snapshot)) => {
            assert_eq!(sdk_snapshot, core_snapshot);
        }
        (sdk, core) => panic!("SDK outcome={sdk:?}; P05 outcome={core:?}"),
    }
}

fn outcome_summary(outcome: &RunOutcome) -> String {
    match outcome {
        RunOutcome::Returned(values) => format!("Returned({} values)", values.len()),
        RunOutcome::LuaError(error) => format!(
            "LuaError({}, {:?}, pc={:?}, proto={:?}, depth={:?})",
            error.diagnostic_id,
            error.kind,
            error.source_pc,
            error.source_prototype,
            error.source_depth
        ),
        RunOutcome::Aborted(reason) => format!("Aborted({reason:?})"),
        RunOutcome::PendingClose(snapshot) => format!("PendingClose({snapshot:?})"),
        outcome @ (RunOutcome::External(_)
        | RunOutcome::CloseBoundaryA5 { .. }
        | RunOutcome::NestedReturned(_)
        | RunOutcome::NestedErrored(_)
        | RunOutcome::NestedFailed(_)) => format!("{outcome:?}"),
    }
}

#[test]
fn sdk_wrapper_encode_emits_rvct_v1_for_both_profiles() {
    assert_eq!(crc32_parts(&[b"123456789"]), 0xcbf4_3926);

    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine
            .compile_named(b"\nreturn 42\n", b"=wrapper-named-source")
            .unwrap();
        let bytes = engine
            .save_module(&module, &budget(ContainerLimits::default()))
            .unwrap();

        assert_eq!(&bytes[0..4], b"RVCT");
        assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 1);
        assert_eq!(u16::from_le_bytes(bytes[6..8].try_into().unwrap()), 0);
        assert_eq!(
            u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            bytes.len() as u64
        );
        let rvlu_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
        let sidecar_len = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
        assert_eq!(40 + rvlu_len + sidecar_len, bytes.len());
        assert_eq!(&bytes[36..40], &[0; 4]);

        let expected_crc = crc32_parts(&[&bytes[..32], &bytes[36..40], &bytes[40..]]);
        assert_eq!(
            u32::from_le_bytes(bytes[32..36].try_into().unwrap()),
            expected_crc
        );

        let mut reserved_change = bytes.clone();
        reserved_change[36] ^= 1;
        assert_ne!(
            expected_crc,
            crc32_parts(&[
                &reserved_change[..32],
                &reserved_change[36..40],
                &reserved_change[40..],
            ])
        );
        let mut payload_change = bytes.clone();
        payload_change[40] ^= 1;
        assert_ne!(
            expected_crc,
            crc32_parts(&[
                &payload_change[..32],
                &payload_change[36..40],
                &payload_change[40..],
            ])
        );
    }
}

#[test]
fn sdk_wrapper_encode_obeys_container_and_work_limits_before_reservation() {
    let engine = Engine::new(LuaProfile::Lua55);
    let module = engine.compile(b"return 1").unwrap();
    let encoded = engine
        .save_module(&module, &budget(ContainerLimits::default()))
        .unwrap();

    let enough = ContainerLimits {
        max_container_bytes: encoded.len() * 4,
        ..ContainerLimits::default()
    };
    assert_eq!(
        engine.save_module(&module, &budget(enough)).unwrap(),
        encoded
    );

    let too_small = ContainerLimits {
        max_container_bytes: 40,
        ..ContainerLimits::default()
    };
    let denied = budget(too_small);
    assert!(engine.save_module(&module, &denied).is_err());
    assert_eq!(denied.allocation_trace().next_ordinal, 1);
    assert_eq!(denied.allocation_snapshot().reserved, 0);

    let no_work = ContainerLimits {
        max_work: 0,
        ..ContainerLimits::default()
    };
    let denied = budget(no_work);
    assert!(engine.save_module(&module, &denied).is_err());
    assert_eq!(denied.allocation_trace().next_ordinal, 1);
    assert_eq!(denied.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_wrapper_encode_allocation_failure_releases_reservation_and_can_retry() {
    let engine = Engine::new(LuaProfile::Lua54);
    let module = engine.compile(b"return 99").unwrap();
    let budget = budget(ContainerLimits::default());
    let next = budget.allocation_trace().next_ordinal;
    budget.fail_once_at_ordinal(next);

    assert!(engine.save_module(&module, &budget).is_err());
    assert_eq!(budget.allocation_snapshot().reserved, 0);
    assert_eq!(budget.allocation_trace().next_ordinal, next + 1);
    assert!(!engine.save_module(&module, &budget).unwrap().is_empty());
    assert_eq!(budget.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_wrapper_test_only_diagnoses_chained_and_nested_closure_calls() {
    let sources: &[(&str, &[u8])] = &[
        (
            "chained-call",
            b"local function make(n) return function(x, ...) return n + x, ... end end\nreturn make(40)(2, 'left', 'right')\n",
        ),
        (
            "callback-packed-inner-closure",
            b"local function make(n)\n  local captured = 'saved'\n  return function(x, ...)\n    local inner = function() return n, captured end\n    local a, b = inner()\n    collectgarbage('collect')\n    return a + x, b, select('#', ...), ...\n  end\nend\nlocal callback = make(40)\nlocal packed = {callback(2, 'left', 'right')}\npacked.n = #packed\nreturn packed\n",
        ),
    ];

    for profile in profiles() {
        for (name, source) in sources {
            let (bytes, original_summary) = {
                let engine = Engine::new(profile);
                let module = engine
                    .compile_named(source, format!("=wrapper-{name}").as_bytes())
                    .unwrap();
                let mut original_vm = engine.new_vm().unwrap();
                let original_outcome = original_vm.load_module(&module).unwrap().run().unwrap();
                let original_summary = outcome_summary(&original_outcome);
                let bytes = engine
                    .save_module(&module, &budget(ContainerLimits::default()))
                    .unwrap();
                (bytes, original_summary)
            };

            let engine = Engine::new(profile);
            let module = engine
                .load_module(&bytes, &budget(ContainerLimits::default()))
                .unwrap();
            assert_eq!(module.profile(), profile);
            assert_eq!(module.origin(), ModuleOrigin::NativeRvlu);
            assert_eq!(
                module.source_name(),
                Some(format!("=wrapper-{name}").as_bytes())
            );

            let mut vm = engine.new_vm().unwrap();
            let decoded_outcome = vm.load_module(&module).unwrap().run().unwrap();
            let decoded_summary = outcome_summary(&decoded_outcome);
            eprintln!(
                "{profile:?} {name}: compile=PASS, original={original_summary}, wrapper={decoded_summary}"
            );
            assert_eq!(decoded_summary, original_summary);
        }
    }
}

#[test]
fn sdk_wrapper_native_nested_closure_and_final_constructor_return_five_values() {
    let make = "local function make(n)\n  local saved='saved'\n  return function(x,...)\n    local inner=function() return n,saved end\n    local a,b=inner()\n    return a+x,b,select('#',...),...\n  end\nend\n";
    for profile in profiles() {
        for packed in [false, true] {
            let source = if packed {
                format!("{make}local callback=make(40)\nreturn {{callback(2,'left','right')}}\n")
            } else {
                format!("{make}return make(40)(2,'left','right')\n")
            };
            let engine = Engine::new(profile);
            let original = engine
                .compile_named(source.as_bytes(), b"=wrapper-native-nested")
                .unwrap();
            let bytes = engine
                .save_module(&original, &budget(ContainerLimits::default()))
                .unwrap();
            let restored = engine
                .load_module(&bytes, &budget(ContainerLimits::default()))
                .unwrap();
            for module in [&original, &restored] {
                let mut vm = engine.new_vm().unwrap();
                vm.collect().unwrap();
                let outcome = vm.load_module(module).unwrap().run().unwrap();
                let RunOutcome::Returned(values) = outcome else {
                    panic!("native nested closure 須成功返回：{outcome:?}")
                };
                let values = if packed {
                    assert_eq!(values.len(), 1);
                    let table = vm.root(values[0]).unwrap();
                    vm.collect().unwrap();
                    (1..=5)
                        .map(|index| vm.table_raw_get(&table, Value::Integer(index)).unwrap())
                        .collect::<Vec<_>>()
                } else {
                    values
                };
                assert_eq!(values.len(), 5);
                assert_eq!(values[0], Value::Integer(42));
                assert_eq!(values[2], Value::Integer(2));
                let saved = vm.root(values[1]).unwrap();
                let left = vm.root(values[3]).unwrap();
                let right = vm.root(values[4]).unwrap();
                vm.collect().unwrap();
                assert_eq!(vm.read_byte_string(&saved).unwrap(), b"saved");
                assert_eq!(vm.read_byte_string(&left).unwrap(), b"left");
                assert_eq!(vm.read_byte_string(&right).unwrap(), b"right");
                assert_eq!(vm.allocation_snapshot().reserved, 0);
            }
        }
    }
}

#[test]
fn sdk_wrapper_decodes_official_debug_strip_closure_and_helper_sidecars() {
    for (profile, name) in [
        (LuaProfile::Lua54, "debug"),
        (LuaProfile::Lua54, "strip"),
        (LuaProfile::Lua54, "closure"),
        (LuaProfile::Lua55, "debug"),
        (LuaProfile::Lua55, "strip"),
        (LuaProfile::Lua55, "closure"),
        (LuaProfile::Lua55, "helpers"),
    ] {
        let (verified, bytes) = p05_transport(profile, official_fixture(profile, name));
        let engine = Engine::new(profile);
        let module = engine
            .load_module(&bytes, &budget(ContainerLimits::default()))
            .unwrap();
        let expected_source = verified
            .official_artifact()
            .unwrap()
            .effective_source(rivetlua_core::ProtoId(0));
        let expected_lines = verified
            .official_artifact()
            .unwrap()
            .prototype(rivetlua_core::ProtoId(0))
            .map(|proto| (proto.line_defined, proto.last_line_defined));
        assert_eq!(module.origin(), ModuleOrigin::OfficialImport);
        assert_eq!(module.source_name(), expected_source);
        assert_eq!(module.main_line_range(), expected_lines);

        let mut vm = engine.new_vm().unwrap();
        let (mut core_vm, core_globals) = core_vm_with_sdk_standard_library(profile);
        let core_outcome =
            run_core_with_sdk_environment(&mut core_vm, &core_globals, verified.clone());
        let sdk_outcome = vm.load_module(&module).unwrap().run().unwrap();
        let closure_check = match name {
            "debug" | "strip" => Some(ReturnedClosureCheck::DebugCapture),
            "closure" => Some(ReturnedClosureCheck::SeededNumeric),
            _ => None,
        };
        assert_sdk_outcome_matches_core(
            &mut vm,
            sdk_outcome,
            &mut core_vm,
            core_outcome,
            closure_check,
        );
    }

    for profile in profiles() {
        let (verified, bytes) =
            p05_native_without_debug_transport(profile, official_fixture(profile, "debug"));
        let engine = Engine::new(profile);
        let module = engine
            .load_module(&bytes, &budget(ContainerLimits::default()))
            .unwrap();
        assert_eq!(verified.origin(), ModuleOrigin::NativeRvlu);
        assert_eq!(module.origin(), ModuleOrigin::NativeRvlu);
        assert_eq!(module.source_name(), None);
        assert_eq!(module.main_line_range(), None);
        let mut vm = engine.new_vm().unwrap();
        let (mut core_vm, core_globals) = core_vm_with_sdk_standard_library(profile);
        let core_outcome = run_core_with_sdk_environment(&mut core_vm, &core_globals, verified);
        let sdk_outcome = vm.load_module(&module).unwrap().run().unwrap();
        assert_sdk_outcome_matches_core(
            &mut vm,
            sdk_outcome,
            &mut core_vm,
            core_outcome,
            Some(ReturnedClosureCheck::DebugCapture),
        );
    }
}

#[test]
fn sdk_wrapper_rejects_outer_errors_and_integrity_before_any_ledger_reservation() {
    let engine = Engine::new(LuaProfile::Lua55);
    let module = engine.compile(b"return 7").unwrap();
    let good = engine
        .save_module(&module, &budget(ContainerLimits::default()))
        .unwrap();
    let mut cases: Vec<(Vec<u8>, ContainerErrorKind)> = Vec::new();

    let mut bad = good.clone();
    bad[0] = b'X';
    cases.push((bad, ContainerErrorKind::InvalidFormat));
    let mut bad = good.clone();
    bad[4] = 2;
    cases.push((bad, ContainerErrorKind::UnsupportedVersion));
    let mut bad = good.clone();
    bad[6] = 1;
    cases.push((bad, ContainerErrorKind::InvalidFormat));
    let mut bad = good.clone();
    bad[36] = 1;
    cases.push((bad, ContainerErrorKind::InvalidFormat));
    let mut bad = good.clone();
    bad[8..16].copy_from_slice(&((good.len() as u64) + 1).to_le_bytes());
    refresh_outer_crc(&mut bad);
    cases.push((bad, ContainerErrorKind::InvalidFormat));
    let mut bad = good.clone();
    bad[16..24].copy_from_slice(&u64::MAX.to_le_bytes());
    bad[24..32].copy_from_slice(&1u64.to_le_bytes());
    refresh_outer_crc(&mut bad);
    cases.push((bad, ContainerErrorKind::LimitExceeded));
    let mut bad = good.clone();
    bad[40] ^= 1;
    cases.push((bad, ContainerErrorKind::IntegrityMismatch));
    cases.push((
        good[..good.len() - 1].to_vec(),
        ContainerErrorKind::InvalidFormat,
    ));

    for (bytes, kind) in cases {
        let budget = budget(ContainerLimits::default());
        let error = engine.load_module(&bytes, &budget).unwrap_err();
        assert_eq!(error.kind, kind);
        assert_eq!(budget.allocation_trace().next_ordinal, 1);
        assert_eq!(budget.allocation_snapshot().reserved, 0);
    }

    let too_small = ContainerLimits {
        max_container_bytes: good.len() - 1,
        ..ContainerLimits::default()
    };
    let limited_budget = budget(too_small);
    assert_eq!(
        engine.load_module(&good, &limited_budget).unwrap_err().kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(limited_budget.allocation_trace().next_ordinal, 1);
    assert_eq!(limited_budget.allocation_snapshot().reserved, 0);

    let mut no_rvlu = ContainerLimits::default();
    no_rvlu.transport.verify.max_module_bytes = 0;
    let limited_budget = budget(no_rvlu);
    assert_eq!(
        engine.load_module(&good, &limited_budget).unwrap_err().kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(limited_budget.allocation_trace().next_ordinal, 1);

    let sidecar_len = u64::from_le_bytes(good[24..32].try_into().unwrap()) as usize;
    assert!(sidecar_len > 0);
    let no_sidecar = ContainerLimits {
        transport: TransportLimits {
            max_sidecar_bytes: sidecar_len - 1,
            ..TransportLimits::default()
        },
        ..ContainerLimits::default()
    };
    let limited_budget = budget(no_sidecar);
    assert_eq!(
        engine.load_module(&good, &limited_budget).unwrap_err().kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(limited_budget.allocation_trace().next_ordinal, 1);

    let no_checksum_work = ContainerLimits {
        max_work: good.len() as u64 - 1,
        ..ContainerLimits::default()
    };
    let limited_budget = budget(no_checksum_work);
    assert_eq!(
        engine.load_module(&good, &limited_budget).unwrap_err().kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(limited_budget.allocation_trace().next_ordinal, 1);
    assert_eq!(limited_budget.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_wrapper_decode_allocation_failure_releases_escrow_and_can_retry() {
    let engine = Engine::new(LuaProfile::Lua54);
    let original = engine.compile(b"return 55").unwrap();
    let bytes = engine
        .save_module(&original, &budget(ContainerLimits::default()))
        .unwrap();
    let budget = budget(ContainerLimits::default());
    let next = budget.allocation_trace().next_ordinal;
    budget.fail_once_at_ordinal(next);

    assert_eq!(
        engine.load_module(&bytes, &budget).unwrap_err().kind,
        ContainerErrorKind::AllocationFailed
    );
    assert_eq!(budget.allocation_snapshot().reserved, 0);
    assert_eq!(budget.allocation_trace().next_ordinal, next + 1);
    let loaded = engine.load_module(&bytes, &budget).unwrap();
    let mut vm = engine.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&loaded).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(55)])
    );
    assert_eq!(budget.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_wrapper_decode_container_allocation_and_work_limits_accept_exact_and_reject_one_below() {
    let profile = LuaProfile::Lua55;
    let engine = Engine::new(profile);
    let module = engine.compile_named(b"return 44", b"=exact-work").unwrap();
    let bytes = engine
        .save_module(&module, &budget(ContainerLimits::default()))
        .unwrap();

    let baseline = budget(ContainerLimits::default());
    engine.load_module(&bytes, &baseline).unwrap();
    let allocation_exact = baseline
        .allocation_trace()
        .last_attempt
        .expect("成功 decode 應有一次 escrow")
        .bytes;

    let rvlu_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap()) as usize;
    let sidecar_len = u64::from_le_bytes(bytes[24..32].try_into().unwrap()) as usize;
    let rvlu = &bytes[40..40 + rvlu_len];
    let sidecar = &bytes[40 + rvlu_len..40 + rvlu_len + sidecar_len];
    let transport_limits = TransportLimits::default();
    let scan = transport_scan_admission(rvlu.len(), sidecar.len()).unwrap();
    let admission = preflight_transport_decode(rvlu, sidecar, profile, &transport_limits).unwrap();
    let exact_work =
        40u64 + (bytes.len() as u64) * 8 + scan.work + scan.work + admission.subsequent_work + 1;

    let exact = ContainerLimits {
        max_container_bytes: bytes.len(),
        max_allocation_bytes: allocation_exact,
        max_work: exact_work,
        ..ContainerLimits::default()
    };
    let exact_budget = budget(exact);
    assert_eq!(
        engine
            .load_module(&bytes, &exact_budget)
            .unwrap()
            .source_name(),
        Some(b"=exact-work".as_slice())
    );

    let one_below_bytes = ContainerLimits {
        max_container_bytes: bytes.len() - 1,
        ..ContainerLimits::default()
    };
    let one_below_bytes_budget = budget(one_below_bytes);
    assert_eq!(
        engine
            .load_module(&bytes, &one_below_bytes_budget)
            .unwrap_err()
            .kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(one_below_bytes_budget.allocation_trace().next_ordinal, 1);

    let one_below_memory = ContainerLimits {
        max_allocation_bytes: allocation_exact - 1,
        ..ContainerLimits::default()
    };
    let one_below_memory_budget = budget(one_below_memory);
    assert_eq!(
        engine
            .load_module(&bytes, &one_below_memory_budget)
            .unwrap_err()
            .kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(one_below_memory_budget.allocation_trace().next_ordinal, 1);

    let one_below_work = ContainerLimits {
        max_work: exact_work - 1,
        ..ContainerLimits::default()
    };
    let one_below_work_budget = budget(one_below_work);
    assert_eq!(
        engine
            .load_module(&bytes, &one_below_work_budget)
            .unwrap_err()
            .kind,
        ContainerErrorKind::LimitExceeded
    );
    assert_eq!(one_below_work_budget.allocation_trace().next_ordinal, 1);
}

#[test]
fn sdk_wrapper_delegates_valid_crc_payload_errors_to_p05_and_keeps_vm_usable() {
    let profile = LuaProfile::Lua55;
    let (official, good) = p05_transport(profile, official_fixture(profile, "debug"));
    let engine = Engine::new(profile);

    let mut cases = Vec::new();
    let mut bad_version = good.clone();
    bad_version[44..46].copy_from_slice(&3u16.to_le_bytes());
    refresh_outer_crc(&mut bad_version);
    cases.push(bad_version);
    let mut bad_numeric = good.clone();
    bad_numeric[47] = 2;
    refresh_outer_crc(&mut bad_numeric);
    cases.push(bad_numeric);
    let mut bad_rvlu = good.clone();
    bad_rvlu[40] ^= 1;
    refresh_outer_crc(&mut bad_rvlu);
    cases.push(bad_rvlu);
    let mut bad_opcode = good.clone();
    let rvlu_len = u64::from_le_bytes(good[16..24].try_into().unwrap()) as usize;
    let opcode_at = first_rvlu_opcode_offset(&good[40..40 + rvlu_len]);
    bad_opcode[40 + opcode_at] = 0xff;
    refresh_outer_crc(&mut bad_opcode);
    cases.push(bad_opcode);
    let mut bad_sidecar = good.clone();
    let rvlu_len = u64::from_le_bytes(good[16..24].try_into().unwrap()) as usize;
    bad_sidecar[40 + rvlu_len + 16] ^= 1;
    refresh_outer_crc(&mut bad_sidecar);
    cases.push(bad_sidecar);

    for bytes in cases {
        let budget = budget(ContainerLimits::default());
        let error = engine.load_module(&bytes, &budget).unwrap_err();
        assert_eq!(error.kind, ContainerErrorKind::Payload);
        assert!(error.payload_kind.is_some());
        assert_eq!(budget.allocation_snapshot().reserved, 0);
    }

    let wrong_profile = Engine::new(LuaProfile::Lua54);
    assert_eq!(
        wrong_profile
            .load_module(&good, &budget(ContainerLimits::default()))
            .unwrap_err()
            .kind,
        ContainerErrorKind::Payload
    );

    let mut splice = official.module().clone();
    splice.span.end_byte += 1;
    let alien = encode_module(splice, profile, &TransportLimits::default().verify).unwrap();
    let p05_limits = TransportLimits::default();
    let encoded = encode_transport_module(
        &official,
        &p05_limits,
        &mut OfficialWorkBudget::for_limits(&p05_limits.verify).unwrap(),
    )
    .unwrap();
    let spliced = outer_container(alien.bytes(), encoded.sidecar());
    let splice_budget = budget(ContainerLimits::default());
    assert_eq!(
        engine
            .load_module(&spliced, &splice_budget)
            .unwrap_err()
            .kind,
        ContainerErrorKind::Payload
    );
    assert_eq!(splice_budget.allocation_snapshot().reserved, 0);

    let good_native = engine.compile(b"return 123").unwrap();
    let mut vm = engine.new_vm().unwrap();
    assert!(
        engine
            .load_module(
                &casesafe_invalid_bytes(),
                &budget(ContainerLimits::default())
            )
            .is_err()
    );
    assert_eq!(
        vm.load_module(&good_native).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(123)])
    );
}

fn casesafe_invalid_bytes() -> Vec<u8> {
    let engine = Engine::new(LuaProfile::Lua55);
    let module = engine.compile(b"return 8").unwrap();
    let mut bytes = engine
        .save_module(&module, &budget(ContainerLimits::default()))
        .unwrap();
    bytes[40] ^= 0x80;
    refresh_outer_crc(&mut bytes);
    bytes
}
