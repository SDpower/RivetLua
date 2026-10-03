use std::cell::Cell;
use std::rc::Rc;

use rivetlua::{
    AbortReason, CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits, CompileError,
    ContainerErrorKind, ContainerLimits, Engine, HostLoadError, HostLoadErrorKind, HostServices,
    HostSourceReader, InputErrorKind, InputFormat, LoadCapability, LoadLimits, LuaProfile,
    ModuleOrigin, RunOutcome, SdkError, TransportBudget, TransportLimits, Value, VmError,
};
use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{
    InputFormat as CoreInputFormat, IrLimits, VerifyLimits, classify_input, input_scan_admission,
    preflight_input_module,
};
use rivetlua_runtime::{RuntimeErrorKind, Vm as CoreVm};

fn profiles() -> [LuaProfile; 2] {
    [LuaProfile::Lua54, LuaProfile::Lua55]
}

fn transport_budget() -> TransportBudget {
    TransportBudget::new(ContainerLimits::default())
}

struct SdkSourceReader {
    calls: Rc<Cell<usize>>,
    charged: Rc<Cell<bool>>,
    source: &'static [u8],
}

impl SdkSourceReader {
    fn read(&mut self, budget: &mut rivetlua::LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        self.calls.set(self.calls.get() + 1);
        let work = self
            .source
            .len()
            .checked_add(1)
            .ok_or_else(|| HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()))?;
        budget.spend_work(work)?;
        budget.claim_temporary(self.source.len())?;
        self.charged.set(true);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(self.source.len())
            .map_err(|_| HostLoadError::new(HostLoadErrorKind::Failed, Vec::new()))?;
        if bytes.capacity() > self.source.len() {
            return Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new()));
        }
        bytes.extend_from_slice(self.source);
        Ok(bytes)
    }
}

impl HostSourceReader for SdkSourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut rivetlua::LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, b"code.lua");
        self.read(budget)
    }

    fn read_stdin(
        &mut self,
        budget: &mut rivetlua::LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        self.read(budget)
    }
}

struct UnlimitedCompileSink;

impl CompileBudgetSink for UnlimitedCompileSink {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn compile_verified(profile: LuaProfile, source: &[u8]) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    match compile_with_budget(
        source,
        b"=sdk-host-loader-test",
        language,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut UnlimitedCompileSink,
    ) {
        Ok(module) => module,
        Err(BudgetedCompileError::Budget(())) => unreachable!(),
        Err(error) => panic!("測試 fixture 必須編譯成功：{error:?}"),
    }
}

fn compile_budget(max_work: u64, max_allocation_bytes: usize) -> CompileBudget {
    CompileBudget::new(CompileBudgetLimits {
        max_work,
        max_allocation_bytes,
    })
}

fn min_work(profile: LuaProfile, source: &[u8], chunk_name: &[u8]) -> u64 {
    let engine = Engine::new(profile);
    let mut low = 0;
    let mut high = 1 << 30;
    assert!(engine
        .compile_named_with_budget(
            source,
            chunk_name,
            &compile_budget(high, 768 * 1024 * 1024),
        )
        .is_ok());
    while low < high {
        let middle = low + (high - low) / 2;
        let result = engine.compile_named_with_budget(
            source,
            chunk_name,
            &compile_budget(middle, 768 * 1024 * 1024),
        );
        if result.is_ok() {
            high = middle;
        } else {
            assert!(matches!(
                result,
                Err(CompileError::Budget(
                    CompileBudgetErrorKind::WorkLimitExceeded
                ))
            ));
            low = middle + 1;
        }
    }
    low
}

fn min_allocation(profile: LuaProfile, source: &[u8], chunk_name: &[u8]) -> usize {
    let engine = Engine::new(profile);
    let mut low = 0;
    let mut high = 768 * 1024 * 1024;
    assert!(
        engine
            .compile_named_with_budget(source, chunk_name, &compile_budget(u64::MAX, high),)
            .is_ok()
    );
    while low < high {
        let middle = low + (high - low) / 2;
        let result =
            engine.compile_named_with_budget(source, chunk_name, &compile_budget(u64::MAX, middle));
        if result.is_ok() {
            high = middle;
        } else {
            assert!(matches!(
                result,
                Err(CompileError::Budget(
                    CompileBudgetErrorKind::AllocationLimitExceeded
                ))
            ));
            low = middle + 1;
        }
    }
    low
}

fn official_root_varargs(profile: LuaProfile) -> &'static [u8] {
    match profile {
        LuaProfile::Lua54 => {
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-root-varargs.luac"
            )
        }
        LuaProfile::Lua55 => {
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-root-varargs.luac"
            )
        }
    }
}

#[test]
fn sdk_compile_budget_accepts_exact_work_and_memory_and_releases_each_failure() {
    let source = b"local function inner(seed, ...) return seed, ... end; return inner(9, ... )";
    let chunk_name = b"=compile-budget";
    for profile in profiles() {
        let engine = Engine::new(profile);
        let work = min_work(profile, source, chunk_name);
        assert!(
            engine
                .compile_named_with_budget(
                    source,
                    chunk_name,
                    &compile_budget(work, 768 * 1024 * 1024)
                )
                .is_ok()
        );
        let work_below = compile_budget(work - 1, 768 * 1024 * 1024);
        assert!(matches!(
            engine.compile_named_with_budget(source, chunk_name, &work_below),
            Err(CompileError::Budget(
                CompileBudgetErrorKind::WorkLimitExceeded
            ))
        ));
        assert_eq!(work_below.allocation_snapshot().reserved, 0);
        assert_eq!(work_below.allocation_snapshot().committed, 0);

        let allocation = min_allocation(profile, source, chunk_name);
        assert!(
            engine
                .compile_named_with_budget(
                    source,
                    chunk_name,
                    &compile_budget(u64::MAX, allocation)
                )
                .is_ok()
        );
        let below = compile_budget(u64::MAX, allocation - 1);
        assert!(matches!(
            engine.compile_named_with_budget(source, chunk_name, &below),
            Err(CompileError::Budget(
                CompileBudgetErrorKind::AllocationLimitExceeded
            ))
        ));
        assert_eq!(below.allocation_snapshot().reserved, 0);
        assert_eq!(below.allocation_snapshot().committed, 0);

        let measured = compile_budget(u64::MAX, 768 * 1024 * 1024);
        let start = measured.allocation_trace().next_ordinal;
        let measured_module = engine
            .compile_named_with_budget(source, chunk_name, &measured)
            .unwrap();
        let end = measured.allocation_trace().next_ordinal;
        assert!(end > start, "編譯應包含配置申報與 Module Arc charge");
        assert_eq!(measured.allocation_snapshot().reserved, 0);
        assert_eq!(measured.allocation_snapshot().committed, 0);

        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&measured_module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(9)])
        );

        for ordinal in start..end {
            let faulted = compile_budget(u64::MAX, 768 * 1024 * 1024);
            faulted.fail_once_at_ordinal(ordinal);
            assert!(
                matches!(
                    engine.compile_named_with_budget(source, chunk_name, &faulted),
                    Err(CompileError::Budget(
                        CompileBudgetErrorKind::AllocationFailed
                    ))
                ),
                "配置 ordinal {ordinal} 必須失敗"
            );
            assert_eq!(
                faulted
                    .allocation_trace()
                    .last_failure
                    .unwrap()
                    .attempt
                    .ordinal,
                ordinal
            );
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);

            let module = engine
                .compile_named_with_budget(source, chunk_name, &faulted)
                .unwrap();
            assert_eq!(module.source_name(), Some(chunk_name.as_slice()));
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);
            assert_eq!(
                vm.load_module(&module).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![Value::Integer(9)])
            );
        }
    }
}

#[test]
fn sdk_binary_input_dispatches_raw_official_and_rvct_without_promoting_raw_metadata() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine
            .compile_named(b"return 42", b"=binary-input")
            .unwrap();
        let container = engine.save_module(&module, &transport_budget()).unwrap();
        let rvlu_len = u64::from_le_bytes(container[16..24].try_into().unwrap()) as usize;
        let raw = &container[40..40 + rvlu_len];
        assert_eq!(classify_input(raw), CoreInputFormat::RawRvlu);

        let raw_budget = transport_budget();
        let raw_module = engine.load_binary_module(raw, &raw_budget).unwrap();
        assert_eq!(raw_module.origin(), ModuleOrigin::NativeRvlu);
        assert_eq!(raw_module.source_name(), None);
        assert_eq!(raw_budget.allocation_snapshot().reserved, 0);
        let mut vm = engine.new_vm().unwrap();
        assert_eq!(
            vm.load_module(&raw_module).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42)])
        );

        let rvct_module = engine
            .load_binary_module(&container, &transport_budget())
            .unwrap();
        assert_eq!(rvct_module.source_name(), Some(b"=binary-input".as_slice()));
        assert_eq!(rvct_module.origin(), ModuleOrigin::NativeRvlu);

        let official = official_root_varargs(profile);
        assert_eq!(classify_input(official), CoreInputFormat::Official);
        let official_module = engine
            .load_binary_module(official, &transport_budget())
            .unwrap();
        assert_eq!(official_module.origin(), ModuleOrigin::OfficialImport);
        assert!(official_module.source_name().is_some());

        let mut official_vm = engine.new_vm().unwrap();
        let text = official_vm.new_string(b"binary arg").unwrap();
        let text_value = text.value(&official_vm).unwrap();
        official_vm.collect().unwrap();
        let args = [Value::Float(-0.0), Value::Nil, text_value, Value::Nil];
        let values = official_vm
            .load_module_with_args(&official_module, &args)
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = values else {
            panic!("official root-vararg binary fixture 執行結果無效：{values:?}")
        };
        let [Value::Object(table)] = values.as_slice() else {
            panic!("official root-vararg binary fixture 應回傳參數表：{values:?}")
        };
        let table = official_vm.root(Value::Object(*table)).unwrap();
        let Value::Float(negative_zero) = official_vm
            .table_raw_get(&table, Value::Integer(1))
            .unwrap()
        else {
            panic!("official entry 必須保留浮點型別")
        };
        assert_eq!(negative_zero.to_bits(), (-0.0f64).to_bits());
        assert_eq!(
            official_vm
                .table_raw_get(&table, Value::Integer(2))
                .unwrap(),
            Value::Nil
        );
        assert_eq!(
            official_vm
                .table_raw_get(&table, Value::Integer(3))
                .unwrap(),
            text_value
        );
        assert_eq!(
            official_vm
                .table_raw_get(&table, Value::Integer(4))
                .unwrap(),
            Value::Nil
        );
        assert_eq!(official_vm.read_byte_string(&text).unwrap(), b"binary arg");
    }
}

#[test]
fn sdk_binary_input_rejects_source_unknown_truncated_and_wrong_profile_before_allocation() {
    let engine = Engine::new(LuaProfile::Lua55);
    for rejected in [b"return 7".as_slice(), b"RVLU = 1", b"RVLU()", b"\x1bNope"] {
        let budget = transport_budget();
        let error = engine.load_binary_module(rejected, &budget).unwrap_err();
        assert_eq!(error.kind, ContainerErrorKind::InvalidFormat);
        assert!(error.input_kind.is_some());
        assert_eq!(budget.allocation_trace().next_ordinal, 1);
        assert_eq!(budget.allocation_snapshot().reserved, 0);
    }

    for truncated in [b"RVCT".as_slice(), b"RVCT\x01", b"RVLU\x02"] {
        let budget = transport_budget();
        assert!(engine.load_binary_module(truncated, &budget).is_err());
        assert_eq!(budget.allocation_snapshot().reserved, 0);
    }

    let wrong_profile = include_bytes!(
        "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-root-varargs.luac"
    );
    let budget = transport_budget();
    let error = engine
        .load_binary_module(wrong_profile, &budget)
        .unwrap_err();
    assert_eq!(error.input_kind, Some(InputErrorKind::InvalidFormat));
    assert_eq!(budget.allocation_trace().next_ordinal, 1);
    assert_eq!(budget.allocation_snapshot().reserved, 0);

    let valid = engine.compile(b"return 7").unwrap();
    let container = engine.save_module(&valid, &transport_budget()).unwrap();
    let rvlu_len = u64::from_le_bytes(container[16..24].try_into().unwrap()) as usize;
    let raw = &container[40..40 + rvlu_len];
    let mut bad_version = raw.to_vec();
    bad_version[4..6].copy_from_slice(&3u16.to_le_bytes());
    let mut bad_numeric = raw.to_vec();
    bad_numeric[7] = 2;
    for malformed in [bad_version, bad_numeric] {
        let budget = transport_budget();
        let error = engine.load_binary_module(&malformed, &budget).unwrap_err();
        assert!(matches!(
            error.kind,
            ContainerErrorKind::InvalidFormat | ContainerErrorKind::UnsupportedVersion
        ));
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
    }
}

#[test]
fn sdk_source_entry_arguments_preserve_nil_bytes_and_float_bits_and_validate_vm_identity() {
    let source = b"local function make(seed) return function(...) return seed, ... end end; return make(73)(...)";
    for profile in profiles() {
        let engine = Engine::new(profile);
        let module = engine.compile(source).unwrap();
        let mut vm = engine.new_vm().unwrap();
        let text = vm.new_string(b"entry bytes").unwrap();
        let text_value = text.value(&vm).unwrap();
        let args = [
            Value::Integer(7),
            Value::Nil,
            text_value,
            Value::Nil,
            Value::Float(-0.0),
        ];
        vm.collect().unwrap();
        let result = vm
            .load_module_with_args(&module, &args)
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = result else {
            panic!("source entry args 應正常返回：{result:?}")
        };
        assert_eq!(values.len(), 6);
        assert_eq!(values[0], Value::Integer(73));
        assert_eq!(values[1], Value::Integer(7));
        assert_eq!(values[2], Value::Nil);
        assert_eq!(values[3], text_value);
        assert_eq!(values[4], Value::Nil);
        let Value::Float(number) = values[5] else {
            panic!("浮點參數須保持型別")
        };
        assert_eq!(number.to_bits(), (-0.0f64).to_bits());
        assert_eq!(vm.read_byte_string(&text).unwrap(), b"entry bytes");

        let foreign_engine = Engine::new(if profile == LuaProfile::Lua54 {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        });
        let foreign_module = foreign_engine.compile(b"return ...").unwrap();
        assert!(matches!(
            vm.load_module_with_args(&foreign_module, &[Value::Integer(1)]),
            Err(SdkError::ProfileMismatch { .. })
        ));

        let mut other = engine.new_vm().unwrap();
        let foreign_root = other.new_table().unwrap();
        let foreign_value = foreign_root.value(&other).unwrap();
        assert!(matches!(
            vm.load_module_with_args(&module, &[foreign_value]),
            Err(SdkError::Runtime(error))
                if error.kind == RuntimeErrorKind::Heap(VmError::WrongVm)
        ));
        assert_eq!(vm.allocation_snapshot().reserved, 0);
    }
}

#[test]
fn sdk_official_fixed_and_lua55_named_entry_arguments_follow_verified_plan() {
    for (profile, fixed) in [
        (
            LuaProfile::Lua54,
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua54-fixed-entry.luac"
            )
            .as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!(
                "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-fixed-entry.luac"
            )
            .as_slice(),
        ),
    ] {
        let engine = Engine::new(profile);
        let module = engine
            .load_binary_module(fixed, &transport_budget())
            .unwrap();
        let mut vm = engine.new_vm().unwrap();
        let text = vm.new_string(b"fixed arg").unwrap();
        let text_value = text.value(&vm).unwrap();
        vm.collect().unwrap();
        let outcome = vm
            .load_module_with_args(
                &module,
                &[text_value, Value::Float(-0.0), Value::Integer(99)],
            )
            .unwrap()
            .run()
            .unwrap();
        assert!(
            matches!(outcome, RunOutcome::Returned(values) if values.len() == 2 && values[0] == text_value && matches!(values[1], Value::Float(n) if n.to_bits() == (-0.0f64).to_bits()))
        );
        assert_eq!(vm.read_byte_string(&text).unwrap(), b"fixed arg");
    }

    let engine = Engine::new(LuaProfile::Lua55);
    let named = include_bytes!(
        "../../rivetlua-runtime/tests/official_chunk_fixtures/lua55-named-entry.luac"
    );
    let module = engine
        .load_binary_module(named, &transport_budget())
        .unwrap();
    let mut vm = engine.new_vm().unwrap();
    let text = vm.new_string(b"named arg").unwrap();
    let text_value = text.value(&vm).unwrap();
    let outcome = vm
        .load_module_with_args(&module, &[text_value, Value::Integer(7), Value::Nil])
        .unwrap()
        .run()
        .unwrap();
    assert!(matches!(
        outcome,
        RunOutcome::Returned(values)
            if values == [text_value, Value::Integer(2), Value::Integer(7), Value::Nil, Value::Integer(7), Value::Nil]
    ));
    assert_eq!(vm.read_byte_string(&text).unwrap(), b"named arg");
}

#[test]
fn sdk_engine_host_compiler_is_explicit_and_preserves_budget_syntax_and_fuel_results() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let make_services = || {
            HostServices::deny_all()
                .and_load(LoadCapability::deny_all().and_compiler(engine.clone()))
        };
        let runner = engine
            .compile(b"local f=load('return 40+2'); return f() ")
            .unwrap();
        let mut vm = engine.new_vm_with_services(make_services()).unwrap();
        assert_eq!(
            vm.load_module(&runner).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42)])
        );

        let syntax = engine.compile(b"return load('return *')").unwrap();
        let syntax_outcome = vm.load_module(&syntax).unwrap().run().unwrap();
        let RunOutcome::Returned(values) = syntax_outcome else {
            panic!("load 語法錯誤應回傳 nil 與診斷，不應變成資源中止：{syntax_outcome:?}")
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Nil);
        let diagnostic = vm.root(values[1]).unwrap();
        assert!(!vm.read_byte_string(&diagnostic).unwrap().is_empty());

        let other_profile = if profile == LuaProfile::Lua54 {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        };
        let mismatch = Engine::new(other_profile);
        let mismatch_services =
            HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(mismatch));
        let mut mismatch_vm = engine.new_vm_with_services(mismatch_services).unwrap();
        let mismatch_caller = engine.compile(b"return load('return 1')").unwrap();
        let mismatch_outcome = mismatch_vm
            .load_module(&mismatch_caller)
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = mismatch_outcome else {
            panic!("profile mismatch 應保留 load 診斷：{mismatch_outcome:?}")
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Nil);
        let diagnostic = mismatch_vm.root(values[1]).unwrap();
        assert!(
            String::from_utf8_lossy(&mismatch_vm.read_byte_string(&diagnostic).unwrap())
                .contains("profile mismatch")
        );

        for limits in [
            LoadLimits {
                max_work_units: 1,
                ..LoadLimits::default()
            },
            LoadLimits {
                max_temporary_bytes: 0,
                ..LoadLimits::default()
            },
            LoadLimits {
                max_module_allocation_bytes: 0,
                ..LoadLimits::default()
            },
        ] {
            let services = HostServices::deny_all().and_load(
                LoadCapability::deny_all()
                    .and_compiler(engine.clone())
                    .with_limits(limits),
            );
            let mut limited = engine.new_vm_with_services(services).unwrap();
            let outcome = limited.load_module(&runner).unwrap().run().unwrap();
            assert!(
                matches!(outcome, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget)
            );
            assert_eq!(limited.allocation_snapshot().reserved, 0);
        }

        let mut fuel_vm = engine.new_vm_with_services(make_services()).unwrap();
        let mut execution = fuel_vm.load_module(&runner).unwrap();
        execution.set_fuel(500).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Aborted(AbortReason::FuelExhausted)
        );
        drop(execution);
        assert_eq!(fuel_vm.allocation_snapshot().reserved, 0);
        assert_eq!(
            fuel_vm.load_module(&runner).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(42)])
        );
    }
}

#[test]
fn sdk_engine_compiler_adapter_runs_reader_loaded_source_on_the_shared_vm_ledger() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let source = b"return 31, 32";
        let calls = Rc::new(Cell::new(0));
        let charged = Rc::new(Cell::new(false));
        let services = HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .and_reader(SdkSourceReader {
                    calls: calls.clone(),
                    charged: charged.clone(),
                    source,
                })
                .and_compiler(engine.clone()),
        );
        let runner = engine
            .compile(b"local f=assert(loadfile('code.lua')); return f()")
            .unwrap();
        let mut vm = engine.new_vm_with_services(services).unwrap();
        assert_eq!(
            vm.load_module(&runner).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(31), Value::Integer(32)])
        );
        assert_eq!(calls.get(), 1);
        assert!(charged.get(), "reader 必須先扣除 input work/temporary");
        assert_eq!(vm.allocation_snapshot().reserved, 0);

        let calls = Rc::new(Cell::new(0));
        let charged = Rc::new(Cell::new(false));
        let limits = LoadLimits {
            max_module_allocation_bytes: 0,
            ..LoadLimits::default()
        };
        let services = HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .and_reader(SdkSourceReader {
                    calls: calls.clone(),
                    charged: charged.clone(),
                    source,
                })
                .and_compiler(engine.clone())
                .with_limits(limits),
        );
        let mut limited = engine.new_vm_with_services(services).unwrap();
        let outcome = limited.load_module(&runner).unwrap().run().unwrap();
        assert!(matches!(
            outcome,
            RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostLoadBudget
        ));
        assert_eq!(calls.get(), 1);
        assert!(
            charged.get(),
            "compiler limit failure follows paid reader input"
        );
        assert_eq!(limited.allocation_snapshot().reserved, 0);
    }
}

#[test]
fn sdk_binary_input_checks_exact_work_peak_limits_and_retry_after_injected_failure() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let native = engine.compile(b"return 17").unwrap();
        let container = engine.save_module(&native, &transport_budget()).unwrap();
        let rvlu_len = u64::from_le_bytes(container[16..24].try_into().unwrap()) as usize;
        let raw = &container[40..40 + rvlu_len];
        for (bytes, format) in [
            (raw, InputFormat::RawRvlu),
            (official_root_varargs(profile), InputFormat::Official),
        ] {
            let core_format = match format {
                InputFormat::RawRvlu => CoreInputFormat::RawRvlu,
                InputFormat::Official => CoreInputFormat::Official,
                InputFormat::Source | InputFormat::UnsupportedBinary => unreachable!(),
            };
            let transport = TransportLimits::default();
            let scan = input_scan_admission(bytes.len(), core_format).unwrap();
            let preflight = preflight_input_module(bytes, profile, &transport).unwrap();
            let admission = preflight.admission();
            let work = scan.work + admission.subsequent_work + 1;
            let default = transport_budget();
            engine.load_binary_module(bytes, &default).unwrap();
            let peak = default
                .allocation_trace()
                .last_attempt
                .expect("successful binary input reserves a peak")
                .bytes;

            let exact = TransportBudget::new(ContainerLimits {
                max_work: work,
                max_allocation_bytes: peak,
                ..ContainerLimits::default()
            });
            engine.load_binary_module(bytes, &exact).unwrap();
            assert_eq!(exact.allocation_snapshot().reserved, 0);

            for limits in [
                ContainerLimits {
                    max_work: work - 1,
                    ..ContainerLimits::default()
                },
                ContainerLimits {
                    max_allocation_bytes: peak - 1,
                    ..ContainerLimits::default()
                },
            ] {
                let denied = TransportBudget::new(limits);
                assert_eq!(
                    engine.load_binary_module(bytes, &denied).unwrap_err().kind,
                    ContainerErrorKind::LimitExceeded
                );
                assert_eq!(denied.allocation_trace().next_ordinal, 1);
                assert_eq!(denied.allocation_snapshot().reserved, 0);
            }

            let injected = transport_budget();
            injected.fail_once_at_ordinal(injected.allocation_trace().next_ordinal);
            assert_eq!(
                engine
                    .load_binary_module(bytes, &injected)
                    .unwrap_err()
                    .kind,
                ContainerErrorKind::AllocationFailed
            );
            assert_eq!(injected.allocation_snapshot().reserved, 0);
            assert!(engine.load_binary_module(bytes, &injected).is_ok());
            assert_eq!(injected.allocation_snapshot().reserved, 0);
        }
    }
}

#[test]
fn sdk_engine_compiler_adapter_failure_at_each_host_ledger_ordinal_retries() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let runner = compile_verified(profile, b"return load('return 7')()");
        let services = HostServices::deny_all()
            .and_load(LoadCapability::deny_all().and_compiler(engine.clone()));
        let mut vm = CoreVm::new_with_services(profile, services).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _environment_root =
            rivetlua_runtime::HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_error_builtins(environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.collect_major().unwrap();
        let probe = vm.ledger_probe();
        let baseline = probe.trace().next_ordinal;
        let mut execution = vm
            .load_with_environment(runner.clone(), Value::Object(environment))
            .unwrap();
        let callback_start = probe.trace().next_ordinal;
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(7)])
        );
        let callback_end = probe.trace().next_ordinal;
        drop(execution);
        assert!(callback_start >= baseline);
        assert!(callback_end > callback_start);

        for ordinal in callback_start..callback_end {
            let services = HostServices::deny_all()
                .and_load(LoadCapability::deny_all().and_compiler(engine.clone()));
            let mut vm = CoreVm::new_with_services(profile, services).unwrap();
            let environment = vm.allocate_table().unwrap();
            let environment_root =
                rivetlua_runtime::HostHandle::<Value>::new(&mut vm, environment).unwrap();
            vm.install_error_builtins(environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            vm.collect_major().unwrap();
            let probe = vm.ledger_probe();
            assert_eq!(probe.trace().next_ordinal, baseline);
            let baseline_roots = vm.roots().total_count();
            vm.inject_allocation_failure_at(ordinal);
            let failed = vm
                .load_with_environment(runner.clone(), Value::Object(environment))
                .unwrap()
                .run();
            assert!(failed.is_err(), "allocation ordinal {ordinal} must fail");
            assert_eq!(probe.trace().last_failure.unwrap().attempt.ordinal, ordinal);
            assert_eq!(vm.roots().total_count(), baseline_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            vm.collect_major().unwrap();
            assert_eq!(
                vm.load_with_environment(runner.clone(), Value::Object(environment))
                    .unwrap()
                    .run()
                    .unwrap(),
                RunOutcome::Returned(vec![Value::Integer(7)])
            );
            assert_eq!(vm.roots().total_count(), baseline_roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            drop(environment_root);
        }
    }
}
