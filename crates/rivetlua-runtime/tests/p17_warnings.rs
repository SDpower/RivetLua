use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, LuaProfile, ResultMode, Value, VerifyLimits};
use rivetlua_runtime::{
    ExternalCommand, FailPoint, HostServices, HostWarning, HostWarningError, RootKind, RunOutcome,
    RuntimeErrorKind, Vm, VmError,
};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone)]
struct WarningSink(Rc<RefCell<Vec<(Vec<u8>, bool)>>>);

impl HostWarning for WarningSink {
    fn write(&mut self, message: &[u8], tocont: bool) -> Result<(), HostWarningError> {
        self.0.borrow_mut().push((message.to_vec(), tocont));
        Ok(())
    }
}

#[derive(Clone)]
struct FailingWarningSink(Rc<RefCell<usize>>);

impl HostWarning for FailingWarningSink {
    fn write(&mut self, _message: &[u8], _tocont: bool) -> Result<(), HostWarningError> {
        let mut calls = self.0.borrow_mut();
        *calls += 1;
        if *calls == 4 {
            Err(HostWarningError::WriteFailed)
        } else {
            Ok(())
        }
    }
}

fn compile(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"=warning",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

#[test]
fn p17_warning_basic() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let captured = Rc::new(RefCell::new(Vec::new()));
        let mut vm = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(WarningSink(Rc::clone(&captured))),
        )
        .unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let outcome = vm
            .load_with_environment(
                compile(b"warn('part', 17); return 23", language),
                Value::Object(environment),
            )
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(23)]));
        assert_eq!(
            *captured.borrow(),
            vec![(b"part".to_vec(), true), (b"17".to_vec(), false)]
        );
        let outcome = vm
            .load_with_environment(
                compile(b"warn('a\\0tail'); return 1", language),
                Value::Object(environment),
            )
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(1)]));
        assert_eq!(captured.borrow().last(), Some(&(b"a".to_vec(), false)));
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let mut silent = Vm::new_with_services(profile, HostServices::deny_all()).unwrap();
        let globals = silent.allocate_table().unwrap();
        let root = silent.add_root(RootKind::Host, globals).unwrap();
        silent.install_basic_builtins(globals).unwrap();
        let outcome = silent
            .load_with_environment(
                compile(b"return warn('silent')", language),
                Value::Object(globals),
            )
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(Vec::new()));
        silent.remove_root(root).unwrap();
        assert_eq!(silent.ledger_snapshot().reserved, 0);

        // 普通 warn 經 native bridge 返回時，不得誤推進不存在的 finalizer 警告。
        let mut bridged = Vm::new_with_services(profile, HostServices::deny_all()).unwrap();
        let globals = bridged.allocate_table().unwrap();
        let globals_root = bridged.add_root(RootKind::Host, globals).unwrap();
        bridged.install_basic_builtins(globals).unwrap();
        let warning_id = HostFunctionId::new_unique(bridged.id()).unwrap();
        let mut bridge_root = None;
        let bridge = bridged
            .prepare_unpublished_c_closure::<VmError>(
                warning_id,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| bridge_root = Some(root),
            )
            .unwrap();
        bridged
            .attach_native_warning_bridge(warning_id, bridge)
            .unwrap();
        let pending = bridged
            .load_with_environment(
                compile(b"warn('@off'); return 7", language),
                Value::Object(globals),
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(token) = pending else {
            panic!("warn 必須透過 native bridge 停泊");
        };
        assert_eq!(
            bridged
                .continue_external(token, ExternalCommand::Return(Vec::new()))
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(7)])
        );
        drop(bridge_root);
        bridged.remove_root(globals_root).unwrap();
        assert_eq!(bridged.ledger_snapshot().reserved, 0);
    }
}
#[test]
fn p17_warning_control_atomicity() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let captured = Rc::new(RefCell::new(Vec::new()));
        let mut vm = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(WarningSink(Rc::clone(&captured))),
        )
        .unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let source = b"local called = false\nlocal t = setmetatable({}, {__tostring = function() called = true; return 'fake' end})\nlocal a = pcall(warn, 'first', t)\nlocal b = pcall(warn)\nwarn('last', 29)\nreturn a, b, called";
        let outcome = vm
            .load_with_environment(compile(source, language), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![
                Value::Boolean(false),
                Value::Boolean(false),
                Value::Boolean(false),
            ])
        );
        assert_eq!(
            *captured.borrow(),
            vec![(b"last".to_vec(), true), (b"29".to_vec(), false)]
        );
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p17_warning_gc_close_lifecycle() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let captured = Rc::new(RefCell::new(Vec::new()));
        let mut vm = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(WarningSink(Rc::clone(&captured))),
        )
        .unwrap();
        let environment = vm.allocate_table().unwrap();
        let environment_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let source = b"do local t=setmetatable({}, {__gc=function() error('boom') end}) end\ncollectgarbage('collect')\nreturn 9";
        let outcome = vm
            .load_with_environment(compile(source, language), Value::Object(environment))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(9)]));
        assert_eq!(
            *captured.borrow(),
            vec![
                (b"error in ".to_vec(), true),
                (b"__gc".to_vec(), true),
                (b" (".to_vec(), true),
                (b"warning:1: boom".to_vec(), true),
                (b")".to_vec(), false),
            ]
        );
        vm.remove_root(environment_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let shutdown = Rc::new(RefCell::new(Vec::new()));
        let mut closing = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(WarningSink(Rc::clone(&shutdown))),
        )
        .unwrap();
        let globals = closing.allocate_table().unwrap();
        let globals_root = closing.add_root(RootKind::Host, globals).unwrap();
        closing.install_basic_builtins(globals).unwrap();
        let source = b"held=setmetatable({}, {__gc=function() error(37) end}); return 5";
        let outcome = closing
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(5)]));
        closing.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            closing.drain_shutdown_finalizers(),
            Err(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert!(shutdown.borrow().is_empty());
        assert_eq!(closing.ledger_snapshot().reserved, 0);
        closing.drain_shutdown_finalizers().unwrap();
        assert_eq!(
            *shutdown.borrow(),
            vec![
                (b"error in ".to_vec(), true),
                (b"__gc".to_vec(), true),
                (b" (".to_vec(), true),
                (b"error object is not a string".to_vec(), true),
                (b")".to_vec(), false),
            ]
        );
        closing.remove_root(globals_root).unwrap();
        assert_eq!(closing.ledger_snapshot().reserved, 0);

        let warning_calls = Rc::new(RefCell::new(0));
        let mut failed = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(FailingWarningSink(Rc::clone(&warning_calls))),
        )
        .unwrap();
        let globals = failed.allocate_table().unwrap();
        let globals_root = failed.add_root(RootKind::Host, globals).unwrap();
        failed.install_basic_builtins(globals).unwrap();
        let source = b"do local t=setmetatable({}, {__gc=function() error('boom') end}) end\ncollectgarbage('collect')\nreturn 11";
        let error = failed
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap_err();
        assert_eq!(error.kind, RuntimeErrorKind::HostWarningFailed);
        assert_eq!(*warning_calls.borrow(), 4);
        failed.remove_root(globals_root).unwrap();
        assert_eq!(failed.ledger_snapshot().reserved, 0);

        // 祖先 finalizer fragment 停泊時，巢狀 Lua warn 使用相同 bridge；
        // 其返回不可完成祖先 fragment，GC 後仍須逐段交付完整警告。
        let mut native = Vm::new_with_services(profile, HostServices::deny_all()).unwrap();
        let globals = native.allocate_table().unwrap();
        let globals_root = native.add_root(RootKind::Host, globals).unwrap();
        native.install_basic_builtins(globals).unwrap();
        let warning_id = HostFunctionId::new_unique(native.id()).unwrap();
        let mut bridge_root = None;
        let bridge = native
            .prepare_unpublished_c_closure::<VmError>(
                warning_id,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| bridge_root = Some(root),
            )
            .unwrap();
        native
            .attach_native_warning_bridge(warning_id, bridge)
            .unwrap();
        let callback = native
            .load_with_environment(
                compile(b"return function() warn('nested') end", language),
                Value::Object(globals),
            )
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = callback else {
            panic!("巢狀 Lua 函式未回傳");
        };
        let callback = values[0];
        let Value::Object(callback_object) = callback else {
            panic!("巢狀 Lua 函式須為 closure");
        };
        let callback_root = native.add_root(RootKind::Host, callback_object).unwrap();
        let first = native
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(mut token) = first else {
            panic!("finalizer 警告須透過 native bridge 停泊");
        };
        let nested = native
            .continue_external(
                token,
                ExternalCommand::NestedCall {
                    target: callback,
                    args: Vec::new(),
                    results: ResultMode::Fixed(0),
                },
            )
            .unwrap();
        let RunOutcome::External(nested_token) = nested else {
            panic!("巢狀 warn 須透過相同 bridge 停泊");
        };
        assert_eq!(
            native
                .continue_external(nested_token, ExternalCommand::Return(Vec::new()))
                .unwrap(),
            RunOutcome::NestedReturned(Vec::new())
        );
        let nested = native
            .continue_external(
                token,
                ExternalCommand::NestedCall {
                    target: Value::Object(bridge),
                    args: vec![Value::Nil, Value::Boolean(false)],
                    results: ResultMode::Fixed(0),
                },
            )
            .unwrap();
        let RunOutcome::External(nested_token) = nested else {
            panic!("同 bridge 的巢狀 callback 須停泊");
        };
        native.abort_external_nested_callback(nested_token).unwrap();
        native.collect_major().unwrap();
        let expected_segments: [&[u8]; 5] =
            [b"error in ", b"__gc", b" (", b"warning:1: boom", b")"];
        for (segment, expected) in expected_segments.into_iter().enumerate() {
            let event = native.external_event(token).unwrap();
            assert_eq!(event.args[1], Value::Boolean(segment != 4));
            let Value::Object(message) = event.args[0] else {
                panic!("warning segment 須為字串");
            };
            assert_eq!(
                native.with_byte_string(message, |value| value.as_bytes().to_vec()),
                Ok(expected.to_vec())
            );
            let outcome = native
                .continue_external(token, ExternalCommand::Return(Vec::new()))
                .unwrap();
            if segment == 4 {
                assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(11)]));
            } else {
                let RunOutcome::External(next) = outcome else {
                    panic!("finalizer 警告尚有待交付的 fragment");
                };
                token = next;
            }
        }
        let aborted = native
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(abort_token) = aborted else {
            panic!("第二個 finalizer 警告須停泊");
        };
        native.abort_external(abort_token).unwrap();
        let errored = native
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(error_token) = errored else {
            panic!("第三個 finalizer 警告須停泊");
        };
        let outcome = native
            .continue_external(error_token, ExternalCommand::Error(Value::Integer(37)))
            .unwrap();
        let RunOutcome::LuaError(error) = outcome else {
            panic!("callback 錯誤不得被 finalizer 警告收尾覆蓋");
        };
        assert_eq!(error.value, Value::Integer(37));
        drop(error);
        native.remove_root(callback_root).unwrap();
        drop(bridge_root);
        native.remove_root(globals_root).unwrap();
        assert_eq!(native.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p17_shutdown_close_registration_lifecycle() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let warnings = Rc::new(RefCell::new(Vec::new()));
        let mut vm = Vm::new_with_services(
            profile,
            HostServices::deny_all().and_warning(WarningSink(Rc::clone(&warnings))),
        )
        .unwrap();
        let globals = vm.allocate_table().unwrap();
        let globals_root = vm.add_root(RootKind::Host, globals).unwrap();
        let events_key = vm.allocate_byte_string(b"events").unwrap();
        let events_key_root = vm.add_root(RootKind::Host, events_key).unwrap();
        vm.install_basic_builtins(globals).unwrap();

        let source = b"events = {}\n\
            do local t=setmetatable({}, {__gc=function() events[#events+1]=0 end}) end\n\
            collectgarbage('collect')\n\
            first=setmetatable({}, {__gc=function() events[#events+1]=1 end})\n\
            second=setmetatable({}, {__gc=function()\n\
              events[#events+1]=2\n\
              setmetatable({}, {__gc=function() events[#events+1]=3 end})\n\
              events[#events+1]=collectgarbage()==nil and 4 or 9\n\
            end})\n\
            return #events";
        assert_eq!(
            vm.load_with_environment(compile(source, language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)]),
            "profile={profile:?}"
        );

        // 關閉預備失敗尚未開始 close；其後註冊的 finalizer 必須仍可執行。
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert_eq!(
            vm.drain_shutdown_finalizers(),
            Err(VmError::InjectedFailure(FailPoint::WorkReserve))
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let later = b"before_close=setmetatable({}, {__gc=function() events[#events+1]=5 end}); return #events";
        assert_eq!(
            vm.load_with_environment(compile(later, language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)]),
            "profile={profile:?}"
        );

        vm.drain_shutdown_finalizers().unwrap();
        vm.drain_shutdown_finalizers().unwrap();
        let Value::Object(events) = vm.raw_get(globals, Value::Object(events_key)).unwrap() else {
            panic!("關閉期間的事件表須存活");
        };
        for (index, expected) in [0, 5, 2, 4, 1].into_iter().enumerate() {
            assert_eq!(
                vm.raw_get(events, Value::Integer(index as i64 + 1)),
                Ok(Value::Integer(expected)),
                "profile={profile:?} event={index}"
            );
        }
        assert_eq!(vm.raw_get(events, Value::Integer(6)), Ok(Value::Nil));
        assert_eq!(vm.gc_trace().finalizer_pending, 0);
        assert_eq!(vm.gc_trace().finalizer_warnings, 0);
        assert!(warnings.borrow().is_empty());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(events_key_root).unwrap();
        vm.remove_root(globals_root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
