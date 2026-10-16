use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{HostFunctionId, LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{
    ExternalCommand, HostDeadline, HostExitRequest, HostOs, HostOsOperation, HostOsValue,
    HostResourceError, HostResourceErrorKind, HostServices, ObjectKind, ResourceBudget,
    ResourceCapability, ResourceLimits, RootKind, RunOutcome, RuntimeErrorKind, Vm,
};
use std::cell::RefCell;
use std::rc::Rc;

fn compile(source: &[u8], language: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let tokens = lex(source, language, &limits).unwrap();
    let parsed = parse(&tokens, language, &limits).unwrap();
    let resolved = resolve(&parsed, &tokens, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"=p17 exit",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

struct ExitOs(Rc<RefCell<Vec<HostExitRequest>>>);

impl HostOs for ExitOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if matches!(operation, HostOsOperation::Exit(_)) {
            Ok(())
        } else {
            Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ))
        }
    }

    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        budget.spend_work(1)?;
        let HostOsOperation::Exit(request) = operation else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        self.0.borrow_mut().push(request);
        Ok(HostOsValue::ExitRequest(request))
    }
}

struct ActiveDeadline;

impl HostDeadline for ActiveDeadline {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }
}

struct DeniedDeadline;

impl HostDeadline for DeniedDeadline {
    fn check(&mut self, _budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::Deadline,
            Vec::new(),
        ))
    }
}

struct WrongExitOs(bool);

impl HostOs for WrongExitOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        if matches!(operation, HostOsOperation::Exit(_)) {
            Ok(())
        } else {
            Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ))
        }
    }

    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        budget.spend_work(1)?;
        let HostOsOperation::Exit(request) = operation else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        };
        if self.0 {
            Ok(HostOsValue::ExitRequest(HostExitRequest {
                status: request.status + 1,
                close: request.close,
            }))
        } else {
            Ok(HostOsValue::Boolean(true))
        }
    }
}

fn make_vm(
    profile: LuaProfile,
    requests: Rc<RefCell<Vec<HostExitRequest>>>,
) -> (Vm, rivetlua_core::ObjectRef, rivetlua_runtime::RootId) {
    let services = HostServices::deny_all().and_resource(
        ResourceCapability::deny_all()
            .and_os(ExitOs(requests))
            .and_deadline(ActiveDeadline),
    );
    let mut vm = Vm::new_with_services(profile, services).unwrap();
    let globals = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, globals).unwrap();
    vm.install_basic_builtins(globals).unwrap();
    vm.install_io_os_builtins(globals).unwrap();
    vm.install_coroutine_builtins(globals).unwrap();
    (vm, globals, root)
}

fn install_native(vm: &mut Vm, globals: rivetlua_core::ObjectRef) -> HostFunctionId {
    let native = HostFunctionId::new_unique(vm.id()).unwrap();
    let key = vm.allocate_byte_string(b"native").unwrap();
    let key_root = vm.add_root(RootKind::Host, key).unwrap();
    vm.raw_set(globals, Value::Object(key), Value::CFunction(native))
        .unwrap();
    vm.remove_root(key_root).unwrap();
    native
}

#[test]
fn p17_exit_status_and_noncatchable() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        for (source, expected) in [
            (b"os.exit()".as_slice(), HostExitRequest { status: 0, close: false }),
            (b"os.exit(nil, true)".as_slice(), HostExitRequest { status: 0, close: true }),
            (b"os.exit(false)".as_slice(), HostExitRequest { status: 1, close: false }),
            (b"os.exit('17', 0)".as_slice(), HostExitRequest { status: 17, close: true }),
            (b"pcall(os.exit, 42); error('continued')".as_slice(), HostExitRequest { status: 42, close: false }),
            (b"xpcall(function() os.exit(43) end, function() error('caught') end); error('continued')".as_slice(), HostExitRequest { status: 43, close: false }),
            (b"local co=coroutine.create(function() os.exit(44) end); coroutine.resume(co); error('continued')".as_slice(), HostExitRequest { status: 44, close: false }),
            (b"setmetatable({}, {__gc=function() os.exit(45,false) end}); collectgarbage('collect'); error('continued')".as_slice(), HostExitRequest { status: 45, close: false }),
        ] {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let (mut vm, globals, root) = make_vm(profile, Rc::clone(&requests));
            let outcome = vm.load_with_environment(compile(source, language), Value::Object(globals))
                .unwrap().run().unwrap();
            assert_eq!(outcome, RunOutcome::Exited(expected), "{profile:?} {source:?}");
            assert_eq!(&*requests.borrow(), &[expected]);
            vm.remove_root(root).unwrap();
            drop(vm);
        }

        let requests = Rc::new(RefCell::new(Vec::new()));
        let (mut vm, globals, root) = make_vm(profile, Rc::clone(&requests));
        let source = b"assert(not pcall(os.exit, 1.5)); assert(not pcall(os.exit, 'bad')); assert(not pcall(os.exit, {})); return 1";
        assert_eq!(
            vm.load_with_environment(compile(source, language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        assert!(requests.borrow().is_empty());
        assert_eq!(vm.exit_request(), None);
        vm.remove_root(root).unwrap();

        for (services, diagnostic) in [
            (HostServices::deny_all(), "E_HOST_POLICY_OS"),
            (
                HostServices::deny_all().and_resource(
                    ResourceCapability::deny_all()
                        .and_os(WrongExitOs(false))
                        .and_deadline(ActiveDeadline),
                ),
                "E_HOST_PLATFORM_DIFFERENCE",
            ),
            (
                HostServices::deny_all().and_resource(
                    ResourceCapability::deny_all()
                        .and_os(WrongExitOs(true))
                        .and_deadline(ActiveDeadline),
                ),
                "E_HOST_PLATFORM_DIFFERENCE",
            ),
        ] {
            let mut vm = Vm::new_with_services(profile, services).unwrap();
            let globals = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, globals).unwrap();
            vm.install_basic_builtins(globals).unwrap();
            vm.install_io_os_builtins(globals).unwrap();
            let outcome = vm
                .load_with_environment(compile(b"os.exit(7)", language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap();
            let RunOutcome::LuaError(error) = outcome else {
                panic!("未授權或回傳錯型須是 Lua 錯誤：{outcome:?}");
            };
            assert_eq!(error.diagnostic_id, diagnostic);
            assert_eq!(vm.exit_request(), None);
            vm.remove_root(root).unwrap();
        }

        for (deadline_denied, diagnostic) in
            [(false, "E_HOST_RESOURCE_BUDGET"), (true, "E_HOST_DEADLINE")]
        {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let mut resource = ResourceCapability::deny_all().and_os(ExitOs(Rc::clone(&requests)));
            resource = if deadline_denied {
                resource.and_deadline(DeniedDeadline)
            } else {
                resource
                    .and_deadline(ActiveDeadline)
                    .with_limits(ResourceLimits {
                        max_work_units: 0,
                        ..ResourceLimits::default()
                    })
            };
            let mut vm =
                Vm::new_with_services(profile, HostServices::deny_all().and_resource(resource))
                    .unwrap();
            let globals = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, globals).unwrap();
            vm.install_basic_builtins(globals).unwrap();
            vm.install_io_os_builtins(globals).unwrap();
            let outcome = vm
                .load_with_environment(compile(b"os.exit(7)", language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap();
            let RunOutcome::LuaError(error) = outcome else {
                panic!("預算或截止時間失敗不得成為退出：{outcome:?}");
            };
            assert_eq!(error.diagnostic_id, diagnostic);
            assert!(requests.borrow().is_empty());
            assert_eq!(vm.exit_request(), None);
            vm.remove_root(root).unwrap();
        }

        // C callback 保留原 Lua frame 時，open upvalue 必須以 cell 身分讀寫，
        // 不能把新 bootstrap frame 的相同 slot 當作父 frame 的環境或局部值。
        let requests = Rc::new(RefCell::new(Vec::new()));
        let (mut vm, globals, root) = make_vm(profile, Rc::clone(&requests));
        install_native(&mut vm, globals);
        let outcome = vm.load_with_environment(
            compile(b"local saved=1; native(function() saved=61; return os,saved end, function() return saved end); return saved", language),
            Value::Object(globals),
        ).unwrap().run().unwrap();
        let RunOutcome::External(parent) = outcome else {
            panic!("C parent 須停放：{outcome:?}")
        };
        let args = vm.external_event(parent).unwrap().args.to_vec();
        assert_eq!(args.len(), 2);
        let written = vm
            .call_with_parked_parent(parent, args[0], &[])
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::Returned(values) = written else {
            panic!("父 frame 寫入須正常返回：{written:?}")
        };
        assert_eq!(values.len(), 2);
        assert!(
            matches!(values[0], Value::Object(object) if vm.object_kind(object) == Ok(ObjectKind::Table))
        );
        assert_eq!(values[1], Value::Integer(61));
        assert_eq!(
            vm.call_with_parked_parent(parent, args[1], &[])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(61)])
        );
        assert_eq!(
            vm.continue_external(parent, ExternalCommand::Return(vec![]))
                .unwrap(),
            RunOutcome::Returned(vec![Value::Integer(61)])
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);

        let requests = Rc::new(RefCell::new(Vec::new()));
        let (mut vm, globals, root) = make_vm(profile, Rc::clone(&requests));
        install_native(&mut vm, globals);
        let source = b"local saved=62; local outer=native(function() local inner=native(function() saved=saved+1; os.exit(saved,false) end); return inner end); return outer";
        let outcome = vm
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(outer) = outcome else {
            panic!("outer C callback 未停放：{outcome:?}")
        };
        let outer_target = vm.external_event(outer).unwrap().args[0];
        let nested = vm
            .call_with_parked_parent(outer, outer_target, &[])
            .unwrap()
            .run()
            .unwrap();
        let RunOutcome::External(inner) = nested else {
            panic!("nested C callback 未停放：{nested:?}")
        };
        let inner_target = vm.external_event(inner).unwrap().args[0];
        let expected = HostExitRequest {
            status: 63,
            close: false,
        };
        assert_eq!(
            vm.call_with_parked_parent(inner, inner_target, &[])
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Exited(expected)
        );
        assert_eq!(vm.exit_request(), Some(expected));
        assert_eq!(&*requests.borrow(), &[expected]);
        vm.remove_root(root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}

#[test]
fn p17_exit_close_lifecycle() {
    for (language, profile) in [
        (LanguageProfile::Lua55, LuaProfile::Lua55),
        (LanguageProfile::Lua54, LuaProfile::Lua54),
    ] {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let (mut vm, globals, root) = make_vm(profile, Rc::clone(&requests));
        let key = vm.allocate_byte_string(b"events").unwrap();
        let key_root = vm.add_root(RootKind::Host, key).unwrap();
        let source = b"events={}\n\
            first=setmetatable({}, {__gc=function() events[#events+1]=1 end})\n\
            second=setmetatable({}, {__gc=function()\n\
              events[#events+1]=2\n\
              setmetatable({}, {__gc=function() events[#events+1]=99 end})\n\
              os.exit(9,true)\n\
              events[#events+1]=98\n\
            end})\n\
            local x <close> = setmetatable({}, {__close=function() events[#events+1]=3 end})\n\
            os.exit(7,true)\n\
            events[#events+1]=97";
        let outcome = vm
            .load_with_environment(compile(source, language), Value::Object(globals))
            .unwrap()
            .run()
            .unwrap();
        assert_eq!(
            outcome,
            RunOutcome::Exited(HostExitRequest {
                status: 7,
                close: true
            })
        );
        assert!(matches!(
            vm.call(Value::Nil, &[]),
            Err(error) if error.kind == RuntimeErrorKind::TerminalExecution
        ));
        vm.drain_shutdown_finalizers().unwrap();
        assert_eq!(
            vm.exit_request(),
            Some(HostExitRequest {
                status: 9,
                close: true
            })
        );
        let Value::Object(events) = vm.raw_get(globals, Value::Object(key)).unwrap() else {
            panic!("事件表遺失");
        };
        for (index, expected) in [3, 2, 1].into_iter().enumerate() {
            assert_eq!(
                vm.raw_get(events, Value::Integer(index as i64 + 1)),
                Ok(Value::Integer(expected))
            );
        }
        assert_eq!(vm.raw_get(events, Value::Integer(4)), Ok(Value::Nil));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(key_root).unwrap();
        vm.remove_root(root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);

        for (close_again, expected, expected_events) in [
            (
                false,
                HostExitRequest {
                    status: 11,
                    close: false,
                },
                [2, 0],
            ),
            (
                true,
                HostExitRequest {
                    status: 11,
                    close: true,
                },
                [2, 1],
            ),
        ] {
            let requests = Rc::new(RefCell::new(Vec::new()));
            let (mut vm, globals, root) = make_vm(profile, requests);
            let key = vm.allocate_byte_string(b"events").unwrap();
            let key_root = vm.add_root(RootKind::Host, key).unwrap();
            let source = format!(
                "events={{}}; local first <close> = setmetatable({{}}, {{__close=function() events[#events+1]=1 end}}); local second <close> = setmetatable({{}}, {{__close=function() events[#events+1]=2; os.exit(11,{close_again}); events[#events+1]=98 end}}); os.exit(7,true)"
            );
            assert_eq!(
                vm.load_with_environment(
                    compile(source.as_bytes(), language),
                    Value::Object(globals)
                )
                .unwrap()
                .run()
                .unwrap(),
                RunOutcome::Exited(expected)
            );
            assert_eq!(vm.exit_request(), Some(expected));
            let Value::Object(events) = vm.raw_get(globals, Value::Object(key)).unwrap() else {
                panic!("關閉事件表遺失");
            };
            assert_eq!(
                vm.raw_get(events, Value::Integer(1)),
                Ok(Value::Integer(expected_events[0]))
            );
            assert_eq!(
                vm.raw_get(events, Value::Integer(2)),
                if expected_events[1] == 0 {
                    Ok(Value::Nil)
                } else {
                    Ok(Value::Integer(expected_events[1]))
                }
            );
            vm.remove_root(key_root).unwrap();
            vm.remove_root(root).unwrap();
            let probe = vm.ledger_probe();
            drop(vm);
            assert_eq!(probe.snapshot().committed, 0);
            assert_eq!(probe.snapshot().reserved, 0);
        }

        let requests = Rc::new(RefCell::new(Vec::new()));
        let (mut vm, globals, root) = make_vm(profile, requests);
        let key = vm.allocate_byte_string(b"events").unwrap();
        let key_root = vm.add_root(RootKind::Host, key).unwrap();
        let source = b"events={}\n\
            object=setmetatable({}, {__gc=function() events[#events+1]=1 end})\n\
            local x <close> = setmetatable({}, {__close=function() events[#events+1]=2 end})\n\
            os.exit(5,false)\n\
            events[#events+1]=3";
        assert_eq!(
            vm.load_with_environment(compile(source, language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Exited(HostExitRequest {
                status: 5,
                close: false
            })
        );
        vm.drain_shutdown_finalizers().unwrap();
        let Value::Object(events) = vm.raw_get(globals, Value::Object(key)).unwrap() else {
            panic!("事件表遺失");
        };
        assert_eq!(vm.raw_get(events, Value::Integer(1)), Ok(Value::Nil));
        assert!(
            vm.load_with_environment(compile(b"return 1", language), Value::Object(globals))
                .is_err()
        );
        vm.remove_root(key_root).unwrap();
        vm.remove_root(root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
