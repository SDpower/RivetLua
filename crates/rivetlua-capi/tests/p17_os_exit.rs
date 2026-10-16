#![forbid(unsafe_code)]

use rivetlua_capi::stack::NativeSessionFactory;
use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{
    HostDeadline, HostExitRequest, HostOs, HostOsOperation, HostOsValue, HostResourceError,
    HostResourceErrorKind, HostServices, ResourceBudget, ResourceCapability, RootKind, RunOutcome,
    Vm,
};
use std::cell::RefCell;
use std::rc::Rc;

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
        b"=p17-capi-exit",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

#[test]
fn p17_native_shutdown_preserves_recursive_exit_request() {
    #[cfg(feature = "lua54")]
    let (language, profile) = (LanguageProfile::Lua54, LuaProfile::Lua54);
    #[cfg(not(feature = "lua54"))]
    let (language, profile) = (LanguageProfile::Lua55, LuaProfile::Lua55);

    for (source, final_request) in [
        (
            b"collectgarbage('stop'); first=setmetatable({}, {__gc=function() os.exit(9,true) end}); os.exit(7,true)".as_slice(),
            HostExitRequest {
                status: 9,
                close: true,
            },
        ),
        (
            b"collectgarbage('stop'); first=setmetatable({}, {__gc=function() os.exit(99,true) end}); second=setmetatable({}, {__gc=function() os.exit(9,false) end}); os.exit(7,true)".as_slice(),
            HostExitRequest {
                status: 9,
                close: false,
            },
        ),
    ] {
        let requests = Rc::new(RefCell::new(Vec::new()));
        let services = HostServices::deny_all().and_resource(
            ResourceCapability::deny_all()
                .and_os(ExitOs(Rc::clone(&requests)))
                .and_deadline(ActiveDeadline),
        );
        let factory = NativeSessionFactory::new();
        let mut vm =
            Vm::new_with_services_and_admission(profile, services, factory.admission()).unwrap();
        let probe = vm.ledger_probe();
        let globals = vm.allocate_table().unwrap();
        let globals_root = vm.add_root(RootKind::Host, globals).unwrap();
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
        let mut session = factory.attach(&mut vm, globals).unwrap();
        assert_eq!(
            vm.load_with_environment(compile(source, language), Value::Object(globals))
                .unwrap()
                .run()
                .unwrap(),
            RunOutcome::Exited(HostExitRequest {
                status: 7,
                close: true,
            })
        );
        vm.remove_root(globals_root).unwrap();
        if let Err((error, _vm)) = session.loan_native_vm(vm) {
            panic!("同 VM 借出失敗：{error:?}");
        }
        assert_eq!(
            session.close_with_exit_request().unwrap(),
            Some(final_request)
        );
        assert_eq!(
            &*requests.borrow(),
            &[
                HostExitRequest {
                    status: 7,
                    close: true,
                },
                final_request,
            ]
        );
        drop(session);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);
    }
}
