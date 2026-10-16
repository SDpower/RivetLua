use std::cell::RefCell;
use std::rc::Rc;

use rivetlua::{
    AbortReason, ContainerLimits, Engine, ExportDestination, ExportError, ExportPolicy, HostOutput,
    HostOutputError, HostServices, LuaProfile, Module, ModuleOrigin, OutputAudit, OutputBudget,
    PolicyCapabilities, RunOutcome, TransportBudget, Value, Vm, VmPolicy,
};

struct CapturedOutput(Rc<RefCell<Vec<u8>>>);

impl HostOutput for CapturedOutput {
    fn write(&mut self, bytes: &[u8]) -> Result<(), HostOutputError> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(())
    }
}

fn profiles() -> [LuaProfile; 2] {
    [LuaProfile::Lua54, LuaProfile::Lua55]
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

fn assert_export_denied<T>(result: Result<T, ExportError>) {
    let Err(error) = result else {
        panic!("未授權模組匯出應拒絕")
    };
    assert_eq!(error.public_code(), "E_EXPORT_DENIED");
}

fn export_vm(
    engine: &Engine,
    policy: VmPolicy,
    issuer: PolicyCapabilities,
    export_policy: Option<ExportPolicy>,
) -> Vm {
    let services = HostServices::deny_all()
        .and_policy(policy)
        .and_policy_capabilities(issuer);
    let services = match export_policy {
        Some(policy) => services.and_export_policy(policy),
        None => services,
    };
    engine.new_vm_with_services(services).unwrap()
}

fn load_for_export(vm: &mut Vm, module: &Module) {
    drop(vm.load_module(module).unwrap());
}

#[test]
fn output_budget_is_shared_by_print_and_return_across_executions() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        for policy in [VmPolicy::Compatibility, VmPolicy::Sandbox] {
            let output = Rc::new(RefCell::new(Vec::new()));
            let services = HostServices::with_output(CapturedOutput(Rc::clone(&output)))
                .and_policy(policy)
                .and_output_budget(OutputBudget {
                    max_bytes: 3,
                    max_events: 2,
                    max_depth: 0,
                    max_work_units: 32,
                });
            let mut vm = engine.new_vm_with_services(services).unwrap();

            let first = engine.compile(b"print('x'); return 7").unwrap();
            assert_eq!(
                vm.load_module(&first).unwrap().run().unwrap(),
                RunOutcome::Returned(vec![Value::Integer(7)])
            );
            assert_eq!(output.borrow().as_slice(), b"x\n");
            assert_eq!(
                vm.output_audit(),
                OutputAudit {
                    emitted_bytes: 3,
                    emitted_events: 2,
                    limit_events: 0,
                }
            );

            let second = engine.compile(b"return 9").unwrap();
            assert!(matches!(
                vm.load_module(&second).unwrap().run().unwrap(),
                RunOutcome::Aborted(AbortReason::OutputLimit)
            ));
            assert_eq!(output.borrow().as_slice(), b"x\n");
            assert_eq!(
                vm.output_audit(),
                OutputAudit {
                    emitted_bytes: 3,
                    emitted_events: 2,
                    limit_events: 1,
                }
            );
        }
    }
}

#[test]
fn restricted_diagnostics_do_not_emit_private_chunk_or_error_text() {
    const PRIVATE_CHUNK: &[u8] = b"p22-private-chunk-marker";
    const PRIVATE_ERROR: &[u8] = b"p22-private-error-marker";

    for profile in profiles() {
        let engine = Engine::new(profile);
        let output = Rc::new(RefCell::new(Vec::new()));
        let services = HostServices::with_output(CapturedOutput(Rc::clone(&output)))
            .and_policy(VmPolicy::Sandbox)
            .and_output_budget(OutputBudget::default());
        let mut vm = engine.new_vm_with_services(services).unwrap();
        let module = engine
            .compile_named(b"error('p22-private-error-marker')", PRIVATE_CHUNK)
            .unwrap();

        let RunOutcome::SafeDiagnostic(diagnostic) =
            vm.load_module(&module).unwrap().run().unwrap()
        else {
            panic!("預期取得安全診斷")
        };
        assert!(!diagnostic.public_code.is_empty());
        assert!(diagnostic.correlation_id > 0);
        assert!(!contains_bytes(
            diagnostic.public_code.as_bytes(),
            PRIVATE_CHUNK
        ));
        assert!(!contains_bytes(
            diagnostic.public_code.as_bytes(),
            PRIVATE_ERROR
        ));
        assert!(!contains_bytes(output.borrow().as_slice(), PRIVATE_CHUNK));
        assert!(!contains_bytes(output.borrow().as_slice(), PRIVATE_ERROR));
    }
}

#[test]
fn module_export_requires_compatibility_owner_and_same_vm_module() {
    for profile in profiles() {
        let engine = Engine::new(profile);
        let issuer = PolicyCapabilities::new().expect("建立宿主 capability issuer");
        let module = engine
            .compile_named(b"return 41", b"@p22-private-module-name")
            .unwrap();
        let wrong_module = engine.compile(b"return 42").unwrap();

        let mut owner_vm = export_vm(
            &engine,
            VmPolicy::Compatibility,
            issuer.clone(),
            Some(ExportPolicy::OwnerModules),
        );
        load_for_export(&mut owner_vm, &module);
        load_for_export(&mut owner_vm, &wrong_module);
        let request = owner_vm
            .prepare_module_export(&issuer, &module, ExportDestination::HostBytes)
            .unwrap();
        let exported = owner_vm.export_module(&request, &module).unwrap();

        let decoded = engine
            .load_binary_module(
                &exported.bytes,
                &TransportBudget::new(ContainerLimits::default()),
            )
            .unwrap();
        assert_eq!(decoded.profile(), profile);
        assert_eq!(decoded.origin(), ModuleOrigin::NativeRvlu);
        assert!(decoded.source_name().is_none(), "匯出不應攜帶私有來源名稱");
        let mut decoded_vm = engine.new_vm().unwrap();
        assert_eq!(
            decoded_vm.load_module(&decoded).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(41)])
        );

        assert_export_denied(owner_vm.export_module(&request, &wrong_module));

        let mut other_owner_vm = export_vm(
            &engine,
            VmPolicy::Compatibility,
            issuer.clone(),
            Some(ExportPolicy::OwnerModules),
        );
        load_for_export(&mut other_owner_vm, &module);
        assert_export_denied(other_owner_vm.export_module(&request, &module));

        let mut default_vm = export_vm(&engine, VmPolicy::Compatibility, issuer.clone(), None);
        load_for_export(&mut default_vm, &module);
        assert_export_denied(default_vm.prepare_module_export(
            &issuer,
            &module,
            ExportDestination::HostBytes,
        ));

        for policy in [VmPolicy::Sandbox, VmPolicy::PrivateService] {
            let mut restricted_vm = export_vm(
                &engine,
                policy,
                issuer.clone(),
                Some(ExportPolicy::OwnerModules),
            );
            load_for_export(&mut restricted_vm, &module);
            assert_export_denied(restricted_vm.prepare_module_export(
                &issuer,
                &module,
                ExportDestination::HostBytes,
            ));
        }
    }
}
