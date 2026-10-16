use rivetlua::{
    Engine, HostResourceError, HostServices, LuaProfile, PolicyCapabilities, PolicyClock,
    PrivateService, ResourceBudget, ResourceLimits, ServiceAccessError, ServiceAudience,
    ServiceOperation, Vm, VmPolicy,
};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
struct TestClock(Arc<AtomicU64>);

impl TestClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }

    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl PolicyClock for TestClock {
    fn now(&self) -> u64 {
        self.now()
    }
}

struct CountingService {
    calls: Arc<AtomicUsize>,
    work_per_call: usize,
}

impl PrivateService for CountingService {
    fn invoke(
        &mut self,
        _input: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Vec<u8>, HostResourceError> {
        budget.spend_work(self.work_per_call)?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(Vec::new())
    }
}

fn service(calls: &Arc<AtomicUsize>, work_per_call: usize) -> CountingService {
    CountingService {
        calls: Arc::clone(calls),
        work_per_call,
    }
}

fn limits(max_work_units: usize) -> ResourceLimits {
    ResourceLimits {
        max_work_units,
        max_temporary_bytes: 1024,
        max_retained_bytes: 1024,
        max_read_bytes: 1024,
        max_write_bytes: 1024,
    }
}

fn policy_vm(
    engine: &Engine,
    policy: VmPolicy,
    capabilities: Option<PolicyCapabilities>,
    clock: TestClock,
) -> Vm {
    let services = HostServices::deny_all()
        .and_policy(policy)
        .and_policy_clock(clock);
    let services = match capabilities {
        Some(capabilities) => services.and_policy_capabilities(capabilities),
        None => services,
    };
    engine.new_vm_with_services(services).unwrap()
}

fn allow<T>(result: Result<T, ServiceAccessError>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("預期服務操作成功，實際錯誤碼：{}", error.public_code()),
    }
}

fn assert_denied<T>(result: Result<T, ServiceAccessError>) {
    let Err(error) = result else {
        panic!("未授權服務操作應拒絕")
    };
    assert_eq!(error.public_code(), "E_SERVICE_DENIED");
}

fn exercise_policy(profile: LuaProfile, policy: VmPolicy) {
    let engine = Engine::new(profile);
    let clock = TestClock::new(10);
    let issuer = PolicyCapabilities::new().expect("建立宿主 capability issuer");

    let calls = Arc::new(AtomicUsize::new(0));
    let mut noissuer_vm = policy_vm(&engine, policy, None, clock.clone());
    assert_eq!(noissuer_vm.policy(), policy);
    assert_denied(noissuer_vm.register_private_service(&issuer, service(&calls, 1)));
    assert_eq!(noissuer_vm.policy(), policy);

    let mut vm = policy_vm(&engine, policy, Some(issuer.clone()), clock.clone());
    assert_eq!(vm.policy(), policy);
    if policy != VmPolicy::PrivateService {
        assert_denied(vm.register_private_service(&issuer, service(&calls, 1)));
        assert_eq!(vm.policy(), policy);
        return;
    }

    let handle = allow(vm.register_private_service(&issuer, service(&calls, 1)));
    let mut legal_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert!(allow(vm.dispatch_private_service(
        &handle,
        &mut legal_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ))
    .is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let other_issuer = PolicyCapabilities::new().expect("建立另一個宿主 issuer");
    assert_denied(vm.issue_service_grant(
        &other_issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert_denied(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Export,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));

    let mut wrong_operation_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert_denied(vm.dispatch_private_service(
        &handle,
        &mut wrong_operation_grant,
        ServiceOperation::Export,
        ServiceAudience::Host,
        b"",
    ));

    let mut wrong_audience_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert_denied(vm.dispatch_private_service(
        &handle,
        &mut wrong_audience_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Guest,
        b"",
    ));

    let expires_at = clock.now() + 1;
    let mut expired_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        expires_at,
    ));
    clock.set(expires_at);
    assert_denied(vm.dispatch_private_service(
        &handle,
        &mut expired_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ));

    let mut other_vm = policy_vm(&engine, policy, Some(issuer.clone()), clock.clone());
    let mut wrong_vm_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert_denied(other_vm.dispatch_private_service(
        &handle,
        &mut wrong_vm_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let mut stale_grant = allow(vm.issue_service_grant(
        &issuer,
        &handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    allow(vm.revoke_private_service(&handle));
    let new_calls = Arc::new(AtomicUsize::new(0));
    let new_handle = allow(vm.register_private_service(&issuer, service(&new_calls, 1)));
    assert_denied(vm.dispatch_private_service(
        &handle,
        &mut stale_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ));
    let mut new_grant = allow(vm.issue_service_grant(
        &issuer,
        &new_handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(32),
        clock.now() + 100,
    ));
    assert!(allow(vm.dispatch_private_service(
        &new_handle,
        &mut new_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ))
    .is_empty());
    assert_eq!(new_calls.load(Ordering::SeqCst), 1);

    let budget_calls = Arc::new(AtomicUsize::new(0));
    let budget_handle = allow(vm.register_private_service(&issuer, service(&budget_calls, 2)));
    let mut budget_grant = allow(vm.issue_service_grant(
        &issuer,
        &budget_handle,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        limits(3),
        clock.now() + 100,
    ));
    assert!(allow(vm.dispatch_private_service(
        &budget_handle,
        &mut budget_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ))
    .is_empty());
    assert_denied(vm.dispatch_private_service(
        &budget_handle,
        &mut budget_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ));
    assert_denied(vm.dispatch_private_service(
        &budget_handle,
        &mut budget_grant,
        ServiceOperation::Invoke,
        ServiceAudience::Host,
        b"",
    ));
    assert_eq!(budget_calls.load(Ordering::SeqCst), 1);
    assert_eq!(vm.policy(), policy);
}

#[test]
fn p22_private_service_policy_enforces_issuer_scope_and_generation() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for policy in [
            VmPolicy::Compatibility,
            VmPolicy::Sandbox,
            VmPolicy::PrivateService,
        ] {
            exercise_policy(profile, policy);
        }
    }
}
