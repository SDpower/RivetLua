//! VM 建立時固定的宿主政策與僅供宿主使用的私有服務授權。

use crate::AllocationCharge;
use crate::host::{HostResourceError, ResourceBudget, ResourceLimits};
use crate::rust_alloc::boxed::Box;
use crate::rust_alloc::vec::Vec;
use rivetlua_core::VmId;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum VmPolicy {
    #[default]
    Compatibility,
    Sandbox,
    PrivateService,
}

/// 宿主發行者身分只可由宿主建立並注入 VM，不會成為 Lua 值。
#[derive(Clone)]
pub struct PolicyCapabilities {
    pub(crate) issuer: VmId,
}

impl PolicyCapabilities {
    pub fn new() -> Option<Self> {
        Some(Self {
            issuer: VmId::new_unique()?,
        })
    }
}

pub trait PolicyClock {
    /// 宿主提供的單調遞增 tick；相同 tick 的期限已過期。
    fn now(&self) -> u64;
}

pub trait PrivateService {
    fn invoke(
        &mut self,
        input: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Vec<u8>, HostResourceError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceOperation {
    Invoke,
    Export,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAudience {
    Host,
    Guest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAccessError {
    Denied,
    OutputLimit,
}

impl ServiceAccessError {
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::Denied => "E_SERVICE_DENIED",
            Self::OutputLimit => "E_OUTPUT_LIMIT",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutputBudget {
    pub max_bytes: usize,
    pub max_events: usize,
    pub max_depth: usize,
    pub max_work_units: usize,
}

impl Default for OutputBudget {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024,
            max_events: 1024,
            max_depth: 8,
            max_work_units: 100_000,
        }
    }
}

impl OutputBudget {
    pub(crate) const fn unlimited() -> Self {
        Self {
            max_bytes: usize::MAX,
            max_events: usize::MAX,
            max_depth: usize::MAX,
            max_work_units: usize::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OutputAudit {
    pub emitted_bytes: usize,
    pub emitted_events: usize,
    pub limit_events: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputError {
    Limit,
    Sink,
}

impl OutputError {
    pub const fn public_code(&self) -> &'static str {
        match self {
            Self::Limit => "E_OUTPUT_LIMIT",
            Self::Sink => "E_OUTPUT_SINK",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SafeDiagnostic {
    pub public_code: &'static str,
    pub correlation_id: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ExportPolicy {
    #[default]
    Deny,
    OwnerModules,
}

pub(crate) struct OutputMeter {
    budget: OutputBudget,
    audit: OutputAudit,
    work_used: usize,
}

impl OutputMeter {
    pub(crate) const fn new(budget: OutputBudget) -> Self {
        Self {
            budget,
            audit: OutputAudit {
                emitted_bytes: 0,
                emitted_events: 0,
                limit_events: 0,
            },
            work_used: 0,
        }
    }

    pub(crate) const fn audit(&self) -> OutputAudit {
        self.audit
    }

    pub(crate) fn charge(
        &mut self,
        bytes: usize,
        depth: usize,
        work: usize,
    ) -> Result<(), OutputError> {
        let next_bytes = self.audit.emitted_bytes.checked_add(bytes);
        let next_events = self.audit.emitted_events.checked_add(1);
        let next_work = self.work_used.checked_add(work);
        if depth > self.budget.max_depth
            || next_bytes.is_none_or(|value| value > self.budget.max_bytes)
            || next_events.is_none_or(|value| value > self.budget.max_events)
            || next_work.is_none_or(|value| value > self.budget.max_work_units)
        {
            self.audit.limit_events = self.audit.limit_events.saturating_add(1);
            return Err(OutputError::Limit);
        }
        self.audit.emitted_bytes = next_bytes.unwrap_or(self.budget.max_bytes);
        self.audit.emitted_events = next_events.unwrap_or(self.budget.max_events);
        self.work_used = next_work.unwrap_or(self.budget.max_work_units);
        Ok(())
    }

    pub(crate) fn reject(&mut self) -> OutputError {
        self.audit.limit_events = self.audit.limit_events.saturating_add(1);
        OutputError::Limit
    }
}

/// 不公開內部欄位、格式化或 guest 轉換，避免名稱與身分外洩。
#[derive(Clone)]
pub struct OpaqueServiceHandle {
    pub(crate) owner: VmId,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) scope: VmPolicy,
}

pub struct CapabilityGrant {
    pub(crate) issuer: VmId,
    pub(crate) owner: VmId,
    pub(crate) slot: usize,
    pub(crate) generation: u64,
    pub(crate) scope: VmPolicy,
    pub(crate) operation: ServiceOperation,
    pub(crate) audience: ServiceAudience,
    pub(crate) expires_at: u64,
    pub(crate) limits: ResourceLimits,
    pub(crate) work_left: u64,
    pub(crate) read_left: usize,
    pub(crate) write_left: usize,
    pub(crate) exhausted: bool,
}

pub(crate) struct ServiceSlot {
    pub(crate) generation: u64,
    pub(crate) service: Option<Box<dyn PrivateService>>,
    pub(crate) _service_charge: Option<AllocationCharge>,
}
