//! VM 局部的受限原生碼政策、快取與可觀測計數。

use crate::rust_alloc::vec::Vec;

use crate::heap::Vm;
use rivetlua_core::ObjectRef;
use rivetlua_native::{NativeArtifact, NativeCompileError, NumericValue};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitPolicy {
    Disabled,
    Enabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitFallbackReason {
    Disabled,
    UnsupportedInstruction,
    NonNumericOperand,
    DebugHook,
    Platform,
    ResourceLimit,
    CompilationFailed,
    Invalidated,
    StateConflict,
    ArtifactUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JitEligibility {
    Supported,
    Unsupported { reason: JitFallbackReason },
    Rejected { reason: JitFallbackReason },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JitStats {
    pub total_logical_instructions: u64,
    pub native_executed_instructions: u64,
    pub fallback_reason: Option<JitFallbackReason>,
    pub jit_compile_ns: u64,
    pub code_bytes: usize,
    pub metadata_bytes: usize,
}

pub(crate) struct JitVmState {
    pub(crate) policy: JitPolicy,
    pub(crate) epoch: u64,
    pub(crate) code_limit_bytes: usize,
    pub(crate) cache_code_limit_bytes: usize,
    pub(crate) cache_metadata_limit_bytes: usize,
    pub(crate) cache: Vec<NativeArtifact>,
}

/// VerifiedModule 在執行期間不可變；key 的 module 參照與 prototype 變化會撤銷此判定。
pub(crate) struct JitPrepared {
    pub(crate) module_ref: Option<ObjectRef>,
    pub(crate) prototype: usize,
    pub(crate) epoch: u64,
    pub(crate) module_digest: [u8; 32],
    pub(crate) eligibility: JitEligibility,
    pub(crate) mask: Vec<bool>,
    pub(crate) scratch: Vec<NumericValue>,
}

impl JitVmState {
    pub(crate) fn new() -> Self {
        Self {
            policy: JitPolicy::Disabled,
            epoch: 1,
            code_limit_bytes: 2 * 1024 * 1024,
            cache_code_limit_bytes: 16 * 1024 * 1024,
            cache_metadata_limit_bytes: 4 * 1024 * 1024,
            cache: Vec::new(),
        }
    }

    pub(crate) fn set_policy(&mut self, policy: JitPolicy) -> bool {
        if self.policy != policy {
            if !self.invalidate() {
                return false;
            }
            self.policy = policy;
        }
        true
    }

    pub(crate) fn invalidate(&mut self) -> bool {
        self.cache = Vec::new();
        let Some(next_epoch) = self.epoch.checked_add(1) else {
            self.policy = JitPolicy::Disabled;
            return false;
        };
        self.epoch = next_epoch;
        true
    }

    pub(crate) fn code_bytes(&self) -> usize {
        self.cache.iter().fold(0usize, |used, artifact| {
            used.saturating_add(artifact.allocated_bytes())
        })
    }

    pub(crate) fn metadata_bytes(&self) -> usize {
        self.cache
            .capacity()
            .saturating_mul(core::mem::size_of::<NativeArtifact>())
            .saturating_add(self.cache.iter().fold(0usize, |used, artifact| {
                used.saturating_add(artifact.metadata_bytes())
            }))
    }

    #[cfg(feature = "jit")]
    pub(crate) fn make_room_for_compile(&mut self) -> bool {
        while !self.cache.is_empty()
            && (self.code_bytes().saturating_add(self.code_limit_bytes)
                > self.cache_code_limit_bytes
                || self.metadata_bytes() > self.cache_metadata_limit_bytes)
        {
            self.cache.remove(0);
            self.cache.shrink_to_fit();
        }
        self.code_limit_bytes <= self.cache_code_limit_bytes
            && self.metadata_bytes() <= self.cache_metadata_limit_bytes
    }

    pub(crate) fn admit(&mut self, artifact: NativeArtifact, prepared_bytes: usize) -> bool {
        let code = artifact.allocated_bytes();
        let metadata = artifact.metadata_bytes();
        while !self.cache.is_empty()
            && (self.code_bytes().saturating_add(code) > self.cache_code_limit_bytes
                || self
                    .metadata_bytes()
                    .saturating_add(metadata)
                    .saturating_add(prepared_bytes)
                    > self.cache_metadata_limit_bytes)
        {
            self.cache.remove(0);
            self.cache.shrink_to_fit();
        }
        if self.cache.try_reserve_exact(1).is_err() {
            return false;
        }
        if self.code_bytes().saturating_add(code) > self.cache_code_limit_bytes
            || self
                .metadata_bytes()
                .saturating_add(metadata)
                .saturating_add(prepared_bytes)
                > self.cache_metadata_limit_bytes
        {
            return false;
        }
        self.cache.push(artifact);
        if self.metadata_bytes().saturating_add(prepared_bytes) > self.cache_metadata_limit_bytes {
            self.cache.pop();
            self.cache.shrink_to_fit();
            return false;
        }
        true
    }

    pub(crate) fn make_room_for_metadata(
        &mut self,
        mut protected_index: usize,
        prepared_bytes: usize,
    ) -> Option<usize> {
        while self.metadata_bytes().saturating_add(prepared_bytes) > self.cache_metadata_limit_bytes
        {
            let victim = if protected_index == 0 { 1 } else { 0 };
            if victim >= self.cache.len() {
                return None;
            }
            self.cache.remove(victim);
            self.cache.shrink_to_fit();
            if victim < protected_index {
                protected_index -= 1;
            }
        }
        Some(protected_index)
    }
}

impl Vm {
    pub fn set_jit_policy(&mut self, policy: JitPolicy) -> Result<(), crate::heap::VmError> {
        if self.jit_state.set_policy(policy) {
            Ok(())
        } else {
            Err(crate::heap::VmError::IdentityExhausted)
        }
    }

    #[cfg(feature = "aot")]
    pub fn install_aot(
        &mut self,
        module: &rivetlua_core::VerifiedModule,
        bytes: &[u8],
        target: &rivetlua_core::TargetDescriptor,
        trust: &rivetlua_native::TrustedAotBuild,
    ) -> Result<(), rivetlua_native::AotError> {
        use rivetlua_native::{AotError, inspect_aot, load_aot};

        if self.execution_running() || !self.parked_executions.is_empty() {
            return Err(AotError::Unsupported("VM execution active"));
        }
        if module.profile() != self.language_profile() {
            return Err(AotError::Mismatch("VM profile"));
        }
        let manifest = inspect_aot(bytes)?;
        if manifest.code_len > self.jit_state.code_limit_bytes {
            return Err(AotError::Unsupported("VM native code cap"));
        }
        if target.code_cap > self.jit_state.cache_code_limit_bytes as u64 {
            return Err(AotError::Unsupported("VM native arena cap"));
        }
        let register_count = module
            .module()
            .prototypes
            .get(manifest.prototype_index)
            .ok_or(AotError::Mismatch("prototype index"))?
            .register_count as usize;
        let prepared_bytes = register_count
            .checked_mul(core::mem::size_of::<NumericValue>())
            .and_then(|n| n.checked_add(core::mem::size_of::<JitPrepared>()))
            .and_then(|n| n.checked_add(register_count))
            .ok_or(AotError::Unsupported("VM metadata cap overflow"))?;
        self.set_jit_policy(JitPolicy::Enabled)
            .map_err(|_| AotError::Unsupported("VM native epoch exhausted"))?;
        let artifact = loop {
            match load_aot(bytes, module, target, trust, self.id()) {
                Ok(artifact) => break artifact,
                Err(AotError::Native(rivetlua_native::NativeError::AllocationFailed))
                    if !self.jit_state.cache.is_empty() =>
                {
                    self.jit_state.cache.remove(0);
                    self.jit_state.cache.shrink_to_fit();
                }
                Err(error) => return Err(error),
            }
        };
        if artifact.allocated_bytes() > self.jit_state.cache_code_limit_bytes {
            return Err(AotError::Unsupported("VM native arena cap"));
        }
        if !artifact.matches_identity(
            module,
            artifact.module_digest(),
            manifest.prototype_index,
            manifest.entry_pc,
            self.id(),
        ) {
            return Err(AotError::Mismatch("VM native identity"));
        }
        if self.jit_state.cache.iter().any(|existing| {
            existing.matches_identity(
                module,
                artifact.module_digest(),
                manifest.prototype_index,
                manifest.entry_pc,
                self.id(),
            )
        }) {
            return Ok(());
        }
        if !self.jit_state.admit(artifact, prepared_bytes) {
            return Err(AotError::Unsupported("VM native cache cap"));
        }
        Ok(())
    }
}

pub(crate) fn classify(error: &NativeCompileError) -> JitEligibility {
    match error {
        NativeCompileError::Unsupported(_) => JitEligibility::Unsupported {
            reason: JitFallbackReason::UnsupportedInstruction,
        },
        NativeCompileError::Rejected(_) => JitEligibility::Rejected {
            reason: JitFallbackReason::ResourceLimit,
        },
        NativeCompileError::Backend(_) => JitEligibility::Rejected {
            reason: JitFallbackReason::CompilationFailed,
        },
        NativeCompileError::Native(_) => JitEligibility::Rejected {
            reason: JitFallbackReason::Platform,
        },
    }
}

pub(crate) fn module_digest(module: &rivetlua_core::VerifiedModule) -> Option<[u8; 32]> {
    let mut work = rivetlua_core::OfficialWorkBudget::new(u64::MAX);
    let encoded = rivetlua_core::bytecode::encode_transport_module(
        module,
        &rivetlua_core::TransportLimits::default(),
        &mut work,
    )
    .ok()?;
    rivetlua_core::sha256_bytes(encoded.rvlu())
}
