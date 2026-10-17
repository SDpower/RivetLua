//! P21 平台 metadata 清單；狀態不代表已在實機執行。

use rivetlua_core::{
    DeploymentStatus, Endian, ExecMemoryPolicy, LuaProfile, RVLU_NUMERIC_I64_F64, TargetDescriptor,
    TargetError,
};
use std::collections::BTreeSet;

mod arm;
mod x86;

pub use arm::validate_board_target;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlatformTarget {
    pub target_triple: &'static str,
    pub isa: &'static str,
    pub os: &'static str,
    pub abi: &'static str,
    pub exec_memory_policy: ExecMemoryPolicy,
    pub aot_codegen: bool,
    pub status: DeploymentStatus,
}

pub fn platform_targets() -> Vec<PlatformTarget> {
    let mut targets = x86::entries();
    targets.extend(arm::entries());
    targets
}

pub fn platform_target(triple: &str) -> Option<PlatformTarget> {
    platform_targets()
        .into_iter()
        .find(|target| target.target_triple == triple)
}

impl PlatformTarget {
    pub fn descriptor(
        &self,
        profile: LuaProfile,
        ram_cap: u64,
        code_cap: u64,
        flash_cap: Option<u64>,
        provenance: &str,
    ) -> Result<TargetDescriptor, TargetError> {
        if self.isa == "unspecified" || self.abi == "unspecified" {
            return Err(TargetError::InvalidField("isa/abi"));
        }
        let target = TargetDescriptor {
            target_triple: self.target_triple.into(),
            isa: self.isa.into(),
            cpu_features: BTreeSet::new(),
            os: self.os.into(),
            abi: self.abi.into(),
            endian: Endian::Little,
            lua_profile: profile,
            numeric_config: RVLU_NUMERIC_I64_F64,
            flash_cap,
            ram_cap,
            code_cap,
            exec_memory_policy: self.exec_memory_policy,
            runtime_version: env!("CARGO_PKG_VERSION").into(),
            compiler_version: env!("CARGO_PKG_VERSION").into(),
            build_provenance: provenance.into(),
        };
        target.validate()?;
        Ok(target)
    }
}
