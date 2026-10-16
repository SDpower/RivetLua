//! P20 可移除的受限原生碼後端。

#[cfg(not(target_pointer_width = "64"))]
compile_error!("RivetLua 原生碼後端只支援 64 位元指標");

mod abi;
mod artifact;
mod aot;
#[cfg(feature = "compiler")]
mod codegen;
mod execmem;
mod targets;

pub use abi::{NativeError, NativeExit, NativeState, NumericValue};
pub use artifact::{NativeArtifact, NativeCompileError, NativeCompileInput};
pub use targets::{PlatformTarget, platform_target, platform_targets, validate_board_target};
pub use aot::{AotArtifact, AotBuildInput, AotError, AotManifest, TrustedAotBuild, inspect_aot, load_aot};
#[cfg(feature = "compiler")]
pub use aot::build_aot;
