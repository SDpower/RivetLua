//! P20 可移除的受限原生碼後端。

#[cfg(not(target_pointer_width = "64"))]
compile_error!("RivetLua 原生碼後端只支援 64 位元指標");

mod abi;
mod codegen;
mod execmem;

pub use abi::{NativeError, NativeExit, NativeState, NumericValue};
pub use codegen::{NativeArtifact, NativeCompileError, NativeCompileInput};
