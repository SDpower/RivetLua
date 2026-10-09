//! 私有 worker RVWK/1 binary 協定；只傳可複製的 Lua scalar 與受信任 artifact 聲明。

pub mod codec;
mod process;

pub use codec::{CopyValue, Frame, FrameKind, Limits, NativeSpec, Request, Response, WireError};
pub use process::{WorkerOutcome, WorkerReport, run_worker, worker_main};
