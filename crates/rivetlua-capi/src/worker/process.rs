//! 每次請求建立新的 worker；父程序只處理 RVWK bytes，不執行 native 或 guest Lua。

use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rivetlua_core::{
    LuaProfile, OfficialWorkBudget, TransportLimits, Value, VerifyLimits, decode_module,
    decode_transport_module,
};
use rivetlua_runtime::{HostServices, OutputBudget, VmPolicy};

use crate::abi;
use crate::native::{self, NativeLibrary};
use crate::stack::{
    StateOwner, lua_gettop, lua_isinteger, lua_pushlstring, lua_settop, lua_toboolean,
    lua_tointegerx, lua_tolstring, lua_tonumberx, lua_type,
};

use super::codec::{
    CopyValue, Frame, FrameKind, HEADER_BYTES, Limits, Request, Response, WireError,
};
use super::isolation;

#[derive(Clone, Debug, PartialEq)]
pub enum WorkerOutcome {
    Complete(Vec<CopyValue>),
    RuntimeError(Vec<u8>),
    Rejected(Vec<u8>),
    NonCopyable { index: u16, lua_type: u8 },
    Crash,
    Deadline,
    Malformed,
}

#[derive(Clone, Debug)]
pub struct WorkerReport {
    pub outcome: WorkerOutcome,
    pub child_pid: Option<u32>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub reaped: bool,
    pub cache_clean: bool,
}

unsafe extern "C" {
    fn rivetlua_worker_set_nonblocking(fd: i32) -> i32;
    fn rivetlua_worker_poll(
        stdout_fd: i32,
        stdin_fd: i32,
        want_write: i32,
        timeout_ms: i32,
        can_read: *mut i32,
        can_write: *mut i32,
    ) -> i32;
    fn lua_pcallk(
        state: *mut crate::stack::lua_State,
        nargs: i32,
        nresults: i32,
        errfunc: i32,
        context: isize,
        continuation: Option<unsafe extern "C" fn(*mut crate::stack::lua_State, i32, isize) -> i32>,
    ) -> i32;
    fn lua_gc(state: *mut crate::stack::lua_State, what: i32, ...) -> i32;
}

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);
// 原每次 call 的預設額度改為同一 worker request 共用，nested/root 不重置剩餘 fuel。
const WORKER_REQUEST_FUEL: u64 = 1_000_000;

fn private_run_dir(root: &Path) -> Result<PathBuf, std::io::Error> {
    if !root.is_absolute() || !root.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "worker cache root 必須存在且為絕對路徑",
        ));
    }
    #[cfg(unix)]
    use std::os::unix::fs::DirBuilderExt;
    for _ in 0..32 {
        let path = root.join(format!(
            "rivetlua-worker-{}-{}",
            std::process::id(),
            NEXT_RUN.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "worker cache 名稱耗盡",
    ))
}

fn unix_signal(status: &ExitStatus) -> Option<i32> {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}

fn finish(
    mut child: Child,
    run_dir: PathBuf,
    mut outcome: WorkerOutcome,
    already_exited: Option<ExitStatus>,
    response_exit_confirmed: bool,
    restricted: bool,
) -> WorkerReport {
    let pid = child.id();
    let (status, group_stopped) = if restricted {
        // leader 尚未 reap，process-group ID 在終止其餘成員前不會被重用。
        let group_stopped = isolation::terminate_group(&mut child);
        (child.wait().ok(), group_stopped)
    } else if let Some(status) = already_exited {
        (Some(status), true)
    } else {
        // 普通自有子程序的終止；timeout/malformed 不能留下活 worker 或 pipe。
        let _ = child.kill();
        (child.wait().ok(), true)
    };
    if restricted && !group_stopped {
        outcome = WorkerOutcome::Crash;
    } else if let Some(status) = &status {
        if !status.success()
            && ((restricted && response_exit_confirmed
                && !matches!(outcome, WorkerOutcome::Deadline | WorkerOutcome::Malformed))
                || (!restricted
                    && !matches!(outcome, WorkerOutcome::Deadline | WorkerOutcome::Malformed)))
        {
            outcome = WorkerOutcome::Crash;
        }
    } else if restricted {
        // 無法確認直系 child 已回收時，不可把完整 RPC 回應當作成功。
        outcome = WorkerOutcome::Crash;
    }
    drop(child);
    let cache_clean = fs::remove_dir_all(&run_dir).is_ok() && !run_dir.exists();
    WorkerReport {
        outcome,
        child_pid: Some(pid),
        exit_code: status.as_ref().and_then(ExitStatus::code),
        signal: status.as_ref().and_then(unix_signal),
        reaped: status.is_some(),
        cache_clean,
    }
}

fn immediate(outcome: WorkerOutcome) -> WorkerReport {
    WorkerReport {
        outcome,
        child_pid: None,
        exit_code: None,
        signal: None,
        reaped: true,
        cache_clean: true,
    }
}

fn frame_length(bytes: &[u8], limits: Limits) -> Result<Option<usize>, WorkerOutcome> {
    if bytes.len() < 12 {
        return Ok(None);
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().expect("四位元組")) as usize;
    if len < HEADER_BYTES || len > limits.frame_bytes {
        return Err(WorkerOutcome::Malformed);
    }
    Ok(Some(len))
}

fn try_frame(bytes: &mut Vec<u8>, limits: Limits) -> Result<Option<Frame>, WorkerOutcome> {
    let Some(len) = frame_length(bytes, limits)? else {
        return Ok(None);
    };
    if bytes.len() < len {
        return Ok(None);
    }
    let frame = Frame::decode(&bytes[..len], limits).map_err(|_| WorkerOutcome::Malformed)?;
    bytes.drain(..len);
    Ok(Some(frame))
}

fn try_frame_before_deadline(
    bytes: &mut Vec<u8>,
    limits: Limits,
    started: Instant,
    deadline: Duration,
) -> Result<Option<Frame>, WorkerOutcome> {
    if remaining_ms(started, deadline).is_none() {
        return Err(WorkerOutcome::Deadline);
    }
    let frame = try_frame(bytes, limits);
    if remaining_ms(started, deadline).is_none() {
        Err(WorkerOutcome::Deadline)
    } else {
        frame
    }
}

fn append_bounded(buffer: &mut Vec<u8>, data: &[u8], limits: Limits) -> Result<(), WorkerOutcome> {
    if buffer
        .len()
        .checked_add(data.len())
        .filter(|length| *length <= limits.frame_bytes + HEADER_BYTES)
        .is_none()
    {
        return Err(WorkerOutcome::Malformed);
    }
    buffer
        .try_reserve(data.len())
        .map_err(|_| WorkerOutcome::Malformed)?;
    buffer.extend_from_slice(data);
    Ok(())
}

fn read_available(
    stdout: &mut impl Read,
    buffer: &mut Vec<u8>,
    limits: Limits,
    started: Instant,
    deadline: Duration,
) -> Result<bool, WorkerOutcome> {
    let mut chunk = [0_u8; 8192];
    loop {
        if remaining_ms(started, deadline).is_none() {
            return Err(WorkerOutcome::Deadline);
        }
        match stdout.read(&mut chunk) {
            Ok(0) => {
                if remaining_ms(started, deadline).is_none() {
                    return Err(WorkerOutcome::Deadline);
                }
                return Ok(true);
            }
            Ok(count) => {
                if remaining_ms(started, deadline).is_none() {
                    return Err(WorkerOutcome::Deadline);
                }
                if let Err(error) = append_bounded(buffer, &chunk[..count], limits) {
                    return Err(if remaining_ms(started, deadline).is_none() {
                        WorkerOutcome::Deadline
                    } else {
                        error
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if remaining_ms(started, deadline).is_none() {
                    return Err(WorkerOutcome::Deadline);
                }
                return Ok(false);
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                return Err(if remaining_ms(started, deadline).is_none() {
                    WorkerOutcome::Deadline
                } else {
                    WorkerOutcome::Malformed
                });
            }
        }
    }
}

fn remaining_ms(start: Instant, deadline: Duration) -> Option<i32> {
    let remaining = deadline.checked_sub(start.elapsed())?;
    Some(
        i32::try_from(remaining.as_millis().min(1000))
            .unwrap_or(1000)
            .max(1),
    )
}

#[cfg(unix)]
fn exited_without_reap(child: &Child) -> Result<bool, ()> {
    let pid = libc::id_t::try_from(child.id()).map_err(|_| ())?;
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // SAFETY：P_PID 綁定未 reap 的本 Child；WNOWAIT 保留 PID/PGID 至 group cleanup，
    // WNOHANG 保證此查詢不越過 request deadline。siginfo buffer 由 kernel 完整填入。
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(());
    }
    // SAFETY：buffer 先清零；waitid 成功後，無事件仍保留零 si_signo。
    let info = unsafe { info.assume_init() };
    Ok(info.si_signo == libc::SIGCHLD)
}

#[cfg(not(unix))]
fn exited_without_reap(_child: &Child) -> Result<bool, ()> {
    Err(())
}

/// 每次建立新 process/VM/heap。宿主提供絕對 worker binary path 與完整 CNoUnwind 聲明。
///
/// # Safety
/// 所有 request native artifact 的 attestation 必須由宿主核准，且 constructors/destructors
/// 不在無效 state 期間呼叫 Lua API、不逃逸 foreign unwind。worker 隔離不會使 UB 合法。
pub unsafe fn run_worker(
    worker_binary: &Path,
    cache_root: &Path,
    request_id: u64,
    request: Request,
    deadline: Duration,
    limits: Limits,
) -> WorkerReport {
    run_worker_inner(worker_binary, cache_root, request_id, request,
        VmPolicy::Compatibility, deadline, limits)
}

/// 在宿主選定的不可變政策下啟動 worker；受限政策缺 OS 證據即拒絕。
///
/// # Safety
/// 宿主仍須核准 request 中每份 native artifact 與 CNoUnwind 聲明；OS 隔離不使 UB 合法。
pub unsafe fn run_worker_with_policy(
    worker_binary: &Path,
    cache_root: &Path,
    request_id: u64,
    request: Request,
    policy: VmPolicy,
    deadline: Duration,
    limits: Limits,
) -> WorkerReport {
    run_worker_inner(worker_binary, cache_root, request_id, request, policy, deadline, limits)
}

fn policy_denied() -> WorkerOutcome {
    WorkerOutcome::Rejected(isolation::PolicyDenied::MissingEvidence.public_code().to_vec())
}

fn run_worker_inner(
    worker_binary: &Path,
    cache_root: &Path,
    request_id: u64,
    request: Request,
    policy: VmPolicy,
    deadline: Duration,
    limits: Limits,
) -> WorkerReport {
    let restricted = policy != VmPolicy::Compatibility;
    if !worker_binary.is_absolute() || !worker_binary.is_file() || deadline.is_zero() {
        return immediate(if restricted { policy_denied() } else {
            WorkerOutcome::Rejected(b"worker binary/deadline invalid".to_vec())
        });
    }
    let started = Instant::now();
    #[cfg(target_os = "linux")]
    let artifact_paths = if restricted {
        if request.native.len() > limits.max_native {
            return immediate(WorkerOutcome::Rejected(b"E_WORKER_REJECTED".to_vec()));
        }
        let mut paths = Vec::new();
        if paths.try_reserve_exact(request.native.len()).is_err() {
            return immediate(WorkerOutcome::Rejected(b"E_WORKER_RESOURCE".to_vec()));
        }
        for spec in &request.native {
            if remaining_ms(started, deadline).is_none() {
                return immediate(WorkerOutcome::Deadline);
            }
            if native::preflight(spec.artifact.clone(), &spec.policy, spec.visibility).is_err() {
                return immediate(policy_denied());
            }
            if remaining_ms(started, deadline).is_none() {
                return immediate(WorkerOutcome::Deadline);
            }
            if !paths.contains(&spec.artifact.path) {
                paths.push(spec.artifact.path.clone());
            }
        }
        paths
    } else {
        Vec::new()
    };
    #[cfg(not(target_os = "linux"))]
    let artifact_paths: Vec<PathBuf> = Vec::new();
    let encoded = (Frame {
        request_id,
        identity: abi::current_identity(),
        kind: FrameKind::Request(request),
    })
    .encode(limits);
    if remaining_ms(started, deadline).is_none() {
        return immediate(WorkerOutcome::Deadline);
    }
    let request_bytes = match encoded {
        Ok(bytes) => bytes,
        Err(_) => return immediate(WorkerOutcome::Rejected(if restricted {
            b"E_WORKER_REJECTED".to_vec()
        } else {
            b"request rejected".to_vec()
        })),
    };
    let run_dir = match private_run_dir(cache_root) {
        Ok(path) => path,
        Err(_) => return immediate(if restricted { policy_denied() } else {
            WorkerOutcome::Rejected(b"worker cache invalid".to_vec())
        }),
    };
    if remaining_ms(started, deadline).is_none() {
        let _ = fs::remove_dir_all(&run_dir);
        return immediate(WorkerOutcome::Deadline);
    }
    let mut command = Command::new(worker_binary);
    command.arg("--rivetlua-worker-v1")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let launch = if restricted {
        match isolation::configure(&mut command, worker_binary, &run_dir, policy, &artifact_paths) {
            Ok(plan) => Some(plan),
            Err(_) => {
                let _ = fs::remove_dir_all(&run_dir);
                return immediate(policy_denied());
            }
        }
    } else {
        command.env("RIVETLUA_P16_WORKER_CACHE", &run_dir);
        None
    };
    let spawned = command.spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(_) => {
            let _ = fs::remove_dir_all(&run_dir);
            return immediate(if restricted { policy_denied() } else {
                WorkerOutcome::Rejected(b"worker spawn failed".to_vec())
            });
        }
    };
    let pid = child.id();
    let mut stdin = Some(child.stdin.take().expect("piped stdin"));
    let mut stdout = child.stdout.take().expect("piped stdout");
    // SAFETY：兩個 fd 都由本 Child pipe 持有且在此函式存活；fcntl 只更新 nonblocking flag。
    if unsafe { rivetlua_worker_set_nonblocking(stdin.as_ref().unwrap().as_raw_fd()) } != 0
        || unsafe { rivetlua_worker_set_nonblocking(stdout.as_raw_fd()) } != 0
    {
        return finish(child, run_dir, if restricted { policy_denied() } else {
            WorkerOutcome::Malformed
        }, None, false, restricted);
    }
    let mut received = Vec::new();
    let mut offset = 0;
    let mut hello = false;
    let mut parent_proof = None;
    let mut response = None;
    let mut eof = false;
    let mut failure = None;
    loop {
        let Some(wait_ms) = remaining_ms(started, deadline) else {
            failure = Some(WorkerOutcome::Deadline);
            break;
        };
        let want_write = hello && (!restricted || parent_proof.as_ref()
            .is_some_and(|proof: &isolation::IsolationProof| proof.matches(policy, pid, true)))
            && offset < request_bytes.len();
        let mut can_read = 0;
        let mut can_write = 0;
        // SAFETY：pipe fd 有效，兩個 out 只在同步 C poll 呼叫期間唯一可寫；無 callback/reentry。
        let stdin_fd = stdin.as_ref().map_or(-1, AsRawFd::as_raw_fd);
        let polled = unsafe {
            rivetlua_worker_poll(
                stdout.as_raw_fd(),
                stdin_fd,
                i32::from(want_write),
                wait_ms,
                &mut can_read,
                &mut can_write,
            )
        };
        if remaining_ms(started, deadline).is_none() {
            failure = Some(WorkerOutcome::Deadline);
            break;
        }
        if polled < 0 {
            failure = Some(if restricted && !hello { policy_denied() } else {
                WorkerOutcome::Malformed
            });
            break;
        }
        if can_read != 0 {
            match read_available(&mut stdout, &mut received, limits, started, deadline) {
                Ok(is_eof) => eof = is_eof,
                Err(error) => {
                    failure = Some(if restricted && !hello
                        && !matches!(error, WorkerOutcome::Deadline)
                    {
                        policy_denied()
                    } else {
                        error
                    });
                    break;
                }
            }
        }
        if !hello {
            match try_frame_before_deadline(&mut received, limits, started, deadline) {
                Ok(Some(Frame {
                    request_id: 0,
                    identity,
                    kind: FrameKind::Hello { pid: hello_pid },
                })) if identity == abi::current_identity()
                    && hello_pid == pid
                    && hello_pid != std::process::id()
                    && received.is_empty() =>
                {
                    if let Some(plan) = &launch {
                        match isolation::parent_probe(&child, plan) {
                            Ok(proof) if proof.matches(policy, pid, true) => parent_proof = Some(proof),
                            _ => {
                                failure = Some(policy_denied());
                                break;
                            }
                        }
                    }
                    hello = true
                }
                Ok(Some(Frame { request_id: 0, identity,
                    kind: FrameKind::Response(Response::Rejected(code)) }))
                    if restricted && identity == abi::current_identity()
                        && code == b"E_POLICY_DENIED" && received.is_empty() =>
                {
                    failure = Some(policy_denied());
                    break;
                }
                Ok(Some(_)) => {
                    failure = Some(if restricted { policy_denied() } else {
                        WorkerOutcome::Malformed
                    });
                    break;
                }
                Err(error) => {
                    failure = Some(if restricted && !matches!(error, WorkerOutcome::Deadline) {
                        policy_denied()
                    } else {
                        error
                    });
                    break;
                }
                Ok(None) if eof => {
                    failure = Some(if restricted { policy_denied() } else {
                        WorkerOutcome::Crash
                    });
                    break;
                }
                Ok(None) => {}
            }
        } else {
            if want_write && can_write != 0 {
                match stdin.as_mut().unwrap().write(&request_bytes[offset..]) {
                    Ok(0) => {
                        failure = Some(WorkerOutcome::Malformed);
                        break;
                    }
                    Ok(count) => offset += count,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => {
                        failure = Some(WorkerOutcome::Malformed);
                        break;
                    }
                }
                if offset == request_bytes.len() {
                    stdin.take();
                }
            }
            if offset == request_bytes.len() && response.is_none() {
                match try_frame_before_deadline(&mut received, limits, started, deadline) {
                    Ok(Some(frame))
                        if frame.request_id == request_id
                            && frame.identity == abi::current_identity() =>
                    {
                        response = Some(match frame.kind {
                            FrameKind::Response(response) if restricted =>
                                restricted_outcome(response),
                            FrameKind::Response(Response::Complete(values)) => WorkerOutcome::Complete(values),
                            FrameKind::Response(Response::RuntimeError(bytes)) => WorkerOutcome::RuntimeError(bytes),
                            FrameKind::Response(Response::Rejected(bytes)) => WorkerOutcome::Rejected(bytes),
                            FrameKind::Response(Response::NonCopyable { index, lua_type }) => {
                                WorkerOutcome::NonCopyable { index, lua_type }
                            }
                            _ => WorkerOutcome::Malformed,
                        });
                    }
                    Ok(Some(_)) => {
                        failure = Some(WorkerOutcome::Malformed);
                        break;
                    }
                    Err(error) => {
                        failure = Some(error);
                        break;
                    }
                    Ok(None) if eof => {
                        failure = Some(WorkerOutcome::Crash);
                        break;
                    }
                    Ok(None) => {}
                }
            }
            if response.is_some() && (!received.is_empty() || eof) {
                if !received.is_empty() {
                    failure = Some(WorkerOutcome::Malformed);
                }
                break;
            }
        }
        if eof && !hello {
            failure = Some(if restricted { policy_denied() } else {
                WorkerOutcome::Crash
            });
            break;
        }
    }
    let mut status = if restricted { None } else { child.try_wait().ok().flatten() };
    let mut response_exit_confirmed = false;
    if failure.is_none() && response.is_some() && eof {
        if restricted {
            loop {
                if remaining_ms(started, deadline).is_none() {
                    failure = Some(WorkerOutcome::Deadline);
                    break;
                }
                match exited_without_reap(&child) {
                    Ok(true) => {
                        response_exit_confirmed = true;
                        break;
                    }
                    Ok(false) => std::thread::sleep(Duration::from_millis(1)),
                    Err(()) => {
                        failure = Some(WorkerOutcome::Crash);
                        break;
                    }
                }
            }
        } else {
            while status.is_none() && remaining_ms(started, deadline).is_some() {
                std::thread::sleep(Duration::from_millis(1));
                status = child.try_wait().ok().flatten();
            }
            if status.is_none() {
                failure = Some(WorkerOutcome::Deadline);
            }
        }
    }
    if remaining_ms(started, deadline).is_none()
        && !matches!(failure.as_ref(), Some(WorkerOutcome::Crash))
    {
        failure = Some(WorkerOutcome::Deadline);
    }
    let outcome = failure.unwrap_or_else(|| response.unwrap_or(WorkerOutcome::Malformed));
    finish(child, run_dir, outcome, status, response_exit_confirmed, restricted)
}

fn restricted_outcome(response: Response) -> WorkerOutcome {
    match sanitize_response(response) {
        Response::Complete(values) => WorkerOutcome::Complete(values),
        Response::RuntimeError(code) => WorkerOutcome::RuntimeError(code),
        Response::Rejected(code) => WorkerOutcome::Rejected(code),
        Response::NonCopyable { index, lua_type } => WorkerOutcome::NonCopyable { index, lua_type },
    }
}

fn sanitize_response(response: Response) -> Response {
    match response {
        Response::Complete(values) => {
            let bytes = values.iter().try_fold(0_usize, |used, value| {
                let size = match value {
                    CopyValue::Nil => 1,
                    CopyValue::Boolean(_) => 2,
                    CopyValue::Integer(_) | CopyValue::NumberBits(_) => 9,
                    CopyValue::Bytes(bytes) => bytes.len().checked_add(5)?,
                };
                used.checked_add(size)
            });
            if bytes.is_none_or(|bytes| bytes > OutputBudget::default().max_bytes) {
                Response::Rejected(b"E_OUTPUT_LIMIT".to_vec())
            } else {
                Response::Complete(values)
            }
        }
        Response::RuntimeError(_) => Response::RuntimeError(b"E_WORKER_RUNTIME".to_vec()),
        Response::Rejected(code) if code == b"E_POLICY_DENIED" => Response::Rejected(code),
        Response::Rejected(code) if code == b"E_WORKER_RESOURCE" => Response::Rejected(code),
        Response::Rejected(code) if code == b"E_OUTPUT_LIMIT"
            || code == b"response exceeds frame bound"
            || code == b"string result exceeds bound"
            || code == b"result count exceeds bound" =>
        {
            Response::Rejected(b"E_OUTPUT_LIMIT".to_vec())
        }
        Response::Rejected(_) => Response::Rejected(b"E_WORKER_REJECTED".to_vec()),
        Response::NonCopyable { index, lua_type } => Response::NonCopyable { index, lua_type },
    }
}

fn status_bytes(bytes: &[u8]) -> Vec<u8> {
    bytes[..bytes.len().min(super::codec::MAX_STATUS_BYTES)].to_vec()
}

fn stack_bytes(state: *mut crate::stack::lua_State, index: i32) -> Option<Vec<u8>> {
    let mut len = 0_usize;
    // SAFETY：state 在本函式存活且 stack slot 有效；返回 pointer 僅在此同步呼叫後立即複製，
    // 不跨其他 C API、GC、reentry 或 state drop；長度限制先檢查再解參照。
    let pointer = unsafe { lua_tolstring(state, index, &mut len) };
    if pointer.is_null() || len > super::codec::MAX_STATUS_BYTES {
        return None;
    }
    // SAFETY：上方 Lua API 保證 pointer 在 slot 存活期間可讀 len bytes，立即複製且不保存別名。
    Some(unsafe { std::slice::from_raw_parts(pointer.cast::<u8>(), len) }.to_vec())
}

fn push_copy(owner: &StateOwner, value: &CopyValue) -> Result<(), Response> {
    let state = owner.as_ptr();
    // SAFETY：owner 保活此 worker 的唯一 state，且此呼叫不借出 stack slot。
    let before = unsafe { lua_gettop(state) };
    if before < 0 {
        return Err(Response::RuntimeError(b"argument stack invalid".to_vec()));
    }
    let Some(expected) = before.checked_add(1) else {
        return Err(Response::RuntimeError(b"argument stack bound".to_vec()));
    };
    let pushed = match value {
        CopyValue::Nil => owner.push_value(Value::Nil).is_ok(),
        CopyValue::Boolean(value) => owner.push_value(Value::Boolean(*value)).is_ok(),
        CopyValue::Integer(value) => owner.push_value(Value::Integer(*value)).is_ok(),
        CopyValue::NumberBits(bits) => owner
            .push_value(Value::Float(f64::from_bits(*bits)))
            .is_ok(),
        CopyValue::Bytes(bytes) => {
            // SAFETY：來源 bytes 在同步 adapter 呼叫期間有效；lua_pushlstring 的 Rust
            // C API 邊界只回傳 nullable/result，不 longjmp，建立 Lua root 後才返回。
            !unsafe { lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()) }.is_null()
        }
    };
    if !pushed {
        return Err(Response::RuntimeError(b"argument push failed".to_vec()));
    }
    // SAFETY：同一 owner 保活 state；若 nullable C adapter 沉默失敗，絕不以缺參數執行 Lua。
    if unsafe { lua_gettop(state) } != expected {
        return Err(Response::RuntimeError(b"argument stack mismatch".to_vec()));
    }
    Ok(())
}

fn charge_response_bytes(used: &mut usize, additional: usize, frame_limit: usize) -> bool {
    match used.checked_add(additional) {
        Some(next) if next <= frame_limit => {
            *used = next;
            true
        }
        _ => false,
    }
}

fn copy_results(state: *mut crate::stack::lua_State, limits: Limits) -> Response {
    // SAFETY：state 存活且僅由本 child thread 操作；API 回傳值即時複製。
    let top = unsafe { lua_gettop(state) };
    if top < 0 || top as usize > limits.max_values {
        return Response::Rejected(b"result count exceeds bound".to_vec());
    }
    // 完整 RVWK frame header + Response::Complete tag/count；每個值在複製 bytes 前
    // 計入 tag、length 與 payload，避免 128 個大 Lua string 先累積到 1 GiB。
    let mut encoded_bytes = HEADER_BYTES + 3;
    if encoded_bytes > limits.frame_bytes {
        return Response::Rejected(b"response exceeds frame bound".to_vec());
    }
    let mut values = Vec::new();
    if values.try_reserve_exact(top as usize).is_err() {
        return Response::RuntimeError(b"result allocation failed".to_vec());
    }
    for index in 1..=top {
        // SAFETY：index 為已檢查的有效 C stack slot；讀取不跨 state drop。
        let tag = unsafe { lua_type(state, index) };
        let value = match tag {
            0 => {
                if !charge_response_bytes(&mut encoded_bytes, 1, limits.frame_bytes) {
                    return Response::Rejected(b"response exceeds frame bound".to_vec());
                }
                CopyValue::Nil
            }
            1 => {
                if !charge_response_bytes(&mut encoded_bytes, 1, limits.frame_bytes) {
                    return Response::Rejected(b"response exceeds frame bound".to_vec());
                }
                CopyValue::Boolean(unsafe { lua_toboolean(state, index) } != 0)
            }
            3 => {
                if !charge_response_bytes(&mut encoded_bytes, 9, limits.frame_bytes) {
                    return Response::Rejected(b"response exceeds frame bound".to_vec());
                }
                if unsafe { lua_isinteger(state, index) } != 0 {
                    CopyValue::Integer(unsafe {
                        lua_tointegerx(state, index, std::ptr::null_mut())
                    })
                } else {
                    CopyValue::NumberBits(
                        unsafe { lua_tonumberx(state, index, std::ptr::null_mut()) }.to_bits(),
                    )
                }
            }
            4 => {
                let mut len = 0_usize;
                let pointer = unsafe { lua_tolstring(state, index, &mut len) };
                if pointer.is_null() || len > super::codec::DEFAULT_FRAME_BYTES {
                    return Response::Rejected(b"string result exceeds bound".to_vec());
                }
                let Some(field_bytes) = 5_usize.checked_add(len) else {
                    return Response::Rejected(b"response exceeds frame bound".to_vec());
                };
                if !charge_response_bytes(&mut encoded_bytes, field_bytes, limits.frame_bytes) {
                    return Response::Rejected(b"response exceeds frame bound".to_vec());
                }
                let mut bytes = Vec::new();
                if bytes.try_reserve_exact(len).is_err() {
                    return Response::RuntimeError(b"string copy allocation failed".to_vec());
                }
                // SAFETY：Lua string slot 與 state 在此同步迴圈內存活，不呼叫任何會
                // 移動/釋放此 slot 的 API；立即複製 raw bytes 後不保存 pointer。
                bytes.extend_from_slice(unsafe {
                    std::slice::from_raw_parts(pointer.cast::<u8>(), len)
                });
                CopyValue::Bytes(bytes)
            }
            other if other >= 0 => {
                return Response::NonCopyable {
                    index: index as u16,
                    lua_type: other as u8,
                };
            }
            _ => return Response::Rejected(b"invalid result slot".to_vec()),
        };
        values.push(value);
    }
    Response::Complete(values)
}

fn shutdown_after_response<L>(mut owner: StateOwner, libraries: L, response: Response) -> Response {
    let response = if owner.close_with_finalizers().is_ok() {
        response
    } else {
        Response::RuntimeError(b"child shutdown failed".to_vec())
    };
    drop(owner);
    drop(libraries);
    response
}

fn execute_request(request: Request, cache_root: &Path, limits: Limits, policy: VmPolicy) -> Response {
    #[cfg(feature = "lua54")]
    let profile = LuaProfile::Lua54;
    #[cfg(feature = "lua55")]
    let profile = LuaProfile::Lua55;
    let verified = if request.sidecar.is_empty() {
        match decode_module(&request.rvlu, profile, &VerifyLimits::default()) {
            Ok(module) => module,
            Err(_) => return Response::Rejected(b"RVLU_V2 decode/verify rejected".to_vec()),
        }
    } else {
        let limits = TransportLimits::default();
        let mut work = match OfficialWorkBudget::for_limits(&limits.verify) {
            Ok(work) => work,
            Err(_) => return Response::Rejected(b"transport work limit".to_vec()),
        };
        match decode_transport_module(&request.rvlu, &request.sidecar, profile, &limits, &mut work)
        {
            Ok(module) => module,
            Err(_) => return Response::Rejected(b"transport decode/verify rejected".to_vec()),
        }
    };
    let mut owner = match if policy == VmPolicy::Compatibility {
        StateOwner::new()
    } else {
        StateOwner::new_with_host_services(
            HostServices::deny_all()
                .and_policy(policy)
                .and_output_budget(OutputBudget::default()),
        )
    } {
        Ok(owner) => owner,
        Err(_) => return Response::RuntimeError(b"child VM creation failed".to_vec()),
    };
    if policy != VmPolicy::Compatibility
        && owner.set_worker_fuel_limit(WORKER_REQUEST_FUEL).is_err()
    {
        return shutdown_after_response(
            owner,
            (),
            Response::Rejected(b"E_WORKER_RESOURCE".to_vec()),
        );
    }
    let state = owner.as_ptr();
    let mut libraries: Vec<Rc<NativeLibrary>> = Vec::new();
    if libraries.try_reserve_exact(request.native.len()).is_err() {
        return Response::RuntimeError(b"native lease list allocation failed".to_vec());
    }
    let response = (|| -> Response {
        for spec in request.native {
            let verified = match native::preflight(spec.artifact, &spec.policy, spec.visibility) {
                Ok(verified) => verified,
                Err(_) => return Response::Rejected(b"native preflight rejected".to_vec()),
            };
            let name = match CString::new(spec.module_name) {
                Ok(name) => name,
                Err(_) => return Response::Rejected(b"module name rejected".to_vec()),
            };
            let symbol = match CString::new(spec.opener_symbol) {
                Ok(symbol) => symbol,
                Err(_) => return Response::Rejected(b"opener symbol rejected".to_vec()),
            };
            if policy != VmPolicy::Compatibility
                && !isolation::child_probe(policy, cache_root)
                    .is_ok_and(|proof| proof.matches(policy, std::process::id(), false))
            {
                return Response::Rejected(b"E_POLICY_DENIED".to_vec());
            }
            // SAFETY：worker 私有 request pipe 由已核准宿主送入；預檢已驗 identity/digest，
            // 宿主 CNoUnwind attestation 涵蓋 ctor/dtor/opener，C checkpoint 不跨 Rust frame。
            let (library, status) = match unsafe {
                native::load_trusted(
                    &owner,
                    verified,
                    cache_root,
                    &name,
                    &symbol,
                    spec.global_result,
                    &libraries,
                )
            } {
                Ok(loaded) => loaded,
                Err(_) => return Response::Rejected(b"native load rejected".to_vec()),
            };
            libraries.push(library);
            if status != 0 {
                return Response::RuntimeError(
                    stack_bytes(state, -1).unwrap_or_else(|| b"native opener failed".to_vec()),
                );
            }
            // SAFETY：requiref result 已由 C stack 持根；清空暫存結果仍保留 package/global binding。
            unsafe { lua_settop(state, 0) };
        }
        // SAFETY：此時只有 child 持有 state；完整 GC 在 native binding 已建立後進行。
        let gc_status = unsafe { lua_gc(state, 2) };
        if gc_status < 0 {
            return Response::RuntimeError(b"child GC failed".to_vec());
        }
        if owner.push_verified_module(verified).is_err() {
            return Response::RuntimeError(b"verified module push failed".to_vec());
        }
        for arg in &request.args {
            if let Err(error) = push_copy(&owner, arg) {
                return error;
            }
        }
        // SAFETY：lua_pcallk 自身在純 C protected driver 中執行 guest/native callback；
        // longjmp 僅回 C checkpoint，不越過此 Rust frame。無 continuation/reentry pointer。
        let status = unsafe { lua_pcallk(state, request.args.len() as i32, -1, 0, 0, None) };
        if status != 0 {
            return Response::RuntimeError(
                stack_bytes(state, -1)
                    .unwrap_or_else(|| status_bytes(format!("Lua status {status}").as_bytes())),
            );
        }
        let response_limits = if policy == VmPolicy::Compatibility {
            limits
        } else {
            Limits {
                frame_bytes: limits.frame_bytes.min(
                    HEADER_BYTES + 3 + OutputBudget::default().max_bytes,
                ),
                ..limits
            }
        };
        copy_results(state, response_limits)
    })();
    shutdown_after_response(owner, libraries, response)
}

pub fn worker_main() -> i32 {
    let mut args = std::env::args_os();
    let _program = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new("--rivetlua-worker-v1")) {
        return 2;
    }
    let policy = match args.next().as_deref() {
        None => VmPolicy::Compatibility,
        Some(arg) if arg == std::ffi::OsStr::new("--rivetlua-policy-sandbox") => VmPolicy::Sandbox,
        Some(arg) if arg == std::ffi::OsStr::new("--rivetlua-policy-private") => VmPolicy::PrivateService,
        _ => return 2,
    };
    if args.next().is_some() {
        return 2;
    }
    let cache = match std::env::var_os("RIVETLUA_P16_WORKER_CACHE") {
        Some(cache) => PathBuf::from(cache),
        None if policy == VmPolicy::Compatibility => return 2,
        None => PathBuf::new(),
    };
    let cache_valid = cache.is_absolute() && cache.is_dir();
    if policy == VmPolicy::Compatibility && !cache_valid {
        return 2;
    }
    let limits = Limits::default();
    if policy != VmPolicy::Compatibility
        && (!cache_valid || !isolation::child_probe(policy, &cache)
            .is_ok_and(|proof| proof.matches(policy, std::process::id(), false)))
    {
        let denial = Frame {
            request_id: 0,
            identity: abi::current_identity(),
            kind: FrameKind::Response(Response::Rejected(b"E_POLICY_DENIED".to_vec())),
        };
        if let Ok(bytes) = denial.encode(limits) {
            let mut output = std::io::stdout().lock();
            let _ = output.write_all(&bytes);
            let _ = output.flush();
        }
        return 2;
    }
    let hello = Frame {
        request_id: 0,
        identity: abi::current_identity(),
        kind: FrameKind::Hello {
            pid: std::process::id(),
        },
    };
    let hello_bytes = match hello.encode(limits) {
        Ok(bytes) => bytes,
        Err(_) => return 2,
    };
    let mut output = std::io::stdout().lock();
    if output.write_all(&hello_bytes).is_err() || output.flush().is_err() {
        return 2;
    }
    let mut input = std::io::stdin().lock();
    let mut header = [0_u8; 12];
    if input.read_exact(&mut header).is_err() {
        return 2;
    }
    let len = u32::from_le_bytes(header[8..12].try_into().expect("四位元組")) as usize;
    if len < HEADER_BYTES || len > limits.frame_bytes {
        return 2;
    }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(len).is_err() {
        return 2;
    }
    bytes.extend_from_slice(&header);
    bytes.resize(len, 0);
    if input.read_exact(&mut bytes[12..]).is_err() {
        return 2;
    }
    let mut trailing = [0_u8; 1];
    if input.read(&mut trailing).ok() != Some(0) {
        return 2;
    }
    let frame = match Frame::decode(&bytes, limits) {
        Ok(frame) => frame,
        Err(_) => return 2,
    };
    let FrameKind::Request(request) = frame.kind else {
        return 2;
    };
    let response = execute_request(request, &cache, limits, policy);
    let response = if policy == VmPolicy::Compatibility {
        response
    } else {
        sanitize_response(response)
    };
    let frame = Frame {
        request_id: frame.request_id,
        identity: abi::current_identity(),
        kind: FrameKind::Response(response),
    };
    let bytes = match frame.encode(limits) {
        Ok(bytes) => bytes,
        Err(WireError::Limit) => {
            let fallback = Frame {
                request_id: frame.request_id,
                identity: abi::current_identity(),
                kind: FrameKind::Response(Response::Rejected(if policy == VmPolicy::Compatibility {
                    b"response exceeds frame bound".to_vec()
                } else {
                    b"E_OUTPUT_LIMIT".to_vec()
                })),
            };
            match fallback.encode(limits) {
                Ok(bytes) => bytes,
                Err(_) => return 2,
            }
        }
        Err(_) => return 2,
    };
    if output.write_all(&bytes).is_err() || output.flush().is_err() {
        return 2;
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stack::{
        lua_createtable, lua_pushcclosure, lua_pushstring, lua_rawset, lua_setmetatable,
    };
    use rivetlua_runtime::LedgerProbe;
    use std::any::Any;
    use std::cell::Cell;
    use std::io;

    thread_local! {
        static CLOSE_FINALIZER_COUNT: Cell<u32> = const { Cell::new(0) };
    }

    unsafe extern "C" fn mark_close_finalizer(_state: *mut crate::stack::lua_State) -> i32 {
        CLOSE_FINALIZER_COUNT.with(|count| count.set(count.get() + 1));
        0
    }

    struct LeaseDrop(Rc<Cell<bool>>);

    impl Drop for LeaseDrop {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    struct DropNotice {
        dropped: Rc<Cell<bool>>,
        lease_dropped: Rc<Cell<bool>>,
        ledger: LedgerProbe,
    }

    impl Drop for DropNotice {
        fn drop(&mut self) {
            assert!(self.lease_dropped.get(), "owner 須先釋放 native lease");
            let snapshot = self.ledger.snapshot();
            assert_eq!(snapshot.committed, 0);
            assert_eq!(snapshot.reserved, 0);
            self.dropped.set(true);
        }
    }

    #[test]
    fn close_failure_overrides_reply_and_releases_libraries() {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let ledger = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        let lease_dropped = Rc::new(Cell::new(false));
        let lease: Rc<dyn Any> = Rc::new(LeaseDrop(Rc::clone(&lease_dropped)));
        owner
            .reserve_native_lease(37)
            .unwrap()
            .publish(lease)
            .unwrap();
        CLOSE_FINALIZER_COUNT.with(|count| count.set(0));
        // SAFETY：私有 state 存活；純 C callback 僅記錄計數，先移除 stack root，
        // 使 shutdown finalizer 路徑有真實待處理物件。
        unsafe {
            lua_createtable(state, 0, 0);
            lua_createtable(state, 0, 1);
            lua_pushstring(state, c"__gc".as_ptr());
            lua_pushcclosure(state, Some(mark_close_finalizer), 0);
            lua_rawset(state, -3);
            assert_eq!(lua_setmetatable(state, -2), 1);
            lua_settop(state, 0);
        }
        for index in 0..20 {
            owner.push_value(Value::Integer(1000 + index)).unwrap();
        }
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
            .unwrap();
        let dropped = Rc::new(Cell::new(false));
        let response = shutdown_after_response(
            owner,
            DropNotice {
                dropped: Rc::clone(&dropped),
                lease_dropped: Rc::clone(&lease_dropped),
                ledger: ledger.clone(),
            },
            Response::Complete(vec![CopyValue::Integer(7)]),
        );
        assert_eq!(
            response,
            Response::RuntimeError(b"child shutdown failed".to_vec())
        );
        assert_eq!(
            ledger.trace().last_failure.unwrap().attempt.ordinal,
            ordinal
        );
        CLOSE_FINALIZER_COUNT.with(|count| assert_eq!(count.get(), 0));
        assert!(lease_dropped.get());
        assert!(dropped.get());
        assert_eq!(ledger.snapshot().committed, 0);
        assert_eq!(ledger.snapshot().reserved, 0);
    }

    #[test]
    fn aggregate_result_frame_limit_precedes_second_string_copy() {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let bytes = vec![0xA5_u8; 4096];
        for _ in 0..2 {
            // SAFETY：owner 保活私有 state；bytes 在同步 adapter 呼叫期間有效。
            assert!(
                !unsafe { lua_pushlstring(state, bytes.as_ptr().cast(), bytes.len()) }.is_null()
            );
        }
        // 兩個 string 各需 tag(1)+len(4)+payload(4096)；僅少一 byte 的總框架上限。
        let limits = Limits {
            frame_bytes: HEADER_BYTES + 3 + 2 * (5 + bytes.len()) - 1,
            ..Limits::default()
        };
        assert_eq!(
            copy_results(state, limits),
            Response::Rejected(b"response exceeds frame bound".to_vec())
        );
        let fitting = Limits {
            frame_bytes: limits.frame_bytes + 1,
            ..limits
        };
        assert_eq!(
            copy_results(state, fitting),
            Response::Complete(vec![
                CopyValue::Bytes(bytes.clone()),
                CopyValue::Bytes(bytes)
            ])
        );
    }

    struct RepeatingReader {
        reads: usize,
    }

    impl Read for RepeatingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.reads == 1000 {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            std::thread::sleep(Duration::from_millis(1));
            self.reads += 1;
            buffer[0] = b'X';
            Ok(1)
        }
    }

    #[test]
    fn repeating_stdout_stops_at_deadline_inside_read_loop() {
        let started = Instant::now();
        let mut reader = RepeatingReader { reads: 0 };
        let mut buffer = Vec::new();
        assert!(matches!(
            read_available(
                &mut reader,
                &mut buffer,
                Limits::default(),
                started,
                Duration::from_millis(30)
            ),
            Err(WorkerOutcome::Deadline)
        ));
        assert!(reader.reads < 1000, "不得等流量停下才檢查 deadline");
        assert!(buffer.len() < 1000);
    }

    #[test]
    fn primitive_push_allocation_failure_is_structured_and_keeps_top() {
        let owner = StateOwner::new().unwrap();
        let state = owner.as_ptr();
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
            .unwrap();
        let mut observed = false;
        for _ in 0..1024 {
            // SAFETY：owner 保活私有 state；只在此執行緒同步讀 top。
            let before = unsafe { lua_gettop(state) };
            match push_copy(&owner, &CopyValue::Integer(7)) {
                Ok(()) => assert_eq!(unsafe { lua_gettop(state) }, before + 1),
                Err(Response::RuntimeError(message)) => {
                    assert_eq!(message, b"argument push failed");
                    assert_eq!(unsafe { lua_gettop(state) }, before);
                    observed = true;
                    break;
                }
                other => panic!("參數推入意外結果：{other:?}"),
            }
        }
        assert!(observed, "未命中已注入的 stack allocation failure");
        assert_eq!(
            owner
                .with_vm(|vm| vm
                    .allocation_trace()
                    .last_failure
                    .map(|failure| failure.attempt.ordinal))
                .unwrap(),
            Some(ordinal)
        );
    }
}
