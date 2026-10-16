//! macOS worker 必須由不同簽名身分的 App Sandbox 程序承載。

use std::ffi::{c_char, c_int, c_void, CString, OsStr};
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::ptr::{self, NonNull};

use rivetlua_runtime::VmPolicy;

use super::PolicyDenied;

const SIGNING_INFO: u32 = 1 << 1;
const NO_NETWORK_VALIDATION: u32 = 1 << 29;
const SANDBOX_FILTER_PATH: c_int = 1;
const UTF8: u32 = 0x0800_0100;
const RLIMIT_CPU: c_int = 0;
const RLIMIT_FSIZE: c_int = 1;
const RLIMIT_CORE: c_int = 4;
const RLIMIT_NPROC: c_int = 7;
const RLIMIT_NOFILE: c_int = 8;
const MAX_FILE_BYTES: u64 = crate::native::MAX_NATIVE_BYTES as u64;

pub(super) struct PlatformLaunch {
    binary: PathBuf,
    device: u64,
    inode: u64,
    code_hash: Vec<u8>,
}

pub(super) struct PlatformEvidence {
    _private: (),
}

struct Cf(NonNull<c_void>);

impl Cf {
    fn owned(value: *const c_void) -> Result<Self, PolicyDenied> {
        NonNull::new(value.cast_mut())
            .map(Self)
            .ok_or(PolicyDenied::MissingEvidence)
    }

    fn as_ptr(&self) -> *const c_void {
        self.0.as_ptr()
    }
}

impl Drop for Cf {
    fn drop(&mut self) {
        // SAFETY：Cf 只包住 CoreFoundation 的 +1 回傳值，恰好釋放一次。
        unsafe { CFRelease(self.as_ptr()) };
    }
}

#[repr(C)]
struct Rlimit {
    current: u64,
    maximum: u64,
}

#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: *const c_void);
    fn CFURLCreateFromFileSystemRepresentation(
        allocator: *const c_void,
        path: *const u8,
        length: isize,
        is_directory: u8,
    ) -> *const c_void;
    fn CFStringCreateWithCString(
        allocator: *const c_void,
        text: *const c_char,
        encoding: u32,
    ) -> *const c_void;
    fn CFGetTypeID(value: *const c_void) -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFBooleanGetValue(value: *const c_void) -> u8;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFDictionaryGetCount(value: *const c_void) -> isize;
    fn CFDictionaryGetValue(value: *const c_void, key: *const c_void) -> *const c_void;
    fn CFStringGetTypeID() -> usize;
    fn CFStringGetLength(value: *const c_void) -> isize;
    fn CFStringHasSuffix(value: *const c_void, suffix: *const c_void) -> u8;
    fn CFEqual(left: *const c_void, right: *const c_void) -> u8;
    fn CFDataGetTypeID() -> usize;
    fn CFDataGetLength(value: *const c_void) -> isize;
    fn CFDataGetBytePtr(value: *const c_void) -> *const u8;
}

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoEntitlementsDict: *const c_void;
    static kSecCodeInfoTeamIdentifier: *const c_void;
    static kSecCodeInfoIdentifier: *const c_void;
    static kSecCodeInfoUnique: *const c_void;
    fn SecStaticCodeCreateWithPath(
        path: *const c_void,
        flags: u32,
        code: *mut *const c_void,
    ) -> c_int;
    fn SecStaticCodeCheckValidity(
        code: *const c_void,
        flags: u32,
        requirement: *const c_void,
    ) -> c_int;
    fn SecCodeCopySigningInformation(
        code: *const c_void,
        flags: u32,
        info: *mut *const c_void,
    ) -> c_int;
    fn SecTaskCreateFromSelf(allocator: *const c_void) -> *const c_void;
    fn SecTaskCopyValueForEntitlement(
        task: *const c_void,
        entitlement: *const c_void,
        error: *mut *const c_void,
    ) -> *const c_void;
}

unsafe extern "C" {
    fn getpid() -> c_int;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getpgrp() -> c_int;
    fn getpgid(pid: c_int) -> c_int;
    fn proc_pidpath(pid: c_int, path: *mut c_void, size: u32) -> c_int;
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        argument: u64,
        buffer: *mut c_void,
        size: c_int,
    ) -> c_int;
    fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
    fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn getdtablesize() -> c_int;
    // libSystem 在 macOS SDK 匯出此查詢；只查當前 worker，不查其他程序。
    fn sandbox_check(pid: c_int, operation: *const c_char, filter: c_int, ...) -> c_int;
}

fn cf_string(value: &str) -> Result<Cf, PolicyDenied> {
    let text = CString::new(value).map_err(|_| PolicyDenied::InvalidWorker)?;
    // SAFETY：CString 在呼叫期間有效，CoreFoundation 保留新字串。
    Cf::owned(unsafe { CFStringCreateWithCString(ptr::null(), text.as_ptr(), UTF8) })
}

fn info_value(
    info: &Cf,
    key: *const c_void,
    expected_type: usize,
) -> Result<*const c_void, PolicyDenied> {
    // SAFETY：info 是有效的 CFDictionary；回傳值由 info 保活，不由此處釋放。
    let value = unsafe { CFDictionaryGetValue(info.as_ptr(), key) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != expected_type {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(value)
}

fn signing_info(path: &Path) -> Result<Cf, PolicyDenied> {
    let bytes = path.as_os_str().as_bytes();
    let length = isize::try_from(bytes.len()).map_err(|_| PolicyDenied::InvalidWorker)?;
    // SAFETY：絕對路徑 bytes 在呼叫期間有效；Security 只讀取靜態簽名，不啟動程序。
    let url = Cf::owned(unsafe {
        CFURLCreateFromFileSystemRepresentation(ptr::null(), bytes.as_ptr(), length, 0)
    })?;
    let mut code = ptr::null();
    // SAFETY：out pointer 可寫；成功後的 code 是 +1 CF 物件。
    if unsafe { SecStaticCodeCreateWithPath(url.as_ptr(), 0, &mut code) } != 0 {
        return Err(PolicyDenied::InvalidWorker);
    }
    let code = Cf::owned(code)?;
    // SAFETY：只驗磁碟上的密封內容；禁止驗證過程的網路請求。
    if unsafe { SecStaticCodeCheckValidity(code.as_ptr(), NO_NETWORK_VALIDATION, ptr::null()) }
        != 0
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    let mut info = ptr::null();
    // SAFETY：已驗簽名的 code 保活；成功回傳 +1 CFDictionary。
    if unsafe { SecCodeCopySigningInformation(code.as_ptr(), SIGNING_INFO, &mut info) } != 0 {
        return Err(PolicyDenied::InvalidWorker);
    }
    Cf::owned(info)
}

fn code_hash(info: &Cf) -> Result<Vec<u8>, PolicyDenied> {
    // SAFETY：SDK 的 CFTypeID 與常數 key 在程序生命週期有效。
    let value = info_value(info, unsafe { kSecCodeInfoUnique }, unsafe { CFDataGetTypeID() })?;
    // SAFETY：CFData 由 info 保活，複製後不保留借用指標。
    let length = unsafe { CFDataGetLength(value) };
    if !(20..=64).contains(&length) {
        return Err(PolicyDenied::MissingEvidence);
    }
    let bytes = unsafe { CFDataGetBytePtr(value) };
    if bytes.is_null() {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(unsafe { std::slice::from_raw_parts(bytes, length as usize) }.to_vec())
}

fn minimal_entitlements(info: &Cf) -> Result<(), PolicyDenied> {
    // SAFETY：已驗簽名資訊中的 entitlement 必須是字典，且只能有 App Sandbox。
    let entitlements = info_value(info, unsafe { kSecCodeInfoEntitlementsDict }, unsafe {
        CFDictionaryGetTypeID()
    })?;
    if unsafe { CFDictionaryGetCount(entitlements) } != 1 {
        return Err(PolicyDenied::InvalidWorker);
    }
    let key = cf_string("com.apple.security.app-sandbox")?;
    // SAFETY：key 與 entitlement 字典在呼叫期間有效。
    let sandbox = unsafe { CFDictionaryGetValue(entitlements, key.as_ptr()) };
    if sandbox.is_null()
        || unsafe { CFGetTypeID(sandbox) } != unsafe { CFBooleanGetTypeID() }
        || unsafe { CFBooleanGetValue(sandbox) } == 0
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    Ok(())
}

fn identity(info: &Cf, key: *const c_void) -> Result<*const c_void, PolicyDenied> {
    // SAFETY：SDK 的字串型簽名欄位在 info 存活期間有效。
    let value = info_value(info, key, unsafe { CFStringGetTypeID() })?;
    if unsafe { CFStringGetLength(value) } == 0 {
        return Err(PolicyDenied::InvalidWorker);
    }
    Ok(value)
}

fn private_run_dir(path: &Path) -> Result<(), PolicyDenied> {
    let metadata = fs::metadata(path).map_err(|_| PolicyDenied::InvalidWorker)?;
    if !path.is_absolute() || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != unsafe { geteuid() }
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    Ok(())
}

pub(super) fn configure(
    cmd: &mut Command,
    binary: &Path,
    run_dir: &Path,
    policy: VmPolicy,
) -> Result<PlatformLaunch, PolicyDenied> {
    if policy == VmPolicy::Compatibility
        || !binary.is_absolute()
        || unsafe { getuid() } == 0
        || unsafe { geteuid() } == 0
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    private_run_dir(run_dir)?;
    let binary = fs::canonicalize(binary).map_err(|_| PolicyDenied::InvalidWorker)?;
    let metadata = fs::metadata(&binary).map_err(|_| PolicyDenied::InvalidWorker)?;
    if binary.file_name() != Some(OsStr::new("rivetlua-native-worker"))
        || !metadata.is_file()
        || metadata.mode() & 0o6022 != 0
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    let worker = signing_info(&binary)?;
    minimal_entitlements(&worker)?;
    let host_path = std::env::current_exe().map_err(|_| PolicyDenied::InvalidWorker)?;
    let host = signing_info(&host_path)?;
    // SAFETY：team 與 identifier 欄位均由兩份已驗靜態簽名保活。
    let worker_team = identity(&worker, unsafe { kSecCodeInfoTeamIdentifier })?;
    let host_team = identity(&host, unsafe { kSecCodeInfoTeamIdentifier })?;
    let worker_id = identity(&worker, unsafe { kSecCodeInfoIdentifier })?;
    let host_id = identity(&host, unsafe { kSecCodeInfoIdentifier })?;
    let worker_name = cf_string("rivetlua-native-worker")?;
    let worker_suffix = cf_string(".rivetlua-native-worker")?;
    if unsafe { CFEqual(worker_team, host_team) } == 0
        || unsafe { CFEqual(worker_id, host_id) } != 0
        || (unsafe { CFEqual(worker_id, worker_name.as_ptr()) } == 0
            && unsafe { CFStringHasSuffix(worker_id, worker_suffix.as_ptr()) } == 0)
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    let code_hash = code_hash(&worker)?;
    // SAFETY：getdtablesize 僅在 parent 呼叫；child 的 pre_exec 不呼叫非 async-signal-safe 查詢。
    let fd_limit = unsafe { getdtablesize() };
    if !(3..=1_048_576).contains(&fd_limit) {
        return Err(PolicyDenied::Resource);
    }
    // SAFETY：pre_exec 僅執行 async-signal-safe 的 rlimit/close 系統呼叫；不觸及 Rust 鎖或配置。
    unsafe {
        cmd.pre_exec(move || {
            for (resource, value) in [
                (RLIMIT_CPU, 30),
                (RLIMIT_FSIZE, MAX_FILE_BYTES),
                (RLIMIT_CORE, 0),
                (RLIMIT_NPROC, 0),
                (RLIMIT_NOFILE, 64),
            ] {
                let limit = Rlimit { current: value, maximum: value };
                if setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for fd in 3..fd_limit {
                close(fd);
            }
            Ok(())
        });
    }
    Ok(PlatformLaunch {
        binary,
        device: metadata.dev(),
        inode: metadata.ino(),
        code_hash,
    })
}

pub(super) fn parent_probe(
    child: &Child,
    launch: &PlatformLaunch,
    policy: VmPolicy,
) -> Result<PlatformEvidence, PolicyDenied> {
    let pid = c_int::try_from(child.id()).map_err(|_| PolicyDenied::MissingEvidence)?;
    if policy == VmPolicy::Compatibility || pid <= 0 || unsafe { getpgid(pid) } != pid {
        return Err(PolicyDenied::MissingEvidence);
    }
    let mut path = [0_u8; 4096];
    // SAFETY：proc_pidpath 僅讀 kernel 的程序路徑，沒有 task port 或 process attach。
    let length = unsafe { proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if length <= 0 || length as usize >= path.len() {
        return Err(PolicyDenied::MissingEvidence);
    }
    let bytes = &path[..length as usize];
    let bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
    if bytes.contains(&0) {
        return Err(PolicyDenied::MissingEvidence);
    }
    let observed = PathBuf::from(OsStr::from_bytes(bytes));
    if fs::canonicalize(observed).ok().as_deref() != Some(launch.binary.as_path()) {
        return Err(PolicyDenied::MissingEvidence);
    }
    let metadata = fs::metadata(&launch.binary).map_err(|_| PolicyDenied::MissingEvidence)?;
    if metadata.dev() != launch.device || metadata.ino() != launch.inode {
        return Err(PolicyDenied::MissingEvidence);
    }
    let info = signing_info(&launch.binary)?;
    minimal_entitlements(&info)?;
    if code_hash(&info)? != launch.code_hash {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(PlatformEvidence { _private: () })
}

fn kernel_policy(operation: &str, path: Option<&Path>, allowed: bool) -> Result<(), PolicyDenied> {
    let operation = CString::new(operation).map_err(|_| PolicyDenied::MissingEvidence)?;
    // SAFETY：只對當前程序查詢 kernel sandbox policy；路徑 CString 在呼叫期間有效。
    let result = match path {
        Some(path) => {
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| PolicyDenied::MissingEvidence)?;
            unsafe {
                sandbox_check(getpid(), operation.as_ptr(), SANDBOX_FILTER_PATH, path.as_ptr())
            }
        }
        None => unsafe { sandbox_check(getpid(), operation.as_ptr(), 0) },
    };
    if (allowed && result == 0) || (!allowed && result == 1) {
        Ok(())
    } else {
        Err(PolicyDenied::MissingEvidence)
    }
}

fn resource_limits() -> Result<(), PolicyDenied> {
    for (resource, expected) in [
        (RLIMIT_CPU, 30),
        (RLIMIT_FSIZE, MAX_FILE_BYTES),
        (RLIMIT_CORE, 0),
        (RLIMIT_NPROC, 0),
        (RLIMIT_NOFILE, 64),
    ] {
        let mut limit = Rlimit { current: u64::MAX, maximum: u64::MAX };
        // SAFETY：getrlimit 寫入固定大小的 C 結構；返回值在使用前核對。
        if unsafe { getrlimit(resource, &mut limit) } != 0
            || limit.current > expected
            || limit.maximum > expected
        {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    Ok(())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FdInfo {
    fd: i32,
    _kind: u32,
}

fn only_stdio_fds() -> Result<(), PolicyDenied> {
    let mut fds = [FdInfo { fd: -1, _kind: 0 }; 64];
    let size = c_int::try_from(std::mem::size_of_val(&fds))
        .map_err(|_| PolicyDenied::MissingEvidence)?;
    // SAFETY：proc_pidinfo 僅列舉自身 kernel FD 表，buffer 長度與 C 結構一致。
    let bytes = unsafe { proc_pidinfo(getpid(), 1, 0, fds.as_mut_ptr().cast(), size) };
    let entry_size = std::mem::size_of::<FdInfo>();
    if bytes <= 0 || bytes as usize > std::mem::size_of_val(&fds)
        || bytes as usize % entry_size != 0
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    let count = bytes as usize / entry_size;
    if count != 3
        || fds[..count]
            .iter()
            .try_fold(0_u8, |seen, entry| {
                let bit = 1_u8.checked_shl(entry.fd.try_into().ok()?)?;
                if bit > 0b100 || seen & bit != 0 { None } else { Some(seen | bit) }
            }) != Some(0b111)
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(())
}

pub(super) fn child_probe(
    policy: VmPolicy,
    run_dir: &Path,
) -> Result<PlatformEvidence, PolicyDenied> {
    if policy == VmPolicy::Compatibility
        || unsafe { getuid() } == 0
        || unsafe { geteuid() } == 0
        || unsafe { getpid() } != unsafe { getpgrp() }
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    private_run_dir(run_dir)?;
    resource_limits()?;
    only_stdio_fds()?;
    let task = Cf::owned(unsafe { SecTaskCreateFromSelf(ptr::null()) })?;
    let key = cf_string("com.apple.security.app-sandbox")?;
    // SAFETY：SecTask 代表當前程序；只讀取 kernel 已賦予的 entitlement。
    let sandbox = Cf::owned(unsafe {
        SecTaskCopyValueForEntitlement(task.as_ptr(), key.as_ptr(), ptr::null_mut())
    })?;
    if unsafe { CFGetTypeID(sandbox.as_ptr()) } != unsafe { CFBooleanGetTypeID() }
        || unsafe { CFBooleanGetValue(sandbox.as_ptr()) } == 0
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    kernel_policy("network-inbound", None, false)?;
    kernel_policy("network-outbound", None, false)?;
    // 原生碼不能建立子孫程序；group leader 自身不能 setsid，最後由 Child::kill 終止。
    kernel_policy("process-fork", None, false)?;
    kernel_policy("process-exec", None, false)?;
    kernel_policy(
        "file-read-data",
        Some(Path::new("/private/var/db/dslocal/nodes/Default/users")),
        false,
    )?;
    kernel_policy("file-write-data", Some(Path::new("/private/etc/hosts")), false)?;
    kernel_policy("file-read-data", Some(Path::new("/dev/disk0")), false)?;
    kernel_policy("file-read-data", Some(run_dir), true)?;
    kernel_policy("file-write-create", Some(&run_dir.join("rivetlua-native-probe")), true)?;
    Ok(PlatformEvidence { _private: () })
}
