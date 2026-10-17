//! Linux 受限 worker：只有核心實際建立且雙端探測完整隔離後才產生證據。

use std::ffi::{CString, c_void};
use std::fs::{self, File};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};

use rivetlua_runtime::VmPolicy;

use super::PolicyDenied;

const WORKER_UID: u32 = 65534;
const WORKER_GID: u32 = 65534;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const ROOT_FLAGS: libc::c_ulong = (libc::MS_NOSUID | libc::MS_NODEV) as libc::c_ulong;
const BIND_FLAGS: libc::c_ulong =
    (libc::MS_BIND | libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV)
        as libc::c_ulong;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 4;
const LIMITS: &[(libc::c_uint, libc::rlim_t)] = &[
    (libc::RLIMIT_AS, 512 * 1024 * 1024),
    (libc::RLIMIT_CPU, 10),
    (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
    (libc::RLIMIT_NOFILE, 64),
    (libc::RLIMIT_NPROC, 0),
    (libc::RLIMIT_CORE, 0),
];

pub(super) struct PlatformLaunch {
    policy: VmPolicy,
    binary_id: (u64, u64),
    root: PathBuf,
    mounts: Vec<(String, (u64, u64))>,
    parent_namespaces: [PathBuf; 3],
}

pub(super) struct PlatformEvidence {
    _private: (),
}

struct Bind {
    source: CString,
    target: CString,
    file: bool,
    _opened: File,
}

struct Setup {
    root: CString,
    directories: Vec<CString>,
    cache: CString,
    binds: Vec<Bind>,
    cap_last: u32,
}

static FILTER_INSTALLED: AtomicBool = AtomicBool::new(false);

fn c_path(path: &Path) -> Result<CString, PolicyDenied> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| PolicyDenied::InvalidWorker)
}

fn pinned(path: &Path) -> Result<File, PolicyDenied> {
    let opened = File::open(path).map_err(|_| PolicyDenied::InvalidWorker)?;
    // SAFETY：新 fd 由 F_DUPFD_CLOEXEC 唯一建立；確保 stdio 重定向不覆寫 bind 來源。
    let fd = unsafe { libc::fcntl(opened.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        return Err(PolicyDenied::Resource);
    }
    // SAFETY：fcntl 成功回傳尚無 Rust owner 的新 fd，交給 File 獨占關閉。
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn normal_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && path.to_str().is_some_and(|text| {
            !text
                .bytes()
                .any(|byte| matches!(byte, b' ' | b'\\' | b'\n' | b'\t'))
        })
}

fn identity(path: &Path) -> Result<(u64, u64), PolicyDenied> {
    let meta = fs::metadata(path).map_err(|_| PolicyDenied::InvalidWorker)?;
    if !meta.is_file() {
        return Err(PolicyDenied::InvalidWorker);
    }
    Ok((meta.dev(), meta.ino()))
}

fn add_directories(path: &Path, directories: &mut Vec<CString>) -> Result<(), PolicyDenied> {
    let mut prefix = PathBuf::new();
    for part in path.components() {
        let Component::Normal(name) = part else {
            return Err(PolicyDenied::InvalidWorker);
        };
        prefix.push(name);
        let entry = c_path(&prefix)?;
        if !directories.iter().any(|known| known == &entry) {
            directories.push(entry);
        }
    }
    Ok(())
}

fn prepare(
    binary: &Path,
    run_dir: &Path,
    artifacts: &[PathBuf],
) -> Result<(Setup, Vec<(String, (u64, u64))>), PolicyDenied> {
    if artifacts.len() > 16 {
        return Err(PolicyDenied::InvalidWorker);
    }
    let mut directories = Vec::new();
    let mut binds = Vec::new();
    let mut mounts = Vec::new();
    let library_paths = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"];
    for name in library_paths {
        let path = Path::new(name);
        if !path.is_dir() {
            continue;
        }
        if binary.starts_with(path) || run_dir.starts_with(path) {
            return Err(PolicyDenied::InvalidWorker);
        }
        let target = path
            .strip_prefix("/")
            .map_err(|_| PolicyDenied::InvalidWorker)?;
        add_directories(target, &mut directories)?;
        let opened = pinned(path).map_err(|_| PolicyDenied::Unsupported)?;
        let meta = opened.metadata().map_err(|_| PolicyDenied::Unsupported)?;
        binds.push(Bind {
            source: CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
                .map_err(|_| PolicyDenied::InvalidWorker)?,
            target: c_path(target)?,
            file: false,
            _opened: opened,
        });
        mounts.push((name.to_owned(), (meta.dev(), meta.ino())));
    }
    let binary_target = binary
        .strip_prefix("/")
        .map_err(|_| PolicyDenied::InvalidWorker)?;
    add_directories(
        binary_target.parent().ok_or(PolicyDenied::InvalidWorker)?,
        &mut directories,
    )?;
    let opened = pinned(binary)?;
    let meta = opened.metadata().map_err(|_| PolicyDenied::InvalidWorker)?;
    binds.push(Bind {
        source: CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
            .map_err(|_| PolicyDenied::InvalidWorker)?,
        target: c_path(binary_target)?,
        file: true,
        _opened: opened,
    });
    mounts.push((
        binary
            .to_str()
            .ok_or(PolicyDenied::InvalidWorker)?
            .to_owned(),
        (meta.dev(), meta.ino()),
    ));
    for artifact in artifacts {
        if !normal_absolute(artifact)
            || artifact == binary
            || artifact.starts_with(run_dir)
            || library_paths
                .iter()
                .any(|path| artifact.starts_with(Path::new(path)))
            || mounts
                .iter()
                .any(|(path, _)| Path::new(path.as_str()) == artifact)
            || !fs::symlink_metadata(artifact)
                .map_err(|_| PolicyDenied::InvalidWorker)?
                .is_file()
        {
            return Err(PolicyDenied::InvalidWorker);
        }
        let target = artifact
            .strip_prefix("/")
            .map_err(|_| PolicyDenied::InvalidWorker)?;
        add_directories(
            target.parent().ok_or(PolicyDenied::InvalidWorker)?,
            &mut directories,
        )?;
        let opened = pinned(artifact)?;
        let meta = opened.metadata().map_err(|_| PolicyDenied::InvalidWorker)?;
        if !meta.is_file() {
            return Err(PolicyDenied::InvalidWorker);
        }
        binds.push(Bind {
            source: CString::new(format!("/proc/self/fd/{}", opened.as_raw_fd()))
                .map_err(|_| PolicyDenied::InvalidWorker)?,
            target: c_path(target)?,
            file: true,
            _opened: opened,
        });
        mounts.push((
            artifact
                .to_str()
                .ok_or(PolicyDenied::InvalidWorker)?
                .to_owned(),
            (meta.dev(), meta.ino()),
        ));
    }
    let cache = run_dir
        .strip_prefix("/")
        .map_err(|_| PolicyDenied::InvalidWorker)?;
    add_directories(cache, &mut directories)?;
    let cap_last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|_| PolicyDenied::Unsupported)?
        .trim()
        .parse::<u32>()
        .map_err(|_| PolicyDenied::Unsupported)?;
    if cap_last > 63 {
        return Err(PolicyDenied::Unsupported);
    }
    Ok((
        Setup {
            root: c_path(run_dir)?,
            directories,
            cache: c_path(cache)?,
            binds,
            cap_last,
        },
        mounts,
    ))
}

pub(super) fn configure(
    command: &mut Command,
    binary: &Path,
    run_dir: &Path,
    policy: VmPolicy,
    artifacts: &[PathBuf],
) -> Result<PlatformLaunch, PolicyDenied> {
    if policy == VmPolicy::Compatibility
        || !normal_absolute(binary)
        || !normal_absolute(run_dir)
        || !run_dir.is_dir()
    {
        return Err(PolicyDenied::InvalidWorker);
    }
    // 目前沒有獨立 worker 映像的受信任簽章契約；只接受宿主自己的同一 inode。
    let binary_id = identity(binary)?;
    let binary_meta = fs::metadata(binary).map_err(|_| PolicyDenied::InvalidWorker)?;
    if binary_meta.uid() != 0 || binary_meta.mode() & 0o022 != 0 {
        return Err(PolicyDenied::Unsupported);
    }
    let own_exe = fs::read_link("/proc/self/exe").map_err(|_| PolicyDenied::Unsupported)?;
    if binary_id != identity(&own_exe)? {
        return Err(PolicyDenied::InvalidWorker);
    }
    // 要取得與宿主不同的外層 UID/GID，啟動者須能在 fork 後先降為 nobody。
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return Err(PolicyDenied::Unsupported);
    }
    let root = fs::canonicalize(run_dir).map_err(|_| PolicyDenied::InvalidWorker)?;
    let parent_namespaces =
        ["user", "mnt", "net"].map(|name| fs::read_link(format!("/proc/self/ns/{name}")));
    let parent_namespaces = [
        parent_namespaces[0]
            .as_ref()
            .map_err(|_| PolicyDenied::Unsupported)?
            .clone(),
        parent_namespaces[1]
            .as_ref()
            .map_err(|_| PolicyDenied::Unsupported)?
            .clone(),
        parent_namespaces[2]
            .as_ref()
            .map_err(|_| PolicyDenied::Unsupported)?
            .clone(),
    ];
    let (setup, mounts) = prepare(binary, run_dir, artifacts)?;
    // SAFETY：callback 只操作已預製 C 字串與裸 syscall，不配置、不鎖定、不觸碰 Rust I/O。
    unsafe {
        command.pre_exec(move || setup_child(&setup));
    }
    Ok(PlatformLaunch {
        policy,
        binary_id,
        root,
        mounts,
        parent_namespaces,
    })
}

fn syscall_ok(value: libc::c_int) -> io::Result<()> {
    if value == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn write_map(path: &std::ffi::CStr, data: &[u8]) -> io::Result<()> {
    // SAFETY：固定 /proc/self 路徑及預先格式化 bytes；僅呼叫 open/write/close。
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = unsafe { libc::write(fd, data.as_ptr().cast::<c_void>(), data.len()) };
    let write_error = if count == data.len() as isize {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    let closed = unsafe { libc::close(fd) };
    if let Some(error) = write_error {
        Err(error)
    } else {
        syscall_ok(closed)
    }
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}
#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

unsafe fn drop_capabilities(last: u32) -> io::Result<()> {
    // SAFETY：只改本子程序的 securebits、ambient/bounding set 與 v3 capability set。
    syscall_ok(unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    })?;
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_SECUREBITS, 0x0f, 0, 0, 0) })?;
    for cap in 0..=last {
        syscall_ok(unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap) })?;
    }
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let result = unsafe { libc::syscall(libc::SYS_capset, &header, data.as_ptr()) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

unsafe fn setup_child(setup: &Setup) -> io::Result<()> {
    // SAFETY：先建立獨立 mount namespace，避免任何掛載傳回宿主。
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWNS) })?;
    syscall_ok(unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as libc::c_ulong,
            std::ptr::null(),
        )
    })?;
    syscall_ok(unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            setup.root.as_ptr(),
            c"tmpfs".as_ptr(),
            ROOT_FLAGS,
            c"size=67108864,mode=0700".as_ptr().cast(),
        )
    })?;
    // SAFETY：覆掛後以絕對路徑重新進入新 tmpfs；不能沿用指向舊 mount 的 cwd。
    syscall_ok(unsafe { libc::chdir(setup.root.as_ptr()) })?;
    syscall_ok(unsafe { libc::chown(c".".as_ptr(), WORKER_UID, WORKER_GID) })?;
    for directory in &setup.directories {
        let result = unsafe { libc::mkdir(directory.as_ptr(), 0o755) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    for bind in &setup.binds {
        if bind.file {
            let fd = unsafe {
                libc::open(
                    bind.target.as_ptr(),
                    libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_WRONLY,
                    0o555,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            syscall_ok(unsafe { libc::close(fd) })?;
        }
        syscall_ok(unsafe {
            libc::mount(
                bind.source.as_ptr(),
                bind.target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND as libc::c_ulong,
                std::ptr::null(),
            )
        })?;
        syscall_ok(unsafe {
            libc::mount(
                std::ptr::null(),
                bind.target.as_ptr(),
                std::ptr::null(),
                BIND_FLAGS,
                std::ptr::null(),
            )
        })?;
    }
    syscall_ok(unsafe { libc::chmod(setup.cache.as_ptr(), 0o700) })?;
    syscall_ok(unsafe { libc::chown(setup.cache.as_ptr(), WORKER_UID, WORKER_GID) })?;
    // SAFETY：掛載與 bind 完成後，清群組並永久降為與宿主不同的外層 UID/GID。
    syscall_ok(unsafe { libc::setgroups(0, std::ptr::null()) })?;
    syscall_ok(unsafe { libc::setresgid(WORKER_GID, WORKER_GID, WORKER_GID) })?;
    syscall_ok(unsafe { libc::setresuid(WORKER_UID, WORKER_UID, WORKER_UID) })?;
    // SAFETY：讓 self 的 uid/gid_map 在換 UID 後仍可寫；exec 後 child_probe 再禁止同 UID attach。
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) })?;
    syscall_ok(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    syscall_ok(unsafe { libc::unshare(libc::CLONE_NEWUSER) })?;
    unsafe { write_map(c"/proc/self/setgroups", b"deny\n")? };
    unsafe { write_map(c"/proc/self/uid_map", b"65534 65534 1\n")? };
    unsafe { write_map(c"/proc/self/gid_map", b"65534 65534 1\n")? };
    syscall_ok(unsafe {
        libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWIPC | libc::CLONE_NEWUTS)
    })?;
    syscall_ok(unsafe { libc::chroot(c".".as_ptr()) })?;
    syscall_ok(unsafe { libc::chdir(c"/".as_ptr()) })?;
    for &(resource, maximum) in LIMITS {
        let value = libc::rlimit {
            rlim_cur: maximum,
            rlim_max: maximum,
        };
        syscall_ok(unsafe { libc::setrlimit(resource as _, &value) })?;
    }
    unsafe { drop_capabilities(setup.cap_last)? };
    // SAFETY：CLOEXEC 保留 Rust spawn 的錯誤通道至 exec，其他繼承 fd 均在 exec 關閉。
    let closed =
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, CLOSE_RANGE_CLOEXEC) };
    if closed != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn status_value<'a>(status: &'a str, name: &str) -> Result<&'a str, PolicyDenied> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(name).map(str::trim))
        .ok_or(PolicyDenied::MissingEvidence)
}

fn zero_hex(status: &str, name: &str) -> Result<bool, PolicyDenied> {
    let value = status_value(status, name)?;
    Ok(!value.is_empty() && value.bytes().all(|byte| byte == b'0'))
}

fn check_status(status: &str, cap_last: u32) -> Result<(), PolicyDenied> {
    let expected = [WORKER_UID; 4];
    let uids: Vec<u32> = status_value(status, "Uid:")?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| PolicyDenied::MissingEvidence)?;
    let gids: Vec<u32> = status_value(status, "Gid:")?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| PolicyDenied::MissingEvidence)?;
    if uids.as_slice() != expected.as_slice()
        || gids.as_slice() != expected.as_slice()
        || !status_value(status, "Groups:")?.is_empty()
        || status_value(status, "NoNewPrivs:")? != "1"
        || status_value(status, "Seccomp:")? != "2"
        || status_value(status, "Seccomp_filters:")?
            .parse::<u32>()
            .unwrap_or(0)
            == 0
        || status_value(status, "TracerPid:")? != "0"
        || !zero_hex(status, "CapInh:")?
        || !zero_hex(status, "CapPrm:")?
        || !zero_hex(status, "CapEff:")?
        || !zero_hex(status, "CapBnd:")?
        || !zero_hex(status, "CapAmb:")?
        || cap_last > 63
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(())
}

fn check_mounts(text: &str, expected: &[(String, (u64, u64))]) -> Result<(), PolicyDenied> {
    let mut seen = Vec::new();
    for line in text.lines() {
        let (left, right) = line
            .split_once(" - ")
            .ok_or(PolicyDenied::MissingEvidence)?;
        let fields: Vec<_> = left.split_whitespace().collect();
        let mount = *fields.get(4).ok_or(PolicyDenied::MissingEvidence)?;
        let options = *fields.get(5).ok_or(PolicyDenied::MissingEvidence)?;
        if mount == "/" {
            if right.split_whitespace().next() != Some("tmpfs")
                || !options.split(',').any(|item| item == "rw")
                || !options.split(',').any(|item| item == "nosuid")
                || !options.split(',').any(|item| item == "nodev")
            {
                return Err(PolicyDenied::MissingEvidence);
            }
        } else if !expected.iter().any(|(item, _)| item == mount)
            || !options.split(',').any(|item| item == "ro")
            || !options.split(',').any(|item| item == "nosuid")
            || !options.split(',').any(|item| item == "nodev")
        {
            return Err(PolicyDenied::MissingEvidence);
        }
        if seen.iter().any(|item| item == mount) {
            return Err(PolicyDenied::MissingEvidence);
        }
        seen.push(mount);
    }
    if seen.len() != expected.len() + 1
        || !seen.contains(&"/")
        || expected
            .iter()
            .any(|(item, _)| !seen.contains(&item.as_str()))
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    Ok(())
}

fn check_limits(pid: libc::pid_t) -> Result<(), PolicyDenied> {
    for &(resource, maximum) in LIMITS {
        let mut actual = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY：只讀取指定子程序的 OS rlimit，不修改其狀態。
        if unsafe { libc::prlimit(pid, resource as _, std::ptr::null(), &mut actual) } != 0
            || actual.rlim_cur != maximum
            || actual.rlim_max != maximum
        {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    Ok(())
}

pub(super) fn parent_probe(
    child: &Child,
    launch: &PlatformLaunch,
    policy: VmPolicy,
) -> Result<PlatformEvidence, PolicyDenied> {
    if policy == VmPolicy::Compatibility || policy != launch.policy {
        return Err(PolicyDenied::InvalidWorker);
    }
    let pid = i32::try_from(child.id()).map_err(|_| PolicyDenied::InvalidWorker)?;
    if pid <= 1 {
        return Err(PolicyDenied::InvalidWorker);
    }
    let proc = PathBuf::from(format!("/proc/{pid}"));
    if identity(&proc.join("exe"))? != launch.binary_id
        || fs::read_link(proc.join("root")).map_err(|_| PolicyDenied::MissingEvidence)?
            != launch.root
        || fs::read_to_string(proc.join("uid_map"))
            .map_err(|_| PolicyDenied::MissingEvidence)?
            .split_whitespace()
            .collect::<Vec<_>>()
            != ["65534", "65534", "1"]
        || fs::read_to_string(proc.join("gid_map"))
            .map_err(|_| PolicyDenied::MissingEvidence)?
            .split_whitespace()
            .collect::<Vec<_>>()
            != ["65534", "65534", "1"]
        || fs::read_to_string(proc.join("setgroups"))
            .map_err(|_| PolicyDenied::MissingEvidence)?
            .trim()
            != "deny"
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    for (name, previous) in ["user", "mnt", "net"]
        .into_iter()
        .zip(&launch.parent_namespaces)
    {
        let current =
            fs::read_link(proc.join("ns").join(name)).map_err(|_| PolicyDenied::MissingEvidence)?;
        if current == *previous {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    let cap_last = fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .map_err(|_| PolicyDenied::MissingEvidence)?
        .trim()
        .parse::<u32>()
        .map_err(|_| PolicyDenied::MissingEvidence)?;
    let status =
        fs::read_to_string(proc.join("status")).map_err(|_| PolicyDenied::MissingEvidence)?;
    check_status(&status, cap_last)?;
    let mountinfo =
        fs::read_to_string(proc.join("mountinfo")).map_err(|_| PolicyDenied::MissingEvidence)?;
    check_mounts(&mountinfo, &launch.mounts)?;
    for (path, expected_id) in &launch.mounts {
        let relative = path
            .strip_prefix('/')
            .ok_or(PolicyDenied::MissingEvidence)?;
        let actual = fs::metadata(proc.join("root").join(relative))
            .map_err(|_| PolicyDenied::MissingEvidence)?;
        if (actual.dev(), actual.ino()) != *expected_id {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    check_limits(pid)?;
    // SAFETY：查詢指定 Child 的程序群組；不向其送訊號。
    if unsafe { libc::getpgid(pid) } != pid {
        return Err(PolicyDenied::MissingEvidence);
    }
    for entry in fs::read_dir(proc.join("fd")).map_err(|_| PolicyDenied::MissingEvidence)? {
        let entry = entry.map_err(|_| PolicyDenied::MissingEvidence)?;
        let number = entry
            .file_name()
            .to_string_lossy()
            .parse::<u32>()
            .map_err(|_| PolicyDenied::MissingEvidence)?;
        if number > 2 {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    Ok(PlatformEvidence { _private: () })
}

fn syscall_filter() -> Result<(), PolicyDenied> {
    #[cfg(target_arch = "x86_64")]
    const ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(PolicyDenied::Unsupported);
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let allowed: &[libc::c_long] = &[
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_readv,
            libc::SYS_writev,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
            libc::SYS_close,
            libc::SYS_lseek,
            libc::SYS_fstat,
            libc::SYS_newfstatat,
            libc::SYS_statx,
            libc::SYS_openat,
            libc::SYS_faccessat,
            libc::SYS_faccessat2,
            libc::SYS_readlinkat,
            libc::SYS_getdents64,
            libc::SYS_getcwd,
            libc::SYS_mkdirat,
            libc::SYS_unlinkat,
            libc::SYS_fchmodat,
            libc::SYS_ftruncate,
            libc::SYS_fsync,
            libc::SYS_fdatasync,
            libc::SYS_mmap,
            libc::SYS_mprotect,
            libc::SYS_munmap,
            libc::SYS_mremap,
            libc::SYS_madvise,
            libc::SYS_brk,
            libc::SYS_ioctl,
            libc::SYS_fcntl,
            libc::SYS_dup,
            libc::SYS_dup3,
            libc::SYS_rt_sigaction,
            libc::SYS_rt_sigprocmask,
            libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack,
            libc::SYS_futex,
            libc::SYS_set_robust_list,
            libc::SYS_rseq,
            libc::SYS_getpid,
            libc::SYS_getppid,
            libc::SYS_gettid,
            libc::SYS_getuid,
            libc::SYS_geteuid,
            libc::SYS_getgid,
            libc::SYS_getegid,
            libc::SYS_getgroups,
            libc::SYS_getpgid,
            libc::SYS_clock_gettime,
            libc::SYS_clock_getres,
            libc::SYS_clock_nanosleep,
            libc::SYS_nanosleep,
            libc::SYS_gettimeofday,
            libc::SYS_getrandom,
            libc::SYS_sched_yield,
            libc::SYS_sched_getaffinity,
            libc::SYS_prctl,
            libc::SYS_capget,
            libc::SYS_statfs,
            libc::SYS_fstatfs,
            libc::SYS_prlimit64,
            libc::SYS_uname,
            libc::SYS_getrusage,
            libc::SYS_exit,
            libc::SYS_exit_group,
        ];
        #[cfg(target_arch = "x86_64")]
        let arch_allowed: &[libc::c_long] = &[
            libc::SYS_open,
            libc::SYS_readlink,
            libc::SYS_access,
            libc::SYS_poll,
            libc::SYS_arch_prctl,
            libc::SYS_getpgrp,
        ];
        #[cfg(target_arch = "aarch64")]
        let arch_allowed: &[libc::c_long] = &[];
        let mut code = Vec::new();
        code.try_reserve_exact(5 + 2 * (allowed.len() + arch_allowed.len()))
            .map_err(|_| PolicyDenied::Resource)?;
        let ins = |code: u16, jt: u8, jf: u8, k: u32| libc::sock_filter { code, jt, jf, k };
        code.push(ins(0x20, 0, 0, 4)); // 先核對系統呼叫架構。
        code.push(ins(0x15, 1, 0, ARCH));
        code.push(ins(0x06, 0, 0, 0x8000_0000)); // 架構不符即終止程序。
        code.push(ins(0x20, 0, 0, 0)); // 再讀取系統呼叫編號。
        for &number in allowed.iter().chain(arch_allowed.iter()) {
            code.push(ins(0x15, 0, 1, number as u32));
            code.push(ins(0x06, 0, 0, 0x7fff_0000)); // 僅允許明列項目。
        }
        code.push(ins(0x06, 0, 0, 0x8000_0000));
        let program = libc::sock_fprog {
            len: u16::try_from(code.len()).map_err(|_| PolicyDenied::Resource)?,
            filter: code.as_mut_ptr(),
        };
        // SAFETY：BPF 陣列在同步 prctl 呼叫期間存活；架構不符與未知 syscall 一律終止。
        if unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const _ as libc::c_ulong,
                0,
                0,
            )
        } != 0
        {
            return Err(PolicyDenied::Unsupported);
        }
        FILTER_INSTALLED.store(true, Ordering::Release);
        Ok(())
    }
}

fn own_capabilities_empty() -> bool {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY：capget 只填寫本函式持有的 v3 header 與兩筆 data。
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return false;
    }
    data.iter()
        .all(|part| part.effective == 0 && part.permitted == 0 && part.inheritable == 0)
        && (0..=63).all(|cap| {
            // SAFETY：只查詢本程序的 bounding set；未知 cap 回 EINVAL，既有 cap 必須為零。
            let result = unsafe { libc::prctl(libc::PR_CAPBSET_READ, cap) };
            result == 0
                || (result == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL))
        })
}

fn tmpfs(path: &Path) -> bool {
    let Ok(path) = c_path(path) else {
        return false;
    };
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY：有效 C 路徑；statfs 成功才讀取已初始化的輸出緩衝區。
    unsafe {
        libc::statfs(path.as_ptr(), info.as_mut_ptr()) == 0
            && info.assume_init().f_type == TMPFS_MAGIC
    }
}

pub(super) fn child_probe(
    policy: VmPolicy,
    run_dir: &Path,
) -> Result<PlatformEvidence, PolicyDenied> {
    if policy == VmPolicy::Compatibility
        || !normal_absolute(run_dir)
        || !tmpfs(Path::new("/"))
        || !tmpfs(run_dir)
    {
        return Err(PolicyDenied::MissingEvidence);
    }
    // SAFETY：只讀取本程序身分與已建立的程序群組、NNP、seccomp 模式。
    let credentials = unsafe {
        libc::getuid() == WORKER_UID
            && libc::geteuid() == WORKER_UID
            && libc::getgid() == WORKER_GID
            && libc::getegid() == WORKER_GID
            && libc::getgroups(0, std::ptr::null_mut()) == 0
            && libc::getpgrp() == libc::getpid()
            && libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
    };
    if !credentials || !own_capabilities_empty() {
        return Err(PolicyDenied::MissingEvidence);
    }
    if !FILTER_INSTALLED.load(Ordering::Acquire) {
        // SAFETY：載入 native 前禁止其他相同 UID 程序讀取或附加 worker。
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(PolicyDenied::MissingEvidence);
        }
        syscall_filter()?;
    }
    // SAFETY：核心返回的 seccomp 模式 2 才能作為已啟用 filter 的證據。
    if unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) } != 2 {
        return Err(PolicyDenied::MissingEvidence);
    }
    // SAFETY：驗證同 UID 不能附加或讀取此 worker 的記憶體。
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(PolicyDenied::MissingEvidence);
    }
    for &(resource, maximum) in LIMITS {
        let mut actual = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY：只查詢本程序的 resource limit。
        if unsafe { libc::getrlimit(resource as _, &mut actual) } != 0
            || actual.rlim_cur != maximum
            || actual.rlim_max != maximum
        {
            return Err(PolicyDenied::MissingEvidence);
        }
    }
    Ok(PlatformEvidence { _private: () })
}
