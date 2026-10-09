//! P16 可信原生載入：先驗宿主授權、完整 ABI 與 binary bytes，再使用私有映像。

mod sha256;

use std::ffi::{CStr, CString, c_int, c_void};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::abi::{self, AbiIdentity, AbiMismatch};
use crate::stack::{StackError, StateOwner, lua_State};

pub const MAX_NATIVE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_PATH_BYTES: usize = 4096;
pub const MAX_NAME_BYTES: usize = 1024;

/// 僅計算 bytes digest；宿主仍須從既定 SDK build provenance 固定預期值。
pub fn binary_sha256(bytes: &[u8]) -> Option<[u8; 32]> {
    sha256::digest(bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnwindAttestation {
    Unknown,
    CNoUnwind,
    ForeignUnwind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SymbolVisibility {
    Local,
    Global,
}

/// 宿主保存的不可變 artifact 聲明；identity 與 digest 必須來自受信任 build provenance。
#[derive(Clone, Debug)]
pub struct NativeArtifact {
    pub path: PathBuf,
    pub identity: AbiIdentity,
    pub sha256: [u8; 32],
    pub unwind: UnwindAttestation,
}

/// 每次載入都由宿主明確提供，預設值拒絕所有原生程式碼。
#[derive(Clone, Debug)]
pub struct NativePolicy {
    pub id: String,
    pub authorized: bool,
    pub accepts_process_permissions: bool,
    pub allow_global_symbols: bool,
}

impl Default for NativePolicy {
    fn default() -> Self {
        Self {
            id: String::new(),
            authorized: false,
            accepts_process_permissions: false,
            allow_global_symbols: false,
        }
    }
}

#[derive(Debug)]
pub enum NativeError {
    Denied,
    Unwind,
    Abi(AbiMismatch),
    Digest,
    Limit,
    InvalidName,
    Io(std::io::Error),
    Load,
    Symbol,
    Stack(StackError),
}

impl From<std::io::Error> for NativeError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StackError> for NativeError {
    fn from(error: StackError) -> Self {
        Self::Stack(error)
    }
}

#[derive(Debug)]
pub struct VerifiedNative {
    artifact: NativeArtifact,
    policy: NativePolicy,
    visibility: SymbolVisibility,
    bytes: Vec<u8>,
}

/// 此函式不接觸 dlopen/dlsym 或 module code；所有拒絕都發生於 constructor 前。
pub fn preflight(
    artifact: NativeArtifact,
    policy: &NativePolicy,
    visibility: SymbolVisibility,
) -> Result<VerifiedNative, NativeError> {
    if !policy.authorized
        || !policy.accepts_process_permissions
        || policy.id.is_empty()
        || policy.id.len() > MAX_NAME_BYTES
        || matches!(visibility, SymbolVisibility::Global) && !policy.allow_global_symbols
    {
        return Err(NativeError::Denied);
    }
    if artifact.unwind != UnwindAttestation::CNoUnwind {
        return Err(NativeError::Unwind);
    }
    abi::compare_identity(&abi::current_identity(), Some(&artifact.identity))
        .map_err(NativeError::Abi)?;
    let path_len = artifact.path.as_os_str().as_encoded_bytes().len();
    if !artifact.path.is_absolute() || path_len == 0 || path_len > MAX_PATH_BYTES {
        return Err(NativeError::Limit);
    }
    let path = CString::new(artifact.path.as_os_str().as_encoded_bytes())
        .map_err(|_| NativeError::Limit)?;
    // SAFETY：C 字串在呼叫期間有效；平台層以 NOFOLLOW/NONBLOCK 開啟候選檔，
    // 不執行任何 module code。成功返回的 fd 唯一交給 File 管理。
    let fd = unsafe { rivetlua_native_open_candidate(path.as_ptr()) };
    if fd < 0 {
        return Err(NativeError::Io(std::io::Error::last_os_error()));
    }
    // SAFETY：fd 是上方成功 open 的唯一 ownership；File 關閉後不再使用。
    let mut file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(NativeError::Limit);
    }
    let declared_len = usize::try_from(file.metadata()?.len()).map_err(|_| NativeError::Limit)?;
    if declared_len > MAX_NATIVE_BYTES {
        return Err(NativeError::Limit);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(declared_len)
        .map_err(|_| NativeError::Limit)?;
    file.take((MAX_NATIVE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_NATIVE_BYTES {
        return Err(NativeError::Limit);
    }
    if sha256::digest(&bytes).ok_or(NativeError::Limit)? != artifact.sha256 {
        return Err(NativeError::Digest);
    }
    Ok(VerifiedNative {
        artifact,
        policy: policy.clone(),
        visibility,
        bytes,
    })
}

static NEXT_STAGE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct StagedImage {
    path: PathBuf,
    directory: PathBuf,
}

impl Drop for StagedImage {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_dir(&self.directory);
    }
}

impl VerifiedNative {
    pub fn retained_bytes(&self) -> Result<usize, NativeError> {
        // 淨保留物件涵蓋 lease、Rc 控制區、政策／路徑與 staged image 的主機 metadata。
        // Native image 由 OS loader 與 module 自身管理；本 VM ledger 無法攔截原生 malloc。
        let base = std::mem::size_of::<NativeLibrary>()
            .checked_add(2 * std::mem::size_of::<usize>())
            .ok_or(NativeError::Limit)?;
        base.checked_add(self.policy.id.len())
            .and_then(|n| n.checked_add(self.artifact.path.as_os_str().as_encoded_bytes().len()))
            .and_then(|n| n.checked_add(2 * MAX_PATH_BYTES))
            .and_then(|n| n.checked_add(self.bytes.len()))
            .ok_or(NativeError::Limit)
    }

    fn stage(&self, cache_root: &Path) -> Result<StagedImage, NativeError> {
        if !cache_root.is_absolute()
            || !cache_root.is_dir()
            || cache_root.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES / 2
        {
            return Err(NativeError::Limit);
        }
        #[cfg(unix)]
        use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
        let mut directory = PathBuf::new();
        for _ in 0..32 {
            let sequence = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
            let candidate =
                cache_root.join(format!("rivetlua-native-{}-{sequence}", std::process::id()));
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => {
                    directory = candidate;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(NativeError::Io(error)),
            }
        }
        if directory.as_os_str().is_empty() {
            return Err(NativeError::Limit);
        }
        let image = directory.join("module.image");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let result = (|| -> Result<(), NativeError> {
            let mut file = options.open(&image)?;
            file.write_all(&self.bytes)?;
            file.flush()?;
            #[cfg(unix)]
            fs::set_permissions(&image, fs::Permissions::from_mode(0o400))?;
            Ok(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_file(&image);
            let _ = fs::remove_dir(&directory);
            return Err(error);
        }
        Ok(StagedImage {
            path: image,
            directory,
        })
    }
}

type NativeOpener = unsafe extern "C" fn(*mut lua_State) -> c_int;

unsafe extern "C" {
    fn rivetlua_native_open_candidate(path: *const i8) -> c_int;
    fn rivetlua_native_open(path: *const i8, global: c_int) -> *mut c_void;
    fn rivetlua_native_symbol(
        handle: *mut c_void,
        name: *const i8,
        out: *mut Option<NativeOpener>,
    ) -> c_int;
    fn rivetlua_native_close(handle: *mut c_void);
}

/// 載入時已查核且不可在 preflight 後改寫的宿主授權紀錄。
pub struct NativeReceipt {
    artifact: NativeArtifact,
    policy: NativePolicy,
    visibility: SymbolVisibility,
}

impl NativeReceipt {
    pub fn artifact(&self) -> &NativeArtifact {
        &self.artifact
    }
    pub fn policy(&self) -> &NativePolicy {
        &self.policy
    }
    pub fn visibility(&self) -> SymbolVisibility {
        self.visibility
    }
}

pub struct NativeLibrary {
    handle: *mut c_void,
    image: StagedImage,
    receipt: NativeReceipt,
    // dependency 的 Rc 欄位最後釋放，確保自己先 dlclose。
    _dependencies: Vec<Rc<NativeLibrary>>,
}

impl NativeLibrary {
    pub fn receipt(&self) -> &NativeReceipt {
        &self.receipt
    }

    pub fn staged_path(&self) -> &Path {
        &self.image.path
    }
}

impl Drop for NativeLibrary {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY：handle 只在 C loader 成功時建立，且本 lease 是唯一 dlclose owner；
            // group 持有 lease 至所有 binding/finalizer 結束；CNoUnwind attestation 禁止 destructor unwind。
            unsafe { rivetlua_native_close(self.handle) };
        }
        let _ = &self.image;
    }
}

/// 載入與 opener 執行須依宿主的明確 CNoUnwind 聲明呼叫。
///
/// # Safety
/// 宿主必須確保 artifact 及全部依賴的 constructors、destructors、opener 不逃逸 foreign unwind；
/// constructors 尚未綁定 state、destructors 已在 state close 後，均不得呼叫 Lua API；
/// opener 僅可在 C checkpoint 中 longjmp，不得跨越 Rust frame。宿主不得讓同一原生映像
/// 的 ABI 身分、函式指標或執行緒使用方式違反宣告；此函式無法從 binary bytes 靜態證明。
pub unsafe fn load_trusted(
    state: &StateOwner,
    verified: VerifiedNative,
    cache_root: &Path,
    module_name: &CStr,
    opener_symbol: &CStr,
    global_result: bool,
    dependencies: &[Rc<NativeLibrary>],
) -> Result<(Rc<NativeLibrary>, c_int), NativeError> {
    if module_name.to_bytes().is_empty()
        || module_name.to_bytes().len() > MAX_NAME_BYTES
        || opener_symbol.to_bytes().is_empty()
        || opener_symbol.to_bytes().len() > MAX_NAME_BYTES
        || dependencies.len() > 16
    {
        return Err(NativeError::InvalidName);
    }
    let mut dependency_leases = Vec::new();
    dependency_leases
        .try_reserve_exact(dependencies.len())
        .map_err(|_| NativeError::Limit)?;
    for dependency in dependencies {
        dependency_leases.push(Rc::clone(dependency));
    }
    let dependency_bytes = dependency_leases
        .capacity()
        .checked_mul(std::mem::size_of::<Rc<NativeLibrary>>())
        .ok_or(NativeError::Limit)?;
    let reservation = state.reserve_native_lease(
        verified
            .retained_bytes()?
            .checked_add(dependency_bytes)
            .ok_or(NativeError::Limit)?,
    )?;
    let staged = verified.stage(cache_root)?;
    let path =
        CString::new(staged.path.as_os_str().as_encoded_bytes()).map_err(|_| NativeError::Limit)?;
    let visibility = matches!(verified.visibility, SymbolVisibility::Global) as c_int;
    let mut lease = Rc::new(NativeLibrary {
        handle: std::ptr::null_mut(),
        image: staged,
        receipt: NativeReceipt {
            artifact: verified.artifact,
            policy: verified.policy,
            visibility: verified.visibility,
        },
        _dependencies: dependency_leases,
    });
    // SAFETY：path 指向私有 readonly staged bytes，在 C 呼叫期間有效；CNoUnwind
    // 前置條件覆蓋 constructors，C 函式返回前不保留 path pointer。
    let handle = unsafe { rivetlua_native_open(path.as_ptr(), visibility) };
    if handle.is_null() {
        return Err(NativeError::Load);
    }
    Rc::get_mut(&mut lease).expect("載入前的唯一 Rc").handle = handle;
    let mut opener: Option<NativeOpener> = None;
    // SAFETY：handle 為本次 dlopen 有效值；symbol 名稱 NUL 結尾，out 在 C 呼叫期間唯一可寫。
    let symbol_ok =
        unsafe { rivetlua_native_symbol(handle, opener_symbol.as_ptr(), &mut opener) } != 0;
    if !symbol_ok {
        return Err(NativeError::Symbol);
    }
    let opener = opener.ok_or(NativeError::Symbol)?;
    reservation.publish(Rc::clone(&lease) as Rc<dyn std::any::Any>)?;
    // SAFETY：opener 指向已驗證 staged image 的 CNoUnwind 函式；protected driver
    // 只在純 C checkpoint 呼叫，可處理 Lua longjmp，Rust 此處不持有 VM 借用。
    let result = unsafe { state.requiref_protected(module_name, opener, global_result) }?;
    Ok((lease, result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_bytes_are_private_exact_and_removed() {
        let root = PathBuf::from(
            std::env::var_os("CARGO_TARGET_DIR").expect("P16 測試須指定外接 CARGO_TARGET_DIR"),
        )
        .join("tmp");
        fs::create_dir_all(&root).unwrap();
        let artifact = NativeArtifact {
            path: root.join("source-unused"),
            identity: abi::current_identity(),
            sha256: sha256::digest(b"exact").unwrap(),
            unwind: UnwindAttestation::CNoUnwind,
        };
        let verified = VerifiedNative {
            artifact,
            policy: NativePolicy {
                id: "test".into(),
                authorized: true,
                accepts_process_permissions: true,
                allow_global_symbols: false,
            },
            visibility: SymbolVisibility::Local,
            bytes: b"exact".to_vec(),
        };
        let image = verified.stage(&root).unwrap();
        assert_eq!(fs::read(&image.path).unwrap(), b"exact");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&image.directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
            assert_eq!(
                fs::metadata(&image.path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        let path = image.path.clone();
        let directory = image.directory.clone();
        drop(image);
        assert!(!path.exists());
        assert!(!directory.exists());
    }
}
