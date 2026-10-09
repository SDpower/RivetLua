#[path = "p16/worker-fixtures/evidence.rs"]
mod evidence;

use std::fs;
use std::path::{Path, PathBuf};

use rivetlua_capi::abi::{self, AbiMismatch};
use rivetlua_capi::native::{
    NativeArtifact, NativeError, NativePolicy, SymbolVisibility, UnwindAttestation, binary_sha256,
    load_trusted, preflight,
};
use rivetlua_capi::stack::StateOwner;

unsafe extern "C" {
    fn lua_gc(state: *mut rivetlua_capi::stack::lua_State, what: i32, ...) -> i32;
}

use evidence::{ArtifactRecord, Evidence, build_fixture, hash_file, path, string, write_log};

fn cache() -> PathBuf {
    let tmp =
        PathBuf::from(std::env::var_os("CARGO_TARGET_DIR").expect("外接 target 必填")).join("tmp");
    fs::create_dir_all(&tmp).unwrap();
    tmp
}

fn allowed() -> NativePolicy {
    NativePolicy {
        id: "fixed-sdk-host-approval".into(),
        authorized: true,
        accepts_process_permissions: true,
        allow_global_symbols: false,
    }
}

fn artifact(record: &ArtifactRecord) -> NativeArtifact {
    NativeArtifact {
        path: record.binary_path.clone(),
        identity: abi::current_identity(),
        sha256: binary_sha256(&fs::read(&record.binary_path).unwrap()).unwrap(),
        unwind: UnwindAttestation::CNoUnwind,
    }
}

fn no_marker(marker: &Path) {
    assert!(
        !marker.exists(),
        "constructor 在拒絕情境執行：{}",
        marker.display()
    );
}

fn calibrate(
    e: &Evidence,
    artifacts: &mut Vec<ArtifactRecord>,
) -> (PathBuf, String, PathBuf, String) {
    let marker = e.dir.join("positive/ctor.marker");
    let record = build_fixture(e, "positive", &marker, 4);
    no_marker(&marker);
    let owner = StateOwner::new().unwrap();
    let candidate = artifact(&record);
    let verified = preflight(candidate.clone(), &allowed(), SymbolVisibility::Local).unwrap();
    // SAFETY：fixture 由本測試以固定 SDK/C11 編譯；constructor 僅寫私有 marker，
    // opener 不呼叫 Lua API、不逃逸 foreign unwind，requiref 只在純 C checkpoint 呼叫。
    let (library, status) = unsafe {
        load_trusted(
            &owner,
            verified,
            &cache(),
            c"rivetlua.p16.fixture",
            c"luaopen_rivetlua_p16_fixture",
            false,
            &[],
        )
    }
    .unwrap();
    assert_eq!(status, 0);
    assert_eq!(
        library.receipt().artifact().identity,
        abi::current_identity()
    );
    assert_eq!(library.receipt().artifact().sha256, candidate.sha256);
    assert_eq!(library.receipt().policy().id, allowed().id);
    assert!(library.receipt().policy().authorized);
    assert!(library.receipt().policy().accepts_process_permissions);
    assert_eq!(library.receipt().visibility(), SymbolVisibility::Local);
    let staged_path = library.staged_path().to_path_buf();
    assert_eq!(
        fs::read(&staged_path).unwrap(),
        fs::read(&record.binary_path).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&staged_path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert_eq!(
            fs::metadata(staged_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    assert_eq!(fs::read(&marker).unwrap(), b"constructor\n");
    drop(library);
    drop(owner);
    assert!(!staged_path.exists());
    assert!(!staged_path.parent().unwrap().exists());
    let destructor = PathBuf::from(format!("{}.dtor", marker.display()));
    assert_eq!(fs::read(&destructor).unwrap(), b"destructor\n");
    let log = e.dir.join("positive/load.log");
    let log_sha = write_log(
        &log,
        format!("load_trusted status={status}; marker=constructor\n").as_bytes(),
    );
    let marker_sha = hash_file(&marker);
    artifacts.push(record);
    (marker, marker_sha, log, log_sha)
}

fn constructor_json(positive: &(PathBuf, String, PathBuf, String), rejects: &[String]) -> String {
    format!(
        ",\"constructor\":{{\"positive_marker_path\":{},\"positive_marker_sha256\":{},\"positive_log_path\":{},\"positive_log_sha256\":{},\"calibrated\":true,\"rejections\":[{}]}}",
        path(&positive.0),
        string(&positive.1),
        path(&positive.2),
        string(&positive.3),
        rejects.join(","),
    )
}

fn rejection_json(index: usize, reason: &str, marker: &Path) -> String {
    format!(
        "{{\"index\":{index},\"reason\":{},\"preloader_rejected\":true,\"ctor_marker_seen\":false,\"marker_path\":{}}}",
        string(reason),
        path(marker),
    )
}

#[test]
fn native_library_symbol_failure_gc_and_sibling_lifetime() {
    let e = Evidence::new("NATIVE-LIFETIME");
    let cache = e.scenario("cache");
    let owner = StateOwner::new().unwrap();
    let sibling = owner.new_sibling().unwrap();
    let baseline = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    let missing_marker = e.dir.join("missing/ctor.marker");
    let missing = build_fixture(&e, "missing", &missing_marker, 4);
    let verified = preflight(artifact(&missing), &allowed(), SymbolVisibility::Local).unwrap();
    // SAFETY：測試 C11 fixture 的 ctor/dtor 僅記錄 marker，沒有 foreign unwind；
    // missing symbol 會在呼叫 opener 前返回，無 Lua pointer 逸出。
    let failure = unsafe {
        load_trusted(
            &owner,
            verified,
            &cache,
            c"missing",
            c"luaopen_missing_symbol",
            false,
            &[],
        )
    };
    assert!(matches!(failure, Err(NativeError::Symbol)));
    assert_eq!(fs::read(&missing_marker).unwrap(), b"constructor\n");
    assert_eq!(
        fs::read(format!("{}.dtor", missing_marker.display())).unwrap(),
        b"destructor\n"
    );
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
    assert_eq!(owner.with_vm(|vm| vm.ledger_snapshot()).unwrap(), baseline);

    let success_marker = e.dir.join("success/ctor.marker");
    let success = build_fixture(&e, "success", &success_marker, 4);
    let verified = preflight(artifact(&success), &allowed(), SymbolVisibility::Local).unwrap();
    // SAFETY：fixture opener 只返回 0，constructor/destructor 不使用 state、無 foreign unwind；
    // requiref 由純 C checkpoint 執行，owner/sibling 保活同一 VM group。
    let (library, status) = unsafe {
        load_trusted(
            &owner,
            verified,
            &cache,
            c"rivetlua.p16.lifetime",
            c"luaopen_rivetlua_p16_fixture",
            false,
            &[],
        )
    }
    .unwrap();
    assert_eq!(status, 0);
    let staged = library.staged_path().to_path_buf();
    assert!(staged.exists());
    // SAFETY：owner 在同步 C API 呼叫期間保活 state，無其他執行緒使用該 VM。
    assert_eq!(unsafe { lua_gc(owner.as_ptr(), 2) }, 0);
    drop(library);
    drop(owner);
    assert!(staged.exists(), "sibling 存活期間不得卸載 native 映像");
    assert!(!PathBuf::from(format!("{}.dtor", success_marker.display())).exists());
    drop(sibling);
    assert!(!staged.exists());
    assert_eq!(
        fs::read(format!("{}.dtor", success_marker.display())).unwrap(),
        b"destructor\n"
    );
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
    let _ = e.record(
        ",\"symbol_failure_refunded\":true,\"sibling_retained_until_close\":true",
        &[missing, success],
    );
}

fn field_mutants() -> Vec<(AbiMismatch, fn(&mut NativeArtifact))> {
    vec![
        (AbiMismatch::Revision, |a| a.identity.revision ^= 1),
        (AbiMismatch::Profile, |a| a.identity.profile ^= 1),
        (AbiMismatch::NumericConfig, |a| {
            a.identity.numeric_config ^= 1
        }),
        (AbiMismatch::PointerWidth, |a| {
            a.identity.pointer_width_bits ^= 1
        }),
        (AbiMismatch::Endianness, |a| a.identity.endianness ^= 1),
        (AbiMismatch::Reserved, |a| a.identity.reserved_zero = 1),
        (AbiMismatch::Target, |a| a.identity.target[0] ^= 1),
        (AbiMismatch::HeaderSetSha256, |a| {
            a.identity.header_set_sha256[0] ^= 1
        }),
        (AbiMismatch::LuaHSha256, |a| a.identity.lua_h_sha256[0] ^= 1),
        (AbiMismatch::LauxlibHSha256, |a| {
            a.identity.lauxlib_h_sha256[0] ^= 1
        }),
        (AbiMismatch::LuaconfHSha256, |a| {
            a.identity.luaconf_h_sha256[0] ^= 1
        }),
    ]
}

#[test]
fn abi_005_every_identity_field_rejected_before_loader() {
    let e = Evidence::new("ABI-005");
    let mut artifacts = Vec::new();
    let positive = calibrate(&e, &mut artifacts);
    let mut rejects = Vec::new();
    let mut index = 0;
    for (expected, mutate) in field_mutants() {
        let label = format!("reject_{index:02}");
        let marker = e.dir.join(&label).join("ctor.marker");
        let record = build_fixture(&e, &label, &marker, 4);
        let mut candidate = artifact(&record);
        mutate(&mut candidate);
        no_marker(&marker);
        assert!(
            matches!(preflight(candidate, &allowed(), SymbolVisibility::Local), Err(NativeError::Abi(actual)) if actual == expected)
        );
        no_marker(&marker);
        rejects.push(rejection_json(index, &format!("{expected:?}"), &marker));
        artifacts.push(record);
        index += 1;
    }
    for layout in 0..abi::LAYOUT_COUNT {
        let label = format!("reject_{index:02}");
        let marker = e.dir.join(&label).join("ctor.marker");
        let record = build_fixture(&e, &label, &marker, 4);
        let mut candidate = artifact(&record);
        candidate.identity.layout[layout] ^= 1;
        no_marker(&marker);
        assert!(
            matches!(preflight(candidate, &allowed(), SymbolVisibility::Local), Err(NativeError::Abi(AbiMismatch::Layout(actual))) if actual == layout)
        );
        no_marker(&marker);
        rejects.push(rejection_json(index, &format!("Layout({layout})"), &marker));
        artifacts.push(record);
        index += 1;
    }
    assert_eq!(index, 48);
    let (sidecar, digest) = e.record(&constructor_json(&positive, &rejects), &artifacts);
    e.report(
        &[
            ("ctor_calibrated", "1".into()),
            ("reject_count", "48".into()),
            ("ctor_on_reject", "0".into()),
            (
                "fixture_path",
                artifacts[0].binary_path.display().to_string(),
            ),
            ("fixture_sha256", artifacts[0].binary_sha256.clone()),
            (
                "compile_log",
                artifacts[0].build_log_path.display().to_string(),
            ),
        ],
        &sidecar,
        &digest,
    );
}

#[test]
fn abi_007_denied_digest_and_foreign_unwind_rejected_before_loader() {
    let e = Evidence::new("ABI-007");
    let mut artifacts = Vec::new();
    let positive = calibrate(&e, &mut artifacts);
    let mut rejects = Vec::new();
    for (index, reason) in ["Denied", "Digest", "UnknownUnwind", "ForeignUnwind"]
        .iter()
        .enumerate()
    {
        let label = format!("reject_{index:02}");
        let marker = e.dir.join(&label).join("ctor.marker");
        let record = build_fixture(&e, &label, &marker, 4);
        let mut candidate = artifact(&record);
        no_marker(&marker);
        match index {
            0 => assert!(matches!(
                preflight(candidate, &NativePolicy::default(), SymbolVisibility::Local),
                Err(NativeError::Denied)
            )),
            1 => {
                candidate.sha256[0] ^= 1;
                assert!(matches!(
                    preflight(candidate, &allowed(), SymbolVisibility::Local),
                    Err(NativeError::Digest)
                ));
            }
            2 => {
                candidate.unwind = UnwindAttestation::Unknown;
                assert!(matches!(
                    preflight(candidate, &allowed(), SymbolVisibility::Local),
                    Err(NativeError::Unwind)
                ));
            }
            3 => {
                candidate.unwind = UnwindAttestation::ForeignUnwind;
                assert!(matches!(
                    preflight(candidate, &allowed(), SymbolVisibility::Local),
                    Err(NativeError::Unwind)
                ));
            }
            _ => unreachable!(),
        }
        no_marker(&marker);
        rejects.push(rejection_json(index, reason, &marker));
        artifacts.push(record);
    }
    assert_eq!(rejects.len(), 4);
    assert!(matches!(
        preflight(
            artifact(&artifacts[0]),
            &allowed(),
            SymbolVisibility::Global
        ),
        Err(NativeError::Denied)
    ));
    let (sidecar, digest) = e.record(&constructor_json(&positive, &rejects), &artifacts);
    e.report(
        &[
            ("ctor_calibrated", "1".into()),
            ("reject_count", "4".into()),
            ("ctor_on_reject", "0".into()),
            (
                "fixture_path",
                artifacts[0].binary_path.display().to_string(),
            ),
            ("fixture_sha256", artifacts[0].binary_sha256.clone()),
            (
                "compile_log",
                artifacts[0].build_log_path.display().to_string(),
            ),
        ],
        &sidecar,
        &digest,
    );
}
