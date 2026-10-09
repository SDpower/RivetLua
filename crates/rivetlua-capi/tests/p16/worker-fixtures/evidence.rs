//! B2 測試專用：外接 cache 的不可變 C build/child 觀測紀錄。

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use rivetlua_capi::abi;
use rivetlua_capi::native::binary_sha256;

static NEXT: AtomicU64 = AtomicU64::new(1);

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

pub fn hash_file(path: &Path) -> String {
    hex(&binary_sha256(&fs::read(path).unwrap()).unwrap())
}

pub fn string(value: &str) -> String {
    let mut output = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            c if c <= '\u{001f}' => output.push_str(&format!("\\u{:04x}", c as u32)),
            c => output.push(c),
        }
    }
    output.push('"');
    output
}

pub fn path(path: &Path) -> String {
    string(path.to_str().expect("受控外接 cache 路徑須為 UTF-8"))
}

pub fn optional_i32(value: Option<i32>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

pub fn signal(status: &ExitStatus) -> Option<i32> {
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

pub fn write_readonly(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.flush().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
}

pub struct Evidence {
    pub case: &'static str,
    pub profile: &'static str,
    pub dir: PathBuf,
    pub source: PathBuf,
    pub source_sha256: String,
}

impl Evidence {
    pub fn new(case: &'static str) -> Self {
        let root = PathBuf::from(
            std::env::var_os("RIVETLUA_P16_EVIDENCE_DIR").expect("RIVETLUA_P16_EVIDENCE_DIR 必填"),
        );
        assert!(root.is_absolute(), "evidence dir 必須為絕對路徑");
        let target = PathBuf::from(
            std::env::var_os("CARGO_TARGET_DIR").expect("外接 CARGO_TARGET_DIR 必填"),
        );
        assert!(
            root.starts_with(
                target
                    .parent()
                    .expect("CARGO_TARGET_DIR 須有外接 cache parent")
            )
        );
        let profile = if cfg!(feature = "lua55") {
            "lua55"
        } else {
            "lua54"
        };
        let parent = root.join(profile);
        fs::create_dir_all(&parent).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = parent.join(format!(
            "{case}-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let source = dir.join("module.c");
        let original =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/p16/worker-fixtures/module.c");
        let bytes = fs::read(&original).unwrap();
        write_readonly(&source, &bytes);
        let source_sha256 = hex(&binary_sha256(&bytes).unwrap());
        Self {
            case,
            profile,
            dir,
            source,
            source_sha256,
        }
    }

    pub fn scenario(&self, label: &str) -> PathBuf {
        assert!(
            label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        );
        let dir = self.dir.join(label);
        fs::create_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    pub fn record(&self, extra: &str, artifacts: &[ArtifactRecord]) -> (PathBuf, String) {
        let artifact_json = artifacts
            .iter()
            .map(ArtifactRecord::json)
            .collect::<Vec<_>>()
            .join(",");
        let body = format!(
            "{{\"schema\":\"rivetlua-p16-child-artifacts-v1\",\"case\":{},\"profile\":{},\"target\":{},\"artifacts\":[{}]{} }}\n",
            string(self.case),
            string(self.profile),
            string(abi::TARGET_TRIPLE),
            artifact_json,
            extra,
        );
        let record = self.dir.join("record.json");
        write_readonly(&record, body.as_bytes());
        let digest = hex(&binary_sha256(body.as_bytes()).unwrap());
        (record, digest)
    }

    pub fn report(&self, fields: &[(&str, String)], record: &Path, record_sha256: &str) {
        let mut line = format!(
            "RVP16\tv=1\tcase={}\tprofile={}\tresult=PASS",
            self.case, self.profile
        );
        for (key, value) in fields {
            assert!(
                key.bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            );
            assert!(
                !value
                    .bytes()
                    .any(|byte| matches!(byte, b'\t' | b'\n' | b'\r'))
            );
            line.push('\t');
            line.push_str(key);
            line.push('=');
            line.push_str(value);
        }
        line.push_str("\tartifact_record_path=");
        line.push_str(record.to_str().unwrap());
        line.push_str("\tartifact_record_sha256=");
        line.push_str(record_sha256);
        // libtest --nocapture 會先印出「test name ...」；前置換行確保 receipt 為獨立行。
        println!("\n{line}");
    }
}

pub struct ArtifactRecord {
    pub source_path: PathBuf,
    pub source_sha256: String,
    pub build_command: Vec<String>,
    pub build_exit_code: Option<i32>,
    pub build_signal: Option<i32>,
    pub build_log_path: PathBuf,
    pub build_log_sha256: String,
    pub binary_path: PathBuf,
    pub binary_sha256: String,
}

impl ArtifactRecord {
    fn json(&self) -> String {
        let argv = self
            .build_command
            .iter()
            .map(|part| string(part))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"source_path\":{},\"source_sha256\":{},\"build_command\":[{}],\"build_exit_code\":{},\"build_signal\":{},\"build_log_path\":{},\"build_log_sha256\":{},\"binary_path\":{},\"binary_sha256\":{}}}",
            path(&self.source_path),
            string(&self.source_sha256),
            argv,
            optional_i32(self.build_exit_code),
            optional_i32(self.build_signal),
            path(&self.build_log_path),
            string(&self.build_log_sha256),
            path(&self.binary_path),
            string(&self.binary_sha256),
        )
    }
}

pub fn build_fixture(evidence: &Evidence, label: &str, marker: &Path, kind: u8) -> ArtifactRecord {
    let directory = evidence.scenario(label);
    let binary = directory.join(if cfg!(target_os = "macos") {
        "module.dylib"
    } else {
        "module.so"
    });
    let log = directory.join("build.log");
    let marker_macro = format!("-DRV_MARKER_PATH=\"{}\"", marker.display());
    let kind_macro = format!("-DRV_CASE_KIND={kind}");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let profile_dir = manifest.join(format!("../../include/rivetlua/{}", evidence.profile));
    let header_dir = manifest.join("../../include/rivetlua");
    let mut argv = vec![
        "cc".to_owned(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-fPIC".into(),
    ];
    if cfg!(target_os = "macos") {
        argv.extend([
            "-dynamiclib".into(),
            "-undefined".into(),
            "dynamic_lookup".into(),
        ]);
    } else {
        argv.push("-shared".into());
    }
    argv.extend([
        "-I".into(),
        profile_dir.to_str().unwrap().into(),
        "-I".into(),
        header_dir.to_str().unwrap().into(),
        marker_macro,
        kind_macro,
        evidence.source.to_str().unwrap().into(),
        "-o".into(),
        binary.to_str().unwrap().into(),
    ]);
    let output = Command::new(&argv[0]).args(&argv[1..]).output().unwrap();
    let mut log_bytes = format!(
        "argv={argv:?}\nexit={:?} signal={:?}\n",
        output.status.code(),
        signal(&output.status)
    )
    .into_bytes();
    log_bytes.extend_from_slice(&output.stdout);
    log_bytes.extend_from_slice(&output.stderr);
    write_readonly(&log, &log_bytes);
    assert!(
        output.status.success(),
        "C fixture build 失敗：{}",
        log.display()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o400)).unwrap();
    }
    ArtifactRecord {
        source_path: evidence.source.clone(),
        source_sha256: evidence.source_sha256.clone(),
        build_command: argv,
        build_exit_code: output.status.code(),
        build_signal: signal(&output.status),
        build_log_path: log.clone(),
        build_log_sha256: hash_file(&log),
        binary_path: binary.clone(),
        binary_sha256: hash_file(&binary),
    }
}

pub fn write_log(path: &Path, bytes: &[u8]) -> String {
    write_readonly(path, bytes);
    hex(&binary_sha256(bytes).unwrap())
}
