#[path = "p16/worker-fixtures/evidence.rs"]
mod evidence;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use rivetlua_capi::abi;
use rivetlua_capi::native::{
    NativeArtifact, NativePolicy, SymbolVisibility, UnwindAttestation, binary_sha256,
};
use rivetlua_capi::stack::StateOwner;
use rivetlua_capi::worker::codec::HEADER_BYTES;
use rivetlua_capi::worker::{
    CopyValue, Frame, FrameKind, Limits, NativeSpec, Request, Response, WireError, WorkerOutcome,
    WorkerReport, run_worker,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction, LuaProfile, ProtoId,
    RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, VerifyLimits, encode_module,
};

use evidence::{
    ArtifactRecord, Evidence, build_fixture, hash_file, optional_i32, path, string, write_log,
};

fn profile() -> LuaProfile {
    if cfg!(feature = "lua55") {
        LuaProfile::Lua55
    } else {
        LuaProfile::Lua54
    }
}

enum ModuleAction {
    Noop,
    Call { results: u16 },
    ReturnGlobal,
}

fn rvlu_module(action: ModuleAction) -> Vec<u8> {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let environment = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let instruction = |instruction| BytecodeInstruction {
        instruction,
        span,
        close_path: None,
    };
    let mut lookup = vec![
        instruction(Instruction::LoadConst {
            dest: Register(0),
            constant: ConstId(0),
        }),
        instruction(Instruction::GetTable {
            dest: Register(1),
            table: Register(7),
            key: Register(0),
        }),
    ];
    let instructions = match action {
        ModuleAction::Noop => vec![instruction(Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(0),
        })],
        ModuleAction::Call { results } => {
            lookup.push(instruction(Instruction::Call {
                base: Register(1),
                arg_count: 0,
                result_mode: ResultMode::Fixed(results),
            }));
            lookup.push(instruction(Instruction::Return {
                base: Register(1),
                result_mode: ResultMode::Fixed(results),
            }));
            lookup
        }
        ModuleAction::ReturnGlobal => {
            lookup.push(instruction(Instruction::Return {
                base: Register(1),
                result_mode: ResultMode::Fixed(1),
            }));
            lookup
        }
    };
    encode_module(
        BytecodeModule {
            format_version: RVLU_V2,
            profile: profile(),
            numeric_config: RVLU_NUMERIC_I64_F64,
            span,
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span,
                register_count: 8,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 4096,
                    initial_top: Register(8),
                    dynamic_top: Register(8),
                    return_base: Register(0),
                    environment: Register(7),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(7),
                global_environment_binding: environment,
                binding_registers: vec![(environment, Register(7))],
                constants: vec![BytecodeConstant::String(b"rivetlua_p16_fixture".to_vec())],
                upvalues: vec![],
                instructions,
                close_paths: vec![],
            }],
        },
        profile(),
        &VerifyLimits::default(),
    )
    .unwrap()
    .bytes()
    .to_vec()
}

fn rvlu_return_fixture(results: u16) -> Vec<u8> {
    rvlu_module(ModuleAction::Call { results })
}

fn approved_spec(record: &ArtifactRecord) -> NativeSpec {
    NativeSpec {
        artifact: NativeArtifact {
            path: record.binary_path.clone(),
            identity: abi::current_identity(),
            sha256: binary_sha256(&fs::read(&record.binary_path).unwrap()).unwrap(),
            unwind: UnwindAttestation::CNoUnwind,
        },
        policy: NativePolicy {
            id: "worker-fixture-host-approval".into(),
            authorized: true,
            accepts_process_permissions: true,
            allow_global_symbols: false,
        },
        visibility: SymbolVisibility::Local,
        module_name: "rivetlua_p16_fixture".into(),
        opener_symbol: "luaopen_rivetlua_p16_fixture".into(),
        global_result: true,
    }
}

fn worker_binary() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("RIVETLUA_P16_WORKER_BIN").expect("固定 worker snapshot 必填"),
    );
    assert!(path.is_absolute() && path.is_file());
    path
}

fn run_fixture(
    worker: &Path,
    cache: &Path,
    record: &ArtifactRecord,
    request_id: u64,
    result_count: u16,
    millis: u64,
) -> WorkerReport {
    // SAFETY：fixture 為本測試用固定 SDK/C11 建置；ctor/dtor 僅寫 marker，opener
    // 不逃逸 foreign unwind；各回呼只在 worker 的 C checkpoint 執行。
    unsafe {
        run_worker(
            worker,
            cache,
            request_id,
            Request {
                rvlu: rvlu_return_fixture(result_count),
                sidecar: Vec::new(),
                native: vec![approved_spec(record)],
                args: vec![],
            },
            Duration::from_millis(millis),
            Limits::default(),
        )
    }
}

fn child_event(
    e: &Evidence,
    worker: &Path,
    worker_hash: &str,
    label: &str,
    report: &WorkerReport,
) -> String {
    let log = e.dir.join(format!("{label}.child.log"));
    let body = format!(
        "scenario={label}\nworker_path={}\nworker_sha256={worker_hash}\npid={:?}\noutcome={:?}\nexit_code={:?}\nsignal={:?}\ntimed_out={}\nreaped={}\ncache_clean={}\n",
        worker.display(),
        report.child_pid,
        report.outcome,
        report.exit_code,
        report.signal,
        matches!(report.outcome, WorkerOutcome::Deadline),
        report.reaped,
        report.cache_clean
    );
    let digest = write_log(&log, body.as_bytes());
    format!(
        "{{\"scenario\":{},\"exit_code\":{},\"signal\":{},\"timed_out\":{},\"reaped\":{},\"cache_clean\":{},\"log_path\":{},\"log_sha256\":{}}}",
        string(label),
        optional_i32(report.exit_code),
        optional_i32(report.signal),
        matches!(report.outcome, WorkerOutcome::Deadline),
        report.reaped,
        report.cache_clean,
        path(&log),
        string(&digest)
    )
}

#[test]
fn neg_005_pointer_state_function_tags_and_noncopyable_rejected() {
    let evidence = Evidence::new("ABI-NEG-005");
    let parent = StateOwner::new().unwrap();
    let parent_before = parent.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    let frame = Frame {
        request_id: 7,
        identity: abi::current_identity(),
        kind: FrameKind::Response(Response::Complete(vec![CopyValue::Nil])),
    };
    let baseline = frame.encode(Limits::default()).unwrap();
    // Response/Complete: status, count-u16, first value tag.
    for invalid_tag in [6_u8, 7, 8, 255] {
        let mut message = baseline.clone();
        message[HEADER_BYTES + 3] = invalid_tag;
        assert_eq!(
            Frame::decode(&message, Limits::default()).unwrap_err(),
            WireError::Invalid
        );
    }
    let noncopyable = Frame {
        request_id: 7,
        identity: abi::current_identity(),
        kind: FrameKind::Response(Response::NonCopyable {
            index: 1,
            lua_type: 6,
        }),
    };
    match Frame::decode(
        &noncopyable.encode(Limits::default()).unwrap(),
        Limits::default(),
    )
    .unwrap()
    .kind
    {
        FrameKind::Response(Response::NonCopyable {
            index: 1,
            lua_type: 6,
        }) => {}
        other => panic!("非可複製回應失真：{other:?}"),
    }
    assert_eq!(
        parent.with_vm(|vm| vm.ledger_snapshot()).unwrap(),
        parent_before
    );
    let (record, digest) = evidence.record(
        ",\"packet_only\":1,\"invalid_tags\":[6,7,8,255],\"noncopyable_rejected\":true",
        &[],
    );
    evidence.report(
        &[
            ("invalid_tags", "4".into()),
            ("noncopyable", "1".into()),
            ("parent_unchanged", "1".into()),
        ],
        &record,
        &digest,
    );
}

#[test]
fn abi_006_worker_primitives_bytes_gc_crash_timeout_malformed_and_fresh_reuse() {
    let evidence = Evidence::new("ABI-006");
    let worker = worker_binary();
    let worker_hash = hash_file(&worker);
    let cache = evidence.scenario("worker-cache");
    let parent = StateOwner::new().unwrap();
    let parent_before = parent.with_vm(|vm| vm.ledger_snapshot()).unwrap();
    let labels = [
        "normal",
        "crash",
        "timeout",
        "malformed",
        "fresh_reuse",
        "noncopyable",
    ];
    let kinds = [0_u8, 1, 2, 3, 0, 5];
    let mut artifacts = Vec::new();
    let mut reports = Vec::new();
    let mut events = Vec::new();
    let mut noncopyable_event = None;
    for (&label, &kind) in labels.iter().zip(&kinds) {
        let marker = evidence.dir.join(format!("{label}.ctor.marker"));
        let record = build_fixture(&evidence, label, &marker, kind);
        assert!(!marker.exists());
        let report = run_fixture(
            &worker,
            &cache,
            &record,
            (reports.len() + 1) as u64,
            if kind == 5 { 1 } else { 5 },
            if kind == 2 { 1500 } else { 5000 },
        );
        assert!(report.child_pid.is_some() && report.child_pid != Some(std::process::id()));
        assert!(report.reaped && report.cache_clean, "{label}: {report:?}");
        assert!(
            marker.exists(),
            "{label}: constructor marker 缺失：{report:?}"
        );
        if kind == 0 || kind == 5 {
            assert!(
                marker.with_extension("marker.dtor").exists(),
                "{label}: destructor marker 缺失：{report:?}"
            );
        }
        let event = child_event(&evidence, &worker, &worker_hash, label, &report);
        if label == "noncopyable" {
            noncopyable_event = Some(event);
        } else {
            events.push(event);
        }
        artifacts.push(record);
        reports.push(report);
    }
    assert_eq!(
        reports[0].outcome,
        WorkerOutcome::Complete(vec![
            CopyValue::Nil,
            CopyValue::Boolean(false),
            CopyValue::Integer(123),
            CopyValue::NumberBits(1.25f64.to_bits()),
            CopyValue::Bytes(vec![0, 255, b'A']),
        ])
    );
    assert_eq!(reports[1].outcome, WorkerOutcome::Crash);
    assert!(reports[1].signal.is_some() || reports[1].exit_code.is_some());
    assert_eq!(reports[2].outcome, WorkerOutcome::Deadline);
    assert_eq!(reports[3].outcome, WorkerOutcome::Malformed);
    assert_eq!(reports[4].outcome, reports[0].outcome);
    assert_eq!(
        reports[5].outcome,
        WorkerOutcome::NonCopyable {
            index: 1,
            lua_type: 5
        }
    );
    assert_eq!(
        parent.with_vm(|vm| vm.ledger_snapshot()).unwrap(),
        parent_before
    );
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
    let extra = format!(
        ",\"worker_path\":{},\"worker_sha256\":{},\"child_events\":[{}],\"noncopyable_event\":{}",
        path(&worker),
        string(&worker_hash),
        events.join(","),
        noncopyable_event.unwrap()
    );
    let (record, digest) = evidence.record(&extra, &artifacts);
    evidence.report(
        &[
            (
                "fixture_path",
                artifacts[0].binary_path.display().to_string(),
            ),
            ("fixture_sha256", artifacts[0].binary_sha256.clone()),
            (
                "compile_log",
                artifacts[0].build_log_path.display().to_string(),
            ),
            ("worker_path", worker.display().to_string()),
            ("worker_sha256", worker_hash),
            ("complete", "1".into()),
            ("crash", "1".into()),
            ("deadline", "1".into()),
            ("malformed", "1".into()),
            ("reaped", "1".into()),
            ("cleanup", "1".into()),
            ("fresh_reuse", "1".into()),
        ],
        &record,
        &digest,
    );
}

#[test]
fn native_finalizer_runs_before_library_destructor() {
    let evidence = Evidence::new("NATIVE-FINALIZER");
    let worker = worker_binary();
    let cache = evidence.scenario("worker-cache");
    let cases = ["complete", "runtime_error", "rejected", "noncopyable"];
    let mut artifacts = Vec::new();
    for (index, label) in cases.iter().enumerate() {
        let marker = evidence.dir.join(format!("{label}.ctor.marker"));
        let artifact = build_fixture(&evidence, label, &marker, 6);
        assert!(!marker.exists());
        let mut native = vec![approved_spec(&artifact)];
        let mut rejected_marker = None;
        if *label == "rejected" {
            let path = evidence.dir.join("rejected_second.ctor.marker");
            let rejected = build_fixture(&evidence, "rejected_second", &path, 4);
            let mut bad = approved_spec(&rejected);
            bad.artifact.sha256[0] ^= 1;
            native.push(bad);
            artifacts.push(rejected);
            rejected_marker = Some(path);
        }
        let action = match *label {
            "runtime_error" => ModuleAction::Call { results: 1 },
            "noncopyable" => ModuleAction::ReturnGlobal,
            _ => ModuleAction::Noop,
        };
        // SAFETY：固定 SDK/C11 fixture 的 ctor/dtor 僅寫 marker，__gc callback 僅在
        // worker 私有 VM 的 C checkpoint 執行；無 foreign unwind 或跨 process pointer。
        let report = unsafe {
            run_worker(
                &worker,
                &cache,
                77 + index as u64,
                Request {
                    rvlu: rvlu_module(action),
                    sidecar: Vec::new(),
                    native,
                    args: vec![],
                },
                Duration::from_secs(5),
                Limits::default(),
            )
        };
        match *label {
            "complete" => assert_eq!(report.outcome, WorkerOutcome::Complete(vec![])),
            "runtime_error" => assert!(matches!(report.outcome, WorkerOutcome::RuntimeError(_))),
            "rejected" => assert!(matches!(report.outcome, WorkerOutcome::Rejected(_))),
            "noncopyable" => assert_eq!(
                report.outcome,
                WorkerOutcome::NonCopyable {
                    index: 1,
                    lua_type: 7
                }
            ),
            _ => unreachable!(),
        }
        assert_eq!(report.exit_code, Some(0), "{label}: {report:?}");
        assert!(report.reaped && report.cache_clean, "{label}: {report:?}");
        if let Some(path) = rejected_marker {
            assert!(!path.exists(), "拒絕模組不得執行 constructor");
        }
        assert_eq!(fs::read(&marker).unwrap(), b"constructor\n");
        assert_eq!(
            fs::read(format!("{}.finalizer", marker.display())).unwrap(),
            b"finalizer\n"
        );
        assert_eq!(
            fs::read(format!("{}.dtor", marker.display())).unwrap(),
            b"destructor\n"
        );
        assert_eq!(
            fs::read(format!("{}.order", marker.display())).unwrap(),
            b"constructor\nfinalizer\ndestructor\n"
        );
        artifacts.push(artifact);
    }
    assert_eq!(fs::read_dir(&cache).unwrap().count(), 0);
    let extra = format!(
        ",\"worker_path\":{},\"worker_sha256\":{},\"finalizer_before_dlclose\":true",
        path(&worker),
        string(&hash_file(&worker))
    );
    let _ = evidence.record(&extra, &artifacts);
}

#[test]
fn abi_006_wire_exact_framing_and_scalar_bits() {
    let frame = Frame {
        request_id: 0x1234,
        identity: abi::current_identity(),
        kind: FrameKind::Response(Response::Complete(vec![
            CopyValue::Nil,
            CopyValue::Boolean(false),
            CopyValue::Boolean(true),
            CopyValue::Integer(i64::MIN),
            CopyValue::NumberBits(0x7ff8_0000_0000_0123),
            CopyValue::Bytes(vec![0, 0xff, b'A']),
        ])),
    };
    let bytes = frame.encode(Limits::default()).unwrap();
    let decoded = Frame::decode(&bytes, Limits::default()).unwrap();
    assert_eq!(decoded.request_id, frame.request_id);
    match decoded.kind {
        FrameKind::Response(Response::Complete(values)) => assert_eq!(
            values,
            vec![
                CopyValue::Nil,
                CopyValue::Boolean(false),
                CopyValue::Boolean(true),
                CopyValue::Integer(i64::MIN),
                CopyValue::NumberBits(0x7ff8_0000_0000_0123),
                CopyValue::Bytes(vec![0, 0xff, b'A']),
            ]
        ),
        other => panic!("回應類型失真：{other:?}"),
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        Frame::decode(&trailing, Limits::default()).unwrap_err(),
        WireError::Invalid
    );
    let mut reserved = bytes.clone();
    reserved[22] = 1;
    assert_eq!(
        Frame::decode(&reserved, Limits::default()).unwrap_err(),
        WireError::Invalid
    );
    let mut unknown = bytes.clone();
    unknown[6] = 99;
    assert_eq!(
        Frame::decode(&unknown, Limits::default()).unwrap_err(),
        WireError::Invalid
    );
    let mut profile = bytes;
    profile[20] ^= 1;
    assert_eq!(
        Frame::decode(&profile, Limits::default()).unwrap_err(),
        WireError::Abi
    );
}

#[test]
fn worker_request_is_bounded_and_rechecks_full_artifact_identity() {
    let spec = NativeSpec {
        artifact: NativeArtifact {
            path: std::env::temp_dir().join("module.image"),
            identity: abi::current_identity(),
            sha256: [9; 32],
            unwind: UnwindAttestation::CNoUnwind,
        },
        policy: NativePolicy {
            id: "test-policy".into(),
            authorized: true,
            accepts_process_permissions: true,
            allow_global_symbols: false,
        },
        visibility: SymbolVisibility::Local,
        module_name: "spec.module".into(),
        opener_symbol: "luaopen_spec_module".into(),
        global_result: false,
    };
    let frame = Frame {
        request_id: 8,
        identity: abi::current_identity(),
        kind: FrameKind::Request(Request {
            rvlu: b"RVLU invalid here, decoded later in child".to_vec(),
            sidecar: Vec::new(),
            native: vec![spec.clone()],
            args: vec![CopyValue::Bytes(vec![0, 255])],
        }),
    };
    let wire = frame.encode(Limits::default()).unwrap();
    match Frame::decode(&wire, Limits::default()).unwrap().kind {
        FrameKind::Request(request) => {
            assert_eq!(request.native.len(), 1);
            assert_eq!(request.native[0].artifact.sha256, [9; 32]);
            assert_eq!(request.args, vec![CopyValue::Bytes(vec![0, 255])]);
        }
        other => panic!("請求類型失真：{other:?}"),
    }
    let mut bad = frame;
    if let FrameKind::Request(request) = &mut bad.kind {
        request.native[0].artifact.identity.layout[36] ^= 1;
    }
    assert_eq!(bad.encode(Limits::default()).unwrap_err(), WireError::Abi);
    let mut bad = spec;
    bad.module_name = "m".repeat(1025);
    let frame = Frame {
        request_id: 9,
        identity: abi::current_identity(),
        kind: FrameKind::Request(Request {
            rvlu: Vec::new(),
            sidecar: Vec::new(),
            native: vec![bad],
            args: Vec::new(),
        }),
    };
    assert_eq!(
        frame.encode(Limits::default()).unwrap_err(),
        WireError::Limit
    );
}
