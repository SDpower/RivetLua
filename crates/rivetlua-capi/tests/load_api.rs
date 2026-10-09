use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::ptr;
use std::time::{SystemTime, UNIX_EPOCH};

use rivetlua_capi::stack::{
    StateOwner, lua_State, lua_checkstack, lua_gettop, lua_pushinteger, lua_settop, lua_tointegerx,
    lua_type,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, EnvironmentSource, FrameLayout, Instruction, LuaProfile, ProtoId,
    RVLU_NUMERIC_I64_F64, RVLU_V2, Register, ResultMode, TransportLimits, Value, VerifyLimits,
    encode_module, preflight_input_module,
};
use rivetlua_runtime::{AllocationFailureKind, LoadLimits, RootKind};

const LUA_OK: c_int = 0;
const LUA_ERRSYNTAX: c_int = 3;
const LUA_ERRFILE: c_int = 6;
const LUA_TFUNCTION: c_int = 6;
const LUA_TSTRING: c_int = 4;

unsafe extern "C" {
    fn lua_load(
        state: *mut lua_State,
        reader: Option<
            unsafe extern "C" fn(*mut lua_State, *mut c_void, *mut usize) -> *const c_char,
        >,
        data: *mut c_void,
        chunkname: *const c_char,
        mode: *const c_char,
    ) -> c_int;
    fn lua_dump(
        state: *mut lua_State,
        writer: Option<
            unsafe extern "C" fn(*mut lua_State, *const c_void, usize, *mut c_void) -> c_int,
        >,
        data: *mut c_void,
        strip: c_int,
    ) -> c_int;
    fn luaL_loadbufferx(
        state: *mut lua_State,
        source: *const c_char,
        len: usize,
        name: *const c_char,
        mode: *const c_char,
    ) -> c_int;
    fn luaL_loadstring(state: *mut lua_State, source: *const c_char) -> c_int;
    fn luaL_loadfilex(state: *mut lua_State, filename: *const c_char, mode: *const c_char)
    -> c_int;
}

fn load_buffer(state: *mut lua_State, source: &[u8], mode: *const c_char) -> c_int {
    // SAFETY：source/name/mode 在同步呼叫期間有效；長度明確，不讀取尾端 NUL。
    unsafe {
        luaL_loadbufferx(
            state,
            source.as_ptr().cast(),
            source.len(),
            c"=load-api".as_ptr(),
            mode,
        )
    }
}

fn active_profile() -> LuaProfile {
    if cfg!(feature = "lua55") {
        LuaProfile::Lua55
    } else {
        LuaProfile::Lua54
    }
}

fn raw_rvlu_with_constant(profile: LuaProfile, constant_len: usize) -> Vec<u8> {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 1,
    };
    let environment = BytecodeBindingId {
        function: 0,
        ordinal: 0,
    };
    let module = BytecodeModule {
        format_version: RVLU_V2,
        profile,
        numeric_config: RVLU_NUMERIC_I64_F64,
        span,
        function_prototypes: vec![(0, ProtoId(0))],
        prototypes: vec![BytecodePrototype {
            id: ProtoId(0),
            function: 0,
            parent: None,
            span,
            register_count: 3,
            parameter_count: 0,
            is_variadic: false,
            named_vararg: None,
            frame: FrameLayout {
                register_limit: 4096,
                initial_top: Register(3),
                dynamic_top: Register(3),
                return_base: Register(0),
                environment: Register(2),
                environment_source: EnvironmentSource::RootExternal,
                registers_start_as_nil: true,
            },
            global_environment: Register(2),
            global_environment_binding: environment,
            binding_registers: vec![(environment, Register(2))],
            constants: vec![BytecodeConstant::String(vec![b'x'; constant_len])],
            upvalues: vec![],
            instructions: vec![BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
                span,
                close_path: None,
            }],
            close_paths: vec![],
        }],
    };
    encode_module(module, profile, &VerifyLimits::default())
        .unwrap()
        .bytes()
        .to_vec()
}

fn raw_rvlu(profile: LuaProfile) -> Vec<u8> {
    raw_rvlu_with_constant(profile, 256)
}

fn fill_prefix(owner: &StateOwner) {
    for index in 0..20 {
        owner.push_value(Value::Integer(1000 + index)).unwrap();
    }
}

fn assert_prefix(state: *mut lua_State) {
    unsafe {
        assert_eq!(lua_gettop(state), 21);
        for index in 0..20 {
            assert_eq!(
                lua_tointegerx(state, index + 1, ptr::null_mut()),
                i64::from(1000 + index)
            );
        }
    }
}

fn assert_allocation_ordinals_fail_and_refund(source: &[u8], mode: *const c_char) {
    let dry = StateOwner::new().unwrap();
    fill_prefix(&dry);
    assert_eq!(unsafe { lua_checkstack(dry.as_ptr(), 1) }, 1);
    let start = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    assert_eq!(load_buffer(dry.as_ptr(), source, mode), LUA_OK);
    let end = dry
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    let attempts = end - start;
    assert!(attempts > 0);
    assert_prefix(dry.as_ptr());
    assert_eq!(unsafe { lua_type(dry.as_ptr(), -1) }, LUA_TFUNCTION);
    dry.with_vm(|vm| {
        assert_eq!(vm.roots().count(RootKind::Host), 1);
        vm.collect().unwrap();
    })
    .unwrap();
    unsafe { lua_settop(dry.as_ptr(), 20) };
    dry.with_vm(|vm| {
        vm.collect().unwrap();
        assert_eq!(vm.roots().count(RootKind::Host), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    })
    .unwrap();

    let mut failed = 0;
    for offset in 0..attempts {
        let owner = StateOwner::new().unwrap();
        fill_prefix(&owner);
        let state = owner.as_ptr();
        assert_eq!(unsafe { lua_checkstack(state, 1) }, 1);
        let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
        let before = owner.with_vm(|vm| vm.ledger_snapshot()).unwrap();
        let ordinal = owner
            .with_vm(|vm| vm.allocation_trace().next_ordinal)
            .unwrap();
        owner
            .with_vm(|vm| vm.inject_allocation_failure_at(ordinal + offset))
            .unwrap();
        let status = load_buffer(state, source, mode);
        let failure = owner
            .with_vm(|vm| vm.allocation_trace().last_failure)
            .unwrap()
            .expect("dry run 的每個配置點必須到達注入點");
        assert_eq!(failure.attempt.ordinal, ordinal + offset);
        assert_eq!(failure.kind, AllocationFailureKind::Injection);
        assert_eq!(status, 4, "offset={offset} failure={failure:?}");
        failed += 1;
        assert_prefix(state);
        assert_eq!(unsafe { lua_type(state, -1) }, LUA_TSTRING);
        unsafe { lua_settop(state, 20) };
        owner
            .with_vm(|vm| {
                assert_eq!(vm.roots().count(RootKind::Host), 0);
                assert_eq!(vm.roots().count(RootKind::Temporary), 0);
                assert_eq!(vm.ledger_snapshot().reserved, 0);
                vm.collect().unwrap();
                let after = vm.ledger_snapshot();
                assert_eq!(after.reserved, 0);
                assert_eq!(
                    after.host_allocation_bytes, before.host_allocation_bytes,
                    "offset={offset} before={before:?} after={after:?}"
                );
            })
            .unwrap();
        drop(owner);
        assert_eq!(probe.snapshot().committed, 0, "offset={offset}");
        assert_eq!(probe.snapshot().reserved, 0, "offset={offset}");
    }
    assert_eq!(failed, attempts);
    eprintln!("B3 load allocation failed={failed}/attempts={attempts}");
}

#[test]
fn source_load_each_allocation_ordinal_fails_and_refunds() {
    assert_allocation_ordinals_fail_and_refund(b"return 41", c"t".as_ptr());
}

#[test]
fn rvlu_load_each_allocation_ordinal_fails_and_refunds() {
    let binary = raw_rvlu(active_profile());
    assert_allocation_ordinals_fail_and_refund(&binary, c"b".as_ptr());
}

#[test]
fn binary_profile_and_truncation_fail_with_one_error_slot() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    unsafe { lua_pushinteger(state, 73) };
    let foreign = if active_profile() == LuaProfile::Lua55 {
        LuaProfile::Lua54
    } else {
        LuaProfile::Lua55
    };
    assert_eq!(
        load_buffer(state, &raw_rvlu(foreign), c"b".as_ptr()),
        LUA_ERRSYNTAX
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        lua_settop(state, 1);
    }
    let binary = raw_rvlu(active_profile());
    assert_eq!(
        load_buffer(state, &binary[..6], c"b".as_ptr()),
        LUA_ERRSYNTAX
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
    }
}

#[test]
fn loadbuffer_text_modes_empty_and_syntax_preserve_prefix() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：owner 保活 C state。
    unsafe { lua_pushinteger(state, 73) };
    assert_eq!(load_buffer(state, b"return 41", ptr::null()), LUA_OK);
    // SAFETY：成功只新增一個函式，原 prefix 不變。
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
        assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
        lua_settop(state, 1);
    }

    assert_eq!(load_buffer(state, b"", c"t".as_ptr()), LUA_OK);
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
        lua_settop(state, 1);
    }
    assert_eq!(
        load_buffer(state, b"return 41", c"b".as_ptr()),
        LUA_ERRSYNTAX
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        lua_settop(state, 1);
    }
    assert_eq!(
        load_buffer(state, b"return )", c"t".as_ptr()),
        LUA_ERRSYNTAX
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        lua_settop(state, 1);
    }
    assert_eq!(load_buffer(state, b"", c"".as_ptr()), LUA_ERRSYNTAX);
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
    }
}

struct Reader {
    chunks: Vec<Vec<u8>>,
    next: usize,
}

unsafe extern "C" fn read_chunk(
    _state: *mut lua_State,
    data: *mut c_void,
    len: *mut usize,
) -> *const c_char {
    // SAFETY：測試以同步 lua_load 呼叫持有 Reader 與 len；資料保留到下次 reader 呼叫。
    let reader = unsafe { &mut *data.cast::<Reader>() };
    if reader.next == reader.chunks.len() {
        unsafe { *len = 0 };
        return ptr::null();
    }
    let chunk = &reader.chunks[reader.next];
    reader.next += 1;
    unsafe { *len = chunk.len() };
    chunk.as_ptr().cast()
}

#[test]
fn load_reader_fragments_preserve_prefix_and_publish_closure() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    unsafe { lua_pushinteger(state, 19) };
    let mut reader = Reader {
        chunks: vec![b"ret".to_vec(), b"urn ".to_vec(), b"91".to_vec()],
        next: 0,
    };
    // SAFETY：reader context 與各 chunk 在同步 C driver 期間有效，回呼不跳轉。
    let result = unsafe {
        lua_load(
            state,
            Some(read_chunk),
            (&mut reader as *mut Reader).cast(),
            ptr::null(),
            c"t".as_ptr(),
        )
    };
    assert_eq!(result, LUA_OK);
    assert_eq!(reader.next, 3);
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 19);
        assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
    }
}

#[test]
fn fragmented_rvlu_over_source_limit_uses_encoded_spool_limit() {
    let bytes = raw_rvlu_with_constant(active_profile(), 80 * 1024);
    let preflight =
        preflight_input_module(&bytes, active_profile(), &TransportLimits::default()).unwrap();
    let admission = preflight.admission();
    assert_eq!(admission.scan_work, 164_193);
    assert_eq!(admission.subsequent_work, 5_253_633);
    assert_eq!(admission.temporary_bytes, 22_325_760);
    assert_eq!(admission.retained_bytes, 10_506_240);
    assert!(bytes.len() > 64 * 1024);
    assert!(bytes.len() < 4 * 1024 * 1024);
    let default_owner = StateOwner::new().unwrap();
    let default_state = default_owner.as_ptr();
    assert_eq!(unsafe { lua_checkstack(default_state, 1) }, 1);
    let mut default_reader = Reader {
        chunks: vec![bytes[..1].to_vec(), bytes[1..].to_vec()],
        next: 0,
    };
    let default_status = unsafe {
        lua_load(
            default_state,
            Some(read_chunk),
            (&mut default_reader as *mut Reader).cast(),
            c"=rvlu-default-work".as_ptr(),
            c"b".as_ptr(),
        )
    };
    assert_eq!(default_status, 2);
    assert_eq!(unsafe { lua_gettop(default_state) }, 1);

    let owner = StateOwner::new_with_vm_setup(|vm| {
        let limits = LoadLimits {
            // RVLU body 按 64 倍計 work；實測 admission、暫存與保留量均須入限。
            max_work_units: 16_000_000,
            max_temporary_bytes: 32 * 1024 * 1024,
            max_module_allocation_bytes: 16 * 1024 * 1024,
            ..LoadLimits::default()
        };
        assert_eq!(vm.capi_configure_load_limits(limits), Ok(()));
    })
    .unwrap();
    let state = owner.as_ptr();
    assert_eq!(unsafe { lua_checkstack(state, 1) }, 1);
    let mut reader = Reader {
        chunks: vec![bytes[..1].to_vec(), bytes[1..].to_vec()],
        next: 0,
    };
    let status = unsafe {
        lua_load(
            state,
            Some(read_chunk),
            (&mut reader as *mut Reader).cast(),
            c"=rvlu-fragments".as_ptr(),
            c"b".as_ptr(),
        )
    };
    assert_eq!(status, LUA_OK);
    assert_eq!(reader.next, 2);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(unsafe { lua_type(state, -1) }, LUA_TFUNCTION);
}

#[cfg(feature = "lua55")]
#[test]
fn zero_top_allocation_failure_preserves_single_error_and_reuse() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_eq!(unsafe { lua_checkstack(state, 1) }, 1);
    let ordinal = owner
        .with_vm(|vm| vm.allocation_trace().next_ordinal)
        .unwrap();
    owner
        .with_vm(|vm| vm.inject_allocation_failure_at(ordinal))
        .unwrap();
    assert_eq!(load_buffer(state, b"return 1", c"t".as_ptr()), 4);
    assert_eq!(unsafe { lua_gettop(state) }, 1);
    assert_eq!(unsafe { lua_type(state, -1) }, LUA_TSTRING);
    unsafe { lua_settop(state, 0) };
    owner
        .with_vm(|vm| {
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
    assert_eq!(load_buffer(state, b"return 2", c"t".as_ptr()), LUA_OK);
    assert_eq!(unsafe { lua_type(state, -1) }, LUA_TFUNCTION);
}

struct Writer {
    bytes: Vec<u8>,
    calls: usize,
    stop: c_int,
}

unsafe extern "C" fn write_chunk(
    _state: *mut lua_State,
    bytes: *const c_void,
    len: usize,
    data: *mut c_void,
) -> c_int {
    // SAFETY：driver 同步持有資料與 Writer；回呼只複製已給定長度的 byte slice。
    let writer = unsafe { &mut *data.cast::<Writer>() };
    writer.calls += 1;
    if writer.stop != 0 {
        return writer.stop;
    }
    if bytes.is_null() && len == 0 {
        return 0;
    }
    writer
        .bytes
        .extend_from_slice(unsafe { std::slice::from_raw_parts(bytes.cast(), len) });
    0
}

#[test]
fn dump_official_roundtrip_and_writer_status_keep_stack() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    assert_eq!(load_buffer(state, b"return 41", c"t".as_ptr()), LUA_OK);
    let mut writer = Writer {
        bytes: Vec::new(),
        calls: 0,
        stop: 0,
    };
    // SAFETY：同步 writer 不跳轉，state 與 Writer 均保活。
    assert_eq!(
        unsafe {
            lua_dump(
                state,
                Some(write_chunk),
                (&mut writer as *mut Writer).cast(),
                1,
            )
        },
        0
    );
    assert!(writer.calls > 0);
    assert!(writer.bytes.starts_with(b"\x1bLua"));
    assert_eq!(
        writer.bytes[4],
        if cfg!(feature = "lua55") { 0x55 } else { 0x54 }
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    writer.stop = 73;
    assert_eq!(
        unsafe {
            lua_dump(
                state,
                Some(write_chunk),
                (&mut writer as *mut Writer).cast(),
                0,
            )
        },
        73
    );
    assert_eq!(unsafe { lua_gettop(state) }, 1);

    assert_eq!(load_buffer(state, &writer.bytes, c"b".as_ptr()), LUA_OK);
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
    }
}

#[test]
fn loadstring_uses_fixed_profile_mode() {
    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    // SAFETY：NUL 結束的來源與 state 在同步呼叫期間有效。
    assert_eq!(
        unsafe { luaL_loadstring(state, c"return 7".as_ptr()) },
        LUA_OK
    );
    assert_eq!(unsafe { lua_type(state, -1) }, LUA_TFUNCTION);
}

#[test]
fn loadfile_modes_missing_file_preserve_prefix_and_reuse() {
    struct TestSource(PathBuf);
    impl Drop for TestSource {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let source = TestSource(std::env::temp_dir().join(format!(
        "rivetlua-p16-b3-loadfilex-{}-{suffix}.lua",
        std::process::id()
    )));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source.0)
        .unwrap();
    file.write_all(b"return 41\n").unwrap();
    drop(file);
    let filename = CString::new(source.0.to_str().unwrap()).unwrap();

    let owner = StateOwner::new().unwrap();
    let state = owner.as_ptr();
    let probe = owner.with_vm(|vm| vm.ledger_probe()).unwrap();
    // SAFETY：owner 保活 state；filename 在所有同步 C 呼叫期間有效。
    unsafe { lua_pushinteger(state, 73) };
    for mode in [c"t".as_ptr(), ptr::null()] {
        // SAFETY：state 與 CString 保活；可能的 Lua 跳轉由純 C checkpoint 截止，不穿越 Rust frame。
        assert_eq!(
            unsafe { luaL_loadfilex(state, filename.as_ptr(), mode) },
            LUA_OK
        );
        unsafe {
            assert_eq!(lua_gettop(state), 2);
            assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
            assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
            lua_settop(state, 1);
        }
    }
    assert_eq!(
        unsafe { luaL_loadfilex(state, filename.as_ptr(), c"b".as_ptr()) },
        LUA_ERRSYNTAX
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        lua_settop(state, 1);
    }
    std::fs::remove_file(&source.0).unwrap();
    assert_eq!(
        unsafe { luaL_loadfilex(state, filename.as_ptr(), ptr::null()) },
        LUA_ERRFILE
    );
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
        assert_eq!(lua_type(state, -1), LUA_TSTRING);
        lua_settop(state, 1);
    }
    assert_eq!(load_buffer(state, b"return 42", c"t".as_ptr()), LUA_OK);
    unsafe {
        assert_eq!(lua_gettop(state), 2);
        assert_eq!(lua_tointegerx(state, 1, ptr::null_mut()), 73);
        assert_eq!(lua_type(state, -1), LUA_TFUNCTION);
        lua_settop(state, 1);
    }
    owner
        .with_vm(|vm| {
            vm.collect().unwrap();
            assert_eq!(vm.roots().count(RootKind::Host), 0);
            assert_eq!(vm.roots().count(RootKind::Temporary), 0);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
        })
        .unwrap();
    drop(owner);
    assert_eq!(probe.snapshot().reserved, 0);
    assert_eq!(probe.snapshot().committed, 0);
}
