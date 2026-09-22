use rivetlua_compiler::{
    BytecodeErrorCode, CompileLimits, ConstId, Instruction, IrLimits, LanguageProfile, LuaProfile,
    Register, ResultMode, VerifyLimits, decode_module, emit, lex, lower, parse, resolve,
    verify_module,
};
use std::{env, fs, path::PathBuf};

fn selected_profile() -> (LanguageProfile, LuaProfile, &'static str) {
    match env::var("RIVETLUA_P05_PROFILE").as_deref() {
        Ok("lua55-i64f64") | Err(_) => (LanguageProfile::Lua55, LuaProfile::Lua55, "lua55-i64f64"),
        Ok("lua54-i64f64") => (LanguageProfile::Lua54, LuaProfile::Lua54, "lua54-i64f64"),
        Ok(_) => panic!("P05 case profile 不合法"),
    }
}

fn expectations() -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest.parent().and_then(|path| path.parent()).unwrap();
    fs::read_to_string(root.join("tests/p05/bytecode-expectations.fixture"))
        .expect("P05 expectations fixture 必須存在")
}

fn expected(key: &str) -> String {
    expectations()
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .find_map(|line| line.split_once('=').filter(|(name, _)| *name == key))
        .map(|(_, value)| value.trim().to_owned())
        .unwrap_or_else(|| panic!("P05 expectations fixture 缺少 {key}"))
}

fn expected_bool(key: &str) -> bool {
    match expected(key).as_str() {
        "true" => true,
        "false" => false,
        value => panic!("P05 expectations fixture 的 {key} 不是 bool：{value}"),
    }
}

fn expected_usize(key: &str) -> usize {
    expected(key)
        .parse()
        .unwrap_or_else(|_| panic!("P05 expectations fixture 的 {key} 不是 usize"))
}

fn record(id: &str, input: &[u8], actual: &impl core::fmt::Debug) {
    if !expected_bool(&format!("{id}.enabled")) {
        return;
    }
    let input = String::from_utf8_lossy(input)
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    let actual = format!("{actual:?}")
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\t', "\\t");
    println!("P05_CASE\t{id}\t{input}\t{actual}");
}

fn ir(input: &[u8], profile: LanguageProfile) -> rivetlua_compiler::IrModule {
    let limits = CompileLimits::default();
    let chunk = lex(input, profile, &limits).unwrap();
    let module = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&module, &chunk, profile, &limits).unwrap();
    lower(&resolved, &IrLimits::default()).unwrap()
}

fn encoded(input: &[u8], profile: LanguageProfile) -> rivetlua_compiler::EncodedModule {
    emit(&ir(input, profile), &VerifyLimits::default()).unwrap()
}

fn first_root_opcode_offset(bytes: &[u8]) -> usize {
    let root_record = 36usize;
    let fixed_prefix = 49usize;
    let constants_length_offset = root_record + fixed_prefix;
    let constants_length = u32::from_le_bytes(
        bytes[constants_length_offset..constants_length_offset + 4]
            .try_into()
            .expect("RVLU constants 長度欄位必須完整"),
    ) as usize;
    let instructions_length_offset = constants_length_offset + 4 + constants_length;
    let instructions = instructions_length_offset + 4;
    instructions + 4
}

fn verified_module_compile_fail() -> String {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap()
        .to_owned();
    let directory = env::temp_dir().join(format!("rivetlua-p05-private-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir_all(directory.join("src")).unwrap();
    fs::write(
        directory.join("Cargo.toml"),
        format!(
            "[package]\nname=\"rivetlua-p05-private\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[dependencies]\nrivetlua-core={{path=\"{}\"}}\n",
            root.join("crates/rivetlua-core").display()
        ),
    )
    .unwrap();
    fs::write(
        directory.join("src/main.rs"),
        "fn main() { let _forged = rivetlua_core::VerifiedModule {}; }\n",
    )
    .unwrap();
    let output = std::process::Command::new("cargo")
        .args(["check", "--offline"])
        .current_dir(&directory)
        .output()
        .expect("compile-fail cargo 子行程必須可啟動");
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let _ = fs::remove_dir_all(&directory);
    assert!(
        !output.status.success(),
        "VerifiedModule 私有建構必須編譯失敗：{diagnostic}"
    );
    diagnostic
}

fn expect_error_code<T: core::fmt::Debug>(
    result: Result<T, rivetlua_compiler::BytecodeError>,
    code: BytecodeErrorCode,
) -> rivetlua_compiler::BytecodeError {
    let error = result.expect_err("P05 contract 必須拒絕不合法 bytecode");
    assert_eq!(error.code, code);
    error
}

#[test]
fn p05_contract_cases_for_one_profile() {
    let (profile, bytecode_profile, full_profile) = selected_profile();
    assert_eq!(expected(&format!("profile.{full_profile}")), full_profile);

    let input = b"return 1+2";
    let output = encoded(input, profile);
    let verified =
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
    assert_eq!(verified.profile(), bytecode_profile);
    assert!(
        verified.module().prototypes[0]
            .instructions
            .iter()
            .any(|item| matches!(item.instruction, Instruction::BinaryOp { .. }))
    );
    record("BC-001", input, &verified.module());

    let input = b"return 1+2";
    let output = encoded(input, profile);
    let mut malformed = output.verified().module().clone();
    malformed.prototypes[0].instructions[0].instruction = Instruction::LoadConst {
        dest: Register(0),
        constant: ConstId(u32::MAX),
    };
    let error = expect_error_code(
        verify_module(malformed, bytecode_profile, &VerifyLimits::default()),
        BytecodeErrorCode::Verify,
    );
    record("BC-002", input, &error);

    let input = b"local x=true; if x then return 1 end; return 2";
    let output = encoded(input, profile);
    let mut malformed = output.verified().module().clone();
    malformed.prototypes[0].instructions[0].instruction = Instruction::Jump {
        target: rivetlua_compiler::InstructionOffset(u32::MAX),
    };
    let error = expect_error_code(
        verify_module(malformed, bytecode_profile, &VerifyLimits::default()),
        BytecodeErrorCode::Verify,
    );
    record("BC-003", input, &error);

    let input = b"return 1+2";
    let output = encoded(input, profile);
    let mut malformed = output.verified().module().clone();
    let root = &mut malformed.prototypes[0];
    let return_index = root
        .instructions
        .iter()
        .position(|item| matches!(item.instruction, Instruction::Return { .. }))
        .expect("fixture 必須產生 return");
    root.instructions[return_index].instruction = Instruction::Return {
        base: Register(0),
        result_mode: ResultMode::All,
    };
    let rejected = verify_module(malformed, bytecode_profile, &VerifyLimits::default()).is_err();
    assert_eq!(rejected, expected("BC-004.all_result") == "reject");
    record("BC-004", input, &output.bytes());

    let input = b"local x=1; return x+2";
    let first = encoded(input, profile);
    let second = encoded(input, profile);
    assert_eq!(first.bytes(), second.bytes());
    record("BC-005", input, &first.bytes());

    let input = b"return 1";
    let compile_fail = verified_module_compile_fail();
    assert!(compile_fail.contains("private"));
    record("BC-006", input, &compile_fail);

    let input = b"return 1+2";
    let output = encoded(input, profile);
    let mut bytes = output.bytes().to_vec();
    let opcode_offset = first_root_opcode_offset(&bytes);
    bytes[opcode_offset] = 0xff;
    let unknown_error = expect_error_code(
        decode_module(&bytes, bytecode_profile, &VerifyLimits::default()),
        BytecodeErrorCode::Verify,
    );
    assert_eq!(
        unknown_error.code == BytecodeErrorCode::Verify,
        expected("BC-ERR-001.unknown_opcode") == "reject"
    );
    record("BC-ERR-001", input, &unknown_error);

    let input = b"local x; local function f() return x end; return f";
    let output = encoded(input, profile);
    let section_limits = VerifyLimits {
        max_module_bytes: expected_usize("BC-ERR-002.section_limit"),
        ..VerifyLimits::default()
    };
    let section_error = expect_error_code(
        decode_module(output.bytes(), bytecode_profile, &section_limits),
        BytecodeErrorCode::CompileLimit,
    );
    let register_limits = VerifyLimits {
        max_registers: expected_usize("BC-ERR-002.register_limit") as u16,
        ..VerifyLimits::default()
    };
    let register_error = expect_error_code(
        verify_module(
            output.verified().module().clone(),
            bytecode_profile,
            &register_limits,
        ),
        BytecodeErrorCode::CompileLimit,
    );
    let upvalue_limits = VerifyLimits {
        max_upvalues_per_prototype: expected_usize("BC-ERR-002.upvalue_limit"),
        ..VerifyLimits::default()
    };
    let upvalue_error = expect_error_code(
        verify_module(
            output.verified().module().clone(),
            bytecode_profile,
            &upvalue_limits,
        ),
        BytecodeErrorCode::CompileLimit,
    );
    record(
        "BC-ERR-002",
        input,
        &(section_error, register_error, upvalue_error),
    );
}
