use rivetlua_compiler::{
    BytecodeErrorCode, CompileLimits, ConstId, Instruction, IrLimits, LanguageProfile, LuaProfile,
    RVLU_V1, RVLU_V2, Register, ResultMode, VerifyLimits, decode_module, emit, lex, lower, parse,
    resolve, verify_module,
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
    // prototype header：v2 加入 parameter_count、is_variadic、named-vararg flag。
    let fixed_prefix = 53usize;
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

fn assert_method_self_signature_survives_bytecode_round_trip(
    profile: LanguageProfile,
    bytecode_profile: LuaProfile,
) {
    for (input, parameter_count, arg_count, variadic) in [
        (
            b"local t={}; function t:m() return self end; return t:m()".as_slice(),
            1,
            1,
            false,
        ),
        (
            b"local t={}; function t:m(x,y,...) return self,x,y end; return t:m(1,2,3)".as_slice(),
            3,
            4,
            true,
        ),
    ] {
        let output = encoded(input, profile);
        let decoded =
            decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
        let method = &decoded.module().prototypes[1];
        assert_eq!(method.parameter_count, parameter_count);
        assert_eq!(method.is_variadic, variadic);
        let root = &decoded.module().prototypes[0];
        assert!(root.instructions.iter().any(|entry| matches!(
            entry.instruction,
            Instruction::TailCall { arg_count: count, .. } if count == arg_count
        )));
    }
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
    assert_method_self_signature_survives_bytecode_round_trip(profile, bytecode_profile);

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
    assert_eq!(output.verified().format_version(), RVLU_V2);
    let mut v1 = output.bytes().to_vec();
    v1[4..6].copy_from_slice(&RVLU_V1.0.to_le_bytes());
    let v1_error = expect_error_code(
        decode_module(&v1, bytecode_profile, &VerifyLimits::default()),
        BytecodeErrorCode::Verify,
    );
    record(
        "BC-007",
        input,
        &(output.verified().format_version(), v1_error),
    );

    let input = if profile == LanguageProfile::Lua55 {
        b"return function(a,... args) return a end".as_slice()
    } else {
        b"return function(a,...) return a end".as_slice()
    };
    let output = encoded(input, profile);
    let child = &output.verified().module().prototypes[1];
    assert_eq!(child.parameter_count, 1);
    assert!(child.is_variadic);
    assert_eq!(
        child.named_vararg.is_some(),
        profile == LanguageProfile::Lua55
    );
    record(
        "BC-008",
        input,
        &(child.parameter_count, child.is_variadic, child.named_vararg),
    );

    let input = b"local i,t; i,t[i]=i+1,20; for n=2,1,-1 do end; return {7}[1]";
    let output = encoded(input, profile);
    let root = &output.verified().module().prototypes[0];
    assert!(root.instructions.iter().any(|entry| matches!(
        entry.instruction,
        Instruction::NumericForPrepare { .. } | Instruction::NumericForNext { .. }
    )));
    assert!(
        root.instructions
            .iter()
            .any(|entry| entry.instruction.effects().safe_point)
    );
    let (set_index, table_snapshot, key_snapshot) = root
        .instructions
        .iter()
        .enumerate()
        .find_map(|(index, entry)| match entry.instruction {
            Instruction::SetTable { table, key, .. } => Some((index, table, key)),
            _ => None,
        })
        .expect("BC-009 i,t[i] 必須產生 SetTable");
    let (table_snapshot_index, table_binding) = root.instructions[..set_index]
        .iter()
        .enumerate()
        .find_map(|(index, entry)| match entry.instruction {
            Instruction::Move { dest, src } if dest == table_snapshot => Some((index, src)),
            _ => None,
        })
        .expect("BC-009 table 必須有 snapshot");
    let (key_snapshot_index, i_binding) = root.instructions[..set_index]
        .iter()
        .enumerate()
        .find_map(|(index, entry)| match entry.instruction {
            Instruction::Move { dest, src } if dest == key_snapshot => Some((index, src)),
            _ => None,
        })
        .expect("BC-009 key 必須有 snapshot");
    let i_write = root.instructions[key_snapshot_index + 1..set_index]
        .iter()
        .position(|entry| matches!(entry.instruction, Instruction::Move { dest, .. } if dest == i_binding))
        .map(|offset| key_snapshot_index + 1 + offset)
        .expect("BC-009 必須先寫 i 再寫 table");
    assert_ne!(table_snapshot, table_binding);
    assert_ne!(key_snapshot, i_binding);
    assert!(table_snapshot_index < key_snapshot_index);
    assert!(key_snapshot_index < i_write && i_write < set_index);
    let call_snapshot_input =
        b"local t,k; local function f() t={}; k=2; return {},20 end; t[k],k=f(); return t";
    let call_snapshot_output = encoded(call_snapshot_input, profile);
    let call_snapshot_root = &call_snapshot_output.verified().module().prototypes[0];
    let (call_set_index, call_table_snapshot, call_key_snapshot) = call_snapshot_root
        .instructions
        .iter()
        .enumerate()
        .find_map(|(index, entry)| match entry.instruction {
            Instruction::SetTable { table, key, .. } => Some((index, table, key)),
            _ => None,
        })
        .expect("BC-009 RHS Call case 必須產生 SetTable");
    let call_index = call_snapshot_root
        .instructions
        .iter()
        .enumerate()
        .find_map(|(index, entry)| {
            matches!(
                entry.instruction,
                Instruction::Call {
                    arg_count: 0,
                    result_mode: ResultMode::Fixed(2),
                    ..
                }
            )
            .then_some(index)
        })
        .expect("BC-009 RHS f() 必須以兩個固定結果呼叫");
    for snapshot in [call_table_snapshot, call_key_snapshot] {
        let snapshot_index = call_snapshot_root.instructions[..call_index]
            .iter()
            .enumerate()
            .find_map(|(index, entry)| {
                matches!(
                    entry.instruction,
                    Instruction::Move { dest, .. } if dest == snapshot
                )
                .then_some(index)
            })
            .expect("BC-009 RHS Call 前必須固定 table/key");
        assert!(snapshot_index < call_index && call_index < call_set_index);
    }
    let effect_source = encoded(b"return 1+2", profile);
    let mut effect_mismatch = effect_source.bytes().to_vec();
    // 此 module 的第一條 instruction 是 `LoadConst { dest, constant }`：
    // opcode(1) 加 u16/u32 後即為 RVLU_V2 canonical effect byte。
    let first_effect = first_root_opcode_offset(&effect_mismatch) + 7;
    effect_mismatch[first_effect] ^= 1;
    let effect_error = expect_error_code(
        decode_module(&effect_mismatch, bytecode_profile, &VerifyLimits::default()),
        BytecodeErrorCode::Verify,
    );
    for short_circuit in [
        b"local f; return false and f()".as_slice(),
        b"local f; return true or f()".as_slice(),
    ] {
        let short = encoded(short_circuit, profile);
        let instructions = &short.verified().module().prototypes[0].instructions;
        assert!(
            instructions
                .iter()
                .any(|entry| matches!(entry.instruction, Instruction::JumpIfFalse { .. }))
        );
        assert!(
            instructions
                .iter()
                .any(|entry| matches!(entry.instruction, Instruction::Call { .. }))
        );
        assert!(!instructions.iter().any(|entry| matches!(
            entry.instruction,
            Instruction::BinaryOp {
                op: rivetlua_compiler::BinaryOperation::And
                    | rivetlua_compiler::BinaryOperation::Or,
                ..
            }
        )));
    }
    record("BC-009", input, &(root.instructions.len(), effect_error));

    let input =
        b"local f,a,b,c; a,b,c=f(1,2,3,4); a,b=(f(1,2,3,4)); for k in f(1,2,3,4) do end; return a";
    let output = encoded(input, profile);
    let root = &output.verified().module().prototypes[0];
    let fixed_results = root
        .instructions
        .iter()
        .filter_map(|entry| match entry.instruction {
            Instruction::Call {
                arg_count: 4,
                result_mode: ResultMode::Fixed(count),
                ..
            } => Some(count),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        fixed_results.windows(3).any(|counts| counts == [3, 1, 4]),
        "P05 必須保留 assignment 最後 open result、括號單值與 generic-for 四值 closing：{fixed_results:?}"
    );
    assert!(
        root.instructions
            .iter()
            .any(|entry| matches!(entry.instruction, Instruction::LoadNil { count: 1, .. }))
    );
    let vararg_input =
        b"local function g(...) local a,b,c=...; for k in ... do end; return a end; return g";
    let vararg_output = encoded(vararg_input, profile);
    let child = &vararg_output.verified().module().prototypes[1];
    let vararg_results = child
        .instructions
        .iter()
        .filter_map(|entry| match entry.instruction {
            Instruction::Vararg {
                result_mode: ResultMode::Fixed(count),
                ..
            } => Some(count),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        vararg_results.windows(2).any(|counts| counts == [3, 4]),
        "最後 Vararg 必須按 assignment 三值與 generic-for 四值調整：{vararg_results:?}"
    );
    record("BC-010", input, &(fixed_results, vararg_results));

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
