use rivetlua_compiler::{
    BytecodeErrorCode, BytecodeExitKind, CompileLimits, ConstId, Instruction, IrLimits,
    LanguageProfile, LuaProfile, RVLU_V1, RVLU_V2, Register, ResultMode, VerifyLimits,
    decode_module, emit, lex, lower, parse, resolve, verify_module,
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

#[test]
fn p11_3_close_declaration_marker_roundtrips() {
    let (profile, bytecode_profile, _) = selected_profile();
    for source in [
        b"do local x <close> = nil end".as_slice(),
        b"for k in f,nil,nil,nil do break end".as_slice(),
    ] {
        let output = encoded(source, profile);
        let root = &output.verified().module().prototypes[0];
        let markers: Vec<_> = root
            .instructions
            .iter()
            .filter_map(|entry| match (&entry.instruction, &entry.close_path) {
                (Instruction::Move { dest, .. }, Some(path)) => Some((*dest, entry.span, path)),
                _ => None,
            })
            .collect();
        assert_eq!(markers.len(), 1, "每個 close binding 恰一宣告 marker");
        let (dest, span, marker) = markers[0];
        assert_eq!(marker.kind, BytecodeExitKind::Normal);
        assert_eq!(marker.target_scope, Some(marker.from_scope));
        assert_eq!(marker.span, span);
        assert_eq!(marker.registers, vec![dest]);
        assert_eq!(marker.bindings.len(), 1);
        assert!(root.close_paths.iter().any(|exit| {
            exit.bindings.contains(&marker.bindings[0]) && exit.registers.contains(&dest)
        }));
        assert!(!root.close_paths.contains(marker));
        let decoded = decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default())
            .expect("含宣告 marker 的 RVLU_V2 模組須可解碼");
        assert_eq!(
            decoded.module().prototypes[0].instructions,
            root.instructions
        );
    }
}

#[test]
fn p11_3_function_implicit_return_closes_root_binding() {
    let (profile, bytecode_profile, _) = selected_profile();
    let source = b"local function f() local x <close> = nil; error(9) end; return f";
    let lowered = ir(source, profile);
    let child = &lowered.prototypes[1];
    let marker = child
        .instructions
        .iter()
        .find_map(|entry| {
            matches!(entry.instruction, Instruction::Move { .. })
                .then_some(entry.close_path.as_ref())
                .flatten()
        })
        .expect("函式 root close binding 應有宣告 marker");
    let binding = marker.bindings[0];
    let register = marker.registers[0];
    let exit = child
        .close_paths
        .iter()
        .find(|path| {
            path.kind == rivetlua_compiler::ExitKind::Normal
                && path.target_scope.is_none()
                && path.bindings == [binding]
                && path.registers == [register]
        })
        .expect("隱含 return 前須有 Normal ClosePath");
    assert!(child.instructions.windows(2).any(|pair| {
        matches!(pair[0].instruction, Instruction::Close { base, count: 1 } if base == register)
            && pair[0].close_path.as_ref() == Some(exit)
            && matches!(pair[1].instruction, Instruction::Return { .. })
    }));
    let output = emit(&lowered, &VerifyLimits::default()).unwrap();
    decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();

    let mut missing = output.verified().module().clone();
    missing.prototypes[1].close_paths.clear();
    assert!(verify_module(missing, bytecode_profile, &VerifyLimits::default()).is_err());
    let mut wrong = output.verified().module().clone();
    let entry = wrong.prototypes[1]
        .instructions
        .iter_mut()
        .find(|entry| {
            matches!(entry.instruction, Instruction::Move { .. }) && entry.close_path.is_some()
        })
        .unwrap();
    entry.close_path.as_mut().unwrap().target_scope = None;
    assert!(verify_module(wrong, bytecode_profile, &VerifyLimits::default()).is_err());

    for ordinary in [
        b"local function f() return 7 end; return f".as_slice(),
        b"local function f() local x <close> = nil; return 7 end; return f".as_slice(),
    ] {
        let output = encoded(ordinary, profile);
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
    }
}

#[test]
fn p09_2_scope_close_producer_preserves_exit_and_tail_paths() {
    let (profile, bytecode_profile, _) = selected_profile();
    let nil_covers = |instruction: &Instruction, register: Register| {
        matches!(instruction, Instruction::LoadNil { start, count }
            if u32::from(start.0) <= u32::from(register.0)
                && u32::from(register.0) < u32::from(start.0) + u32::from(*count))
    };
    for source in [
        b"local f; while true do local x=7; f=function() return x end; break end; return f"
            .as_slice(),
        b"local f; do local x=7; f=function() return x end; goto L end ::L:: return f".as_slice(),
    ] {
        let output = encoded(source, profile);
        let root = &output.verified().module().prototypes[0];
        let exits = root
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(close_pc, entry)| {
                let Instruction::Close { base, count: 0 } = entry.instruction else {
                    return None;
                };
                if entry.close_path.is_some() {
                    return None;
                }
                let jump_pc = (close_pc + 1..root.instructions.len()).find(|&pc| {
                    !matches!(
                        root.instructions[pc].instruction,
                        Instruction::LoadNil { .. }
                    )
                })?;
                matches!(root.instructions[jump_pc].instruction,
                    Instruction::Jump { target } if target.0 as usize > jump_pc)
                .then_some((close_pc, jump_pc, base))
            })
            .collect::<Vec<_>>();
        assert_eq!(exits.len(), 1, "break/goto 須有唯一 captured close 與 jump");
        let (close_pc, jump_pc, base) = exits[0];
        assert!(close_pc + 1 < jump_pc, "離開 scope 前須清 captured binding");
        assert!(
            root.instructions[close_pc + 1..jump_pc]
                .iter()
                .all(|entry| matches!(entry.instruction, Instruction::LoadNil { .. }))
        );
        assert!(
            root.instructions[close_pc + 1..jump_pc]
                .iter()
                .any(|entry| nil_covers(&entry.instruction, base))
        );
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
    }

    let output = encoded(
        b"do local x=7; local f=function() return x end; return f end",
        profile,
    );
    let root = &output.verified().module().prototypes[0];
    let (close_pc, return_pc, closed) = root
        .instructions
        .iter()
        .enumerate()
        .find_map(|(close_pc, entry)| {
            let Instruction::Close { base, count: 0 } = entry.instruction else {
                return None;
            };
            let return_pc = close_pc + 1;
            matches!(
                root.instructions
                    .get(return_pc)
                    .map(|entry| &entry.instruction),
                Some(Instruction::Return { .. })
            )
            .then_some((close_pc, return_pc, base))
        })
        .expect("非 tail return 須先 close captured binding，再直接 Return");
    let Instruction::Return {
        base: return_base,
        result_mode: ResultMode::Fixed(return_count),
    } = root.instructions[return_pc].instruction
    else {
        panic!("此 return f 案例須回傳固定值");
    };
    assert_eq!(return_pc, close_pc + 1);
    assert_eq!(return_count, 1);
    for offset in 0..return_count {
        let result = Register(return_base.0 + offset);
        assert_ne!(
            result, closed,
            "return payload R{} 不可與 closed local 重疊",
            result.0
        );
    }
    decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();

    let output = encoded(
        b"local f=function() return 7 end; do local x=7; local g=function() return x end; return f() end",
        profile,
    );
    let root = &output.verified().module().prototypes[0];
    assert!(root.instructions.windows(2).any(|window| {
        matches!(window[0].instruction, Instruction::Close { count: 0, .. })
            && matches!(window[1].instruction, Instruction::TailCall { .. })
    }));

    let output = encoded(
        b"local f; do local x=7; local c <close> = {}; f=function() return x end end; return f",
        profile,
    );
    let root = &output.verified().module().prototypes[0];
    let (captured_pc, captured, closer) = root
        .instructions
        .windows(2)
        .enumerate()
        .find_map(
            |(pc, window)| match (&window[0].instruction, &window[1].instruction) {
                (
                    Instruction::Close {
                        base: captured,
                        count: 0,
                    },
                    Instruction::Close {
                        base: closer,
                        count: 1,
                    },
                ) if window[0].close_path.is_none() && window[1].close_path.is_some() => {
                    Some((pc, *captured, *closer))
                }
                _ => None,
            },
        )
        .expect("captured close 須先於 <close> callback");
    let cleanup = &root.instructions[captured_pc + 2..];
    let cleanup_len = cleanup
        .iter()
        .take_while(|entry| matches!(entry.instruction, Instruction::LoadNil { .. }))
        .count();
    assert!(cleanup_len > 0);
    for register in [captured, closer] {
        assert!(
            cleanup[..cleanup_len]
                .iter()
                .any(|entry| nil_covers(&entry.instruction, register))
        );
    }
}

#[test]
fn p09_3_prefix_open_return_contract() {
    let (profile, bytecode_profile, selected) = selected_profile();
    for (case, source, prefix) in [
        (
            "call-one",
            b"local f=function() return 1,2,3 end; return 9,f()".as_slice(),
            1,
        ),
        (
            "call-two",
            b"local f=function() return 1,2,3 end; return 9,8,f()".as_slice(),
            2,
        ),
        (
            "vararg-one",
            b"local f=function(a,...) return a,... end; local x,y,z=f(7,nil,9); return x,y,z"
                .as_slice(),
            1,
        ),
        (
            "close-one",
            b"local f=function() return 1,2 end; local c <close> = {}; return 9,f()"
                .as_slice(),
            1,
        ),
        (
            "scope-close-one",
            b"local f=function() return 1,2 end; do local x=9; local g=function() return x end; return x,f() end"
                .as_slice(),
            1,
        ),
    ] {
        let output = encoded(source, profile);
        assert_eq!(output.verified().format_version(), RVLU_V2);
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
        assert!(output.verified().module().prototypes.iter().any(|prototype| {
            prototype.instructions.iter().enumerate().any(|(index, entry)| {
                let producer = match entry.instruction {
                    Instruction::Call {
                        base,
                        result_mode: ResultMode::All,
                        ..
                    }
                    | Instruction::Vararg {
                        base,
                        result_mode: ResultMode::All,
                    } => base,
                    _ => return false,
                };
                let next = prototype.instructions[index + 1..]
                    .iter()
                    .find(|next| !matches!(next.instruction, Instruction::Close { .. }));
                matches!(next.map(|next| &next.instruction), Some(Instruction::Return { base, result_mode: ResultMode::All }) if producer.0 - base.0 == prefix)
            })
        }), "{case}: 前綴與 open producer base 差須保持");
        println!("P09_CASE\tPREFIX-OPEN-{case}\t{selected}\tstatus=PASS");
    }
}

#[test]
fn p09_3_dynamic_call_arguments_contract() {
    let (profile, bytecode_profile, selected) = selected_profile();
    for (case, source, expect_vararg, expect_tail) in [
        (
            "call",
            b"local f=function(...) return ... end; local g=function() return 1,2 end; local a,b=f(9,g()); return a,b".as_slice(),
            false,
            false,
        ),
        (
            "vararg",
            b"local f=function(...) return ... end; local w=function(...) local a,b=f(...); return a,b end; local x,y=w(1,2); return x,y".as_slice(),
            true,
            false,
        ),
        (
            "method",
            b"local t={m=function(self,...) return ... end}; local g=function() return 1,2 end; local a,b=t:m(g()); return a,b".as_slice(),
            false,
            false,
        ),
        (
            "statement",
            b"local f=function(...) end; local g=function() return 1,2 end; f(g()); return 7".as_slice(),
            false,
            false,
        ),
        (
            "tail",
            b"local f=function(...) return ... end; local g=function() return 1,2 end; return f(g())".as_slice(),
            false,
            true,
        ),
    ] {
        let output = encoded(source, profile);
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
        assert!(output.verified().module().prototypes.iter().any(|prototype| {
            prototype.instructions.windows(2).any(|window| {
                let producer = match window[0].instruction {
                    Instruction::Call { base, result_mode: ResultMode::All, .. } if !expect_vararg => base,
                    Instruction::Vararg { base, result_mode: ResultMode::All } if expect_vararg => base,
                    _ => return false,
                };
                match window[1].instruction {
                    Instruction::Call { base, arg_count: u16::MAX, .. } if !expect_tail => producer.0 > base.0,
                    Instruction::TailCall { base, arg_count: u16::MAX, .. } if expect_tail => producer.0 > base.0,
                    _ => false,
                }
            })
        }), "{case}");
        println!("P09_CASE\tDYNAMIC-CALL-ARGUMENTS-{case}\t{selected}\tstatus=PASS");
    }
}

#[test]
fn review_tail_dynamic_arguments_keep_open_producer_adjacent() {
    let (profile, bytecode_profile, _) = selected_profile();
    for (case, source) in [
        ("call", b"local function outer() local x=1; local h=function() return x end; local function g() x=9; return 2,nil end; local function f(...) return h(),... end; return f(g()) end; return outer()".as_slice()),
        ("vararg", b"local function outer(...) local x=1; local h=function() return x end; local function f(...) return h(),... end; return f(...) end; return outer(2,nil)".as_slice()),
        ("method", b"local function outer() local x=1; local h=function() return x end; local t={f=function(self,...) return h(),... end}; local function g() x=9; return 2,nil end; return t:f(g()) end; return outer()".as_slice()),
    ] {
        let output = encoded(source, profile);
        decode_module(output.bytes(), bytecode_profile, &VerifyLimits::default()).unwrap();
        assert!(
            output
                .verified()
                .module()
                .prototypes
                .iter()
                .any(|prototype| {
                    prototype.instructions.windows(2).any(|pair| {
                        matches!(
                            pair[0].instruction,
                            Instruction::Call { result_mode: ResultMode::All, .. }
                                | Instruction::Vararg { result_mode: ResultMode::All, .. }
                        ) && matches!(
                            pair[1].instruction,
                            Instruction::TailCall { arg_count: u16::MAX, result_mode: ResultMode::All, .. }
                        )
                    })
                }),
            "{case}"
        );
    }
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
