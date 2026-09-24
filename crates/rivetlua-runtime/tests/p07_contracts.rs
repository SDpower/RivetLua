use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit, lex, lower, parse, resolve,
};
use rivetlua_core::{
    BytecodeBindingId, BytecodeConstant, BytecodeInstruction, BytecodeModule, BytecodePrototype,
    BytecodeSpan, ConstId, EnvironmentSource, FrameLayout, Instruction, InstructionOffset,
    LuaProfile, ProtoId, RVLU_NUMERIC_I64_F64, RVLU_V1, RVLU_V2, Register, ResultMode, Value,
    VerifyLimits, verify_module,
};
use rivetlua_runtime::{FailPoint, RunOutcome, RuntimeErrorKind, Vm, VmError};

fn profile_name(profile: LanguageProfile) -> &'static str {
    match profile {
        LanguageProfile::Lua55 => "lua55-i64f64",
        LanguageProfile::Lua54 => "lua54-i64f64",
    }
}

fn record_case(profile: LanguageProfile, case_id: &str, input: &str, actual: &str) {
    let Ok(required_profile) = std::env::var("RIVETLUA_P07_PROFILE") else {
        return;
    };
    assert!(matches!(
        required_profile.as_str(),
        "lua55-i64f64" | "lua54-i64f64"
    ));
    assert!(!input.contains('\t') && !input.contains('\n'));
    assert!(!actual.contains('\t') && !actual.contains('\n'));
    if required_profile == profile_name(profile) {
        println!("P07_CASE\t{case_id}\t{required_profile}\t{input}\t{actual}");
    }
}

fn candidate(instructions: Vec<Instruction>, constants: Vec<BytecodeConstant>) -> BytecodeModule {
    let span = BytecodeSpan {
        start_byte: 0,
        end_byte: 10,
    };
    BytecodeModule {
        format_version: RVLU_V2,
        profile: LuaProfile::Lua55,
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
            global_environment_binding: BytecodeBindingId {
                function: 0,
                ordinal: 0,
            },
            binding_registers: vec![(
                BytecodeBindingId {
                    function: 0,
                    ordinal: 0,
                },
                Register(2),
            )],
            constants,
            upvalues: vec![],
            instructions: instructions
                .into_iter()
                .map(|instruction| BytecodeInstruction {
                    instruction,
                    span,
                    close_path: None,
                })
                .collect(),
            close_paths: vec![],
        }],
    }
}

fn run(instructions: Vec<Instruction>, constants: Vec<BytecodeConstant>) -> RunOutcome {
    let verified = verify_module(
        candidate(instructions, constants),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(verified).unwrap();
    execution.run().unwrap()
}

#[test]
fn verified_module_loads_and_executes_move_nil_return() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let mut source = candidate(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Move {
                    dest: Register(1),
                    src: Register(0),
                },
                Instruction::LoadNil {
                    start: Register(0),
                    count: 1,
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(2),
                },
            ],
            vec![BytecodeConstant::Integer(41)],
        );
        source.profile = profile;
        let verified = verify_module(source, profile, &VerifyLimits::default()).unwrap();
        let mut vm = Vm::new().unwrap();
        let actual = vm.load(verified).unwrap().run().unwrap();
        assert_eq!(
            actual,
            RunOutcome::Returned(vec![Value::Nil, Value::Integer(41)])
        );
    }
}

#[test]
fn conditional_jump_uses_lua_truthiness() {
    for (constant, expected) in [
        (BytecodeConstant::Boolean(false), Value::Nil),
        (BytecodeConstant::Integer(0), Value::Integer(0)),
    ] {
        let actual = run(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::JumpIfFalse {
                    condition: Register(0),
                    target: InstructionOffset(3),
                },
                Instruction::Jump {
                    target: InstructionOffset(4),
                },
                Instruction::LoadNil {
                    start: Register(0),
                    count: 1,
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![constant],
        );
        assert_eq!(actual, RunOutcome::Returned(vec![expected]));
    }
}

#[test]
fn unsupported_instructions_and_string_constant_are_rejected() {
    for instruction in [
        Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::Fixed(1),
        },
        Instruction::GetTable {
            dest: Register(0),
            table: Register(0),
            key: Register(1),
        },
    ] {
        let opcode = instruction.opcode();
        let verified = verify_module(
            candidate(
                vec![
                    instruction,
                    Instruction::Return {
                        base: Register(0),
                        result_mode: ResultMode::Fixed(1),
                    },
                ],
                vec![],
            ),
            LuaProfile::Lua55,
            &VerifyLimits::default(),
        )
        .unwrap();
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.load(verified).err().unwrap().kind,
            RuntimeErrorKind::UnsupportedInstruction(opcode)
        );
    }
    let verified = verify_module(
        candidate(
            vec![
                Instruction::LoadConst {
                    dest: Register(0),
                    constant: ConstId(0),
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
            ],
            vec![BytecodeConstant::String(b"hello".to_vec())],
        ),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let mut vm = Vm::new().unwrap();
    assert_eq!(
        vm.load(verified).err().unwrap().kind,
        RuntimeErrorKind::UnsupportedConstant
    );
}

#[test]
fn version_and_broken_cfg_never_become_verified() {
    let instructions = vec![Instruction::Return {
        base: Register(0),
        result_mode: ResultMode::Fixed(0),
    }];
    let mut old = candidate(instructions.clone(), vec![]);
    old.format_version = RVLU_V1;
    assert!(verify_module(old, LuaProfile::Lua55, &VerifyLimits::default()).is_err());
    let broken = candidate(
        vec![Instruction::LoadNil {
            start: Register(0),
            count: 1,
        }],
        vec![],
    );
    assert!(verify_module(broken, LuaProfile::Lua55, &VerifyLimits::default()).is_err());
}

#[test]
fn execution_is_tied_to_its_original_vm() {
    let verified = verify_module(
        candidate(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        ),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let mut original = Vm::new().unwrap();
    let other = Vm::new().unwrap();
    let expected = original.id();
    let mut execution = original.load(verified).unwrap();
    assert_eq!(execution.vm_id(), expected);
    assert_ne!(execution.vm_id(), other.id());
    assert_eq!(execution.pc(), 0);
    assert_eq!(execution.run(), Ok(RunOutcome::Returned(vec![])));
    assert_eq!(execution.fuel_remaining(), 999_999);
    assert_eq!(
        execution.run().err().unwrap().kind,
        RuntimeErrorKind::TerminalExecution
    );
}

#[test]
fn closure_opcode_is_rejected_after_successful_verification() {
    let mut module = candidate(
        vec![
            Instruction::Closure {
                dest: Register(0),
                proto: ProtoId(1),
            },
            Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(1),
            },
        ],
        vec![],
    );
    let mut child = module.prototypes[0].clone();
    child.id = ProtoId(1);
    child.function = 1;
    child.parent = Some(ProtoId(0));
    child.frame.environment_source = EnvironmentSource::ParentFrame {
        parent: ProtoId(0),
        register: Register(2),
    };
    child.global_environment_binding = BytecodeBindingId {
        function: 1,
        ordinal: 0,
    };
    child.binding_registers = vec![(child.global_environment_binding, Register(2))];
    child.instructions = vec![BytecodeInstruction {
        instruction: Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(0),
        },
        span: module.span,
        close_path: None,
    }];
    module.function_prototypes.push((1, ProtoId(1)));
    module.prototypes.push(child);
    let verified = verify_module(module, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
    let mut vm = Vm::new().unwrap();
    let error = vm.load(verified).err().unwrap();
    assert_eq!(
        error.kind,
        RuntimeErrorKind::UnsupportedInstruction(rivetlua_core::Opcode::Closure)
    );
    assert_eq!(error.diagnostic_id, "E_VM_OPCODE_UNSUPPORTED");
}

#[test]
fn frame_quota_failure_leaves_no_root_or_ledger_debt() {
    let verified = verify_module(
        candidate(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        ),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let mut vm = Vm::new().unwrap();
    vm.set_allocation_limit(vm.ledger_snapshot().committed);
    let before = vm.ledger_snapshot();
    let error = vm.load(verified).err().unwrap();
    assert_eq!(
        error.kind,
        RuntimeErrorKind::Heap(rivetlua_runtime::VmError::AllocationFailed)
    );
    assert_eq!(error.diagnostic_id, "E_ALLOCATION_FAILED");
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), 0);
}

#[test]
fn frame_reserve_failpoints_and_second_reservation_quota_roll_back() {
    let verified = verify_module(
        candidate(
            vec![Instruction::Return {
                base: Register(0),
                result_mode: ResultMode::Fixed(0),
            }],
            vec![],
        ),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    for point in [
        FailPoint::FrameRegistersReserve,
        FailPoint::FrameRootsReserve,
    ] {
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(point);
        assert_eq!(
            vm.load(verified.clone()).err().unwrap().kind,
            RuntimeErrorKind::Heap(VmError::InjectedFailure(point))
        );
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.roots().total_count(), 0);
    }

    let mut vm = Vm::new().unwrap();
    let register_bytes = 3 * std::mem::size_of::<Value>();
    vm.set_allocation_limit(register_bytes);
    let before = vm.ledger_snapshot();
    assert_eq!(
        vm.load(verified).err().unwrap().kind,
        RuntimeErrorKind::Heap(VmError::AllocationFailed)
    );
    assert_eq!(vm.ledger_snapshot(), before);
    assert_eq!(vm.roots().total_count(), 0);
}

fn compiled(input: &[u8], profile: LanguageProfile) -> rivetlua_core::VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(input, profile, &limits).unwrap();
    let parsed = parse(&chunk, profile, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, profile, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit(&ir, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn compiled_run(input: &[u8], profile: LanguageProfile) -> (RunOutcome, u64) {
    let verified = compiled(input, profile);
    let mut vm = Vm::new().unwrap();
    let mut execution = vm.load(verified).unwrap();
    let outcome = execution.run().unwrap();
    (outcome, execution.fuel_remaining())
}

fn compiled_run_observed(
    input: &[u8],
    profile: LanguageProfile,
) -> (RunOutcome, u64, usize, usize) {
    let verified = compiled(input, profile);
    let mut vm = Vm::new().unwrap();
    let ledger_before = vm.ledger_snapshot();
    let mut execution = vm.load(verified).unwrap();
    let outcome = execution.run().unwrap();
    let fuel_remaining = execution.fuel_remaining();
    let pc = execution.pc();
    drop(execution);
    let roots_after_drop = vm.roots().total_count();
    assert_eq!(vm.ledger_snapshot(), ledger_before);
    (outcome, fuel_remaining, pc, roots_after_drop)
}

#[test]
fn vm001_compiler_arithmetic_both_profiles() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let (actual, fuel, pc, roots) = compiled_run_observed(b"return 1+2*3", profile);
        assert_eq!(actual, RunOutcome::Returned(vec![Value::Integer(7)]));
        assert_eq!(
            compiled_run(b"return 2^3", profile).0,
            RunOutcome::Returned(vec![Value::Float(8.0)])
        );
        record_case(
            profile,
            "VM-001",
            "return 1+2*3",
            &format!(
                "{actual:?}; power=Float(8.0); fuel_remaining={fuel}; pc={pc}; roots_after_drop={roots}"
            ),
        );
    }
}

#[test]
fn vm004_compiler_repeat_executes_body_before_condition() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = b"local i=0; repeat i=i+1 until i==3; return i";
        let (actual, fuel, pc, roots) = compiled_run_observed(input, profile);
        assert_eq!(actual, RunOutcome::Returned(vec![Value::Integer(3)]));
        record_case(
            profile,
            "VM-004",
            "local i=0; repeat i=i+1 until i==3; return i",
            &format!(
                "{actual:?}; repeat body precedes condition; fuel_remaining={fuel}; pc={pc}; roots_after_drop={roots}"
            ),
        );
    }
}

#[test]
fn vm002_compiler_snapshots_local_rhs_before_committing_swap() {
    let source = b"local a,b=1,2; a,b=b,a; return a,b";
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let verified = compiled(source, profile);
        let root = &verified.module().prototypes[0];
        let binding = |ordinal| {
            root.binding_registers
                .iter()
                .find(|(id, _)| id.function == 0 && id.ordinal == ordinal)
                .map(|(_, register)| *register)
                .unwrap()
        };
        let a = binding(1);
        let b = binding(2);
        let last_write = |target| {
            root.instructions
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match entry.instruction {
                    Instruction::Move { dest, src } if dest == target => Some((index, src)),
                    _ => None,
                })
                .last()
                .unwrap()
        };
        let (a_commit, a_source) = last_write(a);
        let (b_commit, b_source) = last_write(b);
        assert!(a_commit < b_commit);
        assert_ne!(a_source, a);
        assert_ne!(a_source, b);
        assert_ne!(b_source, a);
        assert_ne!(b_source, b);
        assert_ne!(a_source, b_source);
        let snapshot = |dest, src| {
            root.instructions[..a_commit]
                .iter()
                .position(|entry| {
                    matches!(entry.instruction, Instruction::Move { dest: actual_dest, src: actual_src } if actual_dest == dest && actual_src == src)
                })
                .unwrap()
        };
        assert!(snapshot(a_source, b) < a_commit);
        assert!(snapshot(b_source, a) < a_commit);

        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let vm_id = vm.id();
        let mut execution = vm.load(verified).unwrap();
        let actual = execution.run().unwrap();
        assert_eq!(
            actual,
            RunOutcome::Returned(vec![Value::Integer(2), Value::Integer(1)])
        );
        assert_eq!(execution.vm_id(), vm_id);
        let fuel = execution.fuel_remaining();
        let pc = execution.pc();
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        record_case(
            profile,
            "VM-002",
            "local a,b=1,2; a,b=b,a; return a,b",
            &format!(
                "{actual:?}; rhs_snapshot_before_commit=true; fuel_remaining={fuel}; pc={pc}; roots_after_drop=0"
            ),
        );
    }
}

#[test]
fn vm010_compiler_reports_later_error_after_local_assignment() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = b"local a=10; a=20; return a//0";
        let verified = compiled(input, profile);
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let outcome = execution.run().unwrap();
        let RunOutcome::LuaError(error) = outcome else {
            panic!("後續整數除零必須形成 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_INTEGER_DIVIDE_BY_ZERO");
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(1).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        let fuel = execution.fuel_remaining();
        let pc = execution.pc();
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        record_case(
            profile,
            "VM-010",
            "local a=10; a=20; return a//0",
            &format!(
                "LuaError({:?}); diagnostic_id={}; fuel_remaining={fuel}; pc={pc}; roots_after_drop=0",
                error.kind, error.diagnostic_id
            ),
        );
    }
}

#[test]
fn vm003_numeric_for_default_step_sums_one_through_hundred() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = b"local s=0; for i=1,100 do s=s+i end; return s";
        let verified = compiled(input, profile);
        let root = &verified.module().prototypes[0];
        assert_eq!(
            root.instructions
                .iter()
                .filter(|entry| matches!(entry.instruction, Instruction::NumericForPrepare { .. }))
                .count(),
            1
        );
        assert_eq!(
            root.instructions
                .iter()
                .filter(|entry| matches!(entry.instruction, Instruction::NumericForNext { .. }))
                .count(),
            1
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let actual = execution.run().unwrap();
        assert_eq!(actual, RunOutcome::Returned(vec![Value::Integer(5050)]));
        let fuel = execution.fuel_remaining();
        let pc = execution.pc();
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        record_case(
            profile,
            "VM-003",
            "local s=0; for i=1,100 do s=s+i end; return s",
            &format!(
                "{actual:?}; NumericForPrepare=1; NumericForNext=1; control_inputs_evaluated_once=true; fuel_remaining={fuel}; pc={pc}; roots_after_drop=0"
            ),
        );
    }
}

#[test]
fn vm006_numeric_for_zero_step_is_lua_error() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = "local s=0; for i=1,3,0 do s=s+1 end; return s";
        let verified = compiled(input.as_bytes(), profile);
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("numeric for 的零 step 必須形成 LuaError")
        };
        assert_eq!(error.kind, RuntimeErrorKind::NumericForZeroStep);
        assert_eq!(error.diagnostic_id, "E_NUMERIC_FOR_ZERO_STEP");
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        let fuel = execution.fuel_remaining();
        let pc = execution.pc();
        drop(execution);
        let roots = vm.roots().total_count();
        assert_eq!(roots, 0);
        assert_eq!(vm.ledger_snapshot(), before);
        record_case(
            profile,
            "VM-006",
            input,
            &format!(
                "LuaError({:?}); diagnostic_id={}; fuel_remaining={fuel}; pc={pc}; body_not_executed=true; roots_after_drop={roots}",
                error.kind, error.diagnostic_id
            ),
        );
    }
}

#[test]
fn vm008_numeric_for_descends_and_skips_out_of_range_starts() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let cases = [
            (
                b"local s=0; for i=5,1,-2 do s=s+i end; return s".as_slice(),
                Value::Integer(9),
            ),
            (
                b"local s=0; for i=5,1 do s=s+1 end; return s".as_slice(),
                Value::Integer(0),
            ),
            (
                b"local s=0; for i=1,5,-1 do s=s+1 end; return s".as_slice(),
                Value::Integer(0),
            ),
        ];
        let mut outcomes = Vec::new();
        let mut evidence = Vec::new();
        for (index, (source, expected)) in cases.into_iter().enumerate() {
            let (actual, fuel, pc, roots) = compiled_run_observed(source, profile);
            assert_eq!(actual, RunOutcome::Returned(vec![expected]));
            let label = [
                "descending",
                "positive_out_of_range",
                "negative_out_of_range",
            ][index];
            outcomes.push(format!("{label}={actual:?}"));
            evidence.push(format!(
                "{label}[fuel_remaining={fuel}, pc={pc}, roots_after_drop={roots}]"
            ));
        }
        record_case(
            profile,
            "VM-008",
            "local s=0; for i=5,1,-2 do s=s+i end; return s //CASE// local s=0; for i=5,1 do s=s+1 end; return s //CASE// local s=0; for i=1,5,-1 do s=s+1 end; return s",
            &format!(
                "{}; evidence=[{}]",
                outcomes.join("; "),
                evidence.join("; ")
            ),
        );
    }
}

#[test]
fn vm009_numeric_for_integer_edges_stop_without_wrapping() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let sources = [
            b"local n=0; for i=9223372036854775806,9223372036854775807,1 do n=n+1 end; return n".as_slice(),
            b"local n=0; for i=-9223372036854775807,(-9223372036854775807-1),-1 do n=n+1 end; return n".as_slice(),
        ];
        let mut outcomes = Vec::new();
        let mut evidence = Vec::new();
        for (index, source) in sources.into_iter().enumerate() {
            let (actual, fuel, pc, roots) = compiled_run_observed(source, profile);
            assert_eq!(actual, RunOutcome::Returned(vec![Value::Integer(2)]));
            let label = ["upper", "lower"][index];
            outcomes.push(format!("{label}={actual:?}"));
            evidence.push(format!(
                "{label}[fuel_remaining={fuel}, pc={pc}, roots_after_drop={roots}]"
            ));
        }
        record_case(
            profile,
            "VM-009",
            "local n=0; for i=9223372036854775806,9223372036854775807,1 do n=n+1 end; return n //CASE// local n=0; for i=-9223372036854775807,(-9223372036854775807-1),-1 do n=n+1 end; return n",
            &format!(
                "{}; no_wrap=true; evidence=[{}]",
                outcomes.join("; "),
                evidence.join("; ")
            ),
        );
    }
}

#[test]
fn numeric_for_float_and_non_numeric_paths_are_checked() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        assert_eq!(
            compiled_run(
                b"local s=0.0; for i=0.5,1.5,0.5 do s=s+i end; return s",
                profile
            )
            .0,
            RunOutcome::Returned(vec![Value::Float(3.0)])
        );
        assert_eq!(
            compiled_run(b"local s=0; for i=1,3.0,1 do s=s+i end; return s", profile).0,
            RunOutcome::Returned(vec![Value::Integer(6)])
        );
        let verified = compiled(b"for i=true,3,1 do end; return 0", profile);
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        let Ok(RunOutcome::LuaError(error)) = execution.run() else {
            panic!("非數值 numeric for 初值須形成 LuaError")
        };
        assert_eq!(error.diagnostic_id, "E_NOT_NUMERIC");
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
    }
}

#[test]
fn numeric_for_copies_three_control_inputs_before_body_mutations() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        assert_eq!(
            compiled_run(
                b"local a,l,p=1,3,1; local n=0; for i=a,l,p do a=100; l=0; p=0; n=n+1 end; return n",
                profile,
            )
            .0,
            RunOutcome::Returned(vec![Value::Integer(3)])
        );
    }
}

#[test]
fn numeric_for_float_nonprogress_respects_fuel_budget() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let verified = compiled(
            b"for i=9007199254740992.0,9007199254740992.0,1.0 do end; return 0",
            profile,
        );
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(40).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(
                rivetlua_runtime::AbortReason::FuelExhausted
            ))
        );
        assert_eq!(execution.fuel_remaining(), 0);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
    }
}

#[test]
fn compiler_finishes_while_true_with_verified_implicit_return() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let verified = compiled(b"while true do end", profile);
        let instructions = &verified.module().prototypes[0].instructions;
        assert!(matches!(
            instructions.last().map(|entry| &entry.instruction),
            Some(Instruction::Return {
                result_mode: ResultMode::Fixed(0),
                ..
            })
        ));
        let mut vm = Vm::new().unwrap();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(17).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(
                rivetlua_runtime::AbortReason::FuelExhausted
            ))
        );
        assert_eq!(execution.fuel_remaining(), 0);
        assert!((1..=2).contains(&execution.pc()));
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
    }
}

#[test]
fn vm005_finite_fuel_aborts_in_while_loop_both_profiles() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = "while true do end";
        let verified = compiled(input.as_bytes(), profile);
        let instructions = &verified.module().prototypes[0].instructions;
        let (loop_start, loop_end) = instructions
            .iter()
            .enumerate()
            .find_map(|(index, entry)| match entry.instruction {
                Instruction::Jump { target } if (target.0 as usize) < index => {
                    Some((target.0 as usize, index))
                }
                _ => None,
            })
            .unwrap();
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(17).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(
                rivetlua_runtime::AbortReason::FuelExhausted
            ))
        );
        assert_eq!(execution.fuel_remaining(), 0);
        let pc = execution.pc();
        assert!((loop_start..=loop_end).contains(&pc));
        drop(execution);
        let roots = vm.roots().total_count();
        assert_eq!(roots, 0);
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.collect().unwrap(), 0);
        record_case(
            profile,
            "VM-005",
            input,
            &format!(
                "Aborted(FuelExhausted); module=compiler_verified_rvlu_v2; implicit_return=Fixed(0); p05_compiler_used=true; fuel_initial=17; fuel_remaining=0; pc={pc}; loop_pc={loop_start}..={loop_end}; roots_after_drop={roots}; collect=0"
            ),
        );
    }
}

#[test]
fn vm007_aborted_execution_rejects_run_and_refuel() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let input = "while true do end";
        let verified = compiled(input.as_bytes(), profile);
        let mut vm = Vm::new().unwrap();
        let before = vm.ledger_snapshot();
        let mut execution = vm.load(verified).unwrap();
        execution.set_fuel(7).unwrap();
        assert_eq!(
            execution.run(),
            Ok(RunOutcome::Aborted(
                rivetlua_runtime::AbortReason::FuelExhausted
            ))
        );
        let stopped_pc = execution.pc();
        assert_eq!(
            execution.run().err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(
            execution.set_fuel(100).err().unwrap().kind,
            RuntimeErrorKind::TerminalExecution
        );
        assert_eq!(execution.pc(), stopped_pc);
        assert_eq!(execution.fuel_remaining(), 0);
        drop(execution);
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot(), before);
        assert_eq!(vm.collect().unwrap(), 0);
        record_case(
            profile,
            "VM-007",
            input,
            &format!(
                "Aborted(FuelExhausted); module=compiler_verified_rvlu_v2; implicit_return=Fixed(0); p05_compiler_used=true; run_again=TerminalExecution; refuel=TerminalExecution; pc_unchanged=true; fuel_remaining=0; pc={stopped_pc}; roots_after_drop=0; collect=0"
            ),
        );
    }
}

#[test]
fn assignment_table_target_remains_unsupported() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        let verified = compiled(b"local t,i; i,t[i]=i+1,20; return i", profile);
        let mut vm = Vm::new().unwrap();
        assert_eq!(
            vm.load(verified).err().unwrap().kind,
            RuntimeErrorKind::UnsupportedInstruction(rivetlua_core::Opcode::SetTable)
        );
        assert_eq!(vm.roots().total_count(), 0);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn compiler_if_while_and_short_circuit_keep_lua_values() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        assert_eq!(
            compiled_run(b"if 0 then return 1 else return 2 end", profile).0,
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        assert_eq!(
            compiled_run(b"local i=0; while i<3 do i=i+1 end; return i", profile).0,
            RunOutcome::Returned(vec![Value::Integer(3)])
        );
        for (source, expected) in [
            (b"return false or 5".as_slice(), Value::Integer(5)),
            (b"return 0 or 5".as_slice(), Value::Integer(0)),
            (b"return nil and 5".as_slice(), Value::Nil),
            (b"return 7 and 8".as_slice(), Value::Integer(8)),
            (b"return false and (1//0)".as_slice(), Value::Boolean(false)),
            (b"return true or (1//0)".as_slice(), Value::Boolean(true)),
        ] {
            assert_eq!(
                compiled_run(source, profile).0,
                RunOutcome::Returned(vec![expected])
            );
        }
    }
}

#[test]
fn compiler_fixed_returns_keep_exact_value_count() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        assert_eq!(
            compiled_run(b"return", profile).0,
            RunOutcome::Returned(vec![])
        );
        assert_eq!(
            compiled_run(b"return nil,1", profile).0,
            RunOutcome::Returned(vec![Value::Nil, Value::Integer(1)])
        );
    }
}

#[test]
fn compiler_zero_float_is_truthy_and_nil_is_false() {
    for profile in [LanguageProfile::Lua55, LanguageProfile::Lua54] {
        assert_eq!(
            compiled_run(b"if 0.0 then return 1 else return 2 end", profile).0,
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        assert_eq!(
            compiled_run(b"if nil then return 1 else return 2 end", profile).0,
            RunOutcome::Returned(vec![Value::Integer(2)])
        );
    }
}

#[test]
fn verified_open_return_needs_unsupported_call_producer() {
    let verified = verify_module(
        candidate(
            vec![
                Instruction::Call {
                    base: Register(0),
                    arg_count: 0,
                    result_mode: ResultMode::All,
                },
                Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::All,
                },
            ],
            vec![],
        ),
        LuaProfile::Lua55,
        &VerifyLimits::default(),
    )
    .unwrap();
    let mut vm = Vm::new().unwrap();
    assert_eq!(
        vm.load(verified).err().unwrap().kind,
        RuntimeErrorKind::UnsupportedInstruction(rivetlua_core::Opcode::Call)
    );
}
