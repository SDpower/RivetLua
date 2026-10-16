#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::rc::Rc;

use rivetlua_compiler::{
    BudgetedCompileError, CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile,
    compile_with_budget, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{
    DebugCapability, DebugPermission, FileOperation, FileReadFormat, FileSeekOrigin,
    HostCloseResult, HostDeadline, HostFileLease, HostIo, HostLoadCompiler, HostLoadError,
    HostLoadErrorKind, HostResourceError, HostResourceErrorKind, HostServices, LoadBudget,
    LoadCapability, LoadLimits, ResourceBudget, ResourceCapability, RootKind, RunOutcome,
    RuntimeErrorKind, Vm, VmError,
};

fn compile(source: &[u8], name: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let tokens = lex(source, language, &limits).unwrap();
    let parsed = parse(&tokens, language, &limits).unwrap();
    let resolved = resolve(&parsed, &tokens, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(&ir, &resolved, source, name, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

struct Compiler;
struct Meter<'a, 'b>(&'a mut LoadBudget<'b>);

impl CompileBudgetSink for Meter<'_, '_> {
    type Error = HostLoadError;
    fn spend_work(&mut self, n: usize) -> Result<(), Self::Error> {
        self.0.spend_work(n)
    }
    fn claim_temporary(&mut self, n: usize) -> Result<(), Self::Error> {
        self.0.claim_temporary(n)
    }
    fn claim_module_allocation(&mut self, n: usize) -> Result<(), Self::Error> {
        self.0.claim_module_allocation(n)
    }
}

impl HostLoadCompiler for Compiler {
    fn compile(
        &mut self,
        source: &[u8],
        name: &[u8],
        profile: LuaProfile,
        budget: &mut LoadBudget,
    ) -> Result<rivetlua_core::VerifiedModule, HostLoadError> {
        let language = match profile {
            LuaProfile::Lua54 => LanguageProfile::Lua54,
            LuaProfile::Lua55 => LanguageProfile::Lua55,
        };
        match compile_with_budget(
            source,
            name,
            language,
            &CompileLimits::default(),
            &IrLimits::default(),
            &VerifyLimits::default(),
            &mut Meter(budget),
        ) {
            Ok(module) => Ok(module),
            Err(BudgetedCompileError::Budget(error)) => Err(error),
            Err(BudgetedCompileError::Frontend(error)) => {
                budget.spend_work(error.message.len() + 1)?;
                budget.claim_temporary(error.message.len())?;
                Err(HostLoadError::new(
                    HostLoadErrorKind::Compile,
                    error.message.as_bytes(),
                ))
            }
            Err(_) => Err(HostLoadError::new(HostLoadErrorKind::Budget, Vec::new())),
        }
    }
}

#[derive(Default)]
struct ConsoleState {
    input: Vec<u8>,
    cursor: usize,
    stderr: Vec<u8>,
    deadline_checks: usize,
    cancel_at: Option<usize>,
}

struct ConsoleIo(Rc<RefCell<ConsoleState>>);
struct ConsoleFile {
    state: Rc<RefCell<ConsoleState>>,
    stream: u8,
}

impl HostDeadline for ConsoleIo {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        let mut state = self.0.borrow_mut();
        state.deadline_checks += 1;
        if state
            .cancel_at
            .is_some_and(|at| state.deadline_checks >= at)
        {
            return Err(HostResourceError::new(
                HostResourceErrorKind::Cancelled,
                Vec::new(),
            ));
        }
        drop(state);
        budget.spend_work(1)
    }
}

impl HostIo for ConsoleIo {
    fn authorize_path(
        &mut self,
        _: &[u8],
        _: &[u8],
        _: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::PolicyDenied,
            Vec::new(),
        ))
    }
    fn open(
        &mut self,
        _: &[u8],
        _: &[u8],
        _: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::PolicyDenied,
            Vec::new(),
        ))
    }
    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.claim_retained(1)?;
        Ok(Box::new(ConsoleFile {
            state: self.0.clone(),
            stream: 0,
        }))
    }
    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.claim_retained(1)?;
        Ok(Box::new(ConsoleFile {
            state: self.0.clone(),
            stream: 1,
        }))
    }
    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.claim_retained(1)?;
        Ok(Box::new(ConsoleFile {
            state: self.0.clone(),
            stream: 2,
        }))
    }
}

impl HostFileLease for ConsoleFile {
    fn authorize(
        &mut self,
        _: FileOperation,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }
    fn read(
        &mut self,
        format: FileReadFormat,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError> {
        let FileReadFormat::Bytes(1) = format else {
            return Err(HostResourceError::new(
                HostResourceErrorKind::Unsupported,
                Vec::new(),
            ));
        };
        budget.spend_work(1)?;
        let mut state = self.state.borrow_mut();
        if self.stream != 0 || state.cursor == state.input.len() {
            return Ok(None);
        }
        budget.claim_temporary(1)?;
        let byte = state.input[state.cursor];
        state.cursor += 1;
        Ok(Some(vec![byte]))
    }
    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError> {
        budget.spend_work(bytes.len())?;
        if self.stream != 2 {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PolicyDenied,
                Vec::new(),
            ));
        }
        self.state.borrow_mut().stderr.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn seek(
        &mut self,
        _: FileSeekOrigin,
        _: i64,
        _: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError> {
        Err(HostResourceError::new(
            HostResourceErrorKind::Unsupported,
            Vec::new(),
        ))
    }
    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }
    fn close(
        self: Box<Self>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError> {
        budget.spend_work(1)?;
        Ok(HostCloseResult::File)
    }
}

fn run(
    profile: LuaProfile,
    source: &[u8],
    input: &[u8],
    console: bool,
) -> (Vm, RunOutcome, Vec<u8>) {
    run_config(profile, source, input, console, false)
}

fn new_vm(profile: LuaProfile, input: &[u8], console: bool) -> (Vm, Rc<RefCell<ConsoleState>>) {
    let state = Rc::new(RefCell::new(ConsoleState {
        input: input.to_vec(),
        ..ConsoleState::default()
    }));
    let services = HostServices::deny_all()
        .and_load(
            LoadCapability::deny_all()
                .and_compiler(Compiler)
                .with_limits(LoadLimits {
                    max_work_units: 2_000_000,
                    ..LoadLimits::default()
                }),
        )
        .and_resource(
            ResourceCapability::deny_all()
                .and_io(ConsoleIo(state.clone()))
                .and_deadline(ConsoleIo(state.clone())),
        )
        .and_debug(if console {
            DebugCapability::deny_all().allow(DebugPermission::Console)
        } else {
            DebugCapability::deny_all()
        });
    (Vm::new_with_services(profile, services).unwrap(), state)
}

fn run_config(
    profile: LuaProfile,
    source: &[u8],
    input: &[u8],
    console: bool,
    collect: bool,
) -> (Vm, RunOutcome, Vec<u8>) {
    let (mut vm, state) = new_vm(profile, input, console);
    let env = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, env).unwrap();
    vm.install_basic_builtins(env).unwrap();
    vm.install_error_builtins(env).unwrap();
    vm.install_debug_builtins(env).unwrap();
    vm.install_io_os_builtins(env).unwrap();
    vm.set_collect_every_allocation(collect);
    let module = compile(source, b"@console-test.lua", profile);
    let mut execution = vm
        .load_with_environment(module, Value::Object(env))
        .unwrap();
    execution.set_fuel(5_000_000).unwrap();
    let outcome = execution.run().unwrap();
    drop(execution);
    vm.remove_root(root).unwrap();
    let stderr = state.borrow().stderr.clone();
    (vm, outcome, stderr)
}

#[test]
fn p17_debug_console_recovery_and_boundaries() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let (vm, outcome, stderr) = run_config(
            profile,
            b"local private=9; debug.debug(); return answer, private",
            b"answer=private or 15\nerror('bang')\nnot valid lua +\ncont\n",
            true,
            false,
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(15), Value::Integer(9)])
        );
        assert_eq!(
            stderr.iter().filter(|&&byte| byte == b'>').count(),
            4,
            "{stderr:?}"
        );
        assert!(stderr.windows(4).any(|part| part == b"bang"));
        assert!(
            stderr
                .windows(b"(debug command):1: bang".len())
                .any(|part| part == b"(debug command):1: bang")
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let (_, outcome, stderr) = run(
            profile,
            b"debug.debug(); return answer",
            b"answer=7\0ignored\ncont\n",
            true,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> ");

        let (_, outcome, stderr) = run(profile, b"debug.debug(); return 11", b"", true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(11)]));
        assert_eq!(stderr, b"lua_debug> ");

        let (_, outcome, stderr) =
            run(profile, b"debug.debug(); return answer", b"answer=17", true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(17)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> ");

        let mut long_line = vec![b' '; 248];
        long_line.push(b'\n');
        long_line.extend_from_slice(b"answer=8\ncont\n");
        let (_, outcome, stderr) = run(profile, b"debug.debug(); return answer", &long_line, true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(8)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> lua_debug> ");

        let mut split_line = b"answer=5".to_vec();
        split_line.extend(std::iter::repeat_n(b' ', 250));
        split_line.extend_from_slice(b"\ncont\n");
        let (_, outcome, stderr) = run(profile, b"debug.debug(); return answer", &split_line, true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(5)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> lua_debug> ");

        let (_, outcome, stderr) = run(
            profile,
            b"debug.debug(); return answer",
            b"return false\nanswer=23\ncont\n",
            true,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(23)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> lua_debug> ");

        let (vm, outcome, stderr) = run_config(
            profile,
            b"weak=setmetatable({}, {__mode='v'}); debug.debug(); return answer",
            b"weak[1]={}; return false, weak[1]\ncollectgarbage('collect'); answer=weak[1]==nil\ncont\n",
            true,
            false,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(true)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let (vm, outcome, stderr) = run_config(
            profile,
            b"debug.debug(); return answer",
            b"answer=31\ncont\n",
            true,
            true,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(31)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let input = b"local x <close> = setmetatable({}, {__close=function() error('closefail') end}); error('oops')\nanswer=51\ncont\n";
        let (vm, outcome, stderr) = run(profile, b"debug.debug(); return answer", input, true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(51)]));
        assert!(
            stderr
                .windows(b"closefail".len())
                .any(|part| part == b"closefail")
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p17_debug_console_error_stringification() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let input = b"error(setmetatable({}, {__tostring=function() return 'pretty' end}))\nanswer=6\ncont\n";
        let (_, outcome, stderr) =
            run_config(profile, b"debug.debug(); return answer", input, true, true);
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(6)]));
        assert!(
            stderr
                .windows(b"pretty\n".len())
                .any(|part| part == b"pretty\n")
        );
        assert_eq!(stderr.iter().filter(|&&byte| byte == b'>').count(), 3);

        let (_, outcome, stderr) = run(
            profile,
            b"debug.debug(); return answer",
            b"error('before\\0after')\nanswer=9\ncont\n",
            true,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(9)]));
        assert_eq!(
            stderr,
            b"lua_debug> (debug command):1: before\nlua_debug> lua_debug> "
        );

        let input =
            b"error(setmetatable({}, {__tostring=function() error('stringify failed') end}))\n";
        let (vm, outcome, stderr) = run(profile, b"debug.debug(); return 0", input, true);
        assert!(
            matches!(outcome, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::Thrown)
        );
        assert_eq!(stderr, b"lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p17_debug_console_allocation_recovery() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let make = || {
            let state = Rc::new(RefCell::new(ConsoleState {
                input: b"answer=4\ncont\n".to_vec(),
                ..ConsoleState::default()
            }));
            let services = HostServices::deny_all()
                .and_load(
                    LoadCapability::deny_all()
                        .and_compiler(Compiler)
                        .with_limits(LoadLimits {
                            max_work_units: 2_000_000,
                            ..LoadLimits::default()
                        }),
                )
                .and_resource(
                    ResourceCapability::deny_all()
                        .and_io(ConsoleIo(state.clone()))
                        .and_deadline(ConsoleIo(state.clone())),
                )
                .and_debug(DebugCapability::deny_all().allow(DebugPermission::Console));
            let mut vm = Vm::new_with_services(profile, services).unwrap();
            let env = vm.allocate_table().unwrap();
            let root = vm.add_root(RootKind::Host, env).unwrap();
            vm.install_basic_builtins(env).unwrap();
            vm.install_debug_builtins(env).unwrap();
            vm.install_io_os_builtins(env).unwrap();
            vm.set_collect_every_allocation(true);
            (vm, env, root, state)
        };
        let module = compile(b"debug.debug(); return 1", b"@console-failure.lua", profile);
        let (mut dry, dry_env, dry_root, _) = make();
        let dry_start = dry.allocation_trace().next_ordinal;
        let dry_probe = dry.ledger_probe();
        let mut dry_execution = dry
            .load_with_environment(module.clone(), Value::Object(dry_env))
            .unwrap();
        dry_execution.set_fuel(5_000_000).unwrap();
        let run_start = dry_probe.trace().next_ordinal;
        assert_eq!(
            dry_execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        let run_end = dry_probe.trace().next_ordinal;
        assert!(run_end > run_start);
        drop(dry_execution);
        dry.remove_root(dry_root).unwrap();

        let (mut vm, env, root, state) = make();
        assert_eq!(vm.allocation_trace().next_ordinal, dry_start);
        let baseline_roots = vm.roots().total_count();
        let ordinal = run_start;
        vm.inject_allocation_failure_at(ordinal);
        let mut execution = vm
            .load_with_environment(module.clone(), Value::Object(env))
            .unwrap();
        execution.set_fuel(5_000_000).unwrap();
        // 命令期間第一筆配置失敗後，執行與來源物件的 root 必須可完整回收。
        let failure = execution.run();
        drop(execution);
        assert!(
            failure.is_err(),
            "allocation ordinal={ordinal}: {failure:?}"
        );
        assert_eq!(
            vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
            ordinal
        );
        drop(failure);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let mut retry = vm
            .load_with_environment(module.clone(), Value::Object(env))
            .unwrap();
        retry.set_fuel(5_000_000).unwrap();
        assert_eq!(
            retry.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        drop(retry);
        let cancel_at = state.borrow().deadline_checks + 1;
        state.borrow_mut().cancel_at = Some(cancel_at);
        let mut cancelled = vm
            .load_with_environment(module.clone(), Value::Object(env))
            .unwrap();
        cancelled.set_fuel(5_000_000).unwrap();
        assert!(matches!(
            cancelled.run().unwrap(),
            RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostCancelled
        ));
        drop(cancelled);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        state.borrow_mut().cancel_at = None;
        let mut final_retry = vm
            .load_with_environment(module, Value::Object(env))
            .unwrap();
        final_retry.set_fuel(5_000_000).unwrap();
        assert_eq!(
            final_retry.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(1)])
        );
        drop(final_retry);
        vm.remove_root(root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn p17_debug_console_basic() {
    for profile in [LuaProfile::Lua55, LuaProfile::Lua54] {
        let (vm, outcome, stderr) = run(
            profile,
            b"debug.debug(); return answer",
            b"answer=42\ncont\n",
            true,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(42)]));
        assert_eq!(stderr, b"lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let (vm, outcome, stderr) = run(
            profile,
            b"local debugfn=debug.debug; local isolated={debug={debug=debugfn}}; local function call() local _ENV=isolated; probe=5; debug.debug() end; call(); return answer, isolated.probe, isolated.answer",
            b"answer=73\ncont\n",
            true,
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(73), Value::Integer(5), Value::Nil])
        );
        assert_eq!(stderr, b"lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let (vm, outcome, stderr) = run(
            profile,
            b"local debugfn=debug.debug; local isolated={debug={debug=debugfn}}; local f=assert(load('debug.debug()', '@isolated.lua', 't', isolated)); f(); return answer, isolated.answer",
            b"answer=81\ncont\n",
            true,
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Integer(81), Value::Nil])
        );
        assert_eq!(stderr, b"lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);

        let (mut vm, state) = new_vm(profile, b"answer=91\ncont\n", true);
        let globals = vm.allocate_table().unwrap();
        let globals_root = vm.add_root(RootKind::Host, globals).unwrap();
        let baseline_roots = vm.roots().total_count();
        let failed_ordinal = vm.allocation_trace().next_ordinal;
        vm.inject_allocation_failure_at(failed_ordinal);
        assert!(vm.install_basic_builtins(globals).is_err());
        assert_eq!(
            vm.allocation_trace().last_failure.unwrap().attempt.ordinal,
            failed_ordinal
        );
        assert_eq!(vm.roots().total_count(), baseline_roots);
        vm.install_basic_builtins(globals).unwrap();
        vm.install_debug_builtins(globals).unwrap();
        vm.install_io_os_builtins(globals).unwrap();
        let roots_after_globals = vm.roots().total_count();
        let secondary = vm.allocate_table().unwrap();
        vm.install_basic_builtins(secondary).unwrap();
        assert_eq!(vm.roots().total_count(), roots_after_globals);
        let module = compile(
            b"debug.debug(); return answer",
            b"@console-retry.lua",
            profile,
        );
        let mut execution = vm
            .load_with_environment(module, Value::Object(globals))
            .unwrap();
        execution.set_fuel(5_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(91)])
        );
        drop(execution);
        assert_eq!(state.borrow().stderr, b"lua_debug> lua_debug> ");
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        vm.remove_root(globals_root).unwrap();
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);

        let (mut dry, _) = new_vm(profile, b"", true);
        let dry_env = dry.allocate_table().unwrap();
        let dry_root = dry.add_root(RootKind::Host, dry_env).unwrap();
        let install_start = dry.allocation_trace().next_ordinal;
        dry.install_basic_builtins(dry_env).unwrap();
        let publish = dry.allocation_trace().last_attempt.unwrap();
        // RootSet::add 先記錄無 point 的配置，再經 RootReserve checkpoint。
        assert_eq!(publish.point, None);
        assert!(publish.site.file.ends_with("/roots.rs"));
        assert!(publish.ordinal >= install_start);
        assert_eq!(
            publish.ordinal.checked_add(1),
            Some(dry.allocation_trace().next_ordinal)
        );
        dry.remove_root(dry_root).unwrap();
        let dry_probe = dry.ledger_probe();
        drop(dry);
        assert_eq!(dry_probe.snapshot().committed, 0);

        let (mut vm, state) = new_vm(profile, b"answer=97\ncont\n", true);
        let failed_env = vm.allocate_table().unwrap();
        let failed_root = vm.add_root(RootKind::Host, failed_env).unwrap();
        assert_eq!(vm.allocation_trace().next_ordinal, install_start);
        let baseline_roots = vm.roots().total_count();
        vm.inject_allocation_failure_at(publish.ordinal);
        let failure = vm.install_basic_builtins(failed_env).unwrap_err();
        let VmError::InjectedAllocation(attempt) = failure else {
            panic!("globals registry root 注入失敗須傳回原始配置錯誤: {failure:?}");
        };
        assert_eq!(attempt.ordinal, publish.ordinal);
        assert_eq!(attempt.point, None);
        assert_eq!(attempt.site, publish.site);
        assert_eq!(attempt.bytes, publish.bytes);
        assert_eq!(vm.roots().total_count(), baseline_roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let globals = vm.allocate_table().unwrap();
        let globals_root = vm.add_root(RootKind::Host, globals).unwrap();
        vm.install_basic_builtins(globals).unwrap();
        let roots_after_globals = vm.roots().total_count();
        vm.install_basic_builtins(failed_env).unwrap();
        assert_eq!(vm.roots().total_count(), roots_after_globals);
        vm.install_debug_builtins(globals).unwrap();
        vm.install_io_os_builtins(globals).unwrap();
        let module = compile(
            b"debug.debug(); return answer",
            b"@console-root-retry.lua",
            profile,
        );
        let mut execution = vm
            .load_with_environment(module, Value::Object(globals))
            .unwrap();
        execution.set_fuel(5_000_000).unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(97)])
        );
        drop(execution);
        assert_eq!(state.borrow().stderr, b"lua_debug> lua_debug> ");
        vm.remove_root(globals_root).unwrap();
        vm.remove_root(failed_root).unwrap();
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        let probe = vm.ledger_probe();
        drop(vm);
        assert_eq!(probe.snapshot().committed, 0);
        assert_eq!(probe.snapshot().reserved, 0);

        let (_, denied, denied_stderr) = run(profile, b"debug.debug()", b"cont\n", false);
        assert!(
            matches!(denied, RunOutcome::LuaError(error) if error.kind == RuntimeErrorKind::HostPolicyDebug)
        );
        assert!(denied_stderr.is_empty());
    }
}
