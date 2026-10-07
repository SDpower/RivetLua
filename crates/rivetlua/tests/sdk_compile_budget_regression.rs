use rivetlua::{
    CompileBudget, CompileBudgetErrorKind, CompileBudgetLimits, CompileError, Engine, RunOutcome,
    Value,
};
use rivetlua_core::LuaProfile;

fn repeated_locals(lines: usize) -> Vec<u8> {
    b"local x=1\n".repeat(lines)
}

#[test]
fn default_budget_compiles_small_repeated_locals_in_both_profiles() {
    let mut rejected = Vec::new();
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let source_177 = repeated_locals(177);
        let source_178 = repeated_locals(178);
        assert_eq!(source_177.len(), 1770);
        assert_eq!(source_178.len(), 1780);
        let budget = CompileBudget::default();
        assert!(
            engine
                .compile_named_with_budget(&source_177, b"@repro-budget.lua", &budget)
                .is_ok()
        );
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
        let result = engine.compile_named_with_budget(&source_178, b"@repro-budget.lua", &budget);
        eprintln!(
            "{profile:?} default accepted={} snapshot={:?}",
            result.is_ok(),
            budget.allocation_snapshot()
        );
        if result.is_err() {
            rejected.push((profile, format!("{result:?}")));
        }
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
    }
    assert!(
        rejected.is_empty(),
        "178 行來源應可用 SDK 預設編譯額度編譯：{rejected:?}"
    );
}

#[test]
fn close_paths_and_ordinary_capture_execute_under_default_budget() {
    let cases: &[(&str, &[u8], &[Value])] = &[
        ("ordinary-capture-c0", b"local x=7; local function f() return x end; return f()", &[Value::Integer(7)]),
        ("nested-normal", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; do local a <close> = setmetatable({n=1},mt); do local b <close> = setmetatable({n=2},mt) end end; return log", &[Value::Integer(21)]),
        ("break", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; while true do local a <close> = setmetatable({n=1},mt); break end; return log", &[Value::Integer(1)]),
        ("goto", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; do local a <close> = setmetatable({n=1},mt); goto out end ::out:: return log", &[Value::Integer(1)]),
        ("return", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function f() do local a <close> = setmetatable({n=1},mt); return 9 end end; local v=f(); return log,v", &[Value::Integer(1), Value::Integer(9)]),
        ("error", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function f() do local a <close> = setmetatable({n=1},mt); error('boom') end end; local ok=pcall(f); return log,ok", &[Value::Integer(1), Value::Boolean(false)]),
    ];
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        for (name, source, expected) in cases {
            let module = engine
                .compile_named(source, name.as_bytes())
                .unwrap_or_else(|error| panic!("{profile:?}/{name} compile: {error:?}"));
            let mut vm = engine.new_vm().unwrap();
            let outcome = vm
                .load_module(&module)
                .unwrap()
                .run()
                .unwrap_or_else(|error| panic!("{profile:?}/{name} run: {error:?}"));
            assert_eq!(
                outcome,
                RunOutcome::Returned(expected.to_vec()),
                "{profile:?}/{name}"
            );
        }
    }
}

#[test]
fn default_budget_faults_each_allocation_then_retries_same_budget() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let source = repeated_locals(178);
        let measured = CompileBudget::default();
        let first = measured.allocation_trace().next_ordinal;
        assert!(
            engine
                .compile_named_with_budget(&source, b"@repro-budget.lua", &measured)
                .is_ok()
        );
        let end = measured.allocation_trace().next_ordinal;
        assert!(end > first);
        for ordinal in first..end {
            let faulted = CompileBudget::default();
            faulted.fail_once_at_ordinal(ordinal);
            assert!(
                matches!(
                    engine.compile_named_with_budget(&source, b"@repro-budget.lua", &faulted),
                    Err(CompileError::Budget(
                        CompileBudgetErrorKind::AllocationFailed
                    ))
                ),
                "{profile:?} ordinal={ordinal}"
            );
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);
            assert!(
                engine
                    .compile_named_with_budget(&source, b"@repro-budget.lua", &faulted)
                    .is_ok(),
                "{profile:?} ordinal={ordinal} retry"
            );
            assert_eq!(faulted.allocation_snapshot().reserved, 0);
            assert_eq!(faulted.allocation_snapshot().committed, 0);
        }
    }
}

#[test]
fn explicit_low_limit_rejects_then_releases_ledger_for_retry() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let source = repeated_locals(178);
        let mut budget = CompileBudget::new(CompileBudgetLimits {
            max_work: u64::MAX,
            max_allocation_bytes: 64,
        });
        assert!(matches!(
            engine.compile_named_with_budget(&source, b"@repro-budget.lua", &budget),
            Err(CompileError::Budget(
                CompileBudgetErrorKind::AllocationLimitExceeded
            ))
        ));
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
        budget.set_allocation_limit(usize::MAX);
        assert!(
            engine
                .compile_named_with_budget(&source, b"@repro-budget.lua", &budget)
                .is_ok()
        );
        assert_eq!(budget.allocation_snapshot().reserved, 0);
        assert_eq!(budget.allocation_snapshot().committed, 0);
    }
}
