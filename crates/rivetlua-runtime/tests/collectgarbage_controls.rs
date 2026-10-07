use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, ObjectRef, Value, VerifiedModule, VerifyLimits};
use rivetlua_runtime::{GcMode, HostHandle, RunOutcome, RuntimeErrorKind, Vm};

struct TestSink;

impl CompileBudgetSink for TestSink {
    type Error = ();

    fn spend_work(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_temporary(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn claim_module_allocation(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn compile(source: &[u8], language: LanguageProfile) -> VerifiedModule {
    compile_with_budget(
        source,
        b"=collectgarbage-controls",
        language,
        &CompileLimits::default(),
        &IrLimits::default(),
        &VerifyLimits::default(),
        &mut TestSink,
    )
    .unwrap()
}

fn run_on_vm(
    vm: &mut Vm,
    environment: ObjectRef,
    source: &[u8],
    language: LanguageProfile,
) -> RunOutcome {
    vm.load_with_environment(compile(source, language), Value::Object(environment))
        .unwrap()
        .run()
        .unwrap()
}

fn run(source: &[u8], language: LanguageProfile, profile: LuaProfile) -> RunOutcome {
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    let outcome = run_on_vm(&mut vm, environment, source, language);
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    outcome
}

fn late_finalizer_registration(source: &[u8]) {
    let mut mismatches = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let actual = run(source, language, profile);
        let expected = RunOutcome::Returned(vec![
            Value::Integer(1),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
        ]);
        if actual != expected {
            mismatches.push(format!("{profile:?}: {actual:?} != {expected:?}"));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn guest_local_initializer_finalizer_releases_child_and_weak_entries() {
    late_finalizer_registration(
        b"local C=setmetatable({}, {__mode='v'}); local C1=setmetatable({}, {__mode='k'}); \
          local count=0; local seen_v=false; local seen_k=false; \
          local t={}; local a=setmetatable({x=t}, {__gc=function(u) \
            count=count+1; seen_v=C.key==nil; seen_k=type(next(C1))=='table' end}); \
          C.key=t; C1[t]=1; a,t=nil; collectgarbage(); collectgarbage(); \
          return count,seen_v,seen_k,next(C)==nil,next(C1)==nil",
    );
}

#[test]
fn guest_call_statement_finalizer_releases_child_and_weak_entries() {
    late_finalizer_registration(
        b"local C=setmetatable({}, {__mode='v'}); local C1=setmetatable({}, {__mode='k'}); \
          local count=0; local seen_v=false; local seen_k=false; \
          local t={}; local a={x=t}; C.key=t; C1[t]=1; \
          setmetatable(a, {__gc=function(u) \
            count=count+1; seen_v=C.key==nil; seen_k=type(next(C1))=='table' end}); \
          a,t=nil; collectgarbage(); collectgarbage(); \
          return count,seen_v,seen_k,next(C)==nil,next(C1)==nil",
    );
}

fn open_statement_call_releases_dynamic_results(callee: &str) {
    let returns = vec!["x"; 64].join(",");
    let source = format!(
        "local weak=setmetatable({{}},{{__mode='v'}}); local finalized=0; local long=true; \
         local function sink(...) end; \
         local function produce() local x={{}}; \
           setmetatable(x,{{__gc=function() finalized=finalized+1 end}}); \
           weak[long and 1 or 2]=x; \
           if long then return {returns} end; return x end; \
         {callee}(produce()); collectgarbage(); \
         local first=weak[1]==nil and finalized==1; long=false; \
         {callee}(produce()); collectgarbage(); \
         return first,weak[2]==nil,finalized"
    );
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(source.as_bytes(), language, profile),
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Integer(2),
            ]),
            "{profile:?} {callee}"
        );
    }
}

#[test]
fn guest_closure_statement_call_clears_large_then_small_open_results() {
    open_statement_call_releases_dynamic_results("sink");
}

#[test]
fn guest_builtin_statement_call_clears_large_then_small_open_results() {
    open_statement_call_releases_dynamic_results("type");
}

#[test]
fn guest_call_cleanup_backedge_preserves_live_and_later_bindings() {
    let source = b"local keep={v=7}; local sum=0; local calls=0; \
        local function touch() calls=calls+1 end; \
        for i=1,2 do touch(); local later={v=i}; \
          sum=sum+later.v+keep.v end; \
        return sum,calls,keep.v";
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(source, language, profile),
            RunOutcome::Returned(vec![
                Value::Integer(17),
                Value::Integer(2),
                Value::Integer(7),
            ]),
            "{profile:?}"
        );
    }
}

fn check_initial(language: LanguageProfile, profile: LuaProfile) {
    assert_eq!(
        run(b"return collectgarbage('isrunning')", language, profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
}

fn anonymous_weak_assignment(language: LanguageProfile, profile: LuaProfile, source: &[u8]) {
    assert_eq!(
        run(source, language, profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
}

#[test]
fn guest_anonymous_weak_key_assignment_lua54() {
    anonymous_weak_assignment(
        LanguageProfile::Lua54,
        LuaProfile::Lua54,
        b"local a=setmetatable({}, {__mode='k'}); a[{}]=1; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_anonymous_weak_key_assignment_lua55() {
    anonymous_weak_assignment(
        LanguageProfile::Lua55,
        LuaProfile::Lua55,
        b"local a=setmetatable({}, {__mode='k'}); a[{}]=1; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_anonymous_weak_value_assignment_lua54() {
    anonymous_weak_assignment(
        LanguageProfile::Lua54,
        LuaProfile::Lua54,
        b"local a=setmetatable({}, {__mode='v'}); a[1]={}; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_anonymous_weak_value_assignment_lua55() {
    anonymous_weak_assignment(
        LanguageProfile::Lua55,
        LuaProfile::Lua55,
        b"local a=setmetatable({}, {__mode='v'}); a[1]={}; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_anonymous_weak_key_loop_clears_last_iteration_lua54() {
    anonymous_weak_assignment(
        LanguageProfile::Lua54,
        LuaProfile::Lua54,
        b"local a=setmetatable({}, {__mode='k'}); for i=1,8 do a[{}]=i end; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_anonymous_weak_key_loop_clears_last_iteration_lua55() {
    anonymous_weak_assignment(
        LanguageProfile::Lua55,
        LuaProfile::Lua55,
        b"local a=setmetatable({}, {__mode='k'}); for i=1,8 do a[{}]=i end; collectgarbage(); return next(a)==nil",
    );
}

#[test]
fn guest_local_key_and_value_keep_weak_entries_alive() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='k'}); local k={}; a[k]=1; collectgarbage(); return next(a)==k",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='v'}); local v={}; a[1]=v; collectgarbage(); return a[1]==v",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
    }
}

#[test]
fn guest_weak_kv_self_pair_drops_after_local_scope() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='kv'}); do local t={}; a[t]=t end; collectgarbage(); return next(a)==nil",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn guest_weak_kv_self_pair_drops_after_local_nil() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='kv'}); local t={}; a[t]=t; t=nil; collectgarbage(); return next(a)==nil",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn guest_weak_kv_self_pair_drops_after_loop_last_iteration() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='kv'}); for i=1,4 do local t={}; a[t]=t end; collectgarbage(); return next(a)==nil",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn guest_weak_kv_distinct_anonymous_pair_drops_after_assignment() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local a=setmetatable({}, {__mode='kv'}); a[{}]={}; collectgarbage(); return next(a)==nil",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn guest_weak_kv_self_pair_strong_reference_controls() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for source in [
            b"local a={}; do local t={}; a[t]=t end; collectgarbage(); return next(a)~=nil".as_slice(),
            b"local a=setmetatable({}, {__mode='kv'}); local t={}; a[t]=t; collectgarbage(); return next(a)==t",
        ] {
            assert_eq!(
                run(source, language, profile),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?}"
            );
        }
    }
}

#[test]
fn guest_weak_kv_exits_release_locals_after_last_use() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for (case, source) in [
            (
                "break",
                b"local a=setmetatable({}, {__mode='kv'}); while true do local t={}; a[t]=t; break end; collectgarbage(); return next(a)==nil".as_slice(),
            ),
            (
                "goto",
                b"local a=setmetatable({}, {__mode='kv'}); do local t={}; a[t]=t; goto done end; ::done:: collectgarbage(); return next(a)==nil",
            ),
            (
                "repeat",
                b"local a=setmetatable({}, {__mode='kv'}); local i=0; repeat local t={}; a[t]=t; i=i+1 until i==4; collectgarbage(); return next(a)==nil",
            ),
            (
                "repeat condition object",
                b"local a=setmetatable({}, {__mode='kv'}); repeat local t={}; a[t]=t until t; collectgarbage(); return next(a)==nil",
            ),
            (
                "while condition object",
                b"local a=setmetatable({}, {__mode='kv'}); local t={}; a[t]=t; while t do t=nil; break end; collectgarbage(); return next(a)==nil",
            ),
            (
                "if condition object",
                b"local a=setmetatable({}, {__mode='kv'}); local t={}; a[t]=t; if t then t=nil end; collectgarbage(); return next(a)==nil",
            ),
            (
                "error unwind",
                b"local a=setmetatable({}, {__mode='kv'}); local ok=pcall(function() local t={}; a[t]=t; error('boom') end); collectgarbage(); return not ok and next(a)==nil",
            ),
        ] {
            assert_eq!(
                run(source, language, profile),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?}/{case}"
            );
        }
    }
}

#[test]
fn guest_weak_kv_upvalue_and_close_callback_keep_value_until_release() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for (case, source) in [
            (
                "captured upvalue",
                b"local a=setmetatable({}, {__mode='kv'}); local keep; do local t={}; a[t]=t; keep=function() return t end end; collectgarbage(); local alive=next(a)~=nil and keep()~=nil; keep=nil; collectgarbage(); return alive and next(a)==nil".as_slice(),
            ),
            (
                "close callback",
                b"local a=setmetatable({}, {__mode='kv'}); local seen=false; do local t={}; a[t]=t; local c <close> = setmetatable({}, {__close=function() collectgarbage(); seen=a[t]==t end}) end; collectgarbage(); return seen and next(a)==nil",
            ),
        ] {
            assert_eq!(
                run(source, language, profile),
                RunOutcome::Returned(vec![Value::Boolean(true)]),
                "{profile:?}/{case}"
            );
        }
    }
}

#[test]
fn guest_weak_kv_coroutine_yield_keeps_scope_then_releases_it() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let outcome = run_on_vm(
            &mut vm,
            environment,
            b"local a=setmetatable({}, {__mode='kv'}); local co=coroutine.create(function() do local t={}; a[t]=t; coroutine.yield(t) end end); local ok,k=coroutine.resume(co); collectgarbage(); local alive=next(a)~=nil and k~=nil; k=nil; local resumed=coroutine.resume(co); collectgarbage(); return ok and alive and resumed and next(a)==nil",
            language,
        );
        assert_eq!(
            outcome,
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn guest_parallel_table_assignment_keeps_target_snapshot_order() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local i=1; local t={}; i,t[i]=2,3; return i,t[1],t[2]",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Integer(2), Value::Integer(3), Value::Nil])
        );
    }
}

#[test]
fn guest_assignment_newindex_callback_keeps_key_and_value_until_store_finishes() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        assert_eq!(
            run(
                b"local saved={}; local t=setmetatable({}, {__newindex=function(_,k,v) collectgarbage(); saved[k]=v end}); t[{}]={}; local k,v=next(saved); return k~=nil and v~=nil",
                language,
                profile,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
    }
}

#[test]
fn guest_assignment_newindex_yield_resume_survives_collection() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let outcome = run_on_vm(
            &mut vm,
            environment,
            b"local saved={}; local t=setmetatable({}, {__newindex=function(_,k,v) coroutine.yield(1); saved[k]=v end}); local co=coroutine.create(function() t[{}]={} end); local ok,x=coroutine.resume(co); collectgarbage(); local ok2=coroutine.resume(co); local k,v=next(saved); return ok and x==1 and ok2 and k~=nil and v~=nil",
            language,
        );
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Boolean(true)]));
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn guest_assignment_newindex_error_unwinds_temporary_roots() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let roots = vm.roots().total_count();
        let outcome = run_on_vm(
            &mut vm,
            environment,
            b"local t=setmetatable({}, {__newindex=function(_,k,v) collectgarbage(); error('stop') end}); t[{}]={}",
            language,
        );
        assert!(matches!(&outcome, RunOutcome::LuaError(_)));
        drop(outcome);
        vm.collect().unwrap();
        assert_eq!(vm.roots().total_count(), roots);
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn lua55_param_defaults_and_compressed_round_trip() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua55).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return collectgarbage('param','pause'),collectgarbage('param','stepmul')",
            LanguageProfile::Lua55,
        ),
        RunOutcome::Returned(vec![Value::Integer(250), Value::Integer(200)])
    );
    for name in ["pause", "stepmul"] {
        let mut previous = if name == "pause" { 250 } else { 200 };
        for (input, decoded) in [
            (0, 0),
            (2, 2),
            (10, 10),
            (90, 90),
            (500, 500),
            (5000, 5000),
            (30000, 28800),
            (0x7ffffffe, 396800),
        ] {
            let source = format!(
                "local old=collectgarbage('param','{name}',{input}); return old,collectgarbage('param','{name}')"
            );
            assert_eq!(
                run_on_vm(
                    &mut vm,
                    environment,
                    source.as_bytes(),
                    LanguageProfile::Lua55
                ),
                RunOutcome::Returned(vec![Value::Integer(previous), Value::Integer(decoded)]),
                "{name} {input}"
            );
            previous = decoded;
        }
        let source = format!(
            "return collectgarbage('param','{name}',-123),collectgarbage('param','{name}')"
        );
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                source.as_bytes(),
                LanguageProfile::Lua55
            ),
            RunOutcome::Returned(vec![Value::Integer(previous), Value::Integer(previous)]),
            "{name} 負數應僅查詢"
        );
    }
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn lua54_rejects_param_without_changing_gc_controls() {
    let mut vm = Vm::new_with_profile(LuaProfile::Lua54).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return collectgarbage('stop')",
            LanguageProfile::Lua54,
        ),
        RunOutcome::Returned(vec![Value::Integer(0)])
    );
    let RunOutcome::LuaError(error) = run_on_vm(
        &mut vm,
        environment,
        b"return collectgarbage('param','pause',100)",
        LanguageProfile::Lua54,
    ) else {
        panic!("Lua 5.4 應拒絕 param")
    };
    assert_eq!(error.diagnostic_id, "E_BASIC_ARGUMENT");
    drop(error);
    assert_eq!(vm.gc_mode(), GcMode::Generational);
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return collectgarbage('isrunning')",
            LanguageProfile::Lua54,
        ),
        RunOutcome::Returned(vec![Value::Boolean(false)])
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn explicit_step_accepts_optional_and_numeric_string_size_while_stopped() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let outcome = run(
            b"collectgarbage('stop'); local a=collectgarbage('step'); \
              local b=collectgarbage('step',nil); local c=collectgarbage('step',0); \
              local d=collectgarbage('step',2); local e=collectgarbage('step','2',99); \
              return a,b,c,d,e,collectgarbage('isrunning')",
            language,
            profile,
        );
        let RunOutcome::Returned(values) = outcome else {
            panic!("{profile:?} step 應在停止自動 GC 時成功：{outcome:?}")
        };
        assert_eq!(values.len(), 6);
        assert!(
            values[..5]
                .iter()
                .all(|value| matches!(value, Value::Boolean(_)))
        );
        assert_eq!(values[5], Value::Boolean(false));
    }
}

#[test]
fn step_and_param_argument_errors_leave_controls_usable() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return collectgarbage('stop')",
                language,
            ),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        let mut invalid: Vec<&[u8]> = vec![
            b"return collectgarbage('step',false)",
            b"return collectgarbage('step',1.5)",
        ];
        if profile == LuaProfile::Lua55 {
            invalid.extend_from_slice(&[
                b"return collectgarbage('param')",
                b"return collectgarbage('param','unknown',100)",
                b"return collectgarbage('param','pause',false)",
                b"return collectgarbage('param','pause',1.5)",
            ]);
        }
        for source in invalid {
            let RunOutcome::LuaError(error) = run_on_vm(&mut vm, environment, source, language)
            else {
                panic!("{profile:?} 無效 GC 引數應回 LuaError：{source:?}")
            };
            assert_eq!(error.diagnostic_id, "E_BASIC_ARGUMENT");
            drop(error);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(
                run_on_vm(
                    &mut vm,
                    environment,
                    b"return collectgarbage('isrunning')",
                    language,
                ),
                RunOutcome::Returned(vec![Value::Boolean(false)])
            );
        }
        if profile == LuaProfile::Lua55 {
            assert_eq!(
                run_on_vm(
                    &mut vm,
                    environment,
                    b"return collectgarbage('param','pause'),collectgarbage('param','stepmul')",
                    language,
                ),
                RunOutcome::Returned(vec![Value::Integer(250), Value::Integer(200)])
            );
        }
    }
}

fn check_transitions(language: LanguageProfile, profile: LuaProfile) {
    let source = b"local a=collectgarbage('stop'); local b=collectgarbage('isrunning'); \
        local c=collectgarbage('stop'); local d=collectgarbage('isrunning'); \
        local e=collectgarbage('restart'); local f=collectgarbage('isrunning'); \
        local g=collectgarbage('restart'); return a,b,c,d,e,f,g,collectgarbage('isrunning')";
    assert_eq!(
        run(source, language, profile),
        RunOutcome::Returned(vec![
            Value::Integer(0),
            Value::Boolean(false),
            Value::Integer(0),
            Value::Boolean(false),
            Value::Integer(0),
            Value::Boolean(true),
            Value::Integer(0),
            Value::Boolean(true),
        ])
    );
}

#[test]
fn collectgarbage_isrunning_initial_lua54() {
    check_initial(LanguageProfile::Lua54, LuaProfile::Lua54);
}

#[test]
fn collectgarbage_isrunning_initial_lua55() {
    check_initial(LanguageProfile::Lua55, LuaProfile::Lua55);
}

#[test]
fn collectgarbage_stop_restart_lua54() {
    check_transitions(LanguageProfile::Lua54, LuaProfile::Lua54);
}

#[test]
fn collectgarbage_stop_restart_lua55() {
    check_transitions(LanguageProfile::Lua55, LuaProfile::Lua55);
}

#[test]
fn stopped_state_is_shared_by_environments_but_isolated_by_vm() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let first = vm.allocate_table().unwrap();
        let _first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
        let second = vm.allocate_table().unwrap();
        let _second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
        vm.install_basic_builtins(first).unwrap();
        vm.install_basic_builtins(second).unwrap();
        assert_eq!(
            run_on_vm(&mut vm, first, b"return collectgarbage('stop')", language),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        assert_eq!(
            run_on_vm(
                &mut vm,
                second,
                b"return collectgarbage('isrunning')",
                language,
            ),
            RunOutcome::Returned(vec![Value::Boolean(false)])
        );
        assert_eq!(
            run(b"return collectgarbage('isrunning')", language, profile),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn invalid_options_preserve_stopped_state_and_extra_args_are_ignored() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return collectgarbage('stop', 99)",
                language
            ),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        let roots = vm.roots().total_count();
        for source in [
            b"return collectgarbage('ISRUNNING')".as_slice(),
            b"return collectgarbage('invalid-option')",
            b"return collectgarbage(123)",
        ] {
            let RunOutcome::LuaError(error) = run_on_vm(&mut vm, environment, source, language)
            else {
                panic!("{profile:?} 無效選項應回 BasicArgument：{source:?}")
            };
            assert_eq!(error.kind, RuntimeErrorKind::BasicArgument);
            assert_eq!(error.diagnostic_id, "E_BASIC_ARGUMENT");
            drop(error);
            assert_eq!(vm.roots().total_count(), roots);
            assert_eq!(vm.ledger_snapshot().reserved, 0);
            assert_eq!(
                run_on_vm(
                    &mut vm,
                    environment,
                    b"return collectgarbage('isrunning')",
                    language
                ),
                RunOutcome::Returned(vec![Value::Boolean(false)])
            );
        }
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return collectgarbage('restart', 99),collectgarbage('isrunning', 99)",
                language,
            ),
            RunOutcome::Returned(vec![Value::Integer(0), Value::Boolean(true)])
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

#[test]
fn actual_lua_finalizer_observes_nil_controls_without_restarting() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
        vm.install_basic_builtins(environment).unwrap();
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return collectgarbage('stop')",
                language
            ),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        let callback_source = if profile == LuaProfile::Lua55 {
            b"return function(o) \
              local a=collectgarbage('isrunning'); \
              local b=collectgarbage('stop'); \
              local c=collectgarbage('restart'); \
              local d=collectgarbage('step',1000); \
              local e=collectgarbage('param','pause',500); \
              final_a=(a==nil); final_b=(b==nil); final_c=(c==nil); \
              final_d=(d==nil); final_e=(e==nil) end"
                .as_slice()
        } else {
            b"return function(o) \
              local a=collectgarbage('isrunning'); \
              local b=collectgarbage('stop'); \
              local c=collectgarbage('restart'); \
              local d=collectgarbage('step',1000); \
              final_a=(a==nil); final_b=(b==nil); final_c=(c==nil); \
              final_d=(d==nil); final_e=true end"
                .as_slice()
        };
        let RunOutcome::Returned(values) =
            run_on_vm(&mut vm, environment, callback_source, language)
        else {
            panic!("{profile:?} 無法建立 Lua finalizer")
        };
        let Value::Object(callback) = values[0] else {
            panic!("{profile:?} finalizer 必須為 closure")
        };
        let target = vm.allocate_table().unwrap();
        let metatable = vm.allocate_table().unwrap();
        let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
        vm.raw_set(metatable, Value::Object(gc_key), Value::Object(callback))
            .unwrap();
        vm.set_metatable(target, Some(metatable)).unwrap();
        let warnings = vm.gc_trace().finalizer_warnings;
        vm.collect().unwrap();
        assert_eq!(vm.gc_trace().finalizer_warnings, warnings);
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return final_a,final_b,final_c,final_d,final_e,collectgarbage('isrunning')",
                language,
            ),
            RunOutcome::Returned(vec![
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(true),
                Value::Boolean(false),
            ]),
            "{profile:?}"
        );
        if profile == LuaProfile::Lua55 {
            assert_eq!(
                run_on_vm(
                    &mut vm,
                    environment,
                    b"return collectgarbage('param','pause')",
                    language,
                ),
                RunOutcome::Returned(vec![Value::Integer(250)])
            );
        }
        assert_eq!(vm.ledger_snapshot().reserved, 0);
    }
}

fn check_explicit_full_collection(language: LanguageProfile, profile: LuaProfile) {
    let mut vm = Vm::new_with_profile(profile).unwrap();
    let environment = vm.allocate_table().unwrap();
    let _environment_root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"local a=collectgarbage(); return a,collectgarbage('isrunning')",
            language,
        ),
        RunOutcome::Returned(vec![Value::Integer(0), Value::Boolean(true)])
    );
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return collectgarbage('stop')",
            language,
        ),
        RunOutcome::Returned(vec![Value::Integer(0)])
    );

    let retained = vm.allocate_byte_string(b"host-rooted").unwrap();
    let _retained_root = HostHandle::<Value>::new(&mut vm, retained).unwrap();
    for source in [
        b"local held={}; return collectgarbage(),held".as_slice(),
        b"local held={}; return collectgarbage(nil),held",
        b"local held={}; return collectgarbage('collect',99),held",
    ] {
        let unreachable = vm.allocate_byte_string(b"unreachable").unwrap();
        assert_eq!(
            vm.object_kind(unreachable),
            Ok(rivetlua_runtime::ObjectKind::ByteString)
        );
        let RunOutcome::Returned(values) = run_on_vm(&mut vm, environment, source, language) else {
            panic!("{profile:?} 明確回收應正常返回：{source:?}")
        };
        assert_eq!(values.len(), 2);
        assert_eq!(values[0], Value::Integer(0));
        let Value::Object(held) = values[1] else {
            panic!("{profile:?} 執行中可達的 table 應返回")
        };
        assert_eq!(
            vm.object_kind(held),
            Ok(rivetlua_runtime::ObjectKind::Table)
        );
        assert_eq!(
            vm.object_kind(retained),
            Ok(rivetlua_runtime::ObjectKind::ByteString)
        );
        assert_eq!(
            vm.object_kind(unreachable),
            Err(rivetlua_runtime::VmError::StaleObject)
        );
        assert_eq!(
            run_on_vm(
                &mut vm,
                environment,
                b"return collectgarbage('isrunning')",
                language,
            ),
            RunOutcome::Returned(vec![Value::Boolean(false)])
        );
    }
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return select('#',collectgarbage()),select('#',collectgarbage(nil)),select('#',collectgarbage('collect'))",
            language,
        ),
        RunOutcome::Returned(vec![Value::Integer(1); 3])
    );
    assert_eq!(
        run(b"return collectgarbage('isrunning')", language, profile),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );

    let callback_source = b"return function(o) \
        local a=collectgarbage(); local b=collectgarbage(nil); \
        local c=collectgarbage('collect'); \
        final_default=(a==nil and select('#',collectgarbage())==1); \
        final_nil=(b==nil and select('#',collectgarbage(nil))==1); \
        final_collect=(c==nil and select('#',collectgarbage('collect'))==1) end";
    let RunOutcome::Returned(values) = run_on_vm(&mut vm, environment, callback_source, language)
    else {
        panic!("{profile:?} 無法建立明確回收 finalizer")
    };
    let Value::Object(callback) = values[0] else {
        panic!("{profile:?} finalizer 必須為 closure")
    };
    let target = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let gc_key = vm.allocate_byte_string(b"__gc").unwrap();
    vm.raw_set(metatable, Value::Object(gc_key), Value::Object(callback))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    let warnings = vm.gc_trace().finalizer_warnings;
    vm.collect().unwrap();
    assert_eq!(vm.gc_trace().finalizer_warnings, warnings);
    assert_eq!(
        run_on_vm(
            &mut vm,
            environment,
            b"return final_default,final_nil,final_collect,collectgarbage('isrunning')",
            language,
        ),
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(false),
        ])
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn collectgarbage_default_full_collection_lua54() {
    check_explicit_full_collection(LanguageProfile::Lua54, LuaProfile::Lua54);
}

#[test]
fn collectgarbage_default_full_collection_lua55() {
    check_explicit_full_collection(LanguageProfile::Lua55, LuaProfile::Lua55);
}

fn check_mode_sequence(language: LanguageProfile, profile: LuaProfile) {
    let mut vm = Vm::new_with_profile(profile).unwrap();
    assert_eq!(vm.gc_trace().mode, GcMode::Generational);
    let first = vm.allocate_table().unwrap();
    let _first_root = HostHandle::<Value>::new(&mut vm, first).unwrap();
    let second = vm.allocate_table().unwrap();
    let _second_root = HostHandle::<Value>::new(&mut vm, second).unwrap();
    vm.install_basic_builtins(first).unwrap();
    vm.install_basic_builtins(second).unwrap();

    let source = b"local initial=collectgarbage('generational'); \
        local a=collectgarbage('incremental'); \
        local b=collectgarbage('generational'); \
        local c=collectgarbage('generational'); \
        local d=collectgarbage('incremental'); \
        local e=collectgarbage('incremental'); \
        return initial,a,b,c,d,e,collectgarbage('isrunning')";
    let RunOutcome::Returned(values) = run_on_vm(&mut vm, first, source, language) else {
        panic!("{profile:?} 模式切換序列應正常返回")
    };
    assert_eq!(values.len(), 7);
    for (actual, expected) in values[..6].iter().zip([
        b"generational".as_slice(),
        b"generational",
        b"incremental",
        b"generational",
        b"generational",
        b"incremental",
    ]) {
        let Value::Object(string) = actual else {
            panic!("{profile:?} 前模式必須是 VM ByteString：{actual:?}")
        };
        assert!(
            vm.with_byte_string(*string, |bytes| bytes.as_bytes() == expected)
                .unwrap()
        );
    }
    assert_eq!(values[6], Value::Boolean(true));
    assert_eq!(vm.gc_trace().mode, GcMode::Incremental);

    let RunOutcome::Returned(values) = run_on_vm(
        &mut vm,
        second,
        b"return collectgarbage('incremental'),collectgarbage('isrunning')",
        language,
    ) else {
        panic!("{profile:?} 第二環境應共享模式")
    };
    let Value::Object(same_mode) = values[0] else {
        panic!("{profile:?} 第二環境應回傳模式字串")
    };
    assert!(
        vm.with_byte_string(same_mode, |bytes| bytes.as_bytes() == b"incremental")
            .unwrap()
    );
    assert_eq!(values[1], Value::Boolean(true));

    let RunOutcome::Returned(values) = run_on_vm(
        &mut vm,
        first,
        b"collectgarbage('stop'); return collectgarbage('generational'),collectgarbage('isrunning')",
        language,
    ) else {
        panic!("{profile:?} stop 後仍應切換模式")
    };
    let Value::Object(previous) = values[0] else {
        panic!("{profile:?} stop 後應回傳前模式字串")
    };
    assert!(
        vm.with_byte_string(previous, |bytes| bytes.as_bytes() == b"incremental")
            .unwrap()
    );
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(vm.gc_trace().mode, GcMode::Generational);

    let callback_source = b"return function(o) \
        local a=collectgarbage('incremental'); \
        local b=collectgarbage('generational'); \
        final_mode_a=(a==nil and select('#',collectgarbage('incremental'))==1); \
        final_mode_b=(b==nil and select('#',collectgarbage('generational'))==1) end";
    let RunOutcome::Returned(values) = run_on_vm(&mut vm, first, callback_source, language) else {
        panic!("{profile:?} 無法建立模式切換 finalizer")
    };
    let Value::Object(callback) = values[0] else {
        panic!("{profile:?} finalizer 必須為 closure")
    };
    let target = vm.allocate_table().unwrap();
    let metatable = vm.allocate_table().unwrap();
    let key = vm.allocate_byte_string(b"__gc").unwrap();
    vm.raw_set(metatable, Value::Object(key), Value::Object(callback))
        .unwrap();
    vm.set_metatable(target, Some(metatable)).unwrap();
    let warnings = vm.gc_trace().finalizer_warnings;
    vm.collect().unwrap();
    assert_eq!(vm.gc_trace().finalizer_warnings, warnings);
    assert_eq!(vm.gc_trace().mode, GcMode::Generational);
    assert_eq!(
        run_on_vm(
            &mut vm,
            first,
            b"return final_mode_a,final_mode_b,collectgarbage('isrunning')",
            language,
        ),
        RunOutcome::Returned(vec![
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(false),
        ])
    );
    assert_eq!(
        Vm::new_with_profile(profile).unwrap().gc_trace().mode,
        GcMode::Generational
    );
    assert_eq!(vm.ledger_snapshot().reserved, 0);
}

#[test]
fn collectgarbage_mode_sequence_lua54() {
    check_mode_sequence(LanguageProfile::Lua54, LuaProfile::Lua54);
}

#[test]
fn collectgarbage_mode_sequence_lua55() {
    check_mode_sequence(LanguageProfile::Lua55, LuaProfile::Lua55);
}
