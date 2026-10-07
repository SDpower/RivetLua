use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{LuaProfile, Value, VerifyLimits};
use rivetlua_runtime::{HostHandle, RunOutcome, Vm};

struct Unlimited;

impl CompileBudgetSink for Unlimited {
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

#[test]
fn generic_for_debug_scope_preserves_iteration_capture_and_closing() {
    let cases: &[(&str, &[u8], &[Value])] = &[
        ("zero", b"local n=0; local function iter() return nil end; for x in iter,nil,nil,nil do n=n+1 end; return n", &[Value::Integer(0)]),
        ("several", b"local function iter(_,x) if x<3 then return x+1 end end; local sum=0; for x in iter,nil,0,nil do sum=sum+x end; return sum", &[Value::Integer(6)]),
        ("multiple-names", b"local function iter(_,x) if x<2 then return x+1,(x+1)*10 end end; local sum=0; for x,y in iter,nil,0,nil do sum=sum+x+y end; return sum", &[Value::Integer(33)]),
        ("break", b"local function iter(_,x) if x<3 then return x+1 end end; local sum=0; for x in iter,nil,0,nil do sum=sum+x; break end; return sum", &[Value::Integer(1)]),
        ("capture-two-iterations", b"local function iter(_,x) if x<2 then return x+1 end end; local f={}; for x in iter,nil,0,nil do f[x]=function() return x end end; return f[1](),f[2]()", &[Value::Integer(1), Value::Integer(2)]),
        ("capture-break", b"local f; local function iter(_,x) return x+1 end; for x in iter,nil,0,nil do f=function() return x end; break end; return f()", &[Value::Integer(1)]),
        ("capture-error", b"local f; local function iter(_,x) return x+1 end; local ok=pcall(function() for x in iter,nil,0,nil do f=function() return x end; error('bad') end end); return ok,f()", &[Value::Boolean(false), Value::Integer(1)]),
        ("fourth-zero", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter() return nil end; for x in iter,nil,nil,setmetatable({n=3},mt) do end; return log", &[Value::Integer(3)]),
        ("fourth-close", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter(_,x) if x<2 then return x+1 end end; for x in iter,nil,0,setmetatable({n=3},mt) do end; return log", &[Value::Integer(3)]),
        ("fourth-break", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter(_,x) return x+1 end; for x in iter,nil,0,setmetatable({n=3},mt) do break end; return log", &[Value::Integer(3)]),
        ("fourth-return", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter(_,x) return x+1 end; local function f() for x in iter,nil,0,setmetatable({n=3},mt) do return x end end; local v=f(); return log,v", &[Value::Integer(3), Value::Integer(1)]),
        ("fourth-error", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter() error('bad') end; local ok=pcall(function() for x in iter,nil,nil,setmetatable({n=4},mt) do end end); return log,ok", &[Value::Integer(4), Value::Boolean(false)]),
    ];
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source, expected) in cases {
            let module = compile_with_budget(
                source,
                name.as_bytes(),
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut Unlimited,
            )
            .unwrap_or_else(|error| panic!("{profile:?}/{name} compile: {error:?}"));
            let vm_profile = match profile {
                LanguageProfile::Lua54 => LuaProfile::Lua54,
                LanguageProfile::Lua55 => LuaProfile::Lua55,
            };
            let mut vm = Vm::new_with_profile(vm_profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let _root = HostHandle::<Value>::new(&mut vm, environment).unwrap();
            vm.install_basic_builtins(environment).unwrap();
            let outcome = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap()
                .run()
                .unwrap();
            assert_eq!(
                outcome,
                RunOutcome::Returned(expected.to_vec()),
                "{profile:?}/{name}"
            );
            assert_eq!(vm.ledger_snapshot().reserved, 0, "{profile:?}/{name}");
        }
    }
}
