use rivetlua_compiler::{
    CompileBudgetSink, CompileLimits, IrLimits, LanguageProfile, compile_with_budget,
};
use rivetlua_core::{VerifyLimits, verified_module_allocation_bytes};

#[derive(Default)]
struct RecordingSink {
    work: Vec<usize>,
    temporary: Vec<usize>,
    retained: Vec<usize>,
}

impl CompileBudgetSink for RecordingSink {
    type Error = ();

    fn spend_work(&mut self, units: usize) -> Result<(), Self::Error> {
        self.work.push(units);
        Ok(())
    }

    fn claim_temporary(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.temporary.push(bytes);
        Ok(())
    }

    fn claim_module_allocation(&mut self, bytes: usize) -> Result<(), Self::Error> {
        self.retained.push(bytes);
        Ok(())
    }
}

fn repeated_locals(lines: usize) -> Vec<u8> {
    b"local x=1\n".repeat(lines)
}

#[test]
fn repeated_locals_record_each_prepaid_stage_and_retained_size() {
    let mut over_default = Vec::new();
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for lines in [177, 178] {
            let source = repeated_locals(lines);
            let mut sink = RecordingSink::default();
            let module = compile_with_budget(
                &source,
                b"@repro-budget.lua",
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut sink,
            )
            .unwrap();
            let prepaid = sink
                .temporary
                .iter()
                .chain(&sink.retained)
                .copied()
                .sum::<usize>();
            let actual_retained = verified_module_allocation_bytes(&module).unwrap();
            eprintln!(
                "{profile:?} lines={lines} source={} work={:?} temp={:?} retained={:?} prepaid={prepaid} actual_retained={actual_retained}",
                source.len(),
                sink.work,
                sink.temporary,
                sink.retained
            );
            assert_eq!(sink.temporary.len(), 6);
            assert_eq!(sink.retained.len(), 1);
            assert!(actual_retained <= sink.retained[0]);
            if prepaid + 128 > 768 * 1024 * 1024 {
                over_default.push((profile, lines, prepaid + 128));
            }
        }
    }
    assert!(
        over_default.is_empty(),
        "預付超出 SDK 預設 768 MiB 上限：{over_default:?}"
    );
}

#[test]
fn close_path_and_capture_families_keep_admission_sound() {
    let cases: &[(&str, &[u8])] = &[
        ("ordinary-capture-c0", b"local x=7; local function f() return x end; return f()"),
        ("nested-normal", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; do local a <close> = setmetatable({n=1},mt); do local b <close> = setmetatable({n=2},mt) end end; return log"),
        ("break", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; while true do local a <close> = setmetatable({n=1},mt); break end; return log"),
        ("goto", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; do local a <close> = setmetatable({n=1},mt); goto out end ::out:: return log"),
        ("return", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function f() do local a <close> = setmetatable({n=1},mt); return 9 end end; local v=f(); return log,v"),
        ("error", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function f() do local a <close> = setmetatable({n=1},mt); error('boom') end end; local ok=pcall(f); return log,ok"),
    ];
    let mut failures = Vec::new();
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source) in cases {
            let mut sink = RecordingSink::default();
            let result = compile_with_budget(
                source,
                name.as_bytes(),
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut sink,
            );
            if let Err(error) = result {
                failures.push(format!("{profile:?}/{name}: {error:?}"));
            }
            let prepaid: usize = sink.temporary.iter().chain(&sink.retained).sum();
            assert!(
                prepaid + 128 <= 768 * 1024 * 1024,
                "{profile:?}/{name}: {prepaid}"
            );
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn generic_for_hidden_close_admission_remains_sound() {
    let cases: &[(&str, &[u8])] = &[
        ("generic-for-hidden", b"local log=0; local mt={__close=function(self) log=log*10+self.n end}; local function iter() return nil end; for x in iter,nil,nil,setmetatable({n=3},mt) do end; return log"),
        ("generic-for-minimal", b"for x in nil,nil,nil,{} do end"),
    ];
    let mut failures = Vec::new();
    for profile in [LanguageProfile::Lua54, LanguageProfile::Lua55] {
        for (name, source) in cases {
            let mut sink = RecordingSink::default();
            let result = compile_with_budget(
                source,
                name.as_bytes(),
                profile,
                &CompileLimits::default(),
                &IrLimits::default(),
                &VerifyLimits::default(),
                &mut sink,
            );
            if let Err(error) = result {
                failures.push(format!("{profile:?}/{name}: {error:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
