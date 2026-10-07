use rivetlua::{
    Engine, HostLoadError, HostModuleBytes, HostModuleRepository, HostServices, HostSourceReader,
    LoadBudget, LoadCapability, LoadFormat, LuaProfile, RunOutcome, Value,
};

struct SourceReader;

impl HostSourceReader for SourceReader {
    fn read_path(
        &mut self,
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Vec<u8>, HostLoadError> {
        assert_eq!(path, b"code.lua");
        let source = b"return 31, 32";
        budget.spend_work(source.len() + 1)?;
        budget.claim_temporary(source.len())?;
        Ok(source.to_vec())
    }

    fn read_stdin(&mut self, budget: &mut LoadBudget<'_>) -> Result<Vec<u8>, HostLoadError> {
        let source = b"return 5, 6";
        budget.spend_work(source.len() + 1)?;
        budget.claim_temporary(source.len())?;
        Ok(source.to_vec())
    }
}

struct Repository;

impl HostModuleRepository for Repository {
    fn search(
        &mut self,
        _modname: &[u8],
        path: &[u8],
        budget: &mut LoadBudget<'_>,
    ) -> Result<Option<HostModuleBytes>, HostLoadError> {
        budget.spend_work(path.len())?;
        if path != b"pkg/item/init.lua" {
            return Ok(None);
        }
        let source = b"return marker";
        budget.claim_temporary(source.len())?;
        Ok(Some(HostModuleBytes {
            data: source.to_vec(),
            loader_data: Vec::new(),
            format: LoadFormat::Source,
        }))
    }
}

fn run(profile: LuaProfile, source: &[u8], services: HostServices) -> RunOutcome {
    let engine = Engine::new(profile);
    let module = engine.compile(source).unwrap();
    let mut vm = engine.new_vm_with_services(services).unwrap();
    vm.load_module(&module).unwrap().run().unwrap()
}

fn check_profile(profile: LuaProfile) {
    let engine = Engine::new(profile);
    let compiler = || {
        HostServices::deny_all().and_load(LoadCapability::deny_all().and_compiler(engine.clone()))
    };
    let mut failures = Vec::new();
    for (name, source, expected) in [
        (
            "sdk-load",
            b"local f=assert(load('return 40+2')); return f()".as_slice(),
            vec![Value::Integer(42)],
        ),
        (
            "explicit-env",
            b"local f=assert(load('return x',nil,'t',{x=23})); return f()".as_slice(),
            vec![Value::Integer(23)],
        ),
        (
            "rvl",
            b"return assert(load([=[RVL=7; return RVL]=]))()".as_slice(),
            vec![Value::Integer(7)],
        ),
        (
            "rvlu",
            b"return assert(load([=[RVLU=8; return RVLU]=]))()".as_slice(),
            vec![Value::Integer(8)],
        ),
        (
            "rvlu-newline",
            b"return assert(load([=[RVLU\n=9; return RVLU]=]))()".as_slice(),
            vec![Value::Integer(9)],
        ),
        (
            "rvlu-tab",
            b"return assert(load([=[RVLU\t=10; return RVLU]=]))()".as_slice(),
            vec![Value::Integer(10)],
        ),
    ] {
        let outcome = run(profile, source, compiler());
        if outcome != RunOutcome::Returned(expected.clone()) {
            failures.push(format!("{name}: {outcome:?}; expected={expected:?}"));
        }
    }
    let reader_services = || {
        HostServices::deny_all().and_load(
            LoadCapability::deny_all()
                .and_reader(SourceReader)
                .and_compiler(engine.clone()),
        )
    };
    for (name, source, expected) in [
        (
            "sdk-reader",
            b"local f=assert(loadfile('code.lua')); return f()".as_slice(),
            vec![Value::Integer(31), Value::Integer(32)],
        ),
        (
            "dofile-stdin",
            b"return dofile()".as_slice(),
            vec![Value::Integer(5), Value::Integer(6)],
        ),
    ] {
        let outcome = run(profile, source, reader_services());
        if outcome != RunOutcome::Returned(expected.clone()) {
            failures.push(format!("{name}: {outcome:?}; expected={expected:?}"));
        }
    }
    let repository_services = HostServices::deny_all().and_load(
        LoadCapability::deny_all()
            .and_repository(Repository)
            .and_compiler(engine.clone()),
    );
    let outcome = run(
        profile,
        b"marker=73; package.path='?/init.lua;?.lua'; return (require('pkg.item'))",
        repository_services,
    );
    if outcome != RunOutcome::Returned(vec![Value::Integer(73)]) {
        failures.push(format!("repository: {outcome:?}; expected=73"));
    }
    assert!(failures.is_empty(), "{profile:?}: {failures:#?}");
}

#[test]
fn sdk_default_host_load_sources_lua54() {
    check_profile(LuaProfile::Lua54);
}

#[test]
fn sdk_default_host_load_sources_lua55() {
    check_profile(LuaProfile::Lua55);
}
