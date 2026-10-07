use rivetlua::{Engine, LuaProfile, RunOutcome, Value};

fn check_initial(profile: LuaProfile) {
    let engine = Engine::new(profile);
    let module = engine
        .compile(b"return collectgarbage('isrunning')")
        .unwrap();
    let mut vm = engine.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&module).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    assert_eq!(vm.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_lua55_param_codec_and_explicit_step_while_stopped() {
    let engine = Engine::new(LuaProfile::Lua55);
    let module = engine
        .compile(
            b"local p=collectgarbage('param','pause'); \
              local s=collectgarbage('param','stepmul'); \
              local old=collectgarbage('param','stepmul',30000); \
              local rounded=collectgarbage('param','stepmul'); \
              collectgarbage('stop'); \
              local step=collectgarbage('step',10); \
              return p,s,old,rounded,step,collectgarbage('isrunning')",
        )
        .unwrap();
    let mut vm = engine.new_vm().unwrap();
    let RunOutcome::Returned(values) = vm.load_module(&module).unwrap().run().unwrap() else {
        panic!("SDK Lua 5.5 param/step 應成功")
    };
    assert_eq!(
        &values[..4],
        &[
            Value::Integer(250),
            Value::Integer(200),
            Value::Integer(200),
            Value::Integer(28800),
        ]
    );
    assert!(matches!(values[4], Value::Boolean(_)));
    assert_eq!(values[5], Value::Boolean(false));
    assert_eq!(vm.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_lua54_step_is_available_but_param_is_rejected() {
    let engine = Engine::new(LuaProfile::Lua54);
    let mut vm = engine.new_vm().unwrap();
    let param = engine
        .compile(b"return collectgarbage('param','pause',100)")
        .unwrap();
    assert!(matches!(
        vm.load_module(&param).unwrap().run().unwrap(),
        RunOutcome::LuaError(error) if error.diagnostic_id == "E_BASIC_ARGUMENT"
    ));
    let step = engine
        .compile(
            b"collectgarbage('stop'); \
              return collectgarbage('step',0),collectgarbage('isrunning')",
        )
        .unwrap();
    let RunOutcome::Returned(values) = vm.load_module(&step).unwrap().run().unwrap() else {
        panic!("SDK Lua 5.4 step 應成功")
    };
    assert!(matches!(values[0], Value::Boolean(_)));
    assert_eq!(values[1], Value::Boolean(false));
    assert_eq!(vm.allocation_snapshot().reserved, 0);
}

fn check_transitions(profile: LuaProfile) {
    let engine = Engine::new(profile);
    let module = engine
        .compile(
            b"local a=collectgarbage('stop'); local b=collectgarbage('isrunning'); \
          local c=collectgarbage('stop'); local d=collectgarbage('isrunning'); \
          local e=collectgarbage('restart'); local f=collectgarbage('isrunning'); \
          local g=collectgarbage('restart'); return a,b,c,d,e,f,g,collectgarbage('isrunning')",
        )
        .unwrap();
    let mut vm = engine.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&module).unwrap().run().unwrap(),
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
    assert_eq!(vm.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_collectgarbage_isrunning_initial_lua54() {
    check_initial(LuaProfile::Lua54);
}

#[test]
fn sdk_collectgarbage_isrunning_initial_lua55() {
    check_initial(LuaProfile::Lua55);
}

#[test]
fn sdk_collectgarbage_stop_restart_lua54() {
    check_transitions(LuaProfile::Lua54);
}

#[test]
fn sdk_collectgarbage_stop_restart_lua55() {
    check_transitions(LuaProfile::Lua55);
}

#[test]
fn sdk_running_state_is_vm_local_and_invalid_option_keeps_stopped_state() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let engine = Engine::new(profile);
        let stop = engine.compile(b"return collectgarbage('stop')").unwrap();
        let restart = engine.compile(b"return collectgarbage('restart')").unwrap();
        let query = engine
            .compile(b"return collectgarbage('isrunning')")
            .unwrap();
        let invalid = engine
            .compile(b"return collectgarbage('ISRUNNING')")
            .unwrap();
        let mut first = engine.new_vm().unwrap();
        let mut second = engine.new_vm().unwrap();
        assert_eq!(
            first.load_module(&stop).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        assert_eq!(
            first.load_module(&query).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(false)])
        );
        assert_eq!(
            second.load_module(&query).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert!(matches!(
            first.load_module(&invalid).unwrap().run().unwrap(),
            RunOutcome::LuaError(error) if error.diagnostic_id == "E_BASIC_ARGUMENT"
        ));
        assert_eq!(
            first.load_module(&query).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(false)])
        );
        assert_eq!(
            first.load_module(&restart).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Integer(0)])
        );
        assert_eq!(
            first.load_module(&query).unwrap().run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true)])
        );
        assert_eq!(first.allocation_snapshot().reserved, 0);
        assert_eq!(second.allocation_snapshot().reserved, 0);
    }
}

fn check_default_full_collection(profile: LuaProfile) {
    let engine = Engine::new(profile);
    let source = b"collectgarbage('stop'); \
        local held={marker=17}; local hits=0; \
        local function make_dead() local dead=setmetatable({}, {__gc=function() hits=hits+1 end}) end; \
        make_dead(); local a=collectgarbage(); local first=hits; \
        make_dead(); local b=collectgarbage(nil); local second=hits; \
        make_dead(); local c=collectgarbage('collect',99); \
        return a,b,c,first,second,hits,held.marker,collectgarbage('isrunning'),select('#',collectgarbage())";
    let module = engine.compile(source).unwrap();
    let mut vm = engine.new_vm().unwrap();
    assert_eq!(
        vm.load_module(&module).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(0),
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
            Value::Integer(17),
            Value::Boolean(false),
            Value::Integer(1),
        ])
    );
    let finalizer = engine
        .compile(
            b"local hits=0; local a,b,c,arity; \
              local function make_dead() local dead=setmetatable({}, {__gc=function() \
                hits=hits+1; a=collectgarbage(); b=collectgarbage(nil); \
                c=collectgarbage('collect'); arity=select('#',collectgarbage()) end}) end; \
              make_dead(); \
              collectgarbage(); \
              return hits,a==nil,b==nil,c==nil,arity,collectgarbage('isrunning')",
        )
        .unwrap();
    assert_eq!(
        vm.load_module(&finalizer).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![
            Value::Integer(1),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(1),
            Value::Boolean(false),
        ])
    );
    let mut other = engine.new_vm().unwrap();
    let initial = engine
        .compile(b"local a=collectgarbage(); return a,collectgarbage('isrunning')")
        .unwrap();
    assert_eq!(
        other.load_module(&initial).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![Value::Integer(0), Value::Boolean(true)])
    );
    assert_eq!(vm.allocation_snapshot().reserved, 0);
    assert_eq!(other.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_collectgarbage_default_full_collection_lua54() {
    check_default_full_collection(LuaProfile::Lua54);
}

#[test]
fn sdk_collectgarbage_default_full_collection_lua55() {
    check_default_full_collection(LuaProfile::Lua55);
}

fn check_mode_sequence(profile: LuaProfile) {
    let engine = Engine::new(profile);
    let mut vm = engine.new_vm().unwrap();
    let sequence = engine
        .compile(
            b"local initial=collectgarbage('generational'); \
              local a=collectgarbage('incremental'); \
              local b=collectgarbage('generational'); \
              local c=collectgarbage('generational'); \
              local d=collectgarbage('incremental'); \
              local e=collectgarbage('incremental'); \
              return initial,a,b,c,d,e,collectgarbage('isrunning')",
        )
        .unwrap();
    let RunOutcome::Returned(values) = vm.load_module(&sequence).unwrap().run().unwrap() else {
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
        let rooted = vm.root(*actual).unwrap();
        assert_eq!(
            vm.read_byte_string(&rooted).unwrap(),
            expected,
            "{profile:?}"
        );
    }
    assert_eq!(values[6], Value::Boolean(true));

    let stopped = engine
        .compile(
            b"collectgarbage('stop'); \
              local old=collectgarbage('generational'); \
              local same=collectgarbage('generational'); \
              return old,same,collectgarbage('isrunning')",
        )
        .unwrap();
    let RunOutcome::Returned(values) = vm.load_module(&stopped).unwrap().run().unwrap() else {
        panic!("{profile:?} stop 後切換模式應正常返回")
    };
    for (actual, expected) in values[..2]
        .iter()
        .zip([b"incremental".as_slice(), b"generational".as_slice()])
    {
        let rooted = vm.root(*actual).unwrap();
        assert_eq!(
            vm.read_byte_string(&rooted).unwrap(),
            expected,
            "{profile:?}"
        );
    }
    assert_eq!(values[2], Value::Boolean(false));

    let finalizer = engine
        .compile(
            b"local hits=0; local a,b,arity; \
              local function make_dead() local dead=setmetatable({}, {__gc=function() \
                hits=hits+1; a=collectgarbage('incremental'); \
                b=collectgarbage('generational'); \
                arity=select('#',collectgarbage('incremental')) end}) end; \
              make_dead(); collectgarbage(); \
              local mode=collectgarbage('generational'); \
              return hits,a==nil,b==nil,arity,mode=='generational',collectgarbage('isrunning')",
        )
        .unwrap();
    assert_eq!(
        vm.load_module(&finalizer).unwrap().run().unwrap(),
        RunOutcome::Returned(vec![
            Value::Integer(1),
            Value::Boolean(true),
            Value::Boolean(true),
            Value::Integer(1),
            Value::Boolean(true),
            Value::Boolean(false),
        ])
    );

    let mut other = engine.new_vm().unwrap();
    let initial = engine
        .compile(b"return collectgarbage('generational'),collectgarbage('isrunning')")
        .unwrap();
    let RunOutcome::Returned(values) = other.load_module(&initial).unwrap().run().unwrap() else {
        panic!("{profile:?} 新 VM 應可查詢初始模式")
    };
    assert_eq!(values.len(), 2);
    let rooted = other.root(values[0]).unwrap();
    assert_eq!(other.read_byte_string(&rooted).unwrap(), b"generational");
    assert_eq!(values[1], Value::Boolean(true));
    assert_eq!(vm.allocation_snapshot().reserved, 0);
    assert_eq!(other.allocation_snapshot().reserved, 0);
}

#[test]
fn sdk_collectgarbage_mode_sequence_lua54() {
    check_mode_sequence(LuaProfile::Lua54);
}

#[test]
fn sdk_collectgarbage_mode_sequence_lua55() {
    check_mode_sequence(LuaProfile::Lua55);
}
