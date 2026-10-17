use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    InstructionOffset, LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value,
    VerifiedModule, VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{DebugCapability, DebugPermission, HostServices, RootKind, RunOutcome, Vm};

const SWITCH_SOURCE: &[u8] = br#"local trace = ""
local count = 0
local function target()
  local x = 1
  x = x + 1
  x = x + 2
  return x
end
debug.sethook(function(event)
  assert(event == "call")
  debug.sethook(function(kind, line)
    assert(kind == "line")
    local current = debug.getinfo(2, "l").currentline
    trace = trace .. line .. "/" .. current .. ";"
    count = count + 1
    if count == 3 then debug.sethook() end
  end, "l")
end, "c")
local result = target()
assert(result == 4 and count == 3 and not debug.gethook())
return trace
"#;

const ORDINARY_CALL_SOURCE: &[u8] = br#"local observed
local function callee()
  observed = debug.getinfo(2, "l").currentline
end
callee()
local after = 1
return observed .. ":" .. after
"#;

fn compile(source: &[u8], language: LanguageProfile) -> VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let syntax = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&syntax, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-db-hook-switch.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn official(module: &VerifiedModule, profile: LuaProfile) -> VerifiedModule {
    let bytes = emit_official_chunk(
        module,
        ProtoId(0),
        profile,
        false,
        &OfficialChunkLimits::default(),
        &mut OfficialWorkBudget::new(u64::MAX),
    )
    .unwrap();
    let chunk = decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&chunk, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run(module: VerifiedModule, profile: LuaProfile) -> Vec<u8> {
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::EventHook)
        .allow(DebugPermission::Info)
        .allow(DebugPermission::StackInspection);
    let mut vm = Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    vm.install_debug_builtins(environment).unwrap();
    let outcome = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        panic!("debug hook 測試應正常返回: {outcome:?}");
    };
    assert_eq!(values.len(), 1);
    let Value::Object(value) = values[0] else {
        panic!("debug hook 軌跡應為字串: {:?}", values[0]);
    };
    let trace = vm
        .with_byte_string(value, |text| text.as_bytes().to_vec())
        .unwrap();
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    trace
}

fn report_line_boundaries(module: &VerifiedModule, label: &str, event_line: u32) {
    for proto in &module.module().prototypes {
        let native = module
            .native_debug()
            .and_then(|debug| debug.prototype(proto.id));
        let map = module
            .official_artifact()
            .and_then(|artifact| artifact.pc_map(proto.id));
        let line_at = |pc: usize| {
            if let Some(native) = native {
                native.lines.get(pc).copied().filter(|line| *line > 0)
            } else {
                u32::try_from(pc)
                    .ok()
                    .and_then(|pc| map?.line_at_rvlu(InstructionOffset(pc)))
            }
        };
        for pc in 1..proto.instructions.len() {
            if line_at(pc) == Some(event_line) && line_at(pc - 1) != Some(event_line) {
                eprintln!(
                    "{label} {:?} candidate boundary pc={pc} previous={:?} event_line={event_line}",
                    proto.id,
                    line_at(pc - 1)
                );
            }
        }
    }
}

#[test]
fn p17_debug_call_to_line_hook_getinfo_matches_event_line() {
    let mut mismatches = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(SWITCH_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let trace = run(module.clone(), profile);
            eprintln!(
                "{profile:?} {label} line pairs: {}",
                String::from_utf8_lossy(&trace)
            );
            let text = String::from_utf8(trace).unwrap();
            let pairs: Vec<_> = text
                .split(';')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (event, current) = pair.split_once('/').unwrap();
                    (
                        event.parse::<u32>().unwrap(),
                        current.parse::<i64>().unwrap(),
                    )
                })
                .collect();
            assert_eq!(pairs.len(), 3, "{profile:?} {label}: {pairs:?}");
            assert!(
                pairs.windows(2).any(|window| window[0].0 != window[1].0),
                "{profile:?} {label} 應跨越來源行: {pairs:?}"
            );
            for (event, current) in pairs {
                if i64::from(event) != current {
                    report_line_boundaries(&module, label, event);
                    mismatches.push(format!(
                        "{profile:?} {label}: event_line={event}, currentline={current}"
                    ));
                }
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn p17_debug_getinfo_ordinary_caller_keeps_callsite_line() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(ORDINARY_CALL_SOURCE, language);
        let official = official(&native, profile);
        assert_eq!(run(native, profile), b"5:1", "{profile:?} native");
        assert_eq!(run(official, profile), b"5:1", "{profile:?} official");
    }
}
