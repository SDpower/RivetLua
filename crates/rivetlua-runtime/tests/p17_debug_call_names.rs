use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    Instruction, LuaProfile, OfficialChunkLimits, OfficialWorkBudget, ProtoId, Value,
    VerifiedModule, VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{DebugCapability, DebugPermission, HostServices, RootKind, RunOutcome, Vm};

const SOURCE: &[u8] = br#"
local trace = ''
repeat
  local g = {x = function()
    local a = debug.getinfo(2)
    assert(a.name == 'f' and a.namewhat == 'local')
    a = debug.getinfo(1)
    assert(a.name == 'x' and a.namewhat == 'field')
    return 'xixi'
  end}
  local f = function() return 1+1 and (not 1 or g.x()) end
  assert(f() == 'xixi')
  function f(x, name)
    name = name or 'f'
    local a = debug.getinfo(1)
    trace = trace .. (a.name or '<nil>') .. '/' .. a.namewhat .. ';'
    return x
  end
  if 3>4 then break end; f()
  if 3<4 then a=1 else break end; f()
  while 1 do local x=10; break end; f()
  local b = 1
  if 3>4 then return math.sin(1) end; f()
  a = 3<4; f()
  a = 3<4 or 1; f()
  repeat local x=20; if 4>3 then f() else break end; f() until 1
  g = {}
  f(g).x = f(2) and f(10)+f(9)
  assert(g.x == f(19))
  function g(x) if not x then return 3 end return (x('a', 'x')) end
  assert(g(f) == 'a')
until 1
return trace
"#;

const STRIPPED_SOURCE: &[u8] = br#"
local trace = ''
local f = function(x)
  local a = debug.getinfo(1)
  trace = trace .. (a.name or '<nil>') .. '/' .. a.namewhat .. ';'
  return x
end
local g = {}
g.x = f(2) and f(10) + f(9)
assert(g.x == f(19))
return trace
"#;

// 官方 OP_CALL 形式的 generic-for 與一般雙參數呼叫共存。
const ITERATOR_WITH_SEPARATE_NIL_SOURCE: &[u8] = br#"
local iterator_name = ''
do
  local function f()
    local info = debug.getinfo(1)
    iterator_name = (info.name or '<nil>') .. '/' .. info.namewhat
  end
  for i in f do end
end
local function ordinary(x, y)
  local info = debug.getinfo(1)
  return (info.name or '<nil>') .. '/' .. info.namewhat
end
local ordinary_name = ordinary(1, 2)
return iterator_name .. ';' .. ordinary_name
"#;

fn relocate_official_iterator_nil(chunk: &mut rivetlua_core::OfficialChunk) {
    fn opcode(word: u32) -> u32 {
        word & 0x7f
    }
    fn a(word: u32) -> u32 {
        (word >> 7) & 0xff
    }
    fn b(word: u32) -> u32 {
        (word >> 16) & 0xff
    }

    let code = &mut chunk.main.code;
    let candidates: Vec<_> = (0..code.len().saturating_sub(2))
        .filter_map(|call_pc| {
            let (call, result_move, nil_load) =
                (code[call_pc], code[call_pc + 1], code[call_pc + 2]);
            if opcode(call) != 68
                || b(call) != 3
                || (call >> 24) & 0xff != 2
                || opcode(result_move) != 0
                || b(result_move) != a(call)
                || opcode(nil_load) != 8
                || b(nil_load) != 0
                || a(nil_load) == a(result_move)
            {
                return None;
            }
            let result = a(result_move);
            let old_nil = a(nil_load);
            let comparison_pc = (call_pc + 3..code.len().min(call_pc + 16)).find(|&pc| {
                let word = code[pc];
                opcode(word) == 57
                    && ((a(word) == result && b(word) == old_nil)
                        || (a(word) == old_nil && b(word) == result))
            })?;
            Some((call_pc + 2, comparison_pc, old_nil))
        })
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "須有唯一的官方 iterator CALL/MOVE/LOADNIL/EQ；前 64 字={:?}；CALL={:?}",
        &code[..code.len().min(64)],
        code.iter()
            .enumerate()
            .filter(|(_, word)| opcode(**word) == 68)
            .take(8)
            .map(|(pc, &word)| (
                pc,
                a(word),
                b(word),
                (word >> 24) & 0xff,
                &code[pc + 1..(pc + 4).min(code.len())],
            ))
            .collect::<Vec<_>>(),
    );
    let (nil_pc, comparison_pc, old_nil) = candidates[0];
    let spare = u32::from(chunk.main.max_stack_size);
    assert!(spare < 255, "官方 maxstack 須容許新增一個未命名槽");
    assert_ne!(a(code[comparison_pc]), b(code[comparison_pc]));
    code[nil_pc] = (code[nil_pc] & !(0xff << 7)) | (spare << 7);
    code[comparison_pc] = if a(code[comparison_pc]) == old_nil {
        (code[comparison_pc] & !(0xff << 7)) | (spare << 7)
    } else {
        (code[comparison_pc] & !(0xff << 16)) | (spare << 16)
    };
    chunk.main.max_stack_size += 1;
}

fn relay_official_iterator_control(chunk: &mut rivetlua_core::OfficialChunk) {
    fn opcode(word: u32) -> u32 {
        word & 0x7f
    }
    fn a(word: u32) -> u32 {
        (word >> 7) & 0xff
    }
    fn b(word: u32) -> u32 {
        (word >> 16) & 0xff
    }

    let code = &mut chunk.main.code;
    let calls: Vec<_> = (0..code.len().saturating_sub(2))
        .filter(|&pc| {
            opcode(code[pc]) == 68
                && b(code[pc]) == 3
                && (code[pc] >> 24) & 0xff == 2
                && opcode(code[pc + 1]) == 0
                && b(code[pc + 1]) == a(code[pc])
                && opcode(code[pc + 2]) == 8
        })
        .collect();
    assert_eq!(calls.len(), 1, "須有唯一的官方 iterator CALL/MOVE/LOADNIL");
    let call_pc = calls[0];
    let control_arg = a(code[call_pc]) + 2;
    let control_move_pc = (call_pc.saturating_sub(12)..call_pc)
        .rev()
        .find(|&pc| opcode(code[pc]) == 0 && a(code[pc]) == control_arg)
        .expect("iterator CALL 前須裝入 control 參數");
    let control = b(code[control_move_pc]);
    let result = a(code[call_pc + 1]);
    assert!(
        code[call_pc + 3..code.len().min(call_pc + 20)]
            .iter()
            .any(|&word| opcode(word) == 0 && a(word) == control && b(word) == result),
        "原始 iterator 須確實將 result 回寫到 control"
    );
    let relay = u32::from(chunk.main.max_stack_size);
    assert!(relay < 255, "官方 maxstack 須容許新增一個未命名 relay 槽");

    // 僅在第三參數 MOVE 前插入 relay MOVE；相對 JMP 與 debug PC
    // 同步平移，保留原迴圈分支及局部名稱範圍。
    let insert_pc = control_move_pc;
    let old_len = code.len();
    assert!(insert_pc >= 2 && opcode(code[insert_pc - 1]) == 0 && opcode(code[insert_pc - 2]) == 0);
    assert!(!code.iter().any(|&word| matches!(opcode(word), 73..=77)));
    let jumps: Vec<_> = code
        .iter()
        .enumerate()
        .filter(|(_, word)| opcode(**word) == 56)
        .map(|(pc, word)| {
            let target = pc as i64 + 1 + i64::from(*word >> 7) - 16_777_215;
            assert!((0..=old_len as i64).contains(&target));
            (pc, target)
        })
        .collect();
    assert!(!jumps.iter().any(|(_, target)| *target == insert_pc as i64));
    code[control_move_pc] = (code[control_move_pc] & !(0xff << 16)) | (relay << 16);
    code.insert(insert_pc, (relay << 7) | (control << 16));
    for (old_pc, old_target) in jumps {
        let pc = old_pc + if old_pc >= insert_pc { 1 } else { 0 };
        let target = old_target + if old_target >= insert_pc as i64 { 1 } else { 0 };
        let ax = u32::try_from(target - pc as i64 - 1 + 16_777_215).unwrap();
        assert!(ax <= 0x1ff_ffff);
        code[pc] = 56 | (ax << 7);
    }
    if !chunk.main.debug.line_info.is_empty() {
        assert_eq!(chunk.main.debug.line_info.len(), old_len);
        chunk.main.debug.line_info.insert(insert_pc, 0);
    }
    for entry in &mut chunk.main.debug.abs_line_info {
        if entry.pc as usize >= insert_pc {
            entry.pc += 1;
        }
    }
    for local in &mut chunk.main.debug.locals {
        if local.start_pc as usize >= insert_pc {
            local.start_pc += 1;
        }
        if local.end_pc as usize > insert_pc {
            local.end_pc += 1;
        }
    }
    chunk.main.max_stack_size += 1;
}

fn official_call_uses_separate_iterator_nil(module: &VerifiedModule) -> bool {
    let Some(artifact) = module.official_artifact() else {
        return false;
    };
    module.module().prototypes.iter().any(|prototype| {
        let Some(map) = artifact.pc_map(prototype.id) else {
            return false;
        };
        let Some(guest) = artifact.prototype(prototype.id) else {
            return false;
        };
        prototype
            .instructions
            .windows(3)
            .enumerate()
            .any(|(pc, window)| {
                let (
                    Instruction::Call {
                        base, arg_count: 2, ..
                    },
                    Instruction::Move { dest: result, src },
                    Instruction::LoadNil {
                        start: nil,
                        count: 1,
                    },
                ) = (
                    &window[0].instruction,
                    &window[1].instruction,
                    &window[2].instruction,
                )
                else {
                    return false;
                };
                *src == *base
                    && *result != *nil
                    && *nil != *base
                    && map.rvlu_to_official()[pc]
                        .source_pc()
                        .and_then(|source_pc| guest.code.get(source_pc as usize))
                        .is_some_and(|word| word & 0x7f == 68)
            })
    })
}

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
        b"@p17-db-debug-call-names.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn run(module: VerifiedModule, profile: LuaProfile) -> Vec<u8> {
    let debug = DebugCapability::deny_all()
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
        panic!("debug 呼叫應正常返回: {outcome:?}");
    };
    assert_eq!(values.len(), 1);
    let Value::Object(value) = values[0] else {
        panic!("debug 呼叫軌跡應為字串: {:?}", values[0]);
    };
    let trace = vm
        .with_byte_string(value, |text| text.as_bytes().to_vec())
        .unwrap();
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    trace
}

fn diagnose(module: &VerifiedModule, label: &str) {
    for proto in &module.module().prototypes {
        let calls: Vec<_> = proto
            .instructions
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                matches!(
                    entry.instruction,
                    Instruction::Call { .. } | Instruction::TailCall { .. }
                )
            })
            .map(|(pc, entry)| (pc, &entry.instruction))
            .collect();
        eprintln!("{label} {:?} calls={calls:?}", proto.id);
        if let Some(native) = module
            .native_debug()
            .and_then(|debug| debug.prototype(proto.id))
        {
            eprintln!("{label} {:?} native locals={:?}", proto.id, native.locals);
        }
        if let Some(artifact) = module.official_artifact() {
            if let Some(guest) = artifact.prototype(proto.id) {
                eprintln!(
                    "{label} {:?} official locals={:?}",
                    proto.id, guest.debug.locals
                );
            }
            if let Some(map) = artifact.pc_map(proto.id) {
                if let Some(plan) = module.official_execution() {
                    eprintln!(
                        "{label} {:?} slot map={:?}",
                        proto.id,
                        plan.upvalue_map(proto.id)
                    );
                }
                for (pc, _) in calls {
                    eprintln!(
                        "{label} {:?} call pc={pc} official map={:?}",
                        proto.id,
                        map.rvlu_to_official().get(pc)
                    );
                }
            }
        }
        if proto.id == ProtoId(0) || proto.id == ProtoId(4) {
            for (pc, entry) in proto.instructions.iter().enumerate() {
                if (proto.id == ProtoId(0) && (452..=507).contains(&pc))
                    || (proto.id == ProtoId(4) && pc <= 24)
                {
                    eprintln!(
                        "{label} {:?} instruction {pc}: {:?}",
                        proto.id, entry.instruction
                    );
                }
            }
        }
    }
}

#[test]
fn p17_debug_rebound_local_call_names_survive_control_flow_and_full_dump() {
    let mut mismatches = Vec::new();
    let mut expected = Vec::new();
    for _ in 0..13 {
        expected.extend_from_slice(b"f/local;");
    }
    expected.extend_from_slice(b"x/local;");
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(SOURCE, language);
        let bytes = emit_official_chunk(
            &native,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut OfficialWorkBudget::new(u64::MAX),
        )
        .unwrap();
        let chunk =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let official = translate_official_chunk(&chunk, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        for (label, module) in [("native", native), ("official", official)] {
            let actual = run(module.clone(), profile);
            eprintln!(
                "{profile:?} {label} call names: {}",
                String::from_utf8_lossy(&actual)
            );
            if actual != expected {
                diagnose(&module, label);
                mismatches.push(format!(
                    "{profile:?} {label}: expected {}, got {}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn p17_debug_stripped_dump_does_not_invent_local_call_name() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(STRIPPED_SOURCE, language);
        let mut named = Vec::new();
        let mut unnamed = Vec::new();
        for _ in 0..4 {
            named.extend_from_slice(b"f/local;");
            unnamed.extend_from_slice(b"<nil>/;");
        }
        assert_eq!(run(native.clone(), profile), named, "{profile:?} native");
        for (strip, expected) in [(false, &named), (true, &unnamed)] {
            let bytes = emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                strip,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            let chunk =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            let official = translate_official_chunk(&chunk, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            assert_eq!(
                run(official, profile),
                *expected,
                "{profile:?} strip={strip}"
            );
        }
    }
}

#[test]
fn p17_debug_iterator_name_survives_separate_nil_slot_and_plain_call() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(ITERATOR_WITH_SEPARATE_NIL_SOURCE, language);
        assert_eq!(
            run(native.clone(), profile),
            b"for iterator/for iterator;ordinary/local",
            "{profile:?} native"
        );
        let bytes = emit_official_chunk(
            &native,
            ProtoId(0),
            profile,
            false,
            &OfficialChunkLimits::default(),
            &mut OfficialWorkBudget::new(u64::MAX),
        )
        .unwrap();
        let mut chunk =
            decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
        let original = translate_official_chunk(&chunk, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert_eq!(
            run(original, profile),
            b"for iterator/for iterator;ordinary/local",
            "{profile:?} 原官方 roundtrip"
        );
        relocate_official_iterator_nil(&mut chunk);
        relay_official_iterator_control(&mut chunk);
        let official = translate_official_chunk(&chunk, &VerifyLimits::default())
            .unwrap()
            .verified()
            .clone();
        assert!(
            official_call_uses_separate_iterator_nil(&official),
            "{profile:?} 測試需保留 CALL 後 MOVE 結果與獨立 nil 暫存槽"
        );
        assert_eq!(
            run(official, profile),
            b"for iterator/for iterator;ordinary/local",
            "{profile:?} official roundtrip"
        );
    }
}
