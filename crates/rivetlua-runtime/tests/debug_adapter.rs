use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
};
use rivetlua_core::{
    HostFunctionId, LuaProfile, OfficialChunkLimits, ResultMode, Value, VerifyLimits,
    decode_official_chunk, translate_official_chunk,
};
use rivetlua_runtime::{
    DebugFrameKind, DebugHookConfig, ExternalCommand, FailPoint, RootKind, RunOutcome, Vm,
};

fn compile(source: &[u8], profile: LuaProfile) -> rivetlua_core::VerifiedModule {
    let language = match profile {
        LuaProfile::Lua54 => LanguageProfile::Lua54,
        LuaProfile::Lua55 => LanguageProfile::Lua55,
    };
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let parsed = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&parsed, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@debug_adapter",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn parked(vm: &mut Vm, function: HostFunctionId) -> rivetlua_runtime::ExternalToken {
    let mut execution = vm.call(Value::CFunction(function), &[]).unwrap();
    let RunOutcome::External(token) = execution.run().unwrap() else {
        panic!("C callback 必須停放")
    };
    token
}

#[test]
fn debug_adapter_method_call_name_reports_method() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for (source, expected_namewhat) in [
            (&b"return function(t) return t:m(1) end"[..], &b"method"[..]),
            (
                &b"return function(t) return t.m(t,1) end"[..],
                &b"field"[..],
            ),
            (&b"return function(t) return t.m(1) end"[..], &b"field"[..]),
        ] {
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let table = vm.allocate_table().unwrap();
            let table_root = vm.add_root(RootKind::Host, table).unwrap();
            let method = HostFunctionId::new_unique(vm.id()).unwrap();
            let key = vm.allocate_byte_string(b"m").unwrap();
            vm.raw_set(table, Value::Object(key), Value::CFunction(method))
                .unwrap();
            let function = {
                let mut execution = vm.load(compile(source, profile)).unwrap();
                let RunOutcome::Returned(values) = execution.run().unwrap() else {
                    panic!("應建立 Lua closure")
                };
                values[0]
            };
            let token = {
                let mut execution = vm.call(function, &[Value::Object(table)]).unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("C callback 應停放")
                };
                token
            };
            let frame = vm.debug_frame_external(token, 0).unwrap().unwrap();
            let info = vm.debug_frame_info(frame).unwrap();
            assert_eq!(info.name, b"m");
            assert_eq!(info.namewhat, expected_namewhat);
            vm.abort_external(token).unwrap();
            vm.remove_root(table_root).unwrap();
        }
    }
}

#[test]
fn debug_adapter_official_self_and_explicit_field_names() {
    fn abc(opcode: u32, a: u32, b: u32, c: u32, k: bool) -> u32 {
        opcode | (a << 7) | (u32::from(k) << 15) | (b << 16) | (c << 24)
    }

    for (profile, fixture) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-fixed-entry.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-fixed-entry.luac").as_slice(),
        ),
    ] {
        for (self_call, expected_namewhat) in [(true, b"method".as_slice()), (false, b"field")] {
            let mut chunk =
                decode_official_chunk(fixture, profile, &OfficialChunkLimits::default()).unwrap();
            let child = &mut chunk.main;
            child.max_stack_size = 5;
            child.constants = vec![rivetlua_core::OfficialConstant::String {
                bytes: b"m".to_vec(),
                long: false,
            }];
            child.code = if self_call {
                vec![
                    abc(0, 4, 1, 0, false),
                    abc(20, 2, 0, 0, profile == LuaProfile::Lua54),
                    abc(68, 2, 3, 2, false),
                    abc(72, 2, 0, 0, false),
                ]
            } else {
                vec![
                    abc(0, 4, 1, 0, false),
                    abc(14, 2, 0, 0, false),
                    abc(0, 3, 0, 0, false),
                    abc(68, 2, 3, 2, false),
                    abc(72, 2, 0, 0, false),
                ]
            };
            child.debug.line_info = vec![0; child.code.len()];
            child.debug.abs_line_info.clear();
            for local in &mut child.debug.locals {
                local.end_pc = child.code.len() as u32;
            }
            let bytes = rivetlua_core::encode_official_chunk(
                &chunk,
                false,
                &OfficialChunkLimits::default(),
            )
            .unwrap();
            let decoded =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            let module = translate_official_chunk(&decoded, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            let mut vm = Vm::new_with_profile(profile).unwrap();
            let environment = vm.allocate_table().unwrap();
            let env_root = vm.add_root(RootKind::Host, environment).unwrap();
            let table = vm.allocate_table().unwrap();
            let table_root = vm.add_root(RootKind::Host, table).unwrap();
            let method = HostFunctionId::new_unique(vm.id()).unwrap();
            let key = vm.allocate_byte_string(b"m").unwrap();
            vm.raw_set(table, Value::Object(key), Value::CFunction(method))
                .unwrap();
            let token = {
                let mut execution = vm
                    .load_with_environment_and_args(
                        module,
                        Value::Object(environment),
                        &[Value::Object(table), Value::Integer(41)],
                    )
                    .unwrap();
                let RunOutcome::External(token) = execution.run().unwrap() else {
                    panic!("official C callback 應停放")
                };
                token
            };
            let frame = vm.debug_frame_external(token, 0).unwrap().unwrap();
            let info = vm.debug_frame_info(frame).unwrap();
            assert_eq!(info.name, b"m");
            assert_eq!(info.namewhat, expected_namewhat);
            vm.abort_external(token).unwrap();
            vm.remove_root(table_root).unwrap();
            vm.remove_root(env_root).unwrap();
        }
    }
}

#[test]
fn debug_adapter_c_lua_c_stack_order_and_stale_external_handle() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"inner").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(inner))
            .unwrap();
        let module = compile(
            b"return function(x) local saved = x; local result = inner(saved); return result end",
            profile,
        );
        let function = {
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 Lua closure")
            };
            values[0]
        };
        let function_root = match function {
            Value::Object(object) => Some(vm.add_root(RootKind::Host, object).unwrap()),
            _ => panic!("應取得 Lua closure"),
        };
        let outer_token = parked(&mut vm, outer);
        let outer_handle = vm.debug_frame_external(outer_token, 0).unwrap().unwrap();
        assert_eq!(
            vm.debug_frame_info(outer_handle).unwrap().kind,
            DebugFrameKind::C
        );
        let nested = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: function,
                    args: vec![Value::Integer(17)],
                    results: ResultMode::All,
                },
            )
            .unwrap();
        let RunOutcome::External(inner_token) = nested else {
            panic!("內層 C callback 應停放")
        };
        let kinds: Vec<_> = (0..3)
            .map(|level| {
                let handle = vm
                    .debug_frame_external(inner_token, level)
                    .unwrap()
                    .unwrap();
                vm.debug_frame_info(handle).unwrap().kind
            })
            .collect();
        assert_eq!(
            kinds,
            [DebugFrameKind::C, DebugFrameKind::Lua, DebugFrameKind::C]
        );
        let inner_info = vm
            .debug_frame_info(vm.debug_frame_external(inner_token, 0).unwrap().unwrap())
            .unwrap();
        assert_eq!(inner_info.name, b"inner");
        assert!(!inner_info.namewhat.is_empty());
        assert!(vm.debug_frame_info(outer_handle).is_err());
        let lua = vm.debug_frame_external(inner_token, 1).unwrap().unwrap();
        let local = vm.debug_local_read(lua, 1).unwrap().unwrap();
        assert_eq!(local.value, Value::Integer(17));
        assert_eq!(
            vm.continue_external(
                inner_token,
                ExternalCommand::Return(vec![Value::Integer(20)])
            ),
            Ok(RunOutcome::NestedReturned(vec![Value::Integer(20)]))
        );
        assert!(vm.debug_frame_info(lua).is_err());
        assert!(vm.debug_frame_info(outer_handle).is_err());
        let fresh_outer = vm.debug_frame_external(outer_token, 0).unwrap().unwrap();
        assert_eq!(
            vm.debug_frame_info(fresh_outer).unwrap().kind,
            DebugFrameKind::C
        );
        assert_eq!(
            vm.continue_external(outer_token, ExternalCommand::Return(vec![])),
            Ok(RunOutcome::Returned(vec![]))
        );
        assert!(vm.debug_frame_info(outer_handle).is_err());
        vm.remove_root(function_root.unwrap()).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_outer_handle_stays_stale_after_nested_abort_and_start_rollback() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let outer = HostFunctionId::new_unique(vm.id()).unwrap();
        let inner = HostFunctionId::new_unique(vm.id()).unwrap();
        let outer_token = parked(&mut vm, outer);
        let before_abort = vm.debug_frame_external(outer_token, 0).unwrap().unwrap();
        let nested = vm
            .continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![],
                    results: ResultMode::All,
                },
            )
            .unwrap();
        let RunOutcome::External(inner_token) = nested else {
            panic!("內層 C callback 應停放")
        };
        vm.abort_external_nested_callback(inner_token).unwrap();
        assert!(vm.debug_frame_info(before_abort).is_err());
        let before_failure = vm.debug_frame_external(outer_token, 0).unwrap().unwrap();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(
            vm.continue_external(
                outer_token,
                ExternalCommand::NestedCall {
                    target: Value::CFunction(inner),
                    args: vec![Value::Integer(1)],
                    results: ResultMode::All,
                },
            )
            .is_err()
        );
        assert!(vm.debug_frame_info(before_failure).is_err());
        assert_eq!(
            vm.debug_frame_info(vm.debug_frame_external(outer_token, 0).unwrap().unwrap())
                .unwrap()
                .kind,
            DebugFrameKind::C
        );
        vm.abort_external(outer_token).unwrap();
    }
}

#[test]
fn debug_adapter_main_frame_retains_real_function_identity() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"host").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(callback))
            .unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment(
                    compile(b"local answer = host(); return answer", profile),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("主 chunk 的 C callback 應停放")
            };
            token
        };
        let main = vm.debug_frame_external(token, 1).unwrap().unwrap();
        let first = vm.debug_frame_info(main).unwrap();
        let second = vm.debug_frame_info(main).unwrap();
        assert_eq!(first.kind, DebugFrameKind::Main);
        assert!(matches!(first.function, Value::Object(_)));
        assert_eq!(first.function, second.function);
        let function_only = vm.debug_function_info(first.function).unwrap();
        assert_eq!(function_only.function, first.function);
        assert_eq!(function_only.kind, DebugFrameKind::Main);
        assert_eq!(
            vm.continue_external(token, ExternalCommand::Return(vec![Value::Integer(8)])),
            Ok(RunOutcome::Returned(vec![Value::Integer(8)]))
        );
        assert!(vm.debug_frame_info(main).is_err());
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_function_info_and_suspended_coroutine_local_transaction() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let module = compile(
            b"return function(first, ...) local hold = first; coroutine.yield(hold); return hold, ... end",
            profile,
        );
        let function = {
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 Lua closure")
            };
            values[0]
        };
        let info = vm.debug_function_info(function).unwrap();
        assert_eq!(info.kind, DebugFrameKind::Lua);
        assert_eq!(info.nparams, 1);
        assert!(info.isvararg);
        assert!(!info.source.is_empty());
        assert!(!info.short_source.is_empty());
        assert!(info.linedefined >= 0);
        assert!(info.lastlinedefined >= info.linedefined);
        assert!(!info.active_lines.is_empty());
        let co = vm.new_coroutine(function).unwrap().as_value(&vm).unwrap();
        let Value::Object(co) = co else {
            panic!("應取得 coroutine")
        };
        let co_root = vm.add_root(RootKind::Host, co).unwrap();
        let mut execution = vm
            .resume(Value::Object(co), &[Value::Integer(9), Value::Integer(11)])
            .unwrap();
        assert_eq!(
            execution.run().unwrap(),
            RunOutcome::Returned(vec![Value::Boolean(true), Value::Integer(9)])
        );
        drop(execution);
        let frame = vm.debug_frame_coroutine(co, 0).unwrap().unwrap();
        assert!(vm.debug_frame_coroutine(co, usize::MAX).unwrap().is_none());
        assert_eq!(
            vm.debug_frame_info(frame).unwrap().kind,
            DebugFrameKind::Lua
        );
        assert_eq!(
            vm.debug_local_read(frame, -1).unwrap().unwrap().value,
            Value::Integer(11)
        );
        let original = vm.debug_local_read(frame, 1).unwrap().unwrap();
        let object = vm.allocate_table().unwrap();
        let ledger = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::RootReserve);
        assert!(
            vm.debug_local_write(frame, 1, Value::Object(object))
                .is_err()
        );
        assert_eq!(
            vm.debug_local_read(frame, 1).unwrap().unwrap().value,
            original.value
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.ledger_snapshot().committed, ledger.committed);
        assert!(
            vm.debug_local_write(frame, 999, Value::Object(object))
                .unwrap()
                .is_none()
        );
        assert_eq!(
            vm.debug_local_read(frame, 1).unwrap().unwrap().value,
            original.value
        );
        assert!(
            vm.debug_local_write(frame, 1, Value::Object(object))
                .unwrap()
                .is_some()
        );
        vm.collect_major().unwrap();
        assert_eq!(
            vm.debug_local_read(frame, 1).unwrap().unwrap().value,
            Value::Object(object)
        );
        let mut resume = vm.resume(Value::Object(co), &[]).unwrap();
        let _ = resume.run().unwrap();
        drop(resume);
        assert!(vm.debug_frame_info(frame).is_err());
        vm.remove_root(co_root).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_hook_frame_and_snapshot_allocation_rollback() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.debug_set_hook(
            None,
            Some(DebugHookConfig {
                function: hook,
                call: true,
                ret: true,
                line: true,
                count: 1,
            }),
        )
        .unwrap();
        assert_eq!(vm.debug_get_hook(None).unwrap().unwrap().function, hook);
        let module = compile(
            b"local function add_one(x) return x + 1 end; local answer = add_one(3); return answer",
            profile,
        );
        let mut outcome = {
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            execution.run().unwrap()
        };
        let (token, hooked) = (0..32)
            .find_map(|_| {
                let RunOutcome::External(token) = outcome else {
                    return None;
                };
                if let Some(handle) = vm.debug_hook_frame(token).unwrap() {
                    return Some((token, handle));
                }
                outcome = vm
                    .continue_external(token, ExternalCommand::Return(vec![]))
                    .unwrap();
                None
            })
            .expect("應觸發 Lua frame 的 C hook");
        let info = vm.debug_frame_info(hooked).unwrap();
        assert_eq!(info.kind, DebugFrameKind::Main);
        assert!(info.currentline >= 0);
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(vm.debug_frame_info(hooked).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert!(vm.debug_frame_info(hooked).is_ok());
        vm.abort_external(token).unwrap();
        vm.debug_set_hook(None, None).unwrap();
        assert!(vm.debug_get_hook(None).unwrap().is_none());
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_hook_transfer_and_current_pc_without_visible_hook_frame() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.inject_failure_once(FailPoint::RootReserve);
        assert!(
            vm.debug_set_hook(
                None,
                Some(DebugHookConfig {
                    function: hook,
                    call: true,
                    ret: true,
                    line: false,
                    count: 0,
                }),
            )
            .is_err()
        );
        assert!(vm.debug_get_hook(None).unwrap().is_none());
        vm.debug_set_hook(
            None,
            Some(DebugHookConfig {
                function: hook,
                call: true,
                ret: true,
                line: false,
                count: 0,
            }),
        )
        .unwrap();
        let module = compile(
            b"local function add_one(x) return x + 1 end; local answer = add_one(6); return answer",
            profile,
        );
        let mut outcome = {
            let mut execution = vm
                .load_with_environment(module, Value::Object(environment))
                .unwrap();
            execution.run().unwrap()
        };
        let mut saw_transfer = false;
        let mut saw_named_callee = false;
        for _ in 0..32 {
            let RunOutcome::External(token) = outcome else {
                break;
            };
            if let Some(handle) = vm.debug_hook_frame(token).unwrap() {
                let visible = vm.debug_frame_external(token, 0).unwrap().unwrap();
                let info = vm.debug_frame_info(handle).unwrap();
                let ordinary = vm.debug_frame_info(visible).unwrap();
                assert_ne!(ordinary.kind, DebugFrameKind::C);
                assert_eq!(ordinary.currentline, info.currentline);
                assert_eq!(
                    (ordinary.ftransfer, ordinary.ntransfer),
                    (info.ftransfer, info.ntransfer)
                );
                assert_eq!(
                    vm.debug_local_read(visible, 1)
                        .unwrap()
                        .map(|local| local.name),
                    vm.debug_local_read(handle, 1)
                        .unwrap()
                        .map(|local| local.name)
                );
                assert_ne!(info.namewhat, b"hook");
                assert!(info.currentline >= -1);
                if info.ntransfer > 0 {
                    assert!(info.ftransfer >= 1);
                    saw_transfer = true;
                    if info.kind == DebugFrameKind::Lua {
                        assert_eq!(info.name, b"add_one");
                        assert!(!info.namewhat.is_empty());
                        saw_named_callee = true;
                    }
                }
            }
            outcome = vm
                .continue_external(token, ExternalCommand::Return(vec![]))
                .unwrap();
        }
        assert!(saw_transfer, "{profile:?} 的 hook 未保留 transfer metadata");
        assert!(saw_named_callee, "{profile:?} 的具名 callee 未保留來源名稱");
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(7)]));
        vm.debug_set_hook(None, None).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_line_hook_reports_pending_instruction_line() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.debug_set_hook(
            None,
            Some(DebugHookConfig {
                function: hook,
                call: false,
                ret: false,
                line: true,
                count: 0,
            }),
        )
        .unwrap();
        let mut outcome = {
            let mut execution = vm
                .load_with_environment(
                    compile(b"local x = 1\nx = x + 1\nreturn x", profile),
                    Value::Object(environment),
                )
                .unwrap();
            execution.run().unwrap()
        };
        let mut checked = 0;
        for _ in 0..32 {
            let RunOutcome::External(token) = outcome else {
                break;
            };
            let event = vm.external_event(token).unwrap();
            let is_line = matches!(event.args.first(), Some(Value::Object(object)) if vm.with_byte_string(*object, |text| text.as_bytes() == b"line").unwrap());
            let event_line = match event.args.get(1) {
                Some(Value::Integer(line)) => Some(*line),
                _ => None,
            };
            if is_line {
                if let (Some(handle), Some(event_line)) =
                    (vm.debug_hook_frame(token).unwrap(), event_line)
                {
                    let info = vm.debug_frame_info(handle).unwrap();
                    let ordinary = vm
                        .debug_frame_info(vm.debug_frame_external(token, 0).unwrap().unwrap())
                        .unwrap();
                    assert_eq!(info.currentline, event_line, "{profile:?}");
                    assert_eq!(ordinary.currentline, info.currentline, "{profile:?}");
                    assert!(info.active_lines.contains(&(event_line as u32)));
                    checked += 1;
                }
            }
            outcome = vm
                .continue_external(token, ExternalCommand::Return(vec![]))
                .unwrap();
        }
        assert!(checked >= 2, "{profile:?} 應至少檢查兩個 line 事件");
        assert_eq!(outcome, RunOutcome::Returned(vec![Value::Integer(2)]));
        vm.debug_set_hook(None, None).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_coroutine_hook_keeps_c_closure_alive_until_cancelled() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = {
            let mut execution = vm
                .load(compile(b"return function() return 1 end", profile))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 Lua coroutine 入口")
            };
            values[0]
        };
        let coroutine = vm.new_coroutine(function).unwrap().as_value(&vm).unwrap();
        let Value::Object(coroutine) = coroutine else {
            panic!("應建立 coroutine")
        };
        let coroutine_root = vm.add_root(RootKind::Host, coroutine).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Integer(5)],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.debug_set_hook(
            Some(coroutine),
            Some(DebugHookConfig {
                function: hook,
                call: true,
                ret: false,
                line: false,
                count: 3,
            }),
        )
        .unwrap();
        assert_eq!(vm.debug_function_info(Value::Object(hook)).unwrap().nups, 1);
        vm.collect_major().unwrap();
        assert_eq!(
            vm.object_kind(hook),
            Ok(rivetlua_runtime::ObjectKind::CClosure)
        );
        let config = vm.debug_get_hook(Some(coroutine)).unwrap().unwrap();
        assert_eq!(config.function, hook);
        assert_eq!(config.count, 3);
        vm.debug_set_hook(Some(coroutine), None).unwrap();
        vm.collect_major().unwrap();
        assert_eq!(
            vm.object_kind(hook),
            Err(rivetlua_runtime::VmError::StaleObject)
        );
        vm.remove_root(coroutine_root).unwrap();
    }
}

#[test]
fn debug_adapter_function_parameter_names_are_metadata_only_and_transactional() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let function = {
            let mut execution = vm
                .load(compile(
                    b"return function(first, second, ...) return first end",
                    profile,
                ))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立帶名稱參數的 closure")
            };
            values[0]
        };
        let root = match function {
            Value::Object(object) => vm.add_root(RootKind::Host, object).unwrap(),
            _ => panic!("應為 Lua closure"),
        };
        assert_eq!(
            vm.debug_function_parameter_name(function, 1)
                .unwrap()
                .unwrap()
                .name,
            b"first"
        );
        assert_eq!(
            vm.debug_function_parameter_name(function, 2)
                .unwrap()
                .unwrap()
                .name,
            b"second"
        );
        for index in [0, -1, 3, 99] {
            assert!(
                vm.debug_function_parameter_name(function, index)
                    .unwrap()
                    .is_none()
            );
        }
        let c = Value::CFunction(HostFunctionId::new_unique(vm.id()).unwrap());
        assert!(vm.debug_function_parameter_name(c, 1).unwrap().is_none());
        let environment = vm.allocate_table().unwrap();
        vm.install_basic_builtins(environment).unwrap();
        let type_key = vm.allocate_byte_string(b"type").unwrap();
        let builtin = vm.raw_get(environment, Value::Object(type_key)).unwrap();
        assert!(
            vm.debug_function_parameter_name(builtin, 1)
                .unwrap()
                .is_none()
        );
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::WorkReserve);
        assert!(vm.debug_function_parameter_name(function, 1).is_err());
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert_eq!(
            vm.debug_function_parameter_name(function, 1)
                .unwrap()
                .unwrap()
                .name,
            b"first"
        );
        vm.remove_root(root).unwrap();
    }
}

#[test]
fn debug_adapter_external_initializer_temporary_has_exact_bounds_and_rooted_write() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let host = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"host").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(host))
            .unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local function g(a,b) return (a+1)+host() end; return g(0,0)",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("g 的 C callee 應停放")
            };
            token
        };
        let caller = vm.debug_frame_external(token, 1).unwrap().unwrap();
        assert_eq!(
            vm.debug_local_read(caller, 1).unwrap().unwrap().value,
            Value::Integer(0)
        );
        assert_eq!(
            vm.debug_local_read(caller, 2).unwrap().unwrap().value,
            Value::Integer(0)
        );
        let temporary = vm.debug_local_read(caller, 3).unwrap().unwrap();
        assert_eq!(temporary.name, b"(temporary)");
        assert_eq!(temporary.value, Value::Integer(1));
        assert!(vm.debug_local_read(caller, 4).unwrap().is_none());
        assert!(
            vm.debug_local_write(caller, 4, Value::Integer(99))
                .unwrap()
                .is_none()
        );
        let object = vm.allocate_table().unwrap();
        let before = vm.ledger_snapshot();
        vm.inject_failure_once(FailPoint::RootReserve);
        assert!(
            vm.debug_local_write(caller, 3, Value::Object(object))
                .is_err()
        );
        assert_eq!(
            vm.debug_local_read(caller, 3).unwrap().unwrap().value,
            temporary.value
        );
        assert_eq!(vm.ledger_snapshot().reserved, 0);
        assert_eq!(vm.ledger_snapshot().committed, before.committed);
        assert!(
            vm.debug_local_write(caller, 3, Value::Object(object))
                .unwrap()
                .is_some()
        );
        vm.collect_major().unwrap();
        assert_eq!(
            vm.debug_local_read(caller, 3).unwrap().unwrap().value,
            Value::Object(object)
        );
        vm.abort_external(token).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_line_hook_exposes_initializer_temporary_before_local_activation() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.debug_set_hook(
            None,
            Some(DebugHookConfig {
                function: hook,
                call: false,
                ret: false,
                line: true,
                count: 0,
            }),
        )
        .unwrap();
        let mut outcome = {
            let mut execution = vm
                .load(compile(
                    b"local A = function() return 7 end\nreturn A()",
                    profile,
                ))
                .unwrap();
            execution.run().unwrap()
        };
        let mut observed = false;
        for _ in 0..32 {
            let RunOutcome::External(token) = outcome else {
                break;
            };
            let event = vm.external_event(token).unwrap();
            let line_one = matches!(event.args.get(1), Some(Value::Integer(1)));
            if line_one {
                let frame = vm.debug_hook_frame(token).unwrap().unwrap();
                let first = vm.debug_local_read(frame, 1).unwrap().unwrap();
                assert_eq!(first.name, b"(temporary)", "{profile:?}");
                assert_eq!(first.value, Value::Nil);
                assert!(vm.debug_local_read(frame, 2).unwrap().is_none());
                observed = true;
                vm.abort_external(token).unwrap();
                break;
            }
            outcome = vm
                .continue_external(token, ExternalCommand::Return(vec![]))
                .unwrap();
        }
        assert!(observed, "{profile:?} 應觀察到初始化前 line hook");
        vm.debug_set_hook(None, None).unwrap();
    }
}

#[test]
fn debug_adapter_suspended_caller_uses_yield_call_temporary_pc() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let function = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"local function f() coroutine.yield('inside'); return 20 end; return function(a,b) return (a+1)+f() end",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 coroutine 入口")
            };
            values[0]
        };
        let co = vm.new_coroutine(function).unwrap().as_value(&vm).unwrap();
        let Value::Object(co) = co else {
            panic!("應建立 coroutine")
        };
        let co_root = vm.add_root(RootKind::Host, co).unwrap();
        let mut execution = vm
            .resume(Value::Object(co), &[Value::Integer(0), Value::Integer(0)])
            .unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("應由 f yield")
        };
        assert_eq!(values[0], Value::Boolean(true));
        drop(execution);
        let caller = vm.debug_frame_coroutine(co, 1).unwrap().unwrap();
        let temporary = vm.debug_local_read(caller, 3).unwrap().unwrap();
        assert_eq!(temporary.name, b"(temporary)");
        assert_eq!(temporary.value, Value::Integer(1));
        assert!(vm.debug_local_read(caller, 4).unwrap().is_none());
        let object = vm.allocate_table().unwrap();
        assert!(
            vm.debug_local_write(caller, 3, Value::Object(object))
                .unwrap()
                .is_some()
        );
        vm.collect_major().unwrap();
        assert_eq!(
            vm.debug_local_read(caller, 3).unwrap().unwrap().value,
            Value::Object(object)
        );
        vm.remove_root(co_root).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_suspended_yield_initializer_hides_callee_and_arguments() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        vm.install_coroutine_builtins(environment).unwrap();
        let function = {
            let mut execution = vm
                .load_with_environment(
                    compile(
                        b"return function() local value = coroutine.yield('inside'); return value end",
                        profile,
                    ),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 coroutine 入口")
            };
            values[0]
        };
        let co = vm.new_coroutine(function).unwrap().as_value(&vm).unwrap();
        let Value::Object(co) = co else {
            panic!("應建立 coroutine")
        };
        let co_root = vm.add_root(RootKind::Host, co).unwrap();
        let mut execution = vm.resume(Value::Object(co), &[]).unwrap();
        let RunOutcome::Returned(values) = execution.run().unwrap() else {
            panic!("應暫停於 yield")
        };
        assert_eq!(values[0], Value::Boolean(true));
        drop(execution);
        let frame = vm.debug_frame_coroutine(co, 0).unwrap().unwrap();
        let first = vm.debug_local_read(frame, 1).unwrap().unwrap();
        assert_eq!(first.name, b"(temporary)", "{profile:?}");
        assert_eq!(first.value, Value::Nil);
        assert!(vm.debug_local_read(frame, 2).unwrap().is_none());
        vm.remove_root(co_root).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_official_fixtures_expose_info_parameter_and_root_vararg() {
    for (profile, fixed, root_varargs) in [
        (
            LuaProfile::Lua54,
            include_bytes!("official_chunk_fixtures/lua54-fixed-entry.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua54-root-varargs.luac").as_slice(),
        ),
        (
            LuaProfile::Lua55,
            include_bytes!("official_chunk_fixtures/lua55-fixed-entry.luac").as_slice(),
            include_bytes!("official_chunk_fixtures/lua55-root-varargs.luac").as_slice(),
        ),
    ] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let fixed = decode_official_chunk(fixed, profile, &OfficialChunkLimits::default()).unwrap();
        let fixed = translate_official_chunk(&fixed, &VerifyLimits::default()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let callback = HostFunctionId::new_unique(vm.id()).unwrap();
        let hook = vm
            .prepare_unpublished_c_closure::<rivetlua_runtime::VmError>(
                callback,
                &[Value::Nil],
                |_, _| Ok(()),
                |_, root| drop(root),
            )
            .unwrap();
        vm.debug_set_hook(
            None,
            Some(DebugHookConfig {
                function: hook,
                call: true,
                ret: false,
                line: true,
                count: 1,
            }),
        )
        .unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment_and_args(
                    fixed.verified().clone(),
                    Value::Object(environment),
                    &[Value::Integer(31), Value::Integer(41)],
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("fixed-entry call hook 應停放")
            };
            token
        };
        let frame = vm.debug_frame_external(token, 0).unwrap().unwrap();
        let info = vm.debug_frame_info(frame).unwrap();
        assert_eq!(info.kind, DebugFrameKind::Lua);
        assert!(!info.source.is_empty());
        assert_eq!(
            vm.debug_function_parameter_name(info.function, 1)
                .unwrap()
                .unwrap()
                .name,
            b"a"
        );
        assert_eq!(vm.debug_local_read(frame, 1).unwrap().unwrap().name, b"a");
        assert_eq!(
            vm.debug_local_read(frame, 1).unwrap().unwrap().value,
            Value::Integer(31)
        );
        vm.abort_external(token).unwrap();
        vm.remove_root(env_root).unwrap();

        let root_varargs =
            decode_official_chunk(root_varargs, profile, &OfficialChunkLimits::default()).unwrap();
        let root_varargs =
            translate_official_chunk(&root_varargs, &VerifyLimits::default()).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let token = {
            let mut execution = vm
                .load_with_environment_and_args(
                    root_varargs.verified().clone(),
                    Value::Object(environment),
                    &[Value::Integer(73)],
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("root-varargs call hook 應停放")
            };
            token
        };
        let frame = vm.debug_frame_external(token, 0).unwrap().unwrap();
        assert_eq!(
            vm.debug_frame_info(frame).unwrap().kind,
            DebugFrameKind::Main
        );
        assert_eq!(
            vm.debug_local_read(frame, -1).unwrap().unwrap().value,
            Value::Integer(73)
        );
        vm.abort_external(token).unwrap();
        vm.debug_set_hook(None, None).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_tail_called_main_keeps_main_kind_and_tail_flag() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let environment = vm.allocate_table().unwrap();
        let env_root = vm.add_root(RootKind::Host, environment).unwrap();
        let host = HostFunctionId::new_unique(vm.id()).unwrap();
        let key = vm.allocate_byte_string(b"host").unwrap();
        vm.raw_set(environment, Value::Object(key), Value::CFunction(host))
            .unwrap();
        let target_token = {
            let mut execution = vm
                .load_with_environment(
                    compile(b"return host()", profile),
                    Value::Object(environment),
                )
                .unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("主 chunk 應停放")
            };
            token
        };
        let target = vm
            .debug_frame_info(vm.debug_frame_external(target_token, 1).unwrap().unwrap())
            .unwrap()
            .function;
        let Value::Object(target_object) = target else {
            panic!("主 chunk 須為 closure")
        };
        let target_root = vm.add_root(RootKind::Host, target_object).unwrap();
        vm.abort_external(target_token).unwrap();
        let wrapper = {
            let mut execution = vm
                .load(compile(b"return function(f) return f() end", profile))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立 tail caller")
            };
            values[0]
        };
        let token = {
            let mut execution = vm.call(wrapper, &[target]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("尾呼叫主 chunk 應停放")
            };
            token
        };
        let main = vm.debug_frame_external(token, 1).unwrap().unwrap();
        let info = vm.debug_frame_info(main).unwrap();
        assert_eq!(info.kind, DebugFrameKind::Main);
        assert!(info.istailcall);
        vm.abort_external(token).unwrap();
        vm.remove_root(target_root).unwrap();
        vm.remove_root(env_root).unwrap();
    }
}

#[test]
fn debug_adapter_tail_called_external_c_reports_tail_flag() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let mut vm = Vm::new_with_profile(profile).unwrap();
        let host = HostFunctionId::new_unique(vm.id()).unwrap();
        let wrapper = {
            let mut execution = vm
                .load(compile(b"return function(f) return f() end", profile))
                .unwrap();
            let RunOutcome::Returned(values) = execution.run().unwrap() else {
                panic!("應建立尾呼叫 Lua closure")
            };
            values[0]
        };
        let token = {
            let mut execution = vm.call(wrapper, &[Value::CFunction(host)]).unwrap();
            let RunOutcome::External(token) = execution.run().unwrap() else {
                panic!("C callback 應由 Lua TailCall 停放")
            };
            token
        };
        let frame = vm.debug_frame_external(token, 0).unwrap().unwrap();
        let info = vm.debug_frame_info(frame).unwrap();
        assert_eq!(info.kind, DebugFrameKind::C);
        assert!(info.istailcall);
        vm.abort_external(token).unwrap();
        assert!(vm.debug_frame_info(frame).is_err());
    }
}
