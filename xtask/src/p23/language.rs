use super::harness::{CaseOutcome, HarnessLimits};
use rivetlua::{
    CompileBudget, CompileBudgetLimits, CompileError, CompileLimits, Engine, IrLimits, VerifyLimits,
};
use rivetlua_compiler::{DiagnosticCode, LanguageProfile, Stmt, lex, parse};
use rivetlua_core::LuaProfile;

fn input_is_bounded(input: &[u8], limits: &HarnessLimits) -> bool {
    limits.max_input_bytes > 0
        && limits.max_depth > 0
        && limits.fuel > 0
        && limits.heap_bytes > 0
        && input.len() <= limits.max_input_bytes
        && input.len() <= limits.heap_bytes
}

fn bounded_limits(
    limits: &HarnessLimits,
) -> (CompileLimits, IrLimits, VerifyLimits) {
    let work = usize::try_from(limits.fuel).unwrap_or(usize::MAX);
    let bytes = limits.max_input_bytes.min(limits.heap_bytes);

    let mut compile = CompileLimits::default();
    compile.max_source_bytes = compile.max_source_bytes.min(bytes);
    compile.max_token_bytes = compile.max_token_bytes.min(bytes);
    compile.max_tokens = compile.max_tokens.min(work);
    compile.max_lines = compile.max_lines.min(work);
    compile.max_ast_nodes = compile.max_ast_nodes.min(work);
    compile.max_parse_depth = compile.max_parse_depth.min(limits.max_depth);
    compile.max_statements = compile.max_statements.min(work);
    compile.max_list_entries = compile.max_list_entries.min(work);
    compile.max_parameters = compile.max_parameters.min(work);
    compile.max_bindings_per_function = compile.max_bindings_per_function.min(work);
    compile.max_scope_depth = compile.max_scope_depth.min(limits.max_depth);
    compile.max_labels = compile.max_labels.min(work);
    compile.max_gotos = compile.max_gotos.min(work);
    compile.max_upvalues_per_function = compile.max_upvalues_per_function.min(work);

    let mut ir = IrLimits::default();
    ir.max_prototypes = ir.max_prototypes.min(work);
    ir.max_instructions = ir.max_instructions.min(work);
    ir.max_registers = ir
        .max_registers
        .min(u16::try_from(work).unwrap_or(u16::MAX));
    ir.max_upvalues_per_prototype = ir.max_upvalues_per_prototype.min(work);

    let mut verify = VerifyLimits::default();
    verify.max_module_bytes = verify.max_module_bytes.min(limits.heap_bytes);
    verify.max_artifact_bytes = verify.max_artifact_bytes.min(limits.heap_bytes);
    verify.max_prototypes = verify.max_prototypes.min(work);
    verify.max_instructions = verify.max_instructions.min(work);
    verify.max_constants = verify.max_constants.min(work);
    verify.max_registers = verify
        .max_registers
        .min(u16::try_from(work).unwrap_or(u16::MAX));
    verify.max_upvalues_per_prototype = verify.max_upvalues_per_prototype.min(work);

    (compile, ir, verify)
}

pub(super) fn source(
    profile: LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    if !input_is_bounded(input, limits) {
        return CaseOutcome::Limit;
    }

    let (compile_limits, ir_limits, verify_limits) = bounded_limits(limits);
    if input.len() > compile_limits.max_source_bytes {
        return CaseOutcome::Limit;
    }

    let engine = Engine::new(profile).with_limits(compile_limits, ir_limits, verify_limits);
    let budget = CompileBudget::new(CompileBudgetLimits {
        max_work: limits.fuel,
        max_allocation_bytes: limits.heap_bytes,
    });

    match engine.compile_named_with_budget(input, b"=(p23-fz001)", &budget) {
        Ok(_) => CaseOutcome::Accepted,
        Err(CompileError::Budget(_) | CompileError::AdmissionOverflow) => CaseOutcome::Limit,
        Err(CompileError::AdmissionUnderestimated) => {
            CaseOutcome::Finding("FZ001_BUDGET_INVARIANT")
        }
        Err(CompileError::Diagnostic(diagnostic))
            if diagnostic.code == DiagnosticCode::CompileLimit =>
        {
            CaseOutcome::Limit
        }
        Err(_) => CaseOutcome::Rejected,
    }
}

pub(super) fn ast(
    profile: LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    if !input_is_bounded(input, limits) {
        return CaseOutcome::Limit;
    }

    let (compile_limits, ir_limits, verify_limits) = bounded_limits(limits);
    if input.len() > compile_limits.max_source_bytes {
        return CaseOutcome::Limit;
    }

    let lexed = match lex(input, profile, &compile_limits) {
        Ok(lexed) => lexed,
        Err(diagnostic) if diagnostic.code == DiagnosticCode::CompileLimit => {
            return CaseOutcome::Limit;
        }
        Err(_) => return CaseOutcome::Rejected,
    };
    let parsed = match parse(&lexed, profile, &compile_limits) {
        Ok(parsed) => parsed,
        Err(diagnostic) if diagnostic.code == DiagnosticCode::CompileLimit => {
            return CaseOutcome::Limit;
        }
        Err(_) => return CaseOutcome::Rejected,
    };

    let mut mutated = parsed.clone();
    mutated.profile = match profile {
        LanguageProfile::Lua54 => LanguageProfile::Lua55,
        LanguageProfile::Lua55 => LanguageProfile::Lua54,
    };
    if rivetlua_compiler::resolve::resolve(&mutated, &lexed, profile, &compile_limits).is_ok() {
        return CaseOutcome::Finding("FZ002_PROFILE_VALIDATION");
    }
    mutated.profile = profile;

    mutated.span.end_byte = lexed.source_len.saturating_add(1);
    if rivetlua_compiler::resolve::resolve(&mutated, &lexed, profile, &compile_limits).is_ok() {
        return CaseOutcome::Finding("FZ002_MODULE_SPAN_VALIDATION");
    }
    mutated.span = parsed.span;

    let invalid_goto_span = mutated.root.span;
    mutated.root.statements.clear();
    mutated.root.statements.push(Stmt::Goto {
        name: Vec::new(),
        name_span: invalid_goto_span,
        span: invalid_goto_span,
    });
    if rivetlua_compiler::resolve::resolve(&mutated, &lexed, profile, &compile_limits).is_ok() {
        return CaseOutcome::Finding("FZ002_GOTO_BINDING_VALIDATION");
    }

    let resolved = match rivetlua_compiler::resolve::resolve(
        &parsed,
        &lexed,
        profile,
        &compile_limits,
    ) {
        Ok(resolved) => resolved,
        Err(diagnostic) if diagnostic.code == DiagnosticCode::CompileLimit => {
            return CaseOutcome::Limit;
        }
        Err(_) => return CaseOutcome::Rejected,
    };
    let ir = match rivetlua_compiler::lower(&resolved, &ir_limits) {
        Ok(ir) => ir,
        Err(_) => return CaseOutcome::Rejected,
    };
    let encoded = match rivetlua_compiler::emit(&ir, &verify_limits) {
        Ok(encoded) => encoded,
        Err(_) => return CaseOutcome::Rejected,
    };
    if encoded.verified().profile() != profile {
        return CaseOutcome::Finding("FZ002_VERIFIED_PROFILE");
    }

    CaseOutcome::Accepted
}

#[cfg(test)]
mod tests {
    use super::source;
    use crate::p23::harness::{CaseOutcome, HarnessLimits};
    use rivetlua_core::LuaProfile;

    #[test]
    fn fz001_accepts_a_small_lua55_chunk() {
        let limits = HarnessLimits {
            max_input_bytes: 1024,
            max_depth: 32,
            fuel: 1_000_000,
            heap_bytes: 1024 * 1024,
        };

        assert_eq!(
            source(LuaProfile::Lua55, b"return 1", &limits),
            CaseOutcome::Accepted
        );
    }
}
