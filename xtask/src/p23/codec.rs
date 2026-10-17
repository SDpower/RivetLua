//! P23 的 P05 bytecode 與官方 chunk fuzz oracle；不保存輸入或錯誤內容。

use rivetlua_core::{
    BytecodeError, BytecodeErrorCode, OfficialChunkError, OfficialChunkErrorKind,
    OfficialChunkLimits, OfficialTranslationError, OfficialTranslationErrorKind,
    OfficialWorkBudget, RVLU_MAGIC, RVLU_V2, VerifiedModule, VerifyLimits, decode_module,
    decode_official_chunk, encode_module, encode_official_chunk, preflight_official_chunk,
    translate_official_chunk_with_work,
};
use rivetlua_runtime::{AbortReason, RunOutcome, RuntimeErrorKind, Vm, VmError};

use super::harness::{CaseOutcome, HarnessLimits};

// Codec、驗證器及官方轉譯有多份同時存活的表示；限制單個 fuzz case 的放大率。
const MAX_CODEC_BYTES: usize = 256 * 1024;
const MAX_OFFICIAL_BYTES: usize = 64 * 1024;
const MAX_PROTOTYPES: usize = 128;
const MAX_INSTRUCTIONS: usize = 4_096;
const MAX_CONSTANTS: usize = 4_096;

fn verify_limits(limits: &HarnessLimits, byte_cap: usize) -> VerifyLimits {
    let mut result = VerifyLimits::default();
    result.max_module_bytes = byte_cap;
    result.max_artifact_bytes = byte_cap;
    result.max_prototypes = result.max_prototypes.min(MAX_PROTOTYPES);
    result.max_instructions = result
        .max_instructions
        .min(MAX_INSTRUCTIONS)
        .min(usize::try_from(limits.fuel).unwrap_or(usize::MAX));
    result.max_constants = result.max_constants.min(MAX_CONSTANTS);
    result.max_registers = result.max_registers.min(256);
    result
}

fn byte_cap(limits: &HarnessLimits, fixed_cap: usize) -> usize {
    limits
        .max_input_bytes
        .min(fixed_cap)
        .min(limits.heap_bytes / 8)
}

fn bytecode_failure(error: BytecodeError) -> CaseOutcome {
    match error.code {
        BytecodeErrorCode::Verify => CaseOutcome::Rejected,
        BytecodeErrorCode::CompileLimit | BytecodeErrorCode::AllocationFailed => CaseOutcome::Limit,
    }
}

fn canonical_encode_failure(error: BytecodeError) -> CaseOutcome {
    match error.code {
        BytecodeErrorCode::Verify => CaseOutcome::Finding("P05_CANONICAL_VERIFY_FAILED"),
        BytecodeErrorCode::CompileLimit | BytecodeErrorCode::AllocationFailed => CaseOutcome::Limit,
    }
}

fn official_failure(error: OfficialChunkError) -> CaseOutcome {
    match error.kind {
        OfficialChunkErrorKind::Truncated | OfficialChunkErrorKind::InvalidFormat => {
            CaseOutcome::Rejected
        }
        OfficialChunkErrorKind::LimitExceeded
        | OfficialChunkErrorKind::Overflow
        | OfficialChunkErrorKind::AllocationFailed
        | OfficialChunkErrorKind::WorkExhausted => CaseOutcome::Limit,
    }
}

fn official_encode_failure(error: OfficialChunkError) -> CaseOutcome {
    match error.kind {
        OfficialChunkErrorKind::Truncated | OfficialChunkErrorKind::InvalidFormat => {
            CaseOutcome::Finding("OFFICIAL_ENCODE_FAILED")
        }
        _ => CaseOutcome::Limit,
    }
}

fn translation_failure(error: OfficialTranslationError) -> CaseOutcome {
    match error.kind {
        OfficialTranslationErrorKind::InvalidChunk => CaseOutcome::Rejected,
        OfficialTranslationErrorKind::LimitExceeded
        | OfficialTranslationErrorKind::AllocationFailed => CaseOutcome::Limit,
    }
}

fn runtime_failure(kind: RuntimeErrorKind) -> CaseOutcome {
    match kind {
        RuntimeErrorKind::Heap(VmError::AllocationFailed | VmError::ArithmeticOverflow)
        | RuntimeErrorKind::StackLimit => CaseOutcome::Limit,
        RuntimeErrorKind::UnsupportedFormat
        | RuntimeErrorKind::ProfileMismatch { .. }
        | RuntimeErrorKind::MissingEntryPoint
        | RuntimeErrorKind::UnsupportedInstruction(_)
        | RuntimeErrorKind::UnsupportedUnaryOperation(_)
        | RuntimeErrorKind::UnsupportedBinaryOperation(_)
        | RuntimeErrorKind::UnsupportedConstant
        | RuntimeErrorKind::UnsupportedResultMode
        | RuntimeErrorKind::RegisterOutOfBounds
        | RuntimeErrorKind::ProgramCounterOutOfBounds => {
            CaseOutcome::Finding("P05_VM_VERIFIED_INVARIANT")
        }
        _ => CaseOutcome::Accepted,
    }
}

fn canonical_roundtrip(
    verified: &VerifiedModule,
    profile: rivetlua_core::LuaProfile,
    limits: &VerifyLimits,
) -> CaseOutcome {
    let encoded = match encode_module(verified.module().clone(), profile, limits) {
        Ok(encoded) => encoded,
        Err(error) => return canonical_encode_failure(error),
    };
    let decoded = match decode_module(encoded.bytes(), profile, limits) {
        Ok(decoded) => decoded,
        Err(_) => return CaseOutcome::Finding("P05_CANONICAL_REJECTED"),
    };
    if decoded.module() != verified.module() {
        return CaseOutcome::Finding("P05_CANONICAL_CHANGED");
    }
    CaseOutcome::Accepted
}

fn run_verified(
    verified: VerifiedModule,
    profile: rivetlua_core::LuaProfile,
    limits: &HarnessLimits,
) -> CaseOutcome {
    if limits.fuel == 0 || limits.heap_bytes == 0 {
        return CaseOutcome::Limit;
    }
    let mut vm = match Vm::new_with_profile(profile) {
        Ok(vm) => vm,
        Err(_) => return CaseOutcome::Limit,
    };
    vm.set_allocation_limit(limits.heap_bytes);
    let mut execution = match vm.load(verified) {
        Ok(execution) => execution,
        Err(error) => return runtime_failure(error.kind),
    };
    if execution.set_fuel(limits.fuel).is_err() {
        return CaseOutcome::Finding("P05_FUEL_SETUP");
    }
    match execution.run() {
        Ok(RunOutcome::Aborted(AbortReason::FuelExhausted | AbortReason::OutputLimit)) => {
            CaseOutcome::Limit
        }
        Ok(_) => CaseOutcome::Accepted,
        Err(error) => runtime_failure(error.kind),
    }
}

fn rvlu(
    profile: rivetlua_core::LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
    execute: bool,
) -> CaseOutcome {
    let cap = byte_cap(limits, MAX_CODEC_BYTES);
    if input.len() > cap || limits.fuel == 0 {
        return CaseOutcome::Limit;
    }
    // FZ-004 不接受 P14 transport wrapper、RVLU v1 或官方 Lua chunk。
    let verify = verify_limits(limits, cap);
    let verified = match decode_module(input, profile, &verify) {
        Ok(verified) => verified,
        Err(error) => return bytecode_failure(error),
    };
    if verified.format_version() != RVLU_V2 || verified.profile() != profile {
        return CaseOutcome::Finding("P05_DECODE_IDENTITY");
    }
    match canonical_roundtrip(&verified, profile, &verify) {
        CaseOutcome::Accepted => {}
        other => return other,
    }
    if execute {
        run_verified(verified, profile, limits)
    } else {
        CaseOutcome::Accepted
    }
}

pub(super) fn rvlu_bytecode(
    profile: rivetlua_core::LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    rvlu(profile, input, limits, true)
}

pub(super) fn rvlu_header(
    profile: rivetlua_core::LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    if input.starts_with(b"\x1bLua")
        || (input.starts_with(&RVLU_MAGIC) && input.get(4..6) == Some(&[1, 0][..]))
    {
        return CaseOutcome::Rejected;
    }
    rvlu(profile, input, limits, false)
}

pub(super) fn official_chunk(
    profile: rivetlua_core::LuaProfile,
    input: &[u8],
    limits: &HarnessLimits,
) -> CaseOutcome {
    let cap = byte_cap(limits, MAX_OFFICIAL_BYTES);
    if input.len() > cap || limits.max_depth == 0 || limits.fuel == 0 {
        return CaseOutcome::Limit;
    }
    let verify = verify_limits(limits, cap);
    let official = OfficialChunkLimits {
        max_bytes: cap,
        max_depth: limits.max_depth.min(64),
        max_prototypes: verify.max_prototypes,
        max_instructions: verify.max_instructions,
        max_constants: verify.max_constants,
        max_upvalues: 4_096,
        max_debug_entries: 4_096,
        max_strings: 4_096,
        max_string_bytes: cap,
        max_total_string_bytes: cap,
        max_allocated_bytes: limits.heap_bytes / 2,
    };
    let preflight = match preflight_official_chunk(input, profile, &official, &verify) {
        Ok(preflight) => preflight,
        Err(error) => return official_failure(error),
    };
    let scan_work = match input.len().checked_mul(2).and_then(|n| n.checked_add(1)) {
        Some(work) => work as u64,
        None => return CaseOutcome::Limit,
    };
    let required_memory = match preflight
        .temporary_bytes
        .checked_add(preflight.retained_bytes)
    {
        Some(bytes) => bytes,
        None => return CaseOutcome::Limit,
    };
    if required_memory > limits.heap_bytes
        || preflight.decoded_bytes > official.max_allocated_bytes
        || preflight.subsequent_work > limits.fuel.saturating_sub(scan_work)
    {
        return CaseOutcome::Limit;
    }
    let chunk = match decode_official_chunk(input, profile, &official) {
        Ok(chunk) => chunk,
        Err(error) => return official_failure(error),
    };
    let mut work = OfficialWorkBudget::new(limits.fuel.saturating_sub(scan_work));
    let translated = match translate_official_chunk_with_work(&chunk, &verify, &mut work) {
        Ok(translated) => translated,
        Err(error) => return translation_failure(error),
    };
    let verified = translated.into_verified();
    match canonical_roundtrip(&verified, profile, &verify) {
        CaseOutcome::Accepted => {}
        other => return other,
    }
    // 兩種輸出各重新解碼；strip 不要求與原始 debug 資料相等。
    for strip in [false, true] {
        let encoded = match encode_official_chunk(&chunk, strip, &official) {
            Ok(bytes) => bytes,
            Err(error) => return official_encode_failure(error),
        };
        let decoded = match decode_official_chunk(&encoded, profile, &official) {
            Ok(decoded) => decoded,
            Err(_) => return CaseOutcome::Finding("OFFICIAL_ENCODE_REJECTED"),
        };
        let recoded = match encode_official_chunk(&decoded, strip, &official) {
            Ok(bytes) => bytes,
            Err(error) => return official_encode_failure(error),
        };
        if recoded != encoded {
            return CaseOutcome::Finding("OFFICIAL_ROUNDTRIP_CHANGED");
        }
        if strip {
            let mut stripped_work = OfficialWorkBudget::new(work.remaining());
            let stripped =
                match translate_official_chunk_with_work(&decoded, &verify, &mut stripped_work) {
                    Ok(translation) => translation,
                    Err(error) => return translation_failure(error),
                };
            match canonical_roundtrip(stripped.verified(), profile, &verify) {
                CaseOutcome::Accepted => {}
                other => return other,
            }
        }
    }
    run_verified(verified, profile, limits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rivetlua_core::{LuaProfile, OfficialConstant};

    #[test]
    fn rvlu_header_rejects_other_language_formats() {
        let limits = HarnessLimits {
            max_input_bytes: 1024,
            max_depth: 8,
            fuel: 100_000,
            heap_bytes: 1024 * 1024,
        };
        assert!(matches!(
            rvlu_header(rivetlua_core::LuaProfile::Lua55, b"\x1bLua", &limits),
            CaseOutcome::Rejected
        ));
        assert!(matches!(
            rvlu_header(rivetlua_core::LuaProfile::Lua55, b"RVLU\x01\x00", &limits),
            CaseOutcome::Rejected
        ));
    }

    #[test]
    fn official_nan_roundtrip_compares_encoded_bits() {
        const NAN_BITS: u64 = 0x7ff8_0000_0000_0042;
        let limits = OfficialChunkLimits::default();
        let mut chunk = decode_official_chunk(
            include_bytes!(
                "../../../crates/rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac"
            ),
            LuaProfile::Lua55,
            &limits,
        )
        .unwrap();
        chunk
            .main
            .constants
            .push(OfficialConstant::Number(f64::from_bits(NAN_BITS)));
        let encoded = encode_official_chunk(&chunk, false, &limits).unwrap();
        let decoded = decode_official_chunk(&encoded, LuaProfile::Lua55, &limits).unwrap();
        assert!(matches!(
            decoded.main.constants.last(),
            Some(OfficialConstant::Number(value)) if value.to_bits() == NAN_BITS
        ));
        assert_eq!(
            encode_official_chunk(&decoded, false, &limits).unwrap(),
            encoded
        );
    }
}
