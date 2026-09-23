//! RVLU v2 little-endian module codec；只做受限結構驗證，不含 VM 或 CFG/dataflow 驗證。

use super::{
    BinaryOperation, BytecodeVersion, EnvironmentSource, FrameLayout, Instruction,
    InstructionEffects, InstructionOffset, LuaProfile, ProtoId, RVLU_V1, RVLU_V2, Register,
    ResultMode, UnaryOperation, UpvalueId,
};

pub const RVLU_MAGIC: [u8; 4] = *b"RVLU";
pub const RVLU_NUMERIC_I64_F64: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BytecodeErrorCode {
    CompileLimit,
    Verify,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeError {
    pub code: BytecodeErrorCode,
    pub offset: usize,
    pub message: String,
}

impl core::fmt::Display for BytecodeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{} at byte {}", self.message, self.offset)
    }
}

impl std::error::Error for BytecodeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyLimits {
    pub max_module_bytes: usize,
    pub max_prototypes: usize,
    pub max_instructions: usize,
    pub max_constants: usize,
    pub max_registers: u16,
    pub max_upvalues_per_prototype: usize,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: 16 * 1024 * 1024,
            max_prototypes: 4096,
            max_instructions: 100_000,
            max_constants: 100_000,
            max_registers: 4096,
            max_upvalues_per_prototype: 255,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BytecodeSpan {
    pub start_byte: u64,
    pub end_byte: u64,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BytecodeBindingId {
    pub function: u32,
    pub ordinal: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BytecodeExitKind {
    Normal,
    Return,
    Break,
    Goto,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BytecodeUpvalueSource {
    ParentLocal(BytecodeBindingId),
    ParentUpvalue(UpvalueId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeUpvalue {
    pub id: UpvalueId,
    pub source: BytecodeUpvalueSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BytecodeClosePath {
    pub kind: BytecodeExitKind,
    pub span: BytecodeSpan,
    pub from_scope: u32,
    pub target_scope: Option<u32>,
    pub bindings: Vec<BytecodeBindingId>,
    pub registers: Vec<Register>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum BytecodeConstant {
    Integer(i64),
    FloatBits(u64),
    Name(Vec<u8>),
    String(Vec<u8>),
    Boolean(bool),
}

#[derive(Clone, Debug, PartialEq)]
pub struct BytecodeInstruction {
    pub instruction: Instruction,
    pub span: BytecodeSpan,
    /// Close instruction 與 P04 ordered ClosePath 的靜態連結；其他 opcode 必為 None。
    pub close_path: Option<BytecodeClosePath>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BytecodePrototype {
    pub id: ProtoId,
    pub function: u32,
    pub parent: Option<ProtoId>,
    pub span: BytecodeSpan,
    pub register_count: u16,
    pub parameter_count: u16,
    pub is_variadic: bool,
    pub named_vararg: Option<(BytecodeBindingId, Register)>,
    pub frame: FrameLayout,
    pub global_environment: Register,
    pub global_environment_binding: BytecodeBindingId,
    pub binding_registers: Vec<(BytecodeBindingId, Register)>,
    pub constants: Vec<BytecodeConstant>,
    pub upvalues: Vec<BytecodeUpvalue>,
    pub instructions: Vec<BytecodeInstruction>,
    pub close_paths: Vec<BytecodeClosePath>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BytecodeModule {
    pub format_version: BytecodeVersion,
    pub profile: LuaProfile,
    pub numeric_config: u8,
    pub span: BytecodeSpan,
    pub function_prototypes: Vec<(u32, ProtoId)>,
    pub prototypes: Vec<BytecodePrototype>,
}

/// 只能由 `verify_module` 或 `decode_module` 建立；僅提供不可變 candidate 檢視。
///
/// ```compile_fail
/// let _forged = rivetlua_core::VerifiedModule {};
/// ```
#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedModule {
    module: BytecodeModule,
}

impl VerifiedModule {
    pub fn format_version(&self) -> BytecodeVersion {
        self.module.format_version
    }

    pub fn profile(&self) -> LuaProfile {
        self.module.profile
    }

    pub fn module(&self) -> &BytecodeModule {
        &self.module
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EncodedModule {
    bytes: Vec<u8>,
    verified: VerifiedModule,
}

impl EncodedModule {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn verified(&self) -> &VerifiedModule {
        &self.verified
    }
}

pub fn verify_module(
    module: BytecodeModule,
    expected_profile: LuaProfile,
    limits: &VerifyLimits,
) -> Result<VerifiedModule, BytecodeError> {
    if module.format_version != RVLU_V2 {
        return Err(verify(0, "RVLU v1 或未知 format version 不可驗證"));
    }
    if module.profile != expected_profile {
        return Err(verify(0, "RVLU profile 不符"));
    }
    if module.numeric_config != RVLU_NUMERIC_I64_F64 {
        return Err(verify(0, "RVLU numeric configuration 不支援"));
    }
    if module.span.start_byte > module.span.end_byte {
        return Err(verify(0, "RVLU module span 無效"));
    }
    if module.prototypes.len() > limits.max_prototypes {
        return Err(limit(0, "RVLU prototype 數超過限制"));
    }
    if module.function_prototypes.len() != module.prototypes.len() {
        return Err(verify(0, "RVLU function/prototype map 長度不符"));
    }
    let mut seen_prototypes = Vec::new();
    let mut seen_functions = Vec::new();
    let mut total_instructions = 0usize;
    let mut total_constants = 0usize;
    for prototype in &module.prototypes {
        total_instructions = total_instructions
            .checked_add(prototype.instructions.len())
            .ok_or_else(|| limit(0, "RVLU instruction 總量溢位"))?;
        total_constants = total_constants
            .checked_add(prototype.constants.len())
            .ok_or_else(|| limit(0, "RVLU constant 總量溢位"))?;
        if total_instructions > limits.max_instructions {
            return Err(limit(0, "RVLU module instruction 總量超過限制"));
        }
        if total_constants > limits.max_constants {
            return Err(limit(0, "RVLU module constant 總量超過限制"));
        }
        if seen_prototypes.contains(&prototype.id) {
            return Err(verify(0, "RVLU prototype ID 重複"));
        }
        if seen_functions.contains(&prototype.function) {
            return Err(verify(0, "RVLU function ID 重複"));
        }
        seen_prototypes.push(prototype.id);
        seen_functions.push(prototype.function);
        validate_prototype(prototype, &module, limits)?;
    }
    for (function, proto) in &module.function_prototypes {
        let Some(candidate) = module
            .prototypes
            .iter()
            .find(|candidate| candidate.id == *proto)
        else {
            return Err(verify(
                0,
                "RVLU function/prototype map 指向不存在 prototype",
            ));
        };
        if candidate.function != *function {
            return Err(verify(0, "RVLU function/prototype map 不符"));
        }
    }
    Ok(VerifiedModule { module })
}

pub fn encode_module(
    module: BytecodeModule,
    expected_profile: LuaProfile,
    limits: &VerifyLimits,
) -> Result<EncodedModule, BytecodeError> {
    let verified = verify_module(module, expected_profile, limits)?;
    let mut writer = Writer::default();
    writer.bytes(&RVLU_MAGIC);
    writer.u16(RVLU_V2.0);
    writer.u8(profile_tag(verified.profile()));
    writer.u8(verified.module.numeric_config);
    write_span(&mut writer, verified.module.span);
    let prototype_section = encode_prototype_section(&verified.module, limits)?;
    writer.u32(checked_u32(
        prototype_section.len(),
        0,
        "RVLU prototype section 太大",
    )?);
    writer.bytes(&prototype_section);
    if writer.bytes.len() > limits.max_module_bytes {
        return Err(limit(0, "RVLU module bytes 超過限制"));
    }
    Ok(EncodedModule {
        bytes: writer.bytes,
        verified,
    })
}

pub fn decode_module(
    bytes: &[u8],
    expected_profile: LuaProfile,
    limits: &VerifyLimits,
) -> Result<VerifiedModule, BytecodeError> {
    if bytes.len() > limits.max_module_bytes {
        return Err(limit(0, "RVLU module bytes 超過限制"));
    }
    let mut reader = Reader::new(bytes);
    if reader.fixed::<4>()? != RVLU_MAGIC {
        return Err(verify(0, "RVLU magic 不符"));
    }
    let version = BytecodeVersion(reader.u16()?);
    if version == RVLU_V1 {
        return Err(verify(4, "RVLU v1 語意不完整，明確拒絕"));
    }
    if version != RVLU_V2 {
        return Err(verify(4, "RVLU format version 不支援"));
    }
    let profile = parse_profile(reader.u8()?, 6)?;
    if profile != expected_profile {
        return Err(verify(6, "RVLU profile 不符"));
    }
    let numeric_config = reader.u8()?;
    if numeric_config != RVLU_NUMERIC_I64_F64 {
        return Err(verify(7, "RVLU numeric configuration 不支援"));
    }
    let span = read_span(&mut reader)?;
    let prototype_section = reader.section()?;
    if !reader.is_empty() {
        return Err(verify(reader.location(), "RVLU module 有未宣告尾端 bytes"));
    }
    let mut prototypes_reader = Reader::new_at(prototype_section.bytes, prototype_section.start);
    let count = prototypes_reader.count(limits.max_prototypes, "RVLU prototype 數超過限制")?;
    let mut prototypes = Vec::new();
    let mut total_instructions = 0usize;
    let mut total_constants = 0usize;
    for _ in 0..count {
        let record = prototypes_reader.section()?;
        let remaining_instructions = limits
            .max_instructions
            .checked_sub(total_instructions)
            .ok_or_else(|| limit(record.start, "RVLU module instruction 總量超過限制"))?;
        let remaining_constants = limits
            .max_constants
            .checked_sub(total_constants)
            .ok_or_else(|| limit(record.start, "RVLU module constant 總量超過限制"))?;
        let bounded_limits = VerifyLimits {
            max_instructions: remaining_instructions,
            max_constants: remaining_constants,
            ..*limits
        };
        let prototype = decode_prototype(record.bytes, &bounded_limits, record.start)?;
        total_instructions = total_instructions
            .checked_add(prototype.instructions.len())
            .ok_or_else(|| limit(record.start, "RVLU instruction 總量溢位"))?;
        total_constants = total_constants
            .checked_add(prototype.constants.len())
            .ok_or_else(|| limit(record.start, "RVLU constant 總量溢位"))?;
        prototypes.push(prototype);
    }
    if !prototypes_reader.is_empty() {
        return Err(verify(
            prototypes_reader.location(),
            "RVLU prototype section 尾端 bytes 無效",
        ));
    }
    let mut mappings = Vec::new();
    for prototype in &prototypes {
        mappings.push((prototype.function, prototype.id));
    }
    verify_module(
        BytecodeModule {
            format_version: version,
            profile,
            numeric_config,
            span,
            function_prototypes: mappings,
            prototypes,
        },
        expected_profile,
        limits,
    )
}

fn validate_prototype(
    prototype: &BytecodePrototype,
    module: &BytecodeModule,
    limits: &VerifyLimits,
) -> Result<(), BytecodeError> {
    if prototype.span.start_byte > prototype.span.end_byte
        || prototype.span.end_byte > module.span.end_byte
    {
        return Err(verify(0, "RVLU prototype span 無效"));
    }
    if prototype.register_count > limits.max_registers
        || prototype.frame.register_limit > limits.max_registers
        || prototype.frame.environment.0 >= prototype.register_count
        || prototype.frame.return_base.0 >= prototype.register_count
        || prototype.frame.initial_top.0 > prototype.register_count
        || prototype.frame.dynamic_top.0 > prototype.register_count
    {
        return Err(limit(0, "RVLU frame register 超過限制"));
    }
    if prototype.parameter_count >= prototype.register_count {
        return Err(verify(0, "RVLU parameter count 超出 frame"));
    }
    match prototype.named_vararg {
        Some((_binding, _register)) if !prototype.is_variadic => {
            return Err(verify(0, "RVLU named vararg 必須標記 variadic"));
        }
        Some((_binding, _register)) if module.profile != LuaProfile::Lua55 => {
            return Err(verify(0, "lua54 不可攜帶 named vararg metadata"));
        }
        Some((binding, register)) => {
            if register.0 >= prototype.register_count
                || !prototype
                    .binding_registers
                    .iter()
                    .any(|(candidate, mapped)| *candidate == binding && *mapped == register)
            {
                return Err(verify(0, "RVLU named vararg binding/register 無效"));
            }
        }
        None => {}
    }
    if prototype.constants.len() > limits.max_constants {
        return Err(limit(0, "RVLU constant 數超過限制"));
    }
    if prototype.instructions.len() > limits.max_instructions {
        return Err(limit(0, "RVLU instruction 數超過限制"));
    }
    if prototype.upvalues.len() > limits.max_upvalues_per_prototype {
        return Err(limit(0, "RVLU upvalue 數超過限制"));
    }
    if let Some(parent) = prototype.parent {
        if !module
            .prototypes
            .iter()
            .any(|candidate| candidate.id == parent)
        {
            return Err(verify(0, "RVLU parent prototype 不存在"));
        }
    }
    if prototype.frame.environment != prototype.global_environment {
        return Err(verify(0, "RVLU frame environment slot 不符"));
    }
    match prototype.frame.environment_source {
        EnvironmentSource::RootExternal if prototype.parent.is_some() => {
            return Err(verify(0, "非 root frame 不可使用外部 environment source"));
        }
        EnvironmentSource::RootExternal => {}
        EnvironmentSource::ParentFrame { parent, register } => {
            let Some(parent_prototype) = module
                .prototypes
                .iter()
                .find(|candidate| candidate.id == parent)
            else {
                return Err(verify(0, "RVLU environment parent prototype 不存在"));
            };
            if prototype.parent != Some(parent) || register != parent_prototype.frame.environment {
                return Err(verify(0, "RVLU ParentFrame environment source 無效"));
            }
        }
        EnvironmentSource::ParentLocal { upvalue }
        | EnvironmentSource::ParentUpvalue { upvalue } => {
            let Some(source) = prototype.upvalues.get(usize::from(upvalue.0)) else {
                return Err(verify(0, "RVLU environment upvalue 不存在"));
            };
            let matches_source = matches!(
                (prototype.frame.environment_source, &source.source),
                (
                    EnvironmentSource::ParentLocal { .. },
                    BytecodeUpvalueSource::ParentLocal(_)
                ) | (
                    EnvironmentSource::ParentUpvalue { .. },
                    BytecodeUpvalueSource::ParentUpvalue(_)
                )
            );
            if !matches_source {
                return Err(verify(0, "RVLU environment upvalue source 不符"));
            }
        }
    }
    validate_metadata(prototype)?;
    for (index, instruction) in prototype.instructions.iter().enumerate() {
        if instruction.span.start_byte > instruction.span.end_byte
            || instruction.span.end_byte > prototype.span.end_byte
        {
            return Err(verify(0, "RVLU instruction span 無效"));
        }
        validate_instruction_shape(prototype, module, index, instruction)?;
    }
    validate_numeric_for_pairs(prototype)?;
    verify_control_and_dataflow(prototype, limits)
}

fn validate_metadata(prototype: &BytecodePrototype) -> Result<(), BytecodeError> {
    let mut bindings = Vec::new();
    for (binding, register) in &prototype.binding_registers {
        if bindings.contains(binding) || register.0 >= prototype.register_count {
            return Err(verify(0, "RVLU binding/register metadata 無效"));
        }
        bindings.push(*binding);
    }
    if matches!(
        prototype.frame.environment_source,
        EnvironmentSource::RootExternal
    ) && !bindings.contains(&prototype.global_environment_binding)
    {
        return Err(verify(0, "RVLU root environment binding 缺少 register"));
    }
    let mut upvalues = Vec::new();
    for upvalue in &prototype.upvalues {
        if usize::from(upvalue.id.0) >= prototype.upvalues.len() || upvalues.contains(&upvalue.id) {
            return Err(verify(0, "RVLU upvalue metadata 無效"));
        }
        upvalues.push(upvalue.id);
    }
    for path in &prototype.close_paths {
        validate_close_path(prototype, path)?;
    }
    validate_close_sequences(prototype)
}

fn validate_close_sequences(prototype: &BytecodePrototype) -> Result<(), BytecodeError> {
    let mut index = 0usize;
    while index < prototype.instructions.len() {
        let entry = &prototype.instructions[index];
        let (Instruction::Close { .. }, Some(path)) = (&entry.instruction, &entry.close_path)
        else {
            index += 1;
            continue;
        };
        if path.registers.is_empty() {
            return Err(verify(0, "RVLU ClosePath 不可對應空 Close 序列"));
        }
        for (offset, expected) in path.registers.iter().enumerate() {
            let Some(actual) = prototype.instructions.get(index + offset) else {
                return Err(verify(0, "RVLU ClosePath Close 序列缺漏"));
            };
            if !matches!(
                (&actual.instruction, &actual.close_path),
                (Instruction::Close { base, count: 1 }, Some(actual_path))
                    if *base == *expected && actual_path == path
            ) {
                return Err(verify(0, "RVLU ClosePath Close 順序或連續性不符"));
            }
        }
        let after_close = index
            .checked_add(path.registers.len())
            .ok_or_else(|| limit(0, "RVLU ClosePath 序列長度溢位"))?;
        if path.kind == BytecodeExitKind::Return
            && matches!(
                prototype
                    .instructions
                    .get(after_close)
                    .map(|entry| &entry.instruction),
                Some(Instruction::TailCall {
                    result_mode: ResultMode::All,
                    ..
                })
            )
        {
            return Err(verify(
                0,
                "RVLU 有 pending ClosePath 的 return 不可使用 TailCall(All)",
            ));
        }
        index = after_close;
    }
    Ok(())
}

fn validate_close_path(
    prototype: &BytecodePrototype,
    path: &BytecodeClosePath,
) -> Result<(), BytecodeError> {
    if path.span.start_byte > path.span.end_byte
        || path.span.end_byte > prototype.span.end_byte
        || path.bindings.len() != path.registers.len()
    {
        return Err(verify(0, "RVLU ClosePath metadata 無效"));
    }
    for (binding, register) in path.bindings.iter().zip(&path.registers) {
        if prototype
            .binding_registers
            .iter()
            .find_map(|(candidate, mapped)| (*candidate == *binding).then_some(*mapped))
            != Some(*register)
        {
            return Err(verify(0, "RVLU ClosePath binding/register 不符"));
        }
    }
    Ok(())
}

fn validate_instruction_shape(
    prototype: &BytecodePrototype,
    module: &BytecodeModule,
    index: usize,
    instruction: &BytecodeInstruction,
) -> Result<(), BytecodeError> {
    let register =
        |register: Register| register_in_frame(prototype, register, 0, "RVLU register 超出 frame");
    let range = |base: Register, count: u16| {
        register_in_frame(prototype, base, count, "RVLU register range 超出 frame")
    };
    match &instruction.instruction {
        Instruction::LoadConst { dest, constant } => {
            register(*dest)?;
            if constant.0 as usize >= prototype.constants.len() {
                return Err(verify(0, "RVLU constant index 無效"));
            }
        }
        Instruction::LoadNil { start, count } => {
            if *count == 0 {
                return Err(verify(0, "RVLU LoadNil count 不可為零"));
            }
            range(*start, *count - 1)?;
        }
        Instruction::Move { dest, src } => {
            register(*dest)?;
            register(*src)?;
        }
        Instruction::GetUpvalue { dest, upvalue } => {
            register(*dest)?;
            require_upvalue(prototype, *upvalue)?;
        }
        Instruction::SetUpvalue { upvalue, src } => {
            require_upvalue(prototype, *upvalue)?;
            register(*src)?;
        }
        Instruction::NewTable { dest } => register(*dest)?,
        Instruction::GetTable { dest, table, key } => {
            register(*dest)?;
            register(*table)?;
            register(*key)?;
        }
        Instruction::SetTable { table, key, value } => {
            register(*table)?;
            register(*key)?;
            register(*value)?;
        }
        Instruction::UnaryOp { dest, src, .. } => {
            register(*dest)?;
            register(*src)?;
        }
        Instruction::BinaryOp {
            dest,
            op,
            left,
            right,
        } => {
            if matches!(op, BinaryOperation::And | BinaryOperation::Or) {
                return Err(verify(0, "RVLU v2 不可用 BinaryOp 表示 and/or"));
            }
            register(*dest)?;
            register(*left)?;
            register(*right)?;
        }
        Instruction::Jump { target } => require_jump_target(prototype, index, *target)?,
        Instruction::JumpIfFalse { condition, target } => {
            register(*condition)?;
            require_jump_target(prototype, index, *target)?;
        }
        Instruction::Closure { dest, proto } => {
            register(*dest)?;
            if !module
                .prototypes
                .iter()
                .any(|candidate| candidate.id == *proto && candidate.parent == Some(prototype.id))
            {
                return Err(verify(0, "RVLU Closure child prototype 無效"));
            }
        }
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        }
        | Instruction::TailCall {
            base,
            arg_count,
            result_mode,
        } => {
            // 函式位於 base，最後一個引數位於 base + arg_count。
            range(*base, *arg_count)?;
            validate_result_range(prototype, *base, *result_mode)?;
        }
        Instruction::Vararg { base, result_mode } => {
            if !prototype.is_variadic {
                return Err(verify(0, "RVLU 非 variadic prototype 不可使用 Vararg"));
            }
            register(*base)?;
            validate_result_range(prototype, *base, *result_mode)?;
        }
        Instruction::Return { base, result_mode } => {
            register(*base)?;
            validate_result_range(prototype, *base, *result_mode)?;
        }
        Instruction::Close { base, count } => {
            if *count == 0 {
                return Err(verify(0, "RVLU Close count 不可為零"));
            }
            range(*base, *count - 1)?;
        }
        Instruction::NumericForPrepare {
            control,
            limit,
            step,
            visible,
            exit,
        } => {
            validate_numeric_for_registers(register, *control, *limit, *step, *visible)?;
            require_jump_target(prototype, index, *exit)?;
            if exit.0 as usize <= index {
                return Err(verify(0, "RVLU NumericForPrepare exit 必須為前向 CFG edge"));
            }
        }
        Instruction::NumericForNext {
            control,
            limit,
            step,
            visible,
            target,
            exit,
        } => {
            validate_numeric_for_registers(register, *control, *limit, *step, *visible)?;
            require_jump_target(prototype, index, *target)?;
            require_jump_target(prototype, index, *exit)?;
            if target.0 as usize >= index || exit.0 as usize <= index {
                return Err(verify(
                    0,
                    "RVLU NumericForNext 必須有後向回邊與前向 exit CFG edge",
                ));
            }
        }
    }
    match (&instruction.instruction, &instruction.close_path) {
        (Instruction::Close { base, count: 1 }, Some(path)) => {
            validate_close_path(prototype, path)?;
            if !prototype.close_paths.contains(path) || !path.registers.contains(base) {
                return Err(verify(0, "RVLU Close 缺少對應 ClosePath"));
            }
        }
        (Instruction::Close { .. }, _) => {
            return Err(verify(0, "RVLU Close 必須連結單一 ClosePath"));
        }
        (_, Some(_)) => return Err(verify(0, "非 Close instruction 不可攜帶 ClosePath")),
        _ => {}
    }
    Ok(())
}

fn validate_numeric_for_registers(
    register: impl Fn(Register) -> Result<(), BytecodeError>,
    control: Register,
    limit: Register,
    step: Register,
    visible: Register,
) -> Result<(), BytecodeError> {
    for value in [control, limit, step, visible] {
        register(value)?;
    }
    if control == limit
        || control == step
        || control == visible
        || limit == step
        || limit == visible
        || step == visible
    {
        return Err(verify(
            0,
            "RVLU NumericFor 控制/limit/step/可見 variable register 必須分離",
        ));
    }
    Ok(())
}

/// `NumericForNext` 不能自行建立 numeric mode；它必須唯一配對同一組
/// control registers 的 `NumericForPrepare`，並回到該 Prepare 後的 body entry。
fn validate_numeric_for_pairs(prototype: &BytecodePrototype) -> Result<(), BytecodeError> {
    let mut prepares =
        std::collections::BTreeMap::<(u16, u16, u16, u16), Vec<(usize, InstructionOffset)>>::new();
    for (prepare_index, instruction) in prototype.instructions.iter().enumerate() {
        let Instruction::NumericForPrepare {
            control,
            limit,
            step,
            visible,
            exit,
        } = instruction.instruction
        else {
            continue;
        };
        prepares
            .entry((control.0, limit.0, step.0, visible.0))
            .or_default()
            .push((prepare_index, exit));
    }

    let mut pairs = Vec::new();
    for (next_index, instruction) in prototype.instructions.iter().enumerate() {
        let Instruction::NumericForNext {
            control,
            limit,
            step,
            visible,
            target,
            exit,
        } = instruction.instruction
        else {
            continue;
        };
        let Some(candidates) = prepares.get(&(control.0, limit.0, step.0, visible.0)) else {
            return Err(verify(
                0,
                "RVLU NumericForNext 必須唯一配對 NumericForPrepare",
            ));
        };
        let [(prepare_index, prepare_exit)] = candidates.as_slice() else {
            return Err(verify(
                0,
                "RVLU NumericForNext 必須唯一配對 NumericForPrepare",
            ));
        };
        if *prepare_exit != exit
            || prepare_index.checked_add(1) != Some(target.0 as usize)
            || target.0 as usize >= next_index
        {
            return Err(verify(
                0,
                "RVLU NumericForPrepare/Next 的 body target 或 exit 不符",
            ));
        }
        pairs.push((*prepare_index, next_index));
    }
    validate_numeric_for_body_dominance(prototype, &pairs)
}

/// 將 Prepare 的 body edge 拆成獨立 gate；gate 支配 Next 才表示每條
/// 可達路徑都經過 Prepare 的成功分支，不能從入口或 exit 分支跳入 body。
fn validate_numeric_for_body_dominance(
    prototype: &BytecodePrototype,
    pairs: &[(usize, usize)],
) -> Result<(), BytecodeError> {
    if pairs.is_empty() {
        return Ok(());
    }
    let count = prototype.instructions.len();
    let mut gates = vec![None; count];
    let mut next_gate = count;
    for (index, entry) in prototype.instructions.iter().enumerate() {
        if matches!(entry.instruction, Instruction::NumericForPrepare { .. }) {
            gates[index] = Some(next_gate);
            next_gate += 1;
        }
    }
    let mut edges = vec![Vec::new(); next_gate];
    for (index, entry) in prototype.instructions.iter().enumerate() {
        match &entry.instruction {
            Instruction::Jump { target } => edges[index].push(target.0 as usize),
            Instruction::JumpIfFalse { target, .. } => {
                edges[index].push(target.0 as usize);
                if index + 1 < count {
                    edges[index].push(index + 1);
                }
            }
            Instruction::NumericForPrepare { exit, .. } => {
                edges[index].push(exit.0 as usize);
                if let Some(gate) = gates[index] {
                    edges[index].push(gate);
                    edges[gate].push(index + 1);
                }
            }
            Instruction::NumericForNext { target, exit, .. } => {
                edges[index].push(target.0 as usize);
                edges[index].push(exit.0 as usize);
            }
            Instruction::Return { .. } | Instruction::TailCall { .. } => {}
            _ if index + 1 < count => edges[index].push(index + 1),
            _ => {}
        }
    }
    let mut predecessors = vec![Vec::new(); next_gate];
    for (node, successors) in edges.iter().enumerate() {
        for &successor in successors {
            predecessors[successor].push(node);
        }
    }

    let mut visited = vec![false; next_gate];
    let mut postorder = Vec::with_capacity(next_gate);
    let mut stack = vec![(0usize, 0usize)];
    visited[0] = true;
    while let Some((node, next_successor)) = stack.last_mut() {
        if *next_successor < edges[*node].len() {
            let successor = edges[*node][*next_successor];
            *next_successor += 1;
            if !visited[successor] {
                visited[successor] = true;
                stack.push((successor, 0));
            }
        } else {
            let (finished, _) = stack.pop().expect("CFG stack 非空");
            postorder.push(finished);
        }
    }
    postorder.reverse();
    let mut order = vec![usize::MAX; next_gate];
    for (position, &node) in postorder.iter().enumerate() {
        order[node] = position;
    }
    let mut immediate_dominator = vec![None; next_gate];
    immediate_dominator[0] = Some(0usize);
    let mut work_remaining = count.saturating_mul(128);
    let mut spend_work = || {
        work_remaining = work_remaining
            .checked_sub(1)
            .ok_or_else(|| limit(0, "RVLU CFG dominator 工作量超過限制"))?;
        Ok::<(), BytecodeError>(())
    };
    let mut changed = true;
    while changed {
        changed = false;
        for &node in postorder.iter().skip(1) {
            let mut candidate = None;
            for &predecessor in &predecessors[node] {
                spend_work()?;
                if immediate_dominator[predecessor].is_none() {
                    continue;
                }
                candidate = Some(match candidate {
                    None => predecessor,
                    Some(current) => {
                        let mut left = predecessor;
                        let mut right = current;
                        while left != right {
                            while order[left] > order[right] {
                                spend_work()?;
                                left = immediate_dominator[left]
                                    .ok_or_else(|| verify(0, "RVLU CFG dominator state 無效"))?;
                            }
                            while order[right] > order[left] {
                                spend_work()?;
                                right = immediate_dominator[right]
                                    .ok_or_else(|| verify(0, "RVLU CFG dominator state 無效"))?;
                            }
                        }
                        left
                    }
                });
            }
            if immediate_dominator[node] != candidate {
                immediate_dominator[node] = candidate;
                changed = true;
            }
        }
    }

    let mut dominator_children = vec![Vec::new(); next_gate];
    for (node, parent) in immediate_dominator.iter().enumerate().skip(1) {
        if let Some(parent) = parent {
            dominator_children[*parent].push(node);
        }
    }
    let mut entry = vec![0usize; next_gate];
    let mut exit = vec![0usize; next_gate];
    let mut tick = 0usize;
    let mut stack = vec![(0usize, false)];
    while let Some((node, leaving)) = stack.pop() {
        tick += 1;
        if leaving {
            exit[node] = tick;
        } else {
            entry[node] = tick;
            stack.push((node, true));
            for &child in dominator_children[node].iter().rev() {
                stack.push((child, false));
            }
        }
    }
    for &(prepare, next) in pairs {
        if !visited[next] {
            continue;
        }
        let gate = gates[prepare].ok_or_else(|| verify(0, "RVLU NumericForPrepare gate 缺失"))?;
        if !visited[gate] || !(entry[gate] <= entry[next] && exit[next] <= exit[gate]) {
            return Err(verify(
                0,
                "RVLU NumericForNext 路徑未經對應 NumericForPrepare body entry",
            ));
        }
    }
    Ok(())
}

fn register_in_frame(
    prototype: &BytecodePrototype,
    base: Register,
    count: u16,
    message: &str,
) -> Result<(), BytecodeError> {
    let end = u32::from(base.0)
        .checked_add(u32::from(count))
        .ok_or_else(|| verify(0, message))?;
    if end >= u32::from(prototype.register_count) {
        return Err(verify(0, message));
    }
    Ok(())
}

fn validate_result_range(
    prototype: &BytecodePrototype,
    base: Register,
    mode: ResultMode,
) -> Result<(), BytecodeError> {
    match mode {
        ResultMode::Fixed(0) => {
            register_in_frame(prototype, base, 0, "RVLU result base 超出 frame")
        }
        ResultMode::Fixed(count) => {
            register_in_frame(prototype, base, count - 1, "RVLU result range 超出 frame")
        }
        ResultMode::All => {
            register_in_frame(prototype, base, 0, "RVLU open result base 超出 frame")
        }
    }
}

fn require_upvalue(prototype: &BytecodePrototype, upvalue: UpvalueId) -> Result<(), BytecodeError> {
    if prototype
        .upvalues
        .iter()
        .any(|candidate| candidate.id == upvalue)
    {
        Ok(())
    } else {
        Err(verify(0, "RVLU upvalue index 無效"))
    }
}

fn require_jump_target(
    prototype: &BytecodePrototype,
    index: usize,
    target: InstructionOffset,
) -> Result<(), BytecodeError> {
    let target = usize::try_from(target.0).map_err(|_| verify(0, "RVLU jump target 過大"))?;
    if target >= prototype.instructions.len() || target == index {
        return Err(verify(0, "RVLU jump target 無效或 self-loop"));
    }
    Ok(())
}

fn verify_control_and_dataflow(
    prototype: &BytecodePrototype,
    limits: &VerifyLimits,
) -> Result<(), BytecodeError> {
    if prototype.instructions.is_empty() {
        return Err(verify(0, "RVLU prototype 不可空且不得 fall-through"));
    }
    if prototype.frame.dynamic_top.0 < prototype.frame.initial_top.0 {
        return Err(verify(0, "RVLU frame dynamic top 不可低於 initial top"));
    }
    let count = prototype.instructions.len();
    if count > limits.max_instructions {
        return Err(limit(0, "RVLU CFG worklist 超過限制"));
    }
    let mut states: Vec<Option<Option<Register>>> = vec![None; count];
    let mut worklist = Vec::new();
    states[0] = Some(None);
    worklist.push(0usize);
    while let Some(index) = worklist.pop() {
        let Some(open) = states[index] else {
            return Err(verify(0, "RVLU CFG worklist state 遺失"));
        };
        let instruction = &prototype.instructions[index].instruction;
        if open.is_some()
            && !matches!(
                instruction,
                Instruction::Close { .. }
                    | Instruction::Return {
                        result_mode: ResultMode::All,
                        ..
                    }
            )
        {
            return Err(verify(0, "RVLU open result 未立即流向 Return(All)"));
        }
        let next_open = match instruction {
            Instruction::Call {
                base,
                result_mode: ResultMode::All,
                ..
            }
            | Instruction::Vararg {
                base,
                result_mode: ResultMode::All,
            } => Some(*base),
            Instruction::Return {
                base,
                result_mode: ResultMode::All,
            } => {
                if open != Some(*base) {
                    return Err(verify(0, "RVLU Return(All) 缺少相同 open result"));
                }
                None
            }
            Instruction::TailCall {
                result_mode: ResultMode::All,
                ..
            } => None,
            _ => open,
        };
        let mut successors = Vec::new();
        match instruction {
            Instruction::Jump { target } => successors.push(target.0 as usize),
            Instruction::JumpIfFalse { target, .. } => {
                successors.push(target.0 as usize);
                if index.checked_add(1).filter(|next| *next < count).is_none() {
                    return Err(verify(
                        0,
                        "RVLU conditional jump fall-through 到 proto 尾端",
                    ));
                }
                successors.push(index + 1);
            }
            Instruction::NumericForPrepare { exit, .. } => {
                successors.push(exit.0 as usize);
                if index.checked_add(1).filter(|next| *next < count).is_none() {
                    return Err(verify(
                        0,
                        "RVLU NumericForPrepare fall-through 到 proto 尾端",
                    ));
                }
                successors.push(index + 1);
            }
            Instruction::NumericForNext { target, exit, .. } => {
                successors.push(target.0 as usize);
                successors.push(exit.0 as usize);
            }
            Instruction::Return { .. } | Instruction::TailCall { .. } => {}
            _ => {
                if index.checked_add(1).filter(|next| *next < count).is_none() {
                    return Err(verify(0, "RVLU reachable fall-through 到 proto 尾端"));
                }
                successors.push(index + 1);
            }
        }
        for successor in successors {
            let Some(state) = states.get_mut(successor) else {
                return Err(verify(0, "RVLU CFG successor 超出範圍"));
            };
            match state {
                Some(existing) if *existing != next_open => {
                    return Err(verify(0, "RVLU CFG join dynamic top 不一致"));
                }
                Some(_) => {}
                slot @ None => {
                    *slot = Some(next_open);
                    if worklist.len() >= limits.max_instructions {
                        return Err(limit(0, "RVLU CFG worklist 超過限制"));
                    }
                    worklist.push(successor);
                }
            }
        }
    }
    Ok(())
}

fn encode_prototype_section(
    module: &BytecodeModule,
    limits: &VerifyLimits,
) -> Result<Vec<u8>, BytecodeError> {
    let mut writer = Writer::default();
    writer.u32(checked_u32(
        module.prototypes.len(),
        0,
        "RVLU prototype 數過大",
    )?);
    for prototype in &module.prototypes {
        let record = encode_prototype(prototype, limits)?;
        writer.u32(checked_u32(record.len(), 0, "RVLU prototype record 太大")?);
        writer.bytes(&record);
    }
    Ok(writer.bytes)
}

fn encode_prototype(
    prototype: &BytecodePrototype,
    limits: &VerifyLimits,
) -> Result<Vec<u8>, BytecodeError> {
    let mut writer = Writer::default();
    writer.u32(prototype.id.0);
    writer.u32(prototype.function);
    write_optional_proto(&mut writer, prototype.parent);
    write_span(&mut writer, prototype.span);
    writer.u16(prototype.register_count);
    writer.u16(prototype.parameter_count);
    writer.u8(u8::from(prototype.is_variadic));
    match prototype.named_vararg {
        Some((binding, register)) => {
            writer.u8(1);
            write_binding(&mut writer, binding);
            writer.u16(register.0);
        }
        None => writer.u8(0),
    }
    write_frame(&mut writer, prototype.frame);
    writer.u16(prototype.global_environment.0);
    write_binding(&mut writer, prototype.global_environment_binding);
    let constants = encode_constants(&prototype.constants, limits)?;
    writer.u32(checked_u32(
        constants.len(),
        0,
        "RVLU constants section 太大",
    )?);
    writer.bytes(&constants);
    let instructions = encode_instructions(&prototype.instructions, limits)?;
    writer.u32(checked_u32(
        instructions.len(),
        0,
        "RVLU instructions section 太大",
    )?);
    writer.bytes(&instructions);
    let metadata = encode_metadata(prototype, limits)?;
    writer.u32(checked_u32(
        metadata.len(),
        0,
        "RVLU metadata section 太大",
    )?);
    writer.bytes(&metadata);
    Ok(writer.bytes)
}

fn decode_prototype(
    bytes: &[u8],
    limits: &VerifyLimits,
    base: usize,
) -> Result<BytecodePrototype, BytecodeError> {
    let mut reader = Reader::new_at(bytes, base);
    let id = ProtoId(reader.u32()?);
    let function = reader.u32()?;
    let parent = read_optional_proto(&mut reader)?;
    let span = read_span(&mut reader)?;
    let register_count = reader.u16()?;
    let parameter_count = reader.u16()?;
    let is_variadic = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(verify(reader.location() - 1, "RVLU vararg flag 無效")),
    };
    let named_vararg = match reader.u8()? {
        0 => None,
        1 => Some((read_binding(&mut reader)?, Register(reader.u16()?))),
        _ => return Err(verify(reader.location() - 1, "RVLU named vararg flag 無效")),
    };
    let frame = read_frame(&mut reader)?;
    let global_environment = Register(reader.u16()?);
    let global_environment_binding = read_binding(&mut reader)?;
    let constants_section = reader.section()?;
    let constants = decode_constants(constants_section.bytes, limits, constants_section.start)?;
    let instructions_section = reader.section()?;
    let instructions = decode_instructions(
        instructions_section.bytes,
        limits,
        instructions_section.start,
    )?;
    let metadata_section = reader.section()?;
    let (binding_registers, upvalues, close_paths) =
        decode_metadata(metadata_section.bytes, limits, metadata_section.start)?;
    if !reader.is_empty() {
        return Err(verify(
            reader.location(),
            "RVLU prototype record 尾端 bytes 無效",
        ));
    }
    Ok(BytecodePrototype {
        id,
        function,
        parent,
        span,
        register_count,
        parameter_count,
        is_variadic,
        named_vararg,
        frame,
        global_environment,
        global_environment_binding,
        binding_registers,
        constants,
        upvalues,
        instructions,
        close_paths,
    })
}

fn encode_constants(
    constants: &[BytecodeConstant],
    limits: &VerifyLimits,
) -> Result<Vec<u8>, BytecodeError> {
    if constants.len() > limits.max_constants {
        return Err(limit(0, "RVLU constant 數超過限制"));
    }
    let mut writer = Writer::default();
    writer.u32(checked_u32(constants.len(), 0, "RVLU constant 數過大")?);
    for constant in constants {
        match constant {
            BytecodeConstant::Integer(value) => {
                writer.u8(0);
                writer.i64(*value);
            }
            BytecodeConstant::FloatBits(value) => {
                writer.u8(1);
                writer.u64(*value);
            }
            BytecodeConstant::Name(value) => {
                writer.u8(2);
                writer.blob(value)?;
            }
            BytecodeConstant::String(value) => {
                writer.u8(3);
                writer.blob(value)?;
            }
            BytecodeConstant::Boolean(value) => {
                writer.u8(4);
                writer.u8(u8::from(*value));
            }
        }
    }
    Ok(writer.bytes)
}

fn decode_constants(
    bytes: &[u8],
    limits: &VerifyLimits,
    base: usize,
) -> Result<Vec<BytecodeConstant>, BytecodeError> {
    let mut reader = Reader::new_at(bytes, base);
    let count = reader.count(limits.max_constants, "RVLU constant 數超過限制")?;
    let mut constants = Vec::new();
    for _ in 0..count {
        let tag_offset = reader.location();
        let constant = match reader.u8()? {
            0 => BytecodeConstant::Integer(reader.i64()?),
            1 => BytecodeConstant::FloatBits(reader.u64()?),
            2 => BytecodeConstant::Name(reader.blob()?),
            3 => BytecodeConstant::String(reader.blob()?),
            4 => BytecodeConstant::Boolean(match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(verify(tag_offset, "RVLU boolean constant 無效")),
            }),
            _ => return Err(verify(tag_offset, "RVLU constant tag 無效")),
        };
        constants.push(constant);
    }
    if !reader.is_empty() {
        return Err(verify(
            reader.location(),
            "RVLU constants section 尾端 bytes 無效",
        ));
    }
    Ok(constants)
}

fn encode_instructions(
    instructions: &[BytecodeInstruction],
    limits: &VerifyLimits,
) -> Result<Vec<u8>, BytecodeError> {
    if instructions.len() > limits.max_instructions {
        return Err(limit(0, "RVLU instruction 數超過限制"));
    }
    let mut writer = Writer::default();
    writer.u32(checked_u32(
        instructions.len(),
        0,
        "RVLU instruction 數過大",
    )?);
    for instruction in instructions {
        write_instruction(&mut writer, &instruction.instruction);
        writer.u8(instruction.instruction.canonical_effect_flags());
        write_span(&mut writer, instruction.span);
        match &instruction.close_path {
            Some(path) => {
                writer.u8(1);
                write_close_path(&mut writer, path)?;
            }
            None => writer.u8(0),
        }
    }
    Ok(writer.bytes)
}

fn decode_instructions(
    bytes: &[u8],
    limits: &VerifyLimits,
    base: usize,
) -> Result<Vec<BytecodeInstruction>, BytecodeError> {
    let mut reader = Reader::new_at(bytes, base);
    let count = reader.count(limits.max_instructions, "RVLU instruction 數超過限制")?;
    let mut instructions = Vec::new();
    for _ in 0..count {
        let instruction = read_instruction(&mut reader)?;
        let effect_offset = reader.location();
        let encoded_effects = reader.u8()?;
        let canonical_effects = instruction.canonical_effect_flags();
        if encoded_effects & !InstructionEffects::KNOWN_FLAGS != 0 {
            return Err(verify(
                effect_offset,
                "RVLU instruction effect flags 含未知 bit",
            ));
        }
        if encoded_effects != canonical_effects {
            return Err(verify(
                effect_offset,
                "RVLU instruction effect flags 與 canonical effect 不符",
            ));
        }
        let span = read_span(&mut reader)?;
        let close_path = match reader.u8()? {
            0 => None,
            1 => Some(read_close_path(&mut reader, limits)?),
            _ => {
                return Err(verify(
                    reader.location() - 1,
                    "RVLU instruction close flag 無效",
                ));
            }
        };
        instructions.push(BytecodeInstruction {
            instruction,
            span,
            close_path,
        });
    }
    if !reader.is_empty() {
        return Err(verify(
            reader.location(),
            "RVLU instructions section 尾端 bytes 無效",
        ));
    }
    Ok(instructions)
}

fn encode_metadata(
    prototype: &BytecodePrototype,
    limits: &VerifyLimits,
) -> Result<Vec<u8>, BytecodeError> {
    if prototype.upvalues.len() > limits.max_upvalues_per_prototype {
        return Err(limit(0, "RVLU upvalue 數超過限制"));
    }
    let mut writer = Writer::default();
    writer.u32(checked_u32(
        prototype.binding_registers.len(),
        0,
        "RVLU binding metadata 過大",
    )?);
    for (binding, register) in &prototype.binding_registers {
        write_binding(&mut writer, *binding);
        writer.u16(register.0);
    }
    writer.u32(checked_u32(
        prototype.upvalues.len(),
        0,
        "RVLU upvalue metadata 過大",
    )?);
    for upvalue in &prototype.upvalues {
        writer.u16(upvalue.id.0);
        match upvalue.source {
            BytecodeUpvalueSource::ParentLocal(binding) => {
                writer.u8(0);
                write_binding(&mut writer, binding);
            }
            BytecodeUpvalueSource::ParentUpvalue(parent) => {
                writer.u8(1);
                writer.u16(parent.0);
            }
        }
    }
    writer.u32(checked_u32(
        prototype.close_paths.len(),
        0,
        "RVLU close metadata 過大",
    )?);
    for close in &prototype.close_paths {
        write_close_path(&mut writer, close)?;
    }
    Ok(writer.bytes)
}

fn decode_metadata(
    bytes: &[u8],
    limits: &VerifyLimits,
    base: usize,
) -> Result<
    (
        Vec<(BytecodeBindingId, Register)>,
        Vec<BytecodeUpvalue>,
        Vec<BytecodeClosePath>,
    ),
    BytecodeError,
> {
    let mut reader = Reader::new_at(bytes, base);
    let binding_count = reader.count(limits.max_constants, "RVLU binding metadata 超過限制")?;
    let mut binding_registers = Vec::new();
    for _ in 0..binding_count {
        binding_registers.push((read_binding(&mut reader)?, Register(reader.u16()?)));
    }
    let upvalue_count =
        reader.count(limits.max_upvalues_per_prototype, "RVLU upvalue 數超過限制")?;
    let mut upvalues = Vec::new();
    for _ in 0..upvalue_count {
        let id = UpvalueId(reader.u16()?);
        let offset = reader.location();
        let source = match reader.u8()? {
            0 => BytecodeUpvalueSource::ParentLocal(read_binding(&mut reader)?),
            1 => BytecodeUpvalueSource::ParentUpvalue(UpvalueId(reader.u16()?)),
            _ => return Err(verify(offset, "RVLU upvalue source 無效")),
        };
        upvalues.push(BytecodeUpvalue { id, source });
    }
    let close_count = reader.count(limits.max_constants, "RVLU close metadata 超過限制")?;
    let mut close_paths = Vec::new();
    for _ in 0..close_count {
        close_paths.push(read_close_path(&mut reader, limits)?);
    }
    if !reader.is_empty() {
        return Err(verify(
            reader.location(),
            "RVLU metadata section 尾端 bytes 無效",
        ));
    }
    Ok((binding_registers, upvalues, close_paths))
}

fn write_instruction(writer: &mut Writer, instruction: &Instruction) {
    match instruction {
        Instruction::LoadConst { dest, constant } => {
            writer.u8(0);
            writer.u16(dest.0);
            writer.u32(constant.0);
        }
        Instruction::LoadNil { start, count } => {
            writer.u8(1);
            writer.u16(start.0);
            writer.u16(*count);
        }
        Instruction::Move { dest, src } => {
            writer.u8(2);
            writer.u16(dest.0);
            writer.u16(src.0);
        }
        Instruction::GetUpvalue { dest, upvalue } => {
            writer.u8(3);
            writer.u16(dest.0);
            writer.u16(upvalue.0);
        }
        Instruction::SetUpvalue { upvalue, src } => {
            writer.u8(4);
            writer.u16(upvalue.0);
            writer.u16(src.0);
        }
        Instruction::NewTable { dest } => {
            writer.u8(5);
            writer.u16(dest.0);
        }
        Instruction::GetTable { dest, table, key } => {
            writer.u8(6);
            writer.u16(dest.0);
            writer.u16(table.0);
            writer.u16(key.0);
        }
        Instruction::SetTable { table, key, value } => {
            writer.u8(7);
            writer.u16(table.0);
            writer.u16(key.0);
            writer.u16(value.0);
        }
        Instruction::UnaryOp { dest, op, src } => {
            writer.u8(8);
            writer.u16(dest.0);
            writer.u8(unary_tag(*op));
            writer.u16(src.0);
        }
        Instruction::BinaryOp {
            dest,
            op,
            left,
            right,
        } => {
            writer.u8(9);
            writer.u16(dest.0);
            writer.u8(binary_tag(*op));
            writer.u16(left.0);
            writer.u16(right.0);
        }
        Instruction::Jump { target } => {
            writer.u8(10);
            writer.u32(target.0);
        }
        Instruction::JumpIfFalse { condition, target } => {
            writer.u8(11);
            writer.u16(condition.0);
            writer.u32(target.0);
        }
        Instruction::Closure { dest, proto } => {
            writer.u8(12);
            writer.u16(dest.0);
            writer.u32(proto.0);
        }
        Instruction::Call {
            base,
            arg_count,
            result_mode,
        } => {
            writer.u8(13);
            writer.u16(base.0);
            writer.u16(*arg_count);
            write_result_mode(writer, *result_mode);
        }
        Instruction::TailCall {
            base,
            arg_count,
            result_mode,
        } => {
            writer.u8(14);
            writer.u16(base.0);
            writer.u16(*arg_count);
            write_result_mode(writer, *result_mode);
        }
        Instruction::Vararg { base, result_mode } => {
            writer.u8(15);
            writer.u16(base.0);
            write_result_mode(writer, *result_mode);
        }
        Instruction::Return { base, result_mode } => {
            writer.u8(16);
            writer.u16(base.0);
            write_result_mode(writer, *result_mode);
        }
        Instruction::Close { base, count } => {
            writer.u8(17);
            writer.u16(base.0);
            writer.u16(*count);
        }
        Instruction::NumericForPrepare {
            control,
            limit,
            step,
            visible,
            exit,
        } => {
            writer.u8(18);
            writer.u16(control.0);
            writer.u16(limit.0);
            writer.u16(step.0);
            writer.u16(visible.0);
            writer.u32(exit.0);
        }
        Instruction::NumericForNext {
            control,
            limit,
            step,
            visible,
            target,
            exit,
        } => {
            writer.u8(19);
            writer.u16(control.0);
            writer.u16(limit.0);
            writer.u16(step.0);
            writer.u16(visible.0);
            writer.u32(target.0);
            writer.u32(exit.0);
        }
    }
}

fn read_instruction(reader: &mut Reader<'_>) -> Result<Instruction, BytecodeError> {
    let offset = reader.location();
    Ok(match reader.u8()? {
        0 => Instruction::LoadConst {
            dest: Register(reader.u16()?),
            constant: super::ConstId(reader.u32()?),
        },
        1 => Instruction::LoadNil {
            start: Register(reader.u16()?),
            count: reader.u16()?,
        },
        2 => Instruction::Move {
            dest: Register(reader.u16()?),
            src: Register(reader.u16()?),
        },
        3 => Instruction::GetUpvalue {
            dest: Register(reader.u16()?),
            upvalue: UpvalueId(reader.u16()?),
        },
        4 => Instruction::SetUpvalue {
            upvalue: UpvalueId(reader.u16()?),
            src: Register(reader.u16()?),
        },
        5 => Instruction::NewTable {
            dest: Register(reader.u16()?),
        },
        6 => Instruction::GetTable {
            dest: Register(reader.u16()?),
            table: Register(reader.u16()?),
            key: Register(reader.u16()?),
        },
        7 => Instruction::SetTable {
            table: Register(reader.u16()?),
            key: Register(reader.u16()?),
            value: Register(reader.u16()?),
        },
        8 => Instruction::UnaryOp {
            dest: Register(reader.u16()?),
            op: parse_unary(reader.u8()?, offset)?,
            src: Register(reader.u16()?),
        },
        9 => Instruction::BinaryOp {
            dest: Register(reader.u16()?),
            op: parse_binary(reader.u8()?, offset)?,
            left: Register(reader.u16()?),
            right: Register(reader.u16()?),
        },
        10 => Instruction::Jump {
            target: InstructionOffset(reader.u32()?),
        },
        11 => Instruction::JumpIfFalse {
            condition: Register(reader.u16()?),
            target: InstructionOffset(reader.u32()?),
        },
        12 => Instruction::Closure {
            dest: Register(reader.u16()?),
            proto: ProtoId(reader.u32()?),
        },
        13 => Instruction::Call {
            base: Register(reader.u16()?),
            arg_count: reader.u16()?,
            result_mode: read_result_mode(reader)?,
        },
        14 => Instruction::TailCall {
            base: Register(reader.u16()?),
            arg_count: reader.u16()?,
            result_mode: read_result_mode(reader)?,
        },
        15 => Instruction::Vararg {
            base: Register(reader.u16()?),
            result_mode: read_result_mode(reader)?,
        },
        16 => Instruction::Return {
            base: Register(reader.u16()?),
            result_mode: read_result_mode(reader)?,
        },
        17 => Instruction::Close {
            base: Register(reader.u16()?),
            count: reader.u16()?,
        },
        18 => Instruction::NumericForPrepare {
            control: Register(reader.u16()?),
            limit: Register(reader.u16()?),
            step: Register(reader.u16()?),
            visible: Register(reader.u16()?),
            exit: InstructionOffset(reader.u32()?),
        },
        19 => Instruction::NumericForNext {
            control: Register(reader.u16()?),
            limit: Register(reader.u16()?),
            step: Register(reader.u16()?),
            visible: Register(reader.u16()?),
            target: InstructionOffset(reader.u32()?),
            exit: InstructionOffset(reader.u32()?),
        },
        _ => return Err(verify(offset, "RVLU opcode 無效")),
    })
}

fn write_frame(writer: &mut Writer, frame: FrameLayout) {
    writer.u16(frame.register_limit);
    writer.u16(frame.initial_top.0);
    writer.u16(frame.dynamic_top.0);
    writer.u16(frame.return_base.0);
    writer.u16(frame.environment.0);
    match frame.environment_source {
        EnvironmentSource::RootExternal => writer.u8(0),
        EnvironmentSource::ParentFrame { parent, register } => {
            writer.u8(1);
            writer.u32(parent.0);
            writer.u16(register.0)
        }
        EnvironmentSource::ParentLocal { upvalue } => {
            writer.u8(2);
            writer.u16(upvalue.0)
        }
        EnvironmentSource::ParentUpvalue { upvalue } => {
            writer.u8(3);
            writer.u16(upvalue.0)
        }
    };
    writer.u8(u8::from(frame.registers_start_as_nil));
}
fn read_frame(reader: &mut Reader<'_>) -> Result<FrameLayout, BytecodeError> {
    let register_limit = reader.u16()?;
    let initial_top = Register(reader.u16()?);
    let dynamic_top = Register(reader.u16()?);
    let return_base = Register(reader.u16()?);
    let environment = Register(reader.u16()?);
    let offset = reader.location();
    let environment_source = match reader.u8()? {
        0 => EnvironmentSource::RootExternal,
        1 => EnvironmentSource::ParentFrame {
            parent: ProtoId(reader.u32()?),
            register: Register(reader.u16()?),
        },
        2 => EnvironmentSource::ParentLocal {
            upvalue: UpvalueId(reader.u16()?),
        },
        3 => EnvironmentSource::ParentUpvalue {
            upvalue: UpvalueId(reader.u16()?),
        },
        _ => return Err(verify(offset, "RVLU environment source 無效")),
    };
    let registers_start_as_nil = match reader.u8()? {
        0 => false,
        1 => true,
        _ => return Err(verify(reader.location() - 1, "RVLU frame nil flag 無效")),
    };
    Ok(FrameLayout {
        register_limit,
        initial_top,
        dynamic_top,
        return_base,
        environment,
        environment_source,
        registers_start_as_nil,
    })
}

fn write_close_path(writer: &mut Writer, close: &BytecodeClosePath) -> Result<(), BytecodeError> {
    writer.u8(exit_tag(close.kind));
    write_span(writer, close.span);
    writer.u32(close.from_scope);
    match close.target_scope {
        Some(scope) => {
            writer.u8(1);
            writer.u32(scope)
        }
        None => writer.u8(0),
    };
    writer.u32(checked_u32(
        close.bindings.len(),
        0,
        "RVLU close bindings 過大",
    )?);
    for binding in &close.bindings {
        write_binding(writer, *binding)
    }
    writer.u32(checked_u32(
        close.registers.len(),
        0,
        "RVLU close registers 過大",
    )?);
    for register in &close.registers {
        writer.u16(register.0)
    }
    Ok(())
}
fn read_close_path(
    reader: &mut Reader<'_>,
    limits: &VerifyLimits,
) -> Result<BytecodeClosePath, BytecodeError> {
    let offset = reader.location();
    let kind = parse_exit(reader.u8()?, offset)?;
    let span = read_span(reader)?;
    let from_scope = reader.u32()?;
    let target_scope = match reader.u8()? {
        0 => None,
        1 => Some(reader.u32()?),
        _ => {
            return Err(verify(
                reader.location() - 1,
                "RVLU close target scope 無效",
            ));
        }
    };
    let binding_count = reader.count(limits.max_constants, "RVLU close bindings 超過限制")?;
    let mut bindings = Vec::new();
    for _ in 0..binding_count {
        bindings.push(read_binding(reader)?)
    }
    let register_count = reader.count(
        limits.max_registers as usize,
        "RVLU close registers 超過限制",
    )?;
    let mut registers = Vec::new();
    for _ in 0..register_count {
        registers.push(Register(reader.u16()?))
    }
    if bindings.len() != registers.len() {
        return Err(verify(offset, "RVLU close bindings/registers 長度不符"));
    };
    Ok(BytecodeClosePath {
        kind,
        span,
        from_scope,
        target_scope,
        bindings,
        registers,
    })
}

fn write_span(writer: &mut Writer, span: BytecodeSpan) {
    writer.u64(span.start_byte);
    writer.u64(span.end_byte)
}
fn read_span(reader: &mut Reader<'_>) -> Result<BytecodeSpan, BytecodeError> {
    let start_byte = reader.u64()?;
    let end_byte = reader.u64()?;
    if start_byte > end_byte {
        return Err(verify(reader.location() - 16, "RVLU span 無效"));
    }
    Ok(BytecodeSpan {
        start_byte,
        end_byte,
    })
}
fn write_binding(writer: &mut Writer, binding: BytecodeBindingId) {
    writer.u32(binding.function);
    writer.u32(binding.ordinal)
}
fn read_binding(reader: &mut Reader<'_>) -> Result<BytecodeBindingId, BytecodeError> {
    Ok(BytecodeBindingId {
        function: reader.u32()?,
        ordinal: reader.u32()?,
    })
}
fn write_optional_proto(writer: &mut Writer, proto: Option<ProtoId>) {
    match proto {
        Some(proto) => {
            writer.u8(1);
            writer.u32(proto.0)
        }
        None => writer.u8(0),
    }
}
fn read_optional_proto(reader: &mut Reader<'_>) -> Result<Option<ProtoId>, BytecodeError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ProtoId(reader.u32()?))),
        _ => Err(verify(reader.location() - 1, "RVLU parent flag 無效")),
    }
}
fn write_result_mode(writer: &mut Writer, mode: ResultMode) {
    match mode {
        ResultMode::Fixed(count) => {
            writer.u8(0);
            writer.u16(count)
        }
        ResultMode::All => writer.u8(1),
    }
}
fn read_result_mode(reader: &mut Reader<'_>) -> Result<ResultMode, BytecodeError> {
    match reader.u8()? {
        0 => Ok(ResultMode::Fixed(reader.u16()?)),
        1 => Ok(ResultMode::All),
        _ => Err(verify(reader.location() - 1, "RVLU result mode 無效")),
    }
}
fn profile_tag(profile: LuaProfile) -> u8 {
    match profile {
        LuaProfile::Lua55 => 0,
        LuaProfile::Lua54 => 1,
    }
}
fn parse_profile(tag: u8, offset: usize) -> Result<LuaProfile, BytecodeError> {
    match tag {
        0 => Ok(LuaProfile::Lua55),
        1 => Ok(LuaProfile::Lua54),
        _ => Err(verify(offset, "RVLU profile tag 無效")),
    }
}
fn unary_tag(op: UnaryOperation) -> u8 {
    match op {
        UnaryOperation::Negate => 0,
        UnaryOperation::Not => 1,
        UnaryOperation::Length => 2,
        UnaryOperation::BitNot => 3,
    }
}
fn parse_unary(tag: u8, offset: usize) -> Result<UnaryOperation, BytecodeError> {
    match tag {
        0 => Ok(UnaryOperation::Negate),
        1 => Ok(UnaryOperation::Not),
        2 => Ok(UnaryOperation::Length),
        3 => Ok(UnaryOperation::BitNot),
        _ => Err(verify(offset, "RVLU unary op 無效")),
    }
}
fn binary_tag(op: BinaryOperation) -> u8 {
    match op {
        BinaryOperation::Or => 0,
        BinaryOperation::And => 1,
        BinaryOperation::Equal => 2,
        BinaryOperation::NotEqual => 3,
        BinaryOperation::Less => 4,
        BinaryOperation::LessEqual => 5,
        BinaryOperation::Greater => 6,
        BinaryOperation::GreaterEqual => 7,
        BinaryOperation::Pipe => 8,
        BinaryOperation::BitXor => 9,
        BinaryOperation::Ampersand => 10,
        BinaryOperation::ShiftLeft => 11,
        BinaryOperation::ShiftRight => 12,
        BinaryOperation::Concat => 13,
        BinaryOperation::Add => 14,
        BinaryOperation::Subtract => 15,
        BinaryOperation::Multiply => 16,
        BinaryOperation::Divide => 17,
        BinaryOperation::FloorDivide => 18,
        BinaryOperation::Modulo => 19,
        BinaryOperation::Power => 20,
    }
}
fn parse_binary(tag: u8, offset: usize) -> Result<BinaryOperation, BytecodeError> {
    match tag {
        0 => Ok(BinaryOperation::Or),
        1 => Ok(BinaryOperation::And),
        2 => Ok(BinaryOperation::Equal),
        3 => Ok(BinaryOperation::NotEqual),
        4 => Ok(BinaryOperation::Less),
        5 => Ok(BinaryOperation::LessEqual),
        6 => Ok(BinaryOperation::Greater),
        7 => Ok(BinaryOperation::GreaterEqual),
        8 => Ok(BinaryOperation::Pipe),
        9 => Ok(BinaryOperation::BitXor),
        10 => Ok(BinaryOperation::Ampersand),
        11 => Ok(BinaryOperation::ShiftLeft),
        12 => Ok(BinaryOperation::ShiftRight),
        13 => Ok(BinaryOperation::Concat),
        14 => Ok(BinaryOperation::Add),
        15 => Ok(BinaryOperation::Subtract),
        16 => Ok(BinaryOperation::Multiply),
        17 => Ok(BinaryOperation::Divide),
        18 => Ok(BinaryOperation::FloorDivide),
        19 => Ok(BinaryOperation::Modulo),
        20 => Ok(BinaryOperation::Power),
        _ => Err(verify(offset, "RVLU binary op 無效")),
    }
}
fn exit_tag(kind: BytecodeExitKind) -> u8 {
    match kind {
        BytecodeExitKind::Normal => 0,
        BytecodeExitKind::Return => 1,
        BytecodeExitKind::Break => 2,
        BytecodeExitKind::Goto => 3,
        BytecodeExitKind::Error => 4,
    }
}
fn parse_exit(tag: u8, offset: usize) -> Result<BytecodeExitKind, BytecodeError> {
    match tag {
        0 => Ok(BytecodeExitKind::Normal),
        1 => Ok(BytecodeExitKind::Return),
        2 => Ok(BytecodeExitKind::Break),
        3 => Ok(BytecodeExitKind::Goto),
        4 => Ok(BytecodeExitKind::Error),
        _ => Err(verify(offset, "RVLU close exit kind 無效")),
    }
}

#[derive(Default)]
struct Writer {
    bytes: Vec<u8>,
}
impl Writer {
    fn u8(&mut self, value: u8) {
        self.bytes.push(value)
    }
    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes())
    }
    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes())
    }
    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes())
    }
    fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes())
    }
    fn bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value)
    }
    fn blob(&mut self, value: &[u8]) -> Result<(), BytecodeError> {
        self.u32(checked_u32(value.len(), 0, "RVLU blob 過大")?);
        self.bytes(value);
        Ok(())
    }
}
struct Section<'a> {
    bytes: &'a [u8],
    start: usize,
}
struct Reader<'a> {
    bytes: &'a [u8],
    base: usize,
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self::new_at(bytes, 0)
    }
    fn new_at(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            offset: 0,
        }
    }
    fn location(&self) -> usize {
        self.base.checked_add(self.offset).unwrap_or(usize::MAX)
    }
    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], BytecodeError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or_else(|| verify(self.location(), "RVLU offset overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| verify(self.location(), "RVLU bytes 截斷"))?;
        self.offset = end;
        Ok(value)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], BytecodeError> {
        let bytes = self.take(N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, BytecodeError> {
        Ok(self.fixed::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, BytecodeError> {
        Ok(u16::from_le_bytes(self.fixed()?))
    }
    fn u32(&mut self) -> Result<u32, BytecodeError> {
        Ok(u32::from_le_bytes(self.fixed()?))
    }
    fn u64(&mut self) -> Result<u64, BytecodeError> {
        Ok(u64::from_le_bytes(self.fixed()?))
    }
    fn i64(&mut self) -> Result<i64, BytecodeError> {
        Ok(i64::from_le_bytes(self.fixed()?))
    }
    fn count(&mut self, limit_value: usize, message: &str) -> Result<usize, BytecodeError> {
        let offset = self.location();
        let count = usize::try_from(self.u32()?).map_err(|_| limit(offset, message))?;
        if count > limit_value {
            return Err(limit(offset, message));
        }
        Ok(count)
    }
    fn blob(&mut self) -> Result<Vec<u8>, BytecodeError> {
        let offset = self.location();
        let len = usize::try_from(self.u32()?).map_err(|_| limit(offset, "RVLU blob 過大"))?;
        Ok(self.take(len)?.to_vec())
    }
    fn section(&mut self) -> Result<Section<'a>, BytecodeError> {
        let offset = self.location();
        let len =
            usize::try_from(self.u32()?).map_err(|_| limit(offset, "RVLU section 長度過大"))?;
        let start = self.location();
        let bytes = self.take(len)?;
        Ok(Section { bytes, start })
    }
}
fn checked_u32(value: usize, offset: usize, message: &str) -> Result<u32, BytecodeError> {
    u32::try_from(value).map_err(|_| limit(offset, message))
}
fn verify(offset: usize, message: &str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::Verify,
        offset,
        message: message.into(),
    }
}
fn limit(offset: usize, message: &str) -> BytecodeError {
    BytecodeError {
        code: BytecodeErrorCode::CompileLimit,
        offset,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_instruction_offsets(bytes: &[u8]) -> (usize, usize) {
        let mut module_reader = Reader::new(bytes);
        module_reader.take(4).unwrap();
        module_reader.u16().unwrap();
        module_reader.u8().unwrap();
        module_reader.u8().unwrap();
        read_span(&mut module_reader).unwrap();
        let prototypes = module_reader.section().unwrap();
        let mut prototypes_reader = Reader::new_at(prototypes.bytes, prototypes.start);
        prototypes_reader.u32().unwrap();
        let record = prototypes_reader.section().unwrap();
        let mut record_reader = Reader::new_at(record.bytes, record.start);
        record_reader.u32().unwrap();
        record_reader.u32().unwrap();
        read_optional_proto(&mut record_reader).unwrap();
        read_span(&mut record_reader).unwrap();
        record_reader.u16().unwrap();
        record_reader.u16().unwrap();
        record_reader.u8().unwrap();
        record_reader.u8().unwrap();
        read_frame(&mut record_reader).unwrap();
        record_reader.u16().unwrap();
        read_binding(&mut record_reader).unwrap();
        record_reader.section().unwrap();
        let instructions = record_reader.section().unwrap();
        let mut instructions_reader = Reader::new_at(instructions.bytes, instructions.start);
        instructions_reader.u32().unwrap();
        let instruction_offset = instructions_reader.location();
        read_instruction(&mut instructions_reader).unwrap();
        let effect_offset = instructions_reader.location();
        (instruction_offset, effect_offset)
    }

    fn assert_high_count_operand_is_rejected(module: BytecodeModule, relative_offset: usize) {
        let limits = VerifyLimits::default();
        let encoded = encode_module(module.clone(), LuaProfile::Lua55, &limits).unwrap();
        let mut bytes = encoded.bytes().to_vec();
        let (instruction_offset, _) = first_instruction_offsets(&bytes);
        bytes[instruction_offset + relative_offset..instruction_offset + relative_offset + 2]
            .copy_from_slice(&u16::MAX.to_le_bytes());
        let error = decode_module(&bytes, LuaProfile::Lua55, &limits)
            .expect_err("高計數 operand 必須在驗證成功前拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
    }

    fn sample() -> BytecodeModule {
        BytecodeModule {
            format_version: RVLU_V2,
            profile: LuaProfile::Lua55,
            numeric_config: RVLU_NUMERIC_I64_F64,
            span: BytecodeSpan {
                start_byte: 0,
                end_byte: 10,
            },
            function_prototypes: vec![(0, ProtoId(0))],
            prototypes: vec![BytecodePrototype {
                id: ProtoId(0),
                function: 0,
                parent: None,
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 10,
                },
                register_count: 2,
                parameter_count: 0,
                is_variadic: false,
                named_vararg: None,
                frame: FrameLayout {
                    register_limit: 2,
                    initial_top: Register(2),
                    dynamic_top: Register(2),
                    return_base: Register(0),
                    environment: Register(1),
                    environment_source: EnvironmentSource::RootExternal,
                    registers_start_as_nil: true,
                },
                global_environment: Register(1),
                global_environment_binding: BytecodeBindingId {
                    function: 0,
                    ordinal: 0,
                },
                binding_registers: vec![(
                    BytecodeBindingId {
                        function: 0,
                        ordinal: 0,
                    },
                    Register(1),
                )],
                constants: vec![BytecodeConstant::Integer(1)],
                upvalues: vec![],
                instructions: vec![
                    BytecodeInstruction {
                        instruction: Instruction::LoadConst {
                            dest: Register(0),
                            constant: super::super::ConstId(0),
                        },
                        span: BytecodeSpan {
                            start_byte: 0,
                            end_byte: 8,
                        },
                        close_path: None,
                    },
                    BytecodeInstruction {
                        instruction: Instruction::Return {
                            base: Register(0),
                            result_mode: ResultMode::Fixed(1),
                        },
                        span: BytecodeSpan {
                            start_byte: 0,
                            end_byte: 10,
                        },
                        close_path: None,
                    },
                ],
                close_paths: vec![],
            }],
        }
    }

    #[test]
    fn rvlu_roundtrip_is_little_endian_and_verified() {
        let limits = VerifyLimits::default();
        let encoded = encode_module(sample(), LuaProfile::Lua55, &limits).unwrap();
        assert_eq!(&encoded.bytes()[..4], &RVLU_MAGIC);
        assert_eq!(&encoded.bytes()[4..6], &RVLU_V2.0.to_le_bytes());
        assert_eq!(encoded.verified().format_version(), RVLU_V2);
        let decoded = decode_module(encoded.bytes(), LuaProfile::Lua55, &limits).unwrap();
        assert_eq!(decoded.module(), encoded.verified().module());
    }

    #[test]
    fn decoder_rejects_high_count_loadnil_and_call_result_operands() {
        let mut load_nil = sample();
        load_nil.prototypes[0].instructions[0].instruction = Instruction::LoadNil {
            start: Register(0),
            count: 1,
        };
        assert_high_count_operand_is_rejected(load_nil, 3);

        let mut call_arguments = sample();
        call_arguments.prototypes[0].instructions[0].instruction = Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::Fixed(0),
        };
        assert_high_count_operand_is_rejected(call_arguments.clone(), 3);
        assert_high_count_operand_is_rejected(call_arguments, 6);
    }

    #[test]
    fn decoder_rejects_high_count_tailcall_vararg_and_return_operands() {
        let mut tail_call = sample();
        tail_call.prototypes[0].instructions[0].instruction = Instruction::TailCall {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::Fixed(0),
        };
        assert_high_count_operand_is_rejected(tail_call.clone(), 3);
        assert_high_count_operand_is_rejected(tail_call, 6);

        let mut vararg = sample();
        vararg.prototypes[0].is_variadic = true;
        vararg.prototypes[0].instructions[0].instruction = Instruction::Vararg {
            base: Register(0),
            result_mode: ResultMode::Fixed(1),
        };
        assert_high_count_operand_is_rejected(vararg, 4);

        let mut return_ = sample();
        return_.prototypes[0].instructions[0].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::Fixed(1),
        };
        assert_high_count_operand_is_rejected(return_, 4);
    }

    #[test]
    fn decoder_accepts_canonical_effect_flags_and_rejects_unknown_or_mismatched_flags() {
        let limits = VerifyLimits::default();
        let encoded = encode_module(sample(), LuaProfile::Lua55, &limits).unwrap();
        let mut bytes = encoded.bytes().to_vec();
        let (_, effect_offset) = first_instruction_offsets(&bytes);
        assert!(decode_module(&bytes, LuaProfile::Lua55, &limits).is_ok());

        bytes[effect_offset] = InstructionEffects::KNOWN_FLAGS + 1;
        let error = decode_module(&bytes, LuaProfile::Lua55, &limits)
            .expect_err("未知 effect flag 必須拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("未知 bit"));

        bytes[effect_offset] = InstructionEffects::ALLOCATES;
        let error = decode_module(&bytes, LuaProfile::Lua55, &limits)
            .expect_err("已知但矛盾的 effect flag 必須拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("canonical"));
    }

    #[test]
    fn verifier_rejects_bad_operands_cfg_top_and_close_metadata() {
        let limits = VerifyLimits::default();
        let mut bad_constant = sample();
        bad_constant.prototypes[0].instructions[0].instruction = Instruction::LoadConst {
            dest: Register(0),
            constant: super::super::ConstId(1),
        };
        assert_eq!(
            verify_module(bad_constant, LuaProfile::Lua55, &limits)
                .expect_err("const index 必須拒絕")
                .code,
            BytecodeErrorCode::Verify
        );

        let mut bad_upvalue = sample();
        bad_upvalue.prototypes[0].instructions[0].instruction = Instruction::GetUpvalue {
            dest: Register(0),
            upvalue: UpvalueId(0),
        };
        assert!(verify_module(bad_upvalue, LuaProfile::Lua55, &limits).is_err());

        let mut bad_child = sample();
        bad_child.prototypes[0].instructions[0].instruction = Instruction::Closure {
            dest: Register(0),
            proto: ProtoId(9),
        };
        assert!(verify_module(bad_child, LuaProfile::Lua55, &limits).is_err());

        let mut self_jump = sample();
        self_jump.prototypes[0].instructions[0].instruction = Instruction::Jump {
            target: InstructionOffset(0),
        };
        assert!(verify_module(self_jump, LuaProfile::Lua55, &limits).is_err());

        let mut fallthrough = sample();
        fallthrough.prototypes[0].instructions.pop();
        assert!(verify_module(fallthrough, LuaProfile::Lua55, &limits).is_err());

        let mut valid_open = sample();
        valid_open.prototypes[0].instructions[0].instruction = Instruction::Call {
            base: Register(0),
            arg_count: 0,
            result_mode: ResultMode::All,
        };
        valid_open.prototypes[0].instructions[1].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::All,
        };
        verify_module(valid_open, LuaProfile::Lua55, &limits)
            .expect("open result 只流向 Return(All) 必須合法");

        let mut open_without_consumer = sample();
        open_without_consumer.prototypes[0].instructions[1].instruction = Instruction::Return {
            base: Register(0),
            result_mode: ResultMode::All,
        };
        assert!(verify_module(open_without_consumer, LuaProfile::Lua55, &limits).is_err());

        let mut bad_top = sample();
        bad_top.prototypes[0].frame.dynamic_top = Register(1);
        assert!(verify_module(bad_top, LuaProfile::Lua55, &limits).is_err());

        let mut bad_close = sample();
        bad_close.prototypes[0].instructions.insert(
            1,
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(1),
                    count: 1,
                },
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 10,
                },
                close_path: None,
            },
        );
        assert!(verify_module(bad_close, LuaProfile::Lua55, &limits).is_err());

        let instruction_limited = VerifyLimits {
            max_instructions: 1,
            ..limits
        };
        assert_eq!(
            verify_module(sample(), LuaProfile::Lua55, &instruction_limited)
                .expect_err("instruction/worklist 限額必須拒絕")
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn verifier_accepts_last_register_zero_arg_call_and_rejects_true_overflow() {
        let limits = VerifyLimits::default();
        let mut last_register = sample();
        last_register.prototypes[0].instructions[0].instruction = Instruction::Call {
            base: Register(1),
            arg_count: 0,
            result_mode: ResultMode::Fixed(0),
        };
        verify_module(last_register, LuaProfile::Lua55, &limits)
            .expect("base 位於 frame 最後 register 的 zero-argument Call 必須合法");

        let mut overflowing = sample();
        overflowing.prototypes[0].instructions[0].instruction = Instruction::Call {
            base: Register(1),
            arg_count: 1,
            result_mode: ResultMode::Fixed(0),
        };
        assert_eq!(
            verify_module(overflowing, LuaProfile::Lua55, &limits)
                .expect_err("base + arg_count 越界必須拒絕")
                .code,
            BytecodeErrorCode::Verify
        );
    }

    #[test]
    fn verifier_rejects_numeric_for_next_without_matching_prepare() {
        let limits = VerifyLimits::default();
        let mut malformed = sample();
        let prototype = &mut malformed.prototypes[0];
        prototype.register_count = 4;
        prototype.frame.register_limit = 4;
        prototype.frame.initial_top = Register(4);
        prototype.frame.dynamic_top = Register(4);
        prototype.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::LoadNil {
                    start: Register(0),
                    count: 1,
                },
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 1,
                },
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::NumericForNext {
                    control: Register(0),
                    limit: Register(1),
                    step: Register(2),
                    visible: Register(3),
                    target: InstructionOffset(0),
                    exit: InstructionOffset(2),
                },
                span: BytecodeSpan {
                    start_byte: 1,
                    end_byte: 2,
                },
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
                span: BytecodeSpan {
                    start_byte: 2,
                    end_byte: 3,
                },
                close_path: None,
            },
        ];
        let error = verify_module(malformed, LuaProfile::Lua55, &limits)
            .expect_err("沒有 NumericForPrepare 的 Next 必須拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("NumericForNext"));
    }

    #[test]
    fn verifier_requires_numeric_for_prepare_on_every_next_path() {
        let limits = VerifyLimits::default();
        let mut module = sample();
        let prototype = &mut module.prototypes[0];
        prototype.register_count = 4;
        prototype.frame.register_limit = 4;
        prototype.frame.initial_top = Register(4);
        prototype.frame.dynamic_top = Register(4);
        prototype.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::Jump {
                    target: InstructionOffset(1),
                },
                span: prototype.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::NumericForPrepare {
                    control: Register(0),
                    limit: Register(1),
                    step: Register(2),
                    visible: Register(3),
                    exit: InstructionOffset(4),
                },
                span: prototype.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Move {
                    dest: Register(3),
                    src: Register(3),
                },
                span: prototype.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::NumericForNext {
                    control: Register(0),
                    limit: Register(1),
                    step: Register(2),
                    visible: Register(3),
                    target: InstructionOffset(2),
                    exit: InstructionOffset(4),
                },
                span: prototype.span,
                close_path: None,
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(0),
                },
                span: prototype.span,
                close_path: None,
            },
        ];
        verify_module(module.clone(), LuaProfile::Lua55, &limits)
            .expect("Prepare body entry 與 Next 回邊應合法");
        let mut exit_bypass = module.clone();
        exit_bypass.prototypes[0].instructions[4].instruction = Instruction::Jump {
            target: InstructionOffset(2),
        };
        let error = verify_module(exit_bypass, LuaProfile::Lua55, &limits)
            .expect_err("Prepare 的 exit 分支不可回跳至 Next body");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("NumericForNext"));
        module.prototypes[0].instructions[0].instruction = Instruction::Jump {
            target: InstructionOffset(2),
        };
        let error = verify_module(module, LuaProfile::Lua55, &limits)
            .expect_err("從入口跳過 Prepare 進入 Next 必須拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert!(error.message.contains("NumericForNext"));
    }

    #[test]
    fn verifier_and_decoder_reject_vararg_in_non_variadic_prototype() {
        let limits = VerifyLimits::default();
        let mut module = sample();
        module.prototypes[0].instructions[0].instruction = Instruction::Vararg {
            base: Register(0),
            result_mode: ResultMode::Fixed(1),
        };
        let error = verify_module(module.clone(), LuaProfile::Lua55, &limits)
            .expect_err("非 variadic prototype 不可含 Vararg");
        assert_eq!(error.code, BytecodeErrorCode::Verify);

        module.prototypes[0].is_variadic = true;
        let encoded = encode_module(module, LuaProfile::Lua55, &limits)
            .expect("variadic prototype 可使用 Vararg");
        let mut bytes = encoded.bytes().to_vec();
        let mut module_reader = Reader::new(&bytes);
        module_reader.take(4).unwrap();
        module_reader.u16().unwrap();
        module_reader.u8().unwrap();
        module_reader.u8().unwrap();
        read_span(&mut module_reader).unwrap();
        let prototypes = module_reader.section().unwrap();
        let mut prototypes_reader = Reader::new_at(prototypes.bytes, prototypes.start);
        prototypes_reader.u32().unwrap();
        let record = prototypes_reader.section().unwrap();
        let mut record_reader = Reader::new_at(record.bytes, record.start);
        record_reader.u32().unwrap();
        record_reader.u32().unwrap();
        read_optional_proto(&mut record_reader).unwrap();
        read_span(&mut record_reader).unwrap();
        record_reader.u16().unwrap();
        record_reader.u16().unwrap();
        let variadic_flag_offset = record_reader.location();
        bytes[variadic_flag_offset] = 0;
        let error = decode_module(&bytes, LuaProfile::Lua55, &limits)
            .expect_err("decode 不可接受非 variadic prototype 的 Vararg");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
    }

    #[test]
    fn verifier_distinguishes_normal_close_from_pending_return_close() {
        let limits = VerifyLimits::default();
        let mut module = sample();
        let prototype = &mut module.prototypes[0];
        prototype.register_count = 3;
        prototype.frame.register_limit = 3;
        prototype.frame.initial_top = Register(3);
        prototype.frame.dynamic_top = Register(3);
        let binding = BytecodeBindingId {
            function: 0,
            ordinal: 1,
        };
        prototype.binding_registers.push((binding, Register(2)));
        let path = BytecodeClosePath {
            kind: BytecodeExitKind::Normal,
            span: prototype.span,
            from_scope: 1,
            target_scope: Some(0),
            bindings: vec![binding],
            registers: vec![Register(2)],
        };
        prototype.close_paths.push(path.clone());
        prototype.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 1,
                },
                span: prototype.span,
                close_path: Some(path),
            },
            BytecodeInstruction {
                instruction: Instruction::TailCall {
                    base: Register(0),
                    arg_count: 0,
                    result_mode: ResultMode::All,
                },
                span: prototype.span,
                close_path: None,
            },
        ];
        verify_module(module.clone(), LuaProfile::Lua55, &limits)
            .expect("正常區塊 Close 後的 TailCall 應合法");
        module.prototypes[0].close_paths[0].kind = BytecodeExitKind::Return;
        module.prototypes[0].instructions[0]
            .close_path
            .as_mut()
            .unwrap()
            .kind = BytecodeExitKind::Return;
        let error = verify_module(module, LuaProfile::Lua55, &limits)
            .expect_err("pending Return ClosePath 不可接 TailCall");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
    }

    #[test]
    fn verifier_requires_exact_contiguous_close_path_order() {
        let limits = VerifyLimits::default();
        let mut module = sample();
        let prototype = &mut module.prototypes[0];
        prototype.register_count = 3;
        prototype.frame.register_limit = 3;
        prototype.frame.initial_top = Register(3);
        prototype.frame.dynamic_top = Register(3);
        let inner = BytecodeBindingId {
            function: 0,
            ordinal: 1,
        };
        prototype.binding_registers.push((inner, Register(2)));
        let path = BytecodeClosePath {
            kind: BytecodeExitKind::Return,
            span: BytecodeSpan {
                start_byte: 0,
                end_byte: 10,
            },
            from_scope: 1,
            target_scope: None,
            bindings: vec![inner, prototype.global_environment_binding],
            registers: vec![Register(2), Register(1)],
        };
        prototype.close_paths.push(path.clone());
        prototype.instructions = vec![
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(1),
                    count: 1,
                },
                span: path.span,
                close_path: Some(path.clone()),
            },
            BytecodeInstruction {
                instruction: Instruction::Close {
                    base: Register(2),
                    count: 1,
                },
                span: path.span,
                close_path: Some(path),
            },
            BytecodeInstruction {
                instruction: Instruction::Return {
                    base: Register(0),
                    result_mode: ResultMode::Fixed(1),
                },
                span: BytecodeSpan {
                    start_byte: 0,
                    end_byte: 10,
                },
                close_path: None,
            },
        ];
        assert!(verify_module(module, LuaProfile::Lua55, &limits).is_err());
    }

    #[test]
    fn verifier_applies_instruction_and_constant_limits_to_whole_module() {
        let limits = VerifyLimits {
            max_instructions: 3,
            max_constants: 1,
            ..VerifyLimits::default()
        };
        let mut module = sample();
        let mut child = module.prototypes[0].clone();
        child.id = ProtoId(1);
        child.function = 1;
        child.parent = Some(ProtoId(0));
        child.frame.environment_source = EnvironmentSource::ParentFrame {
            parent: ProtoId(0),
            register: Register(1),
        };
        module.prototypes.push(child);
        module.function_prototypes.push((1, ProtoId(1)));
        assert_eq!(
            verify_module(module.clone(), LuaProfile::Lua55, &limits)
                .expect_err("跨 prototype instruction/constant 總量必須拒絕")
                .code,
            BytecodeErrorCode::CompileLimit
        );
        let encoded = encode_module(module, LuaProfile::Lua55, &VerifyLimits::default()).unwrap();
        assert_eq!(
            decode_module(encoded.bytes(), LuaProfile::Lua55, &limits)
                .expect_err("decode 必須在累計配置前套用剩餘總量")
                .code,
            BytecodeErrorCode::CompileLimit
        );
    }

    #[test]
    fn rvlu_rejects_unknown_opcode_with_actual_instruction_offset() {
        let limits = VerifyLimits::default();
        let encoded = encode_module(sample(), LuaProfile::Lua55, &limits).unwrap();
        let mut bytes = encoded.bytes().to_vec();
        let mut module_reader = Reader::new(&bytes);
        module_reader.take(4).unwrap();
        module_reader.u16().unwrap();
        module_reader.u8().unwrap();
        module_reader.u8().unwrap();
        read_span(&mut module_reader).unwrap();
        let prototypes = module_reader.section().unwrap();
        let mut prototypes_reader = Reader::new_at(prototypes.bytes, prototypes.start);
        prototypes_reader.u32().unwrap();
        let record = prototypes_reader.section().unwrap();
        let mut record_reader = Reader::new_at(record.bytes, record.start);
        record_reader.u32().unwrap();
        record_reader.u32().unwrap();
        read_optional_proto(&mut record_reader).unwrap();
        read_span(&mut record_reader).unwrap();
        record_reader.u16().unwrap();
        read_frame(&mut record_reader).unwrap();
        record_reader.u16().unwrap();
        read_binding(&mut record_reader).unwrap();
        record_reader.section().unwrap();
        let instructions = record_reader.section().unwrap();
        let mut instructions_reader = Reader::new_at(instructions.bytes, instructions.start);
        instructions_reader.u32().unwrap();
        let opcode_offset = instructions_reader.location();
        bytes[opcode_offset] = 0xff;
        let error =
            decode_module(&bytes, LuaProfile::Lua55, &limits).expect_err("unknown opcode 必須拒絕");
        assert_eq!(error.code, BytecodeErrorCode::Verify);
        assert_eq!(error.offset, opcode_offset);
    }

    #[test]
    fn rvlu_rejects_header_section_and_limit_failures_without_panic() {
        let limits = VerifyLimits::default();
        let encoded = encode_module(sample(), LuaProfile::Lua55, &limits).unwrap();
        for (offset, value) in [(0, 0xff), (4, 3), (6, 1), (7, 0)] {
            let mut bytes = encoded.bytes().to_vec();
            bytes[offset] = value;
            assert_eq!(
                decode_module(&bytes, LuaProfile::Lua55, &limits)
                    .expect_err("損壞 RVLU header 必須拒絕")
                    .code,
                BytecodeErrorCode::Verify
            );
        }
        let mut v1 = encoded.bytes().to_vec();
        v1[4..6].copy_from_slice(&RVLU_V1.0.to_le_bytes());
        assert_eq!(
            decode_module(&v1, LuaProfile::Lua55, &limits)
                .expect_err("RVLU v1 必須明確拒絕")
                .code,
            BytecodeErrorCode::Verify
        );
        let mut oversized_section = encoded.bytes().to_vec();
        oversized_section[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_module(&oversized_section, LuaProfile::Lua55, &limits)
                .expect_err("溢位 section 長度必須拒絕")
                .code,
            BytecodeErrorCode::Verify
        );
        let restricted = VerifyLimits {
            max_module_bytes: encoded.bytes().len() - 1,
            ..limits
        };
        assert_eq!(
            decode_module(encoded.bytes(), LuaProfile::Lua55, &restricted)
                .expect_err("module bytes 限額必須在讀取前拒絕")
                .code,
            BytecodeErrorCode::CompileLimit
        );
        for length in 0..encoded.bytes().len() {
            assert!(decode_module(&encoded.bytes()[..length], LuaProfile::Lua55, &limits).is_err());
        }
    }
}
