//! P05 owned typed IR；只保存 P04 resolved tree 降階結果，尚未封裝 bytecode 或執行。

use crate::{BindingId, ExitKind, FunctionId, Literal, ScopeId, Span, UpvalueSource};
use rivetlua_core::{
    FrameLayout, Instruction, InstructionOffset, LuaProfile, ProtoId, Register, UpvalueId,
};

#[derive(Clone, Debug, PartialEq)]
pub enum IrConstant {
    Literal(Literal),
    Boolean(bool),
    Name(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrInstruction {
    pub instruction: Instruction,
    pub span: Span,
    pub close_path: Option<IrClosePath>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrClosePath {
    pub kind: ExitKind,
    pub span: Span,
    pub from_scope: ScopeId,
    pub target_scope: Option<ScopeId>,
    pub bindings: Vec<BindingId>,
    pub registers: Vec<Register>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrUpvalue {
    pub id: UpvalueId,
    pub source: UpvalueSource,
}

/// 僅供 P05 native debug sidecar 使用；不屬於 RVLU_V2 wire。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrNativeLocal {
    pub binding: BindingId,
    pub register: Register,
    pub slot: u16,
    pub initialized_pc: u32,
    pub start_pc: u32,
    pub end_pc: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IrNativeDebug {
    pub locals: Vec<IrNativeLocal>,
    pub temporaries: Vec<IrNativeTemporary>,
    pub initializer_temporaries: Vec<IrNativeInitializerTemporary>,
    pub non_counted_pcs: Vec<InstructionOffset>,
    pub max_active_locals: u16,
}

/// 在 child Call 暫停時仍由父表達式持有的語意結果；不屬於 wire。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrNativeTemporary {
    pub call_pc: InstructionOffset,
    pub ordinal: u16,
    pub register: Register,
}

/// local 初始化期間已保留但尚未取得名稱的 guest slot；不屬於 wire。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrNativeInitializerTemporary {
    pub binding: BindingId,
    pub register: Register,
    pub slot: u16,
    pub start_pc: u32,
    pub end_pc: u32,
}

/// 已編譯的 native RawListWrite 呼叫宣告；P05 仍須對 bytecode 重新驗證。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IrNativeListWrite {
    pub call_pc: InstructionOffset,
    pub function_register: Register,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrPrototype {
    pub id: ProtoId,
    pub function: FunctionId,
    pub parent: Option<ProtoId>,
    pub span: Span,
    pub register_count: u16,
    pub parameter_count: u16,
    pub is_variadic: bool,
    pub named_vararg: Option<(BindingId, Register)>,
    pub frame: FrameLayout,
    pub global_environment: Register,
    pub global_environment_binding: BindingId,
    pub binding_registers: Vec<(BindingId, Register)>,
    pub constants: Vec<IrConstant>,
    pub upvalues: Vec<IrUpvalue>,
    pub instructions: Vec<IrInstruction>,
    pub close_paths: Vec<IrClosePath>,
    pub native_debug: Option<IrNativeDebug>,
    pub native_list_write_upvalue: Option<UpvalueId>,
    pub native_list_writes: Vec<IrNativeListWrite>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrModule {
    pub profile: LuaProfile,
    pub span: Span,
    pub function_prototypes: Vec<(FunctionId, ProtoId)>,
    pub prototypes: Vec<IrPrototype>,
}

impl IrModule {
    pub fn proto_id_for(&self, function: FunctionId) -> Option<ProtoId> {
        self.function_prototypes
            .iter()
            .find_map(|(candidate, proto)| (*candidate == function).then_some(*proto))
    }

    pub fn prototype_for(&self, function: FunctionId) -> Option<&IrPrototype> {
        let id = self.proto_id_for(function)?;
        self.prototypes.iter().find(|prototype| prototype.id == id)
    }
}
