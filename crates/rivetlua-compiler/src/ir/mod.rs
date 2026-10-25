//! P05 owned typed IR；只保存 P04 resolved tree 降階結果，尚未封裝 bytecode 或執行。

use crate::{BindingId, ExitKind, FunctionId, Literal, ScopeId, Span, UpvalueSource};
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{SharedBlock, StateAllocator};
use rivetlua_core::{
    FrameLayout, Instruction, InstructionOffset, LuaProfile, ProtoId, Register, UpvalueId,
};

#[derive(Clone, Debug, PartialEq)]
pub enum IrConstant {
    Literal(Literal),
    Boolean(bool),
    Name(crate::ast::AstName),
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrInstruction {
    pub instruction: Instruction,
    pub span: Span,
    pub close_path: Option<IrClosePath>,
}

pub type IrVec<T> = AllocVec<T, StateAllocator>;
pub type IrClosePath = SharedBlock<IrClosePathData>;

#[derive(Debug, PartialEq)]
pub struct IrClosePathData {
    pub kind: ExitKind,
    pub span: Span,
    pub from_scope: ScopeId,
    pub target_scope: Option<ScopeId>,
    pub bindings: IrVec<BindingId>,
    pub registers: IrVec<Register>,
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
    pub locals: IrVec<IrNativeLocal>,
    pub temporaries: IrVec<IrNativeTemporary>,
    pub initializer_temporaries: IrVec<IrNativeInitializerTemporary>,
    pub non_counted_pcs: IrVec<InstructionOffset>,
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
    pub binding_registers: IrVec<(BindingId, Register)>,
    pub constants: IrVec<IrConstant>,
    pub upvalues: IrVec<IrUpvalue>,
    pub instructions: IrVec<IrInstruction>,
    pub close_paths: IrVec<IrClosePath>,
    pub native_debug: Option<IrNativeDebug>,
    pub native_list_write_upvalue: Option<UpvalueId>,
    pub native_list_writes: IrVec<IrNativeListWrite>,
    pub native_global_nil_check_upvalue: Option<UpvalueId>,
    pub native_global_nil_checks: IrVec<(InstructionOffset, Register)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IrModule {
    pub profile: LuaProfile,
    pub span: Span,
    pub function_prototypes: IrVec<(FunctionId, ProtoId)>,
    pub prototypes: IrVec<IrPrototype>,
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
