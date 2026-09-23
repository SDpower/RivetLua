//! P05 owned typed IR；只保存 P04 resolved tree 降階結果，尚未封裝 bytecode 或執行。

use crate::{BindingId, ExitKind, FunctionId, Literal, ScopeId, Span, UpvalueSource};
use rivetlua_core::{FrameLayout, Instruction, LuaProfile, ProtoId, Register, UpvalueId};

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
