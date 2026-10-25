//! P11 的 Lua 錯誤值、受保護呼叫邊界與三個必要內建入口。

use rivetlua_alloc::SharedBlock;

use rivetlua_core::{ObjectRef, Register, ResultMode, Value};

use crate::call::PendingCloseSnapshot;
use crate::roots::StackRoot;
use crate::stdlib::basic::BasicBuiltin;
use crate::stdlib::debug::DebugBuiltin;
use crate::stdlib::io::IoBuiltin;
use crate::stdlib::math::MathBuiltin;
use crate::stdlib::os::OsBuiltin;
use crate::stdlib::package::LoadBuiltin;
use crate::stdlib::string::StringBuiltin;
use crate::stdlib::table::TableBuiltin;
use crate::stdlib::utf8::Utf8Builtin;
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::{HostAllocationCharge, HostHandle, RootId, Vm, VmError};

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum Builtin {
    HostCallback(usize),
    Official(rivetlua_core::OfficialPlanBuiltin),
    Error,
    PCall,
    XPCall,
    CoroutineCreate,
    CoroutineResume,
    CoroutineYield,
    CoroutineStatus,
    CoroutineRunning,
    CoroutineIsYieldable,
    CoroutineClose,
    HostThreadReset,
    CoroutineWrap,
    CoroutineWrapped(rivetlua_core::ObjectRef),
    Basic(BasicBuiltin),
    Debug(DebugBuiltin),
    Math(MathBuiltin),
    Table(TableBuiltin),
    String(StringBuiltin),
    Utf8(Utf8Builtin),
    Load(LoadBuiltin),
    Io(IoBuiltin),
    Os(OsBuiltin),
    StringIterator {
        upvalues: [ObjectRef; 3],
    },
}

/// 固定 C trampoline 的語意編號；同一 kind 在不同 state 維持同一程式碼指標。
/// 捕獲值不參與編號，實際 upvalue 仍由被呼叫的 C closure 持有。
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapiBuiltinId(pub u16);

impl CapiBuiltinId {
    pub const COUNT: usize = 159;

    /// 僅這些官方 C body 使用可續接呼叫，或直接操作協程的 yield 邊界。
    #[doc(hidden)]
    pub fn allows_yield(self) -> bool {
        matches!(self.0, 1 | 2 | 4 | 5 | 8 | 11 | 20 | 119)
    }

    pub(crate) fn simple_builtin(self) -> Option<Builtin> {
        match self.0 {
            0 => Some(Builtin::Error),
            1 => Some(Builtin::PCall),
            2 => Some(Builtin::XPCall),
            3 => Some(Builtin::CoroutineCreate),
            4 => Some(Builtin::CoroutineResume),
            5 => Some(Builtin::CoroutineYield),
            6 => Some(Builtin::CoroutineStatus),
            7 => Some(Builtin::CoroutineRunning),
            8 => Some(Builtin::CoroutineIsYieldable),
            9 => Some(Builtin::CoroutineClose),
            10 => Some(Builtin::CoroutineWrap),
            12 => Some(Builtin::Basic(BasicBuiltin::Assert)),
            13 => Some(Builtin::Basic(BasicBuiltin::Warn)),
            14 => Some(Builtin::Basic(BasicBuiltin::CollectGarbage)),
            15 => Some(Builtin::Basic(BasicBuiltin::Select)),
            16 => Some(Builtin::Basic(BasicBuiltin::Type)),
            17 => Some(Builtin::Basic(BasicBuiltin::ToString)),
            18 => Some(Builtin::Basic(BasicBuiltin::ToNumber)),
            19 => Some(Builtin::Basic(BasicBuiltin::Next)),
            20 => Some(Builtin::Basic(BasicBuiltin::Pairs)),
            21 => Some(Builtin::Basic(BasicBuiltin::IPairs)),
            22 => Some(Builtin::Basic(BasicBuiltin::IPairsAux)),
            23 => Some(Builtin::Basic(BasicBuiltin::GetMetatable)),
            24 => Some(Builtin::Basic(BasicBuiltin::SetMetatable)),
            25 => Some(Builtin::Basic(BasicBuiltin::RawGet)),
            26 => Some(Builtin::Basic(BasicBuiltin::RawSet)),
            27 => Some(Builtin::Basic(BasicBuiltin::RawEqual)),
            28 => Some(Builtin::Basic(BasicBuiltin::RawLen)),
            29 => Some(Builtin::Basic(BasicBuiltin::Print)),
            30 => Some(Builtin::Debug(DebugBuiltin::GetInfo)),
            31 => Some(Builtin::Debug(DebugBuiltin::GetLocal)),
            32 => Some(Builtin::Debug(DebugBuiltin::SetLocal)),
            33 => Some(Builtin::Debug(DebugBuiltin::GetUpvalue)),
            34 => Some(Builtin::Debug(DebugBuiltin::SetUpvalue)),
            35 => Some(Builtin::Debug(DebugBuiltin::UpvalueId)),
            36 => Some(Builtin::Debug(DebugBuiltin::UpvalueJoin)),
            37 => Some(Builtin::Debug(DebugBuiltin::Traceback)),
            38 => Some(Builtin::Debug(DebugBuiltin::SetHook)),
            39 => Some(Builtin::Debug(DebugBuiltin::GetHook)),
            40 => Some(Builtin::Debug(DebugBuiltin::GetMetatable)),
            41 => Some(Builtin::Debug(DebugBuiltin::SetMetatable)),
            42 => Some(Builtin::Debug(DebugBuiltin::GetRegistry)),
            43 => Some(Builtin::Debug(DebugBuiltin::GetUserValue)),
            44 => Some(Builtin::Debug(DebugBuiltin::SetUserValue)),
            45 => Some(Builtin::Debug(DebugBuiltin::Debug)),
            46 => Some(Builtin::Debug(DebugBuiltin::SetCStackLimit)),
            47 => Some(Builtin::Math(MathBuiltin::Abs)),
            48 => Some(Builtin::Math(MathBuiltin::Acos)),
            49 => Some(Builtin::Math(MathBuiltin::Asin)),
            50 => Some(Builtin::Math(MathBuiltin::Atan)),
            51 => Some(Builtin::Math(MathBuiltin::Ceil)),
            52 => Some(Builtin::Math(MathBuiltin::Cos)),
            53 => Some(Builtin::Math(MathBuiltin::Cosh)),
            54 => Some(Builtin::Math(MathBuiltin::Deg)),
            55 => Some(Builtin::Math(MathBuiltin::Exp)),
            56 => Some(Builtin::Math(MathBuiltin::Floor)),
            57 => Some(Builtin::Math(MathBuiltin::Fmod)),
            58 => Some(Builtin::Math(MathBuiltin::Frexp)),
            59 => Some(Builtin::Math(MathBuiltin::Ldexp)),
            60 => Some(Builtin::Math(MathBuiltin::Log)),
            61 => Some(Builtin::Math(MathBuiltin::Log10)),
            62 => Some(Builtin::Math(MathBuiltin::Max)),
            63 => Some(Builtin::Math(MathBuiltin::Min)),
            64 => Some(Builtin::Math(MathBuiltin::Modf)),
            65 => Some(Builtin::Math(MathBuiltin::Pow)),
            66 => Some(Builtin::Math(MathBuiltin::Rad)),
            67 => Some(Builtin::Math(MathBuiltin::Sin)),
            68 => Some(Builtin::Math(MathBuiltin::Sinh)),
            69 => Some(Builtin::Math(MathBuiltin::Sqrt)),
            70 => Some(Builtin::Math(MathBuiltin::Tan)),
            71 => Some(Builtin::Math(MathBuiltin::Tanh)),
            72 => Some(Builtin::Math(MathBuiltin::ToInteger)),
            73 => Some(Builtin::Math(MathBuiltin::Type)),
            74 => Some(Builtin::Math(MathBuiltin::Ult)),
            77 => Some(Builtin::Table(TableBuiltin::Concat)),
            78 => Some(Builtin::Table(TableBuiltin::Create)),
            79 => Some(Builtin::Table(TableBuiltin::Insert)),
            80 => Some(Builtin::Table(TableBuiltin::Remove)),
            81 => Some(Builtin::Table(TableBuiltin::Move)),
            82 => Some(Builtin::Table(TableBuiltin::Pack)),
            83 => Some(Builtin::Table(TableBuiltin::Unpack)),
            84 => Some(Builtin::Table(TableBuiltin::Sort)),
            85 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Add))),
            86 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Subtract))),
            87 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Multiply))),
            88 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Modulo))),
            89 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Power))),
            90 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Divide))),
            91 => Some(Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::FloorDivide))),
            92 => Some(Builtin::String(StringBuiltin::Negate)),
            93 => Some(Builtin::String(StringBuiltin::Byte)),
            94 => Some(Builtin::String(StringBuiltin::Char)),
            95 => Some(Builtin::String(StringBuiltin::Find)),
            96 => Some(Builtin::String(StringBuiltin::Match)),
            97 => Some(Builtin::String(StringBuiltin::GMatch)),
            98 => Some(Builtin::String(StringBuiltin::GSub)),
            99 => Some(Builtin::String(StringBuiltin::Len)),
            100 => Some(Builtin::String(StringBuiltin::Lower)),
            101 => Some(Builtin::String(StringBuiltin::Upper)),
            102 => Some(Builtin::String(StringBuiltin::Rep)),
            103 => Some(Builtin::String(StringBuiltin::Reverse)),
            104 => Some(Builtin::String(StringBuiltin::Sub)),
            105 => Some(Builtin::String(StringBuiltin::Format)),
            106 => Some(Builtin::String(StringBuiltin::Dump)),
            107 => Some(Builtin::String(StringBuiltin::Pack)),
            108 => Some(Builtin::String(StringBuiltin::Unpack)),
            109 => Some(Builtin::String(StringBuiltin::PackSize)),
            110 => Some(Builtin::Utf8(Utf8Builtin::Len)),
            111 => Some(Builtin::Utf8(Utf8Builtin::Codepoint)),
            112 => Some(Builtin::Utf8(Utf8Builtin::Char)),
            114 => Some(Builtin::Utf8(Utf8Builtin::Offset)),
            115 => Some(Builtin::Utf8(Utf8Builtin::Iterator { strict: true })),
            116 => Some(Builtin::Utf8(Utf8Builtin::Iterator { strict: false })),
            122 => Some(Builtin::Load(LoadBuiltin::SearchPath)),
            126 => Some(Builtin::Io(IoBuiltin::Open)),
            127 => Some(Builtin::Io(IoBuiltin::Close)),
            128 => Some(Builtin::Io(IoBuiltin::Flush)),
            129 => Some(Builtin::Io(IoBuiltin::Input)),
            130 => Some(Builtin::Io(IoBuiltin::Output)),
            131 => Some(Builtin::Io(IoBuiltin::Lines)),
            132 => Some(Builtin::Io(IoBuiltin::Read)),
            133 => Some(Builtin::Io(IoBuiltin::Write)),
            134 => Some(Builtin::Io(IoBuiltin::Type)),
            135 => Some(Builtin::Io(IoBuiltin::TmpFile)),
            136 => Some(Builtin::Io(IoBuiltin::POpen)),
            137 => Some(Builtin::Io(IoBuiltin::FileClose)),
            138 => Some(Builtin::Io(IoBuiltin::FileFlush)),
            139 => Some(Builtin::Io(IoBuiltin::FileLines)),
            140 => Some(Builtin::Io(IoBuiltin::FileRead)),
            141 => Some(Builtin::Io(IoBuiltin::FileWrite)),
            142 => Some(Builtin::Io(IoBuiltin::FileSeek)),
            143 => Some(Builtin::Io(IoBuiltin::FileSetVBuf)),
            144 => Some(Builtin::Io(IoBuiltin::FileToString)),
            145 => Some(Builtin::Io(IoBuiltin::FileGc)),
            147 => Some(Builtin::Os(OsBuiltin::Clock)),
            148 => Some(Builtin::Os(OsBuiltin::Date)),
            149 => Some(Builtin::Os(OsBuiltin::Difftime)),
            150 => Some(Builtin::Os(OsBuiltin::Execute)),
            151 => Some(Builtin::Os(OsBuiltin::Exit)),
            152 => Some(Builtin::Os(OsBuiltin::GetEnv)),
            153 => Some(Builtin::Os(OsBuiltin::Remove)),
            154 => Some(Builtin::Os(OsBuiltin::Rename)),
            155 => Some(Builtin::Os(OsBuiltin::SetLocale)),
            156 => Some(Builtin::Os(OsBuiltin::Time)),
            157 => Some(Builtin::Os(OsBuiltin::TmpName)),
            _ => None,
        }
    }
}

impl Builtin {
    pub(crate) fn trace_children(
        self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        match self {
            Self::CoroutineWrapped(cell) => visit(cell)?,
            Self::Math(MathBuiltin::Random { cell } | MathBuiltin::RandomSeed { cell }) => {
                visit(cell)?;
            }
            Self::Utf8(Utf8Builtin::Codes { strict, lax }) => {
                visit(strict)?;
                visit(lax)?;
            }
            Self::Load(kind) => {
                if let Some(owner) = kind.owner() {
                    visit(owner)?;
                }
                if let Some(environment) = kind.environment() {
                    visit(environment)?;
                }
            }
            Self::Io(IoBuiltin::LinesIterator { formats, upvalues, .. }) => {
                visit(formats)?;
                for cell in upvalues {
                    visit(cell)?;
                }
            }
            Self::StringIterator { upvalues } => {
                for cell in upvalues {
                    visit(cell)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    pub(crate) fn capi_id(self) -> Option<CapiBuiltinId> {
        match self {
            Builtin::Error => Some(CapiBuiltinId(0)),
            Builtin::PCall => Some(CapiBuiltinId(1)),
            Builtin::XPCall => Some(CapiBuiltinId(2)),
            Builtin::CoroutineCreate => Some(CapiBuiltinId(3)),
            Builtin::CoroutineResume => Some(CapiBuiltinId(4)),
            Builtin::CoroutineYield => Some(CapiBuiltinId(5)),
            Builtin::CoroutineStatus => Some(CapiBuiltinId(6)),
            Builtin::CoroutineRunning => Some(CapiBuiltinId(7)),
            Builtin::CoroutineIsYieldable => Some(CapiBuiltinId(8)),
            Builtin::CoroutineClose => Some(CapiBuiltinId(9)),
            Builtin::CoroutineWrap => Some(CapiBuiltinId(10)),
            Builtin::CoroutineWrapped(_) => Some(CapiBuiltinId(11)),
            Builtin::Basic(BasicBuiltin::Assert) => Some(CapiBuiltinId(12)),
            Builtin::Basic(BasicBuiltin::Warn) => Some(CapiBuiltinId(13)),
            Builtin::Basic(BasicBuiltin::CollectGarbage) => Some(CapiBuiltinId(14)),
            Builtin::Basic(BasicBuiltin::Select) => Some(CapiBuiltinId(15)),
            Builtin::Basic(BasicBuiltin::Type) => Some(CapiBuiltinId(16)),
            Builtin::Basic(BasicBuiltin::ToString) => Some(CapiBuiltinId(17)),
            Builtin::Basic(BasicBuiltin::ToNumber) => Some(CapiBuiltinId(18)),
            Builtin::Basic(BasicBuiltin::Next) => Some(CapiBuiltinId(19)),
            Builtin::Basic(BasicBuiltin::Pairs) => Some(CapiBuiltinId(20)),
            Builtin::Basic(BasicBuiltin::IPairs) => Some(CapiBuiltinId(21)),
            Builtin::Basic(BasicBuiltin::IPairsAux) => Some(CapiBuiltinId(22)),
            Builtin::Basic(BasicBuiltin::GetMetatable) => Some(CapiBuiltinId(23)),
            Builtin::Basic(BasicBuiltin::SetMetatable) => Some(CapiBuiltinId(24)),
            Builtin::Basic(BasicBuiltin::RawGet) => Some(CapiBuiltinId(25)),
            Builtin::Basic(BasicBuiltin::RawSet) => Some(CapiBuiltinId(26)),
            Builtin::Basic(BasicBuiltin::RawEqual) => Some(CapiBuiltinId(27)),
            Builtin::Basic(BasicBuiltin::RawLen) => Some(CapiBuiltinId(28)),
            Builtin::Basic(BasicBuiltin::Print) => Some(CapiBuiltinId(29)),
            Builtin::Debug(DebugBuiltin::GetInfo) => Some(CapiBuiltinId(30)),
            Builtin::Debug(DebugBuiltin::GetLocal) => Some(CapiBuiltinId(31)),
            Builtin::Debug(DebugBuiltin::SetLocal) => Some(CapiBuiltinId(32)),
            Builtin::Debug(DebugBuiltin::GetUpvalue) => Some(CapiBuiltinId(33)),
            Builtin::Debug(DebugBuiltin::SetUpvalue) => Some(CapiBuiltinId(34)),
            Builtin::Debug(DebugBuiltin::UpvalueId) => Some(CapiBuiltinId(35)),
            Builtin::Debug(DebugBuiltin::UpvalueJoin) => Some(CapiBuiltinId(36)),
            Builtin::Debug(DebugBuiltin::Traceback) => Some(CapiBuiltinId(37)),
            Builtin::Debug(DebugBuiltin::SetHook) => Some(CapiBuiltinId(38)),
            Builtin::Debug(DebugBuiltin::GetHook) => Some(CapiBuiltinId(39)),
            Builtin::Debug(DebugBuiltin::GetMetatable) => Some(CapiBuiltinId(40)),
            Builtin::Debug(DebugBuiltin::SetMetatable) => Some(CapiBuiltinId(41)),
            Builtin::Debug(DebugBuiltin::GetRegistry) => Some(CapiBuiltinId(42)),
            Builtin::Debug(DebugBuiltin::GetUserValue) => Some(CapiBuiltinId(43)),
            Builtin::Debug(DebugBuiltin::SetUserValue) => Some(CapiBuiltinId(44)),
            Builtin::Debug(DebugBuiltin::Debug) => Some(CapiBuiltinId(45)),
            Builtin::Debug(DebugBuiltin::SetCStackLimit) => Some(CapiBuiltinId(46)),
            Builtin::Math(MathBuiltin::Abs) => Some(CapiBuiltinId(47)),
            Builtin::Math(MathBuiltin::Acos) => Some(CapiBuiltinId(48)),
            Builtin::Math(MathBuiltin::Asin) => Some(CapiBuiltinId(49)),
            Builtin::Math(MathBuiltin::Atan) => Some(CapiBuiltinId(50)),
            Builtin::Math(MathBuiltin::Ceil) => Some(CapiBuiltinId(51)),
            Builtin::Math(MathBuiltin::Cos) => Some(CapiBuiltinId(52)),
            Builtin::Math(MathBuiltin::Cosh) => Some(CapiBuiltinId(53)),
            Builtin::Math(MathBuiltin::Deg) => Some(CapiBuiltinId(54)),
            Builtin::Math(MathBuiltin::Exp) => Some(CapiBuiltinId(55)),
            Builtin::Math(MathBuiltin::Floor) => Some(CapiBuiltinId(56)),
            Builtin::Math(MathBuiltin::Fmod) => Some(CapiBuiltinId(57)),
            Builtin::Math(MathBuiltin::Frexp) => Some(CapiBuiltinId(58)),
            Builtin::Math(MathBuiltin::Ldexp) => Some(CapiBuiltinId(59)),
            Builtin::Math(MathBuiltin::Log) => Some(CapiBuiltinId(60)),
            Builtin::Math(MathBuiltin::Log10) => Some(CapiBuiltinId(61)),
            Builtin::Math(MathBuiltin::Max) => Some(CapiBuiltinId(62)),
            Builtin::Math(MathBuiltin::Min) => Some(CapiBuiltinId(63)),
            Builtin::Math(MathBuiltin::Modf) => Some(CapiBuiltinId(64)),
            Builtin::Math(MathBuiltin::Pow) => Some(CapiBuiltinId(65)),
            Builtin::Math(MathBuiltin::Rad) => Some(CapiBuiltinId(66)),
            Builtin::Math(MathBuiltin::Sin) => Some(CapiBuiltinId(67)),
            Builtin::Math(MathBuiltin::Sinh) => Some(CapiBuiltinId(68)),
            Builtin::Math(MathBuiltin::Sqrt) => Some(CapiBuiltinId(69)),
            Builtin::Math(MathBuiltin::Tan) => Some(CapiBuiltinId(70)),
            Builtin::Math(MathBuiltin::Tanh) => Some(CapiBuiltinId(71)),
            Builtin::Math(MathBuiltin::ToInteger) => Some(CapiBuiltinId(72)),
            Builtin::Math(MathBuiltin::Type) => Some(CapiBuiltinId(73)),
            Builtin::Math(MathBuiltin::Ult) => Some(CapiBuiltinId(74)),
            Builtin::Math(MathBuiltin::Random { .. }) => Some(CapiBuiltinId(75)),
            Builtin::Math(MathBuiltin::RandomSeed { .. }) => Some(CapiBuiltinId(76)),
            Builtin::Table(TableBuiltin::Concat) => Some(CapiBuiltinId(77)),
            Builtin::Table(TableBuiltin::Create) => Some(CapiBuiltinId(78)),
            Builtin::Table(TableBuiltin::Insert) => Some(CapiBuiltinId(79)),
            Builtin::Table(TableBuiltin::Remove) => Some(CapiBuiltinId(80)),
            Builtin::Table(TableBuiltin::Move) => Some(CapiBuiltinId(81)),
            Builtin::Table(TableBuiltin::Pack) => Some(CapiBuiltinId(82)),
            Builtin::Table(TableBuiltin::Unpack) => Some(CapiBuiltinId(83)),
            Builtin::Table(TableBuiltin::Sort) => Some(CapiBuiltinId(84)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Add)) => Some(CapiBuiltinId(85)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Subtract)) => Some(CapiBuiltinId(86)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Multiply)) => Some(CapiBuiltinId(87)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Modulo)) => Some(CapiBuiltinId(88)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Power)) => Some(CapiBuiltinId(89)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::Divide)) => Some(CapiBuiltinId(90)),
            Builtin::String(StringBuiltin::Arithmetic(rivetlua_core::BinaryOperation::FloorDivide)) => Some(CapiBuiltinId(91)),
            Builtin::String(StringBuiltin::Negate) => Some(CapiBuiltinId(92)),
            Builtin::String(StringBuiltin::Byte) => Some(CapiBuiltinId(93)),
            Builtin::String(StringBuiltin::Char) => Some(CapiBuiltinId(94)),
            Builtin::String(StringBuiltin::Find) => Some(CapiBuiltinId(95)),
            Builtin::String(StringBuiltin::Match) => Some(CapiBuiltinId(96)),
            Builtin::String(StringBuiltin::GMatch) => Some(CapiBuiltinId(97)),
            Builtin::String(StringBuiltin::GSub) => Some(CapiBuiltinId(98)),
            Builtin::String(StringBuiltin::Len) => Some(CapiBuiltinId(99)),
            Builtin::String(StringBuiltin::Lower) => Some(CapiBuiltinId(100)),
            Builtin::String(StringBuiltin::Upper) => Some(CapiBuiltinId(101)),
            Builtin::String(StringBuiltin::Rep) => Some(CapiBuiltinId(102)),
            Builtin::String(StringBuiltin::Reverse) => Some(CapiBuiltinId(103)),
            Builtin::String(StringBuiltin::Sub) => Some(CapiBuiltinId(104)),
            Builtin::String(StringBuiltin::Format) => Some(CapiBuiltinId(105)),
            Builtin::String(StringBuiltin::Dump) => Some(CapiBuiltinId(106)),
            Builtin::String(StringBuiltin::Pack) => Some(CapiBuiltinId(107)),
            Builtin::String(StringBuiltin::Unpack) => Some(CapiBuiltinId(108)),
            Builtin::String(StringBuiltin::PackSize) => Some(CapiBuiltinId(109)),
            Builtin::Utf8(Utf8Builtin::Len) => Some(CapiBuiltinId(110)),
            Builtin::Utf8(Utf8Builtin::Codepoint) => Some(CapiBuiltinId(111)),
            Builtin::Utf8(Utf8Builtin::Char) => Some(CapiBuiltinId(112)),
            Builtin::Utf8(Utf8Builtin::Codes { .. }) => Some(CapiBuiltinId(113)),
            Builtin::Utf8(Utf8Builtin::Offset) => Some(CapiBuiltinId(114)),
            Builtin::Utf8(Utf8Builtin::Iterator { strict: true }) => Some(CapiBuiltinId(115)),
            Builtin::Utf8(Utf8Builtin::Iterator { strict: false }) => Some(CapiBuiltinId(116)),
            Builtin::Load(LoadBuiltin::Load { .. }) => Some(CapiBuiltinId(117)),
            Builtin::Load(LoadBuiltin::LoadFile { .. }) => Some(CapiBuiltinId(118)),
            Builtin::Load(LoadBuiltin::DoFile { .. }) => Some(CapiBuiltinId(119)),
            Builtin::Load(LoadBuiltin::Require { .. }) => Some(CapiBuiltinId(120)),
            Builtin::Load(LoadBuiltin::PreloadSearcher { .. }) => Some(CapiBuiltinId(121)),
            Builtin::Load(LoadBuiltin::SearchPath) => Some(CapiBuiltinId(122)),
            Builtin::Load(LoadBuiltin::LuaSearcher { .. }) => Some(CapiBuiltinId(123)),
            Builtin::Load(LoadBuiltin::NativeSearcher { root: false, .. }) => Some(CapiBuiltinId(124)),
            Builtin::Load(LoadBuiltin::NativeSearcher { root: true, .. }) => Some(CapiBuiltinId(125)),
            Builtin::Io(IoBuiltin::Open) => Some(CapiBuiltinId(126)),
            Builtin::Io(IoBuiltin::Close) => Some(CapiBuiltinId(127)),
            Builtin::Io(IoBuiltin::Flush) => Some(CapiBuiltinId(128)),
            Builtin::Io(IoBuiltin::Input) => Some(CapiBuiltinId(129)),
            Builtin::Io(IoBuiltin::Output) => Some(CapiBuiltinId(130)),
            Builtin::Io(IoBuiltin::Lines) => Some(CapiBuiltinId(131)),
            Builtin::Io(IoBuiltin::Read) => Some(CapiBuiltinId(132)),
            Builtin::Io(IoBuiltin::Write) => Some(CapiBuiltinId(133)),
            Builtin::Io(IoBuiltin::Type) => Some(CapiBuiltinId(134)),
            Builtin::Io(IoBuiltin::TmpFile) => Some(CapiBuiltinId(135)),
            Builtin::Io(IoBuiltin::POpen) => Some(CapiBuiltinId(136)),
            Builtin::Io(IoBuiltin::FileClose) => Some(CapiBuiltinId(137)),
            Builtin::Io(IoBuiltin::FileFlush) => Some(CapiBuiltinId(138)),
            Builtin::Io(IoBuiltin::FileLines) => Some(CapiBuiltinId(139)),
            Builtin::Io(IoBuiltin::FileRead) => Some(CapiBuiltinId(140)),
            Builtin::Io(IoBuiltin::FileWrite) => Some(CapiBuiltinId(141)),
            Builtin::Io(IoBuiltin::FileSeek) => Some(CapiBuiltinId(142)),
            Builtin::Io(IoBuiltin::FileSetVBuf) => Some(CapiBuiltinId(143)),
            Builtin::Io(IoBuiltin::FileToString) => Some(CapiBuiltinId(144)),
            Builtin::Io(IoBuiltin::FileGc) => Some(CapiBuiltinId(145)),
            Builtin::Io(IoBuiltin::LinesIterator { .. }) => Some(CapiBuiltinId(146)),
            Builtin::Os(OsBuiltin::Clock) => Some(CapiBuiltinId(147)),
            Builtin::Os(OsBuiltin::Date) => Some(CapiBuiltinId(148)),
            Builtin::Os(OsBuiltin::Difftime) => Some(CapiBuiltinId(149)),
            Builtin::Os(OsBuiltin::Execute) => Some(CapiBuiltinId(150)),
            Builtin::Os(OsBuiltin::Exit) => Some(CapiBuiltinId(151)),
            Builtin::Os(OsBuiltin::GetEnv) => Some(CapiBuiltinId(152)),
            Builtin::Os(OsBuiltin::Remove) => Some(CapiBuiltinId(153)),
            Builtin::Os(OsBuiltin::Rename) => Some(CapiBuiltinId(154)),
            Builtin::Os(OsBuiltin::SetLocale) => Some(CapiBuiltinId(155)),
            Builtin::Os(OsBuiltin::Time) => Some(CapiBuiltinId(156)),
            Builtin::Os(OsBuiltin::TmpName) => Some(CapiBuiltinId(157)),
            Builtin::StringIterator { .. } => Some(CapiBuiltinId(158)),
            Builtin::HostCallback(_) | Builtin::Official(_) | Builtin::HostThreadReset
            | Builtin::String(StringBuiltin::Arithmetic(_)) => None,
        }
    }
}

/// 宿主可保留的 Lua error；最後一份複本丟棄時釋放物件 root。
#[derive(Clone)]
pub struct LuaError {
    pub kind: RuntimeErrorKind,
    pub diagnostic_id: &'static str,
    pub value: Value,
    pub source_pc: Option<usize>,
    pub source_prototype: Option<usize>,
    pub source_depth: Option<usize>,
    _root: Option<SharedBlock<LuaErrorRoot>>,
}

struct LuaErrorRoot {
    _owner: LuaErrorRootOwner,
    _charge: HostAllocationCharge,
}

enum LuaErrorRootOwner {
    Host { _handle: HostHandle<Value> },
    CProtected { _root: StackRoot },
}

/// C protected body 執行前建立；錯誤交付時沿同一真根轉移，無須再配置。
pub(crate) struct PreparedLuaErrorRoot(SharedBlock<LuaErrorRoot>);

impl LuaError {
    pub(crate) fn from_runtime(
        vm: &mut Vm,
        error: RuntimeError,
        prototype: usize,
        depth: usize,
        pc: usize,
    ) -> Result<Self, VmError> {
        let root = if let Value::Object(object) = error.value {
            let handle = HostHandle::new(vm, object)?;
            Some(Self::preserve_root(vm, handle)?)
        } else {
            None
        };
        Ok(Self {
            kind: error.kind,
            diagnostic_id: error.diagnostic_id,
            value: error.value,
            source_pc: Some(error.source_pc.unwrap_or(pc)),
            source_prototype: Some(error.source_prototype.unwrap_or(prototype)),
            source_depth: Some(error.source_depth.unwrap_or(depth)),
            _root: root,
        })
    }

    fn preserve_root(
        vm: &mut Vm,
        handle: HostHandle<Value>,
    ) -> Result<SharedBlock<LuaErrorRoot>, VmError> {
        let (pending, ticket) = vm.capi_reserve_host_shared::<LuaErrorRoot>()?;
        let charge = ticket.commit()?;
        Ok(pending.write(LuaErrorRoot {
            _owner: LuaErrorRootOwner::Host { _handle: handle },
            _charge: charge,
        }))
    }

    pub(crate) fn prepare_c_root(
        vm: &mut Vm,
        root: StackRoot,
    ) -> Result<PreparedLuaErrorRoot, VmError> {
        let (pending, ticket) = vm.capi_reserve_host_shared::<LuaErrorRoot>()?;
        let charge = ticket.commit()?;
        Ok(PreparedLuaErrorRoot(pending.write(LuaErrorRoot {
            _owner: LuaErrorRootOwner::CProtected { _root: root },
            _charge: charge,
        })))
    }

    pub(crate) fn from_prepared_c_root(
        error: RuntimeError,
        prototype: usize,
        depth: usize,
        pc: usize,
        prepared: PreparedLuaErrorRoot,
    ) -> Self {
        Self {
            kind: error.kind,
            diagnostic_id: error.diagnostic_id,
            value: error.value,
            source_pc: Some(error.source_pc.unwrap_or(pc)),
            source_prototype: Some(error.source_prototype.unwrap_or(prototype)),
            source_depth: Some(error.source_depth.unwrap_or(depth)),
            _root: matches!(error.value, Value::Object(_)).then_some(prepared.0),
        }
    }
}

impl core::fmt::Debug for LuaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LuaError")
            .field("kind", &self.kind)
            .field("diagnostic_id", &self.diagnostic_id)
            .field("value", &self.value)
            .field("source_pc", &self.source_pc)
            .field("source_prototype", &self.source_prototype)
            .field("source_depth", &self.source_depth)
            .finish()
    }
}

impl PartialEq for LuaError {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
            && self.diagnostic_id == other.diagnostic_id
            && self.value == other.value
            && self.source_pc == other.source_pc
            && self.source_prototype == other.source_prototype
            && self.source_depth == other.source_depth
    }
}

#[cfg(test)]
mod p12_6_tests {
    use rivetlua_core::Value;

    use super::{LuaError, RuntimeError, RuntimeErrorKind};
    use crate::{RootKind, Vm, VmError};

    #[test]
    fn p12_6_lua_error_rc_reserve_failure_rolls_back_host_root() {
        let mut vm = Vm::new().unwrap();
        let value = vm.allocate(Value::Integer(7)).unwrap();
        let before = vm.ledger_snapshot();
        let ordinal = vm.allocation_trace().next_ordinal + 1;
        vm.inject_allocation_failure_at(ordinal);
        let mut source = RuntimeError::new(RuntimeErrorKind::Thrown);
        source.value = Value::Object(value);
        let error = LuaError::from_runtime(&mut vm, source, 0, 0, 0)
            .err()
            .expect("Rc reserve 注入應失敗");
        assert!(
            matches!(error, VmError::InjectedAllocation(attempt) if attempt.ordinal == ordinal && attempt.site.file.ends_with("errors.rs"))
        );
        assert_eq!(vm.roots().count(RootKind::Host), 0);
        assert_eq!(vm.ledger_snapshot(), before);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProtectedStage {
    Body,
    Handler,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum COverlayStage {
    Body,
    AwaitingClose,
}

/// caller 保持在 CallFrame 堆疊，handler 另外持有 root 以跨錯誤 unwind。
pub(crate) struct ProtectedBoundary {
    pub(crate) caller_depth: usize,
    pub(crate) caller_pc: usize,
    pub(crate) resume_pc: usize,
    pub(crate) destination: Register,
    pub(crate) result_mode: ResultMode,
    pub(crate) tail_return: bool,
    pub(crate) inline_target: bool,
    pub(crate) debug_console: bool,
    pub(crate) load_reader: bool,
    pub(crate) host_entry: bool,
    /// C protected call 的 faulting C stack 須在 handler 後才關閉。
    pub(crate) c_overlay: Option<COverlayStage>,
    pub(crate) handler: Option<Value>,
    pub(crate) handler_root: Option<RootId>,
    /// C protected call 在目標執行前建立的可重綁錯誤真根。
    pub(crate) c_error_root: Option<StackRoot>,
    /// 與 c_error_root 共用同一根，於錯誤交付時直接移入 LuaError。
    pub(crate) c_prepared_error: Option<PreparedLuaErrorRoot>,
    /// 停放後重新進入 C handler 時只重綁既有 root，不再向 allocator 請求。
    pub(crate) c_handler_root: Option<StackRoot>,
    pub(crate) stage: ProtectedStage,
    pub(crate) handler_depth: Option<usize>,
    /// handler 所屬協程；它 resume 的子協程不繼承 no-yield 邊界。
    pub(crate) handler_thread: Option<ObjectRef>,
    pub(crate) handler_errors: u8,
    pub(crate) message_error: Option<crate::RuntimeError>,
    pub(crate) handler_completed: bool,
    pub(crate) handler_native: bool,
    /// 此 handler 的 C→Lua 進入基線；跨停放保留直到真正完成或錯誤退出。
    pub(crate) c_call_restore: Option<(ObjectRef, u16)>,
    /// 語意 protected call 的進入深度；handler 完成後才恢復，不受私有 checkpoint 影響。
    pub(crate) c_call_baseline: Option<(ObjectRef, u16)>,
    pub(crate) faulting_native: Option<NativeCallInfo>,
    pub(crate) close_scope: Option<PendingCloseSnapshot>,
    pub(crate) finalizer: Option<rivetlua_core::ObjectRef>,
}

impl ProtectedBoundary {
    /// handler 已完成或不能再重試時，先恢復正式 C protected call 的進入深度。
    /// 關閉過程若再產生新錯誤，仍需保留 baseline 供下一輪 handler 收束。
    pub(crate) fn settle_c_call_baseline(&mut self, vm: &Vm) -> Result<(), VmError> {
        if let Some((thread, baseline)) = self.c_call_baseline {
            self.c_call_restore = None;
            let current = vm.capi_c_call_depth(Some(thread))?;
            if current > baseline {
                vm.capi_set_c_call_depth(Some(thread), baseline)?;
            }
        } else {
            self.restore_c_call_depth(vm)?;
        }
        Ok(())
    }

    pub(crate) fn restore_c_call_depth(&mut self, vm: &Vm) -> Result<(), VmError> {
        if let Some((thread, previous)) = self.c_call_restore {
            let current = vm.capi_c_call_depth(Some(thread))?;
            if current > previous {
                vm.capi_set_c_call_depth(Some(thread), previous)?;
            }
            self.c_call_restore = None;
        }
        Ok(())
    }

    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        self.settle_c_call_baseline(vm)?;
        self.c_call_baseline = None;
        if let Some(root) = self.c_error_root.take() {
            vm.set_stack_root(&root, None)?;
        }
        self.c_prepared_error = None;
        if let Some(root) = self.c_handler_root.take() {
            vm.set_stack_root(&root, None)?;
        }
        self.park_roots(vm)
    }

    pub(crate) fn park_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(mut call) = self.faulting_native.take() {
            call.clear(vm)?;
        }
        if let Some(root) = self.handler_root.take() {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.c_handler_root.as_ref() {
            vm.set_stack_root(root, None)?;
        }
        Ok(())
    }

    pub(crate) fn restore_root(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.c_handler_root.as_ref() {
            return vm.set_stack_root(root, match self.handler {
                Some(Value::Object(object)) => Some(object),
                _ => None,
            });
        }
        if let Some(Value::Object(object)) = self.handler {
            self.handler_root = Some(vm.add_root(crate::RootKind::Temporary, object)?);
        }
        Ok(())
    }
}

/// 尚在錯誤交付堆疊上的真正 native 呼叫；保護它的函式值直到 handler 收束。
pub(crate) struct NativeCallInfo {
    pub(crate) function: Value,
    pub(crate) caller_depth: usize,
    root: Option<RootId>,
}

impl NativeCallInfo {
    pub(crate) fn new(vm: &mut Vm, function: Value, caller_depth: usize) -> Result<Self, VmError> {
        let root = match function {
            Value::Object(object) => Some(vm.add_root(crate::RootKind::Temporary, object)?),
            _ => None,
        };
        Ok(Self {
            function,
            caller_depth,
            root,
        })
    }

    pub(crate) fn clear(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }
}

pub(crate) fn explicit_error(value: Value, pc: usize) -> RuntimeError {
    let mut error = RuntimeError::new(RuntimeErrorKind::Thrown);
    error.value = value;
    error.source_pc = Some(pc);
    error
}
