pub(crate) mod trace;

use rivetlua_core::{LuaProfile, ObjectRef};

use crate::AllocationLedger;
use crate::alloc::{AllocationCharge, AllocationCharges};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcPhase {
    Pause,
    RootMark,
    Propagate,
    Atomic,
    Sweep,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcColor {
    White,
    Gray,
    Black,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcAge {
    Young,
    Survivor,
    Old,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcMode {
    Incremental,
    Generational,
}

/// 固定 Lua profile 的公開 GC 控制要求；不暴露 collector 內部狀態。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcControl {
    Stop,
    Restart,
    Collect,
    Count,
    CountBytes,
    Step(usize),
    SetPause(i32),
    SetStepMultiplier(i32),
    IsRunning,
    Generational {
        minor_mul: i32,
        minor_major: i32,
    },
    Incremental {
        pause: i32,
        step_mul: i32,
        step_size: i32,
    },
    Parameter {
        index: i32,
        value: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcControlResult {
    Integer(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GcParameter {
    Pause,
    StepMultiplier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GcCycleKind {
    Full,
    Minor,
    Major,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WeakMode {
    Strong,
    Keys,
    Values,
    All,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FinalizerState {
    Unregistered,
    Registered,
    Pending,
    Running,
    Finalized,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AtomicFinalizerStage {
    BeforeWeakValues,
    BeforeSeparation,
    AfterSeparation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GcTrace {
    pub phase: GcPhase,
    pub mode: GcMode,
    pub cycle: GcCycleKind,
    pub white: usize,
    pub gray: usize,
    pub black: usize,
    pub worklist_len: usize,
    pub debt_bytes: usize,
    pub barrier_count: usize,
    pub reclaimed_bytes: usize,
    pub transition_count: usize,
    pub young: usize,
    pub survivor: usize,
    pub old: usize,
    pub remembered_len: usize,
    pub major_debt_bytes: usize,
    pub major_threshold_bytes: usize,
    pub promotion_survivals: u8,
    pub ephemeron_iterations: usize,
    pub ephemeron_last_key: Option<ObjectRef>,
    pub ephemeron_converged: bool,
    pub weak_cleared_pairs: usize,
    pub finalizer_pending: usize,
    pub finalizer_warnings: usize,
    pub finalizer_deferred_terminals: usize,
}

pub(crate) struct GcState {
    pub(crate) automatic_running: bool,
    pub(crate) pause_code: u8,
    pub(crate) stepmul_code: u8,
    pub(crate) stepsize_code: u8,
    pub(crate) minor_mul_code: u8,
    pub(crate) major_minor_code: u8,
    pub(crate) minor_major_code: u8,
    pub(crate) stepsize_exponent: u8,
    pub(crate) major_followup: bool,
    pub(crate) major_threshold_override: bool,
    pub(crate) last_major_lua_heap_bytes: usize,
    pub(crate) cycle_start_lua_heap_bytes: usize,
    pub(crate) cycle_start_reclaimed: usize,
    pub(crate) debt_threshold_override: Option<usize>,
    pub phase: GcPhase,
    pub mode: GcMode,
    pub cycle: GcCycleKind,
    pub colors: Vec<GcColor>,
    pub work: Vec<ObjectRef>,
    pub roots: Vec<ObjectRef>,
    pub root_cursor: usize,
    pub remembered_cursor: usize,
    pub sweep_cursor: usize,
    pub debt_bytes: usize,
    pub debt_threshold: usize,
    pub(crate) incremental_debt_threshold: usize,
    pub major_debt_bytes: usize,
    pub major_threshold_bytes: usize,
    pub promotion_survivals: u8,
    pub remembered: Vec<ObjectRef>,
    pub remembered_charge: usize,
    pub remembered_charges: AllocationCharges,
    pub barrier_count: usize,
    pub reclaimed_bytes: usize,
    pub reclaimed_objects: usize,
    pub transition_count: usize,
    pub ephemeron_cursor: usize,
    pub ephemeron_iterations: usize,
    pub ephemeron_last_key: Option<ObjectRef>,
    pub ephemeron_converged: bool,
    pub weak_cleared_pairs: usize,
    pub atomic_finalizer_stage: AtomicFinalizerStage,
    pub charge: usize,
    pub cycle_charges: AllocationCharges,
    pub growth_charges: Vec<(usize, AllocationCharge, AllocationCharge)>,
}

impl GcState {
    pub fn new(profile: LuaProfile, _ledger: AllocationLedger) -> Self {
        Self {
            automatic_running: true,
            pause_code: match profile {
                LuaProfile::Lua54 => 200 / 4,
                LuaProfile::Lua55 => Self::code_param(250),
            },
            stepmul_code: match profile {
                LuaProfile::Lua54 => 100 / 4,
                LuaProfile::Lua55 => Self::code_param(200),
            },
            stepsize_code: Self::code_param(9600),
            minor_mul_code: match profile {
                LuaProfile::Lua54 => 20,
                LuaProfile::Lua55 => Self::code_param(20),
            },
            major_minor_code: Self::code_param(50),
            minor_major_code: match profile {
                LuaProfile::Lua54 => 100 / 4,
                LuaProfile::Lua55 => Self::code_param(70),
            },
            stepsize_exponent: 13,
            major_followup: false,
            major_threshold_override: false,
            last_major_lua_heap_bytes: 0,
            cycle_start_lua_heap_bytes: 0,
            cycle_start_reclaimed: 0,
            debt_threshold_override: None,
            phase: GcPhase::Pause,
            mode: GcMode::Generational,
            cycle: GcCycleKind::Full,
            colors: Vec::new(),
            work: Vec::new(),
            roots: Vec::new(),
            root_cursor: 0,
            remembered_cursor: 0,
            sweep_cursor: 0,
            debt_bytes: 0,
            debt_threshold: 1024 * 1024,
            incremental_debt_threshold: 1024 * 1024,
            major_debt_bytes: 0,
            major_threshold_bytes: 4 * 1024 * 1024,
            promotion_survivals: 2,
            remembered: Vec::new(),
            remembered_charge: 0,
            remembered_charges: AllocationCharges::new(),
            barrier_count: 0,
            reclaimed_bytes: 0,
            reclaimed_objects: 0,
            transition_count: 0,
            ephemeron_cursor: 0,
            ephemeron_iterations: 0,
            ephemeron_last_key: None,
            ephemeron_converged: false,
            weak_cleared_pairs: 0,
            atomic_finalizer_stage: AtomicFinalizerStage::BeforeWeakValues,
            charge: 0,
            cycle_charges: AllocationCharges::new(),
            growth_charges: Vec::new(),
        }
    }

    pub(crate) fn code_param(value: i64) -> u8 {
        let value = value.max(0) as u128;
        if value >= 396_800 {
            return u8::MAX;
        }
        let scaled = (value * 128 + 99) / 100;
        if scaled < 16 {
            return scaled as u8;
        }
        let log = (u128::BITS - scaled.leading_zeros()) - 5;
        (((scaled >> log) - 16) as u8) | (((log + 1) as u8) << 4)
    }

    pub(crate) fn apply_param(code: u8) -> usize {
        let high = usize::from(code >> 4);
        let mantissa = if high == 0 {
            usize::from(code)
        } else {
            usize::from((code & 15) + 16) << (high - 1)
        };
        mantissa.saturating_mul(100) / 128
    }

    pub fn transition(&mut self, next: GcPhase) {
        if self.phase != next {
            self.phase = next;
            self.transition_count += 1;
        }
    }

    pub fn clear_cycle(&mut self) -> Result<(), crate::VmError> {
        self.colors = Vec::new();
        self.work = Vec::new();
        self.roots = Vec::new();
        self.cycle_charges = AllocationCharges::new();
        self.growth_charges.clear();
        self.charge = 0;
        self.root_cursor = 0;
        self.remembered_cursor = 0;
        self.sweep_cursor = 0;
        self.ephemeron_cursor = 0;
        self.atomic_finalizer_stage = AtomicFinalizerStage::BeforeWeakValues;
        self.debt_bytes = 0;
        if self.cycle != GcCycleKind::Minor {
            self.major_debt_bytes = 0;
        }
        self.transition(GcPhase::Pause);
        Ok(())
    }

    pub fn clear_remembered(&mut self) -> Result<(), crate::VmError> {
        self.remembered = Vec::new();
        self.remembered_charges = AllocationCharges::new();
        self.remembered_charge = 0;
        self.remembered_cursor = 0;
        Ok(())
    }
}
