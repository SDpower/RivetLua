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

/// 固定物理 SlotId 的 64 槽摘要；Free 與 Retired 都不參與標記。
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct GcSlotBits {
    pub(crate) occupied: u64,
    pub(crate) reusable_free: u64,
    pub(crate) gray: u64,
    pub(crate) black: u64,
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
    pub(crate) slot_bits: Vec<GcSlotBits>,
    pub(crate) slot_bit_charges: Vec<AllocationCharge>,
    pub(crate) occupied_count: usize,
    pub(crate) work_capacity: usize,
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
    pub growth_charges: Vec<(usize, AllocationCharge)>,
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
            slot_bits: Vec::new(),
            slot_bit_charges: Vec::new(),
            occupied_count: 0,
            work_capacity: 0,
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

    pub(crate) fn color(&self, index: usize) -> Option<GcColor> {
        let page = self.slot_bits.get(index / 64)?;
        let mask = 1u64 << (index % 64);
        if page.occupied & mask == 0 {
            None
        } else if page.gray & mask != 0 {
            Some(GcColor::Gray)
        } else if page.black & mask != 0 {
            Some(GcColor::Black)
        } else {
            Some(GcColor::White)
        }
    }

    pub(crate) fn set_color(&mut self, index: usize, color: GcColor) {
        let page = &mut self.slot_bits[index / 64];
        let mask = 1u64 << (index % 64);
        debug_assert_ne!(page.occupied & mask, 0);
        page.gray &= !mask;
        page.black &= !mask;
        match color {
            GcColor::White => {}
            GcColor::Gray => page.gray |= mask,
            GcColor::Black => page.black |= mask,
        }
    }

    pub(crate) fn clear_colors(&mut self) {
        for page in &mut self.slot_bits {
            page.gray = 0;
            page.black = 0;
        }
    }

    pub(crate) fn publish_occupied(&mut self, index: usize) {
        let page = &mut self.slot_bits[index / 64];
        let mask = 1u64 << (index % 64);
        debug_assert_eq!(page.occupied & mask, 0);
        page.occupied |= mask;
        page.reusable_free &= !mask;
        page.gray &= !mask;
        page.black &= !mask;
        self.occupied_count += 1;
    }

    pub(crate) fn retire_or_free(&mut self, index: usize, reusable: bool) {
        let page = &mut self.slot_bits[index / 64];
        let mask = 1u64 << (index % 64);
        debug_assert_ne!(page.occupied & mask, 0);
        page.occupied &= !mask;
        page.gray &= !mask;
        page.black &= !mask;
        if reusable {
            page.reusable_free |= mask;
        } else {
            page.reusable_free &= !mask;
        }
        self.occupied_count -= 1;
    }

    pub(crate) fn next_occupied(&self, start: usize, end: usize) -> Option<usize> {
        self.next_bit(start, end, false)
    }

    pub(crate) fn next_reusable_free(&self, start: usize, end: usize) -> Option<usize> {
        self.next_bit(start, end, true)
    }

    fn next_bit(&self, start: usize, end: usize, free: bool) -> Option<usize> {
        if start >= end {
            return None;
        }
        let mut page_index = start / 64;
        let mut offset = start % 64;
        while page_index < self.slot_bits.len() {
            let base = page_index * 64;
            if base >= end {
                break;
            }
            let page = &self.slot_bits[page_index];
            let mut bits = if free { page.reusable_free } else { page.occupied };
            bits &= u64::MAX << offset;
            let remaining = end - base;
            if remaining < 64 {
                bits &= (1u64 << remaining) - 1;
            }
            if bits != 0 {
                return Some(base + bits.trailing_zeros() as usize);
            }
            page_index += 1;
            offset = 0;
        }
        None
    }

    pub(crate) fn truncate_slot_pages(&mut self, physical_slots: usize) {
        let wanted = physical_slots / 64 + usize::from(physical_slots % 64 != 0);
        while self.slot_bits.len() > wanted {
            if let Some(page) = self.slot_bits.pop() {
                debug_assert_eq!(page.occupied, 0);
                self.slot_bit_charges.pop();
            }
        }
        if physical_slots % 64 != 0 {
            if let Some(last) = self.slot_bits.last_mut() {
                let valid = (1u64 << (physical_slots % 64)) - 1;
                debug_assert_eq!(last.occupied & !valid, 0);
                last.reusable_free &= valid;
                last.gray &= valid;
                last.black &= valid;
            }
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
        self.clear_colors();
        self.work = Vec::new();
        self.roots = Vec::new();
        self.cycle_charges = AllocationCharges::new();
        self.growth_charges.clear();
        self.charge = 0;
        self.work_capacity = 0;
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
