pub(crate) mod trace;

use rivetlua_core::ObjectRef;

use crate::AllocationLedger;

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
    pub major_debt_bytes: usize,
    pub major_threshold_bytes: usize,
    pub promotion_survivals: u8,
    pub remembered: Vec<ObjectRef>,
    pub remembered_charge: usize,
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
    ledger: AllocationLedger,
}

impl GcState {
    pub fn new(ledger: AllocationLedger) -> Self {
        Self {
            phase: GcPhase::Pause,
            mode: GcMode::Incremental,
            cycle: GcCycleKind::Full,
            colors: Vec::new(),
            work: Vec::new(),
            roots: Vec::new(),
            root_cursor: 0,
            remembered_cursor: 0,
            sweep_cursor: 0,
            debt_bytes: 0,
            debt_threshold: 1024 * 1024,
            major_debt_bytes: 0,
            major_threshold_bytes: 4 * 1024 * 1024,
            promotion_survivals: 2,
            remembered: Vec::new(),
            remembered_charge: 0,
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
            ledger,
        }
    }

    pub fn transition(&mut self, next: GcPhase) {
        if self.phase != next {
            self.phase = next;
            self.transition_count += 1;
        }
    }

    pub fn clear_cycle(&mut self) -> Result<(), crate::VmError> {
        self.ledger.refund(self.charge)?;
        self.charge = 0;
        self.colors = Vec::new();
        self.work = Vec::new();
        self.roots = Vec::new();
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
        self.ledger.refund(self.remembered_charge)?;
        self.remembered_charge = 0;
        self.remembered = Vec::new();
        self.remembered_cursor = 0;
        Ok(())
    }
}

impl Drop for GcState {
    fn drop(&mut self) {
        if self.charge != 0 {
            self.ledger.refund_on_drop(self.charge);
        }
        if self.remembered_charge != 0 {
            self.ledger.refund_on_drop(self.remembered_charge);
        }
    }
}
