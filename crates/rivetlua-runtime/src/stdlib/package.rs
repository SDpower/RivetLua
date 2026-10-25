//! 受宿主能力控制的 chunk 與 package 狀態。

use rivetlua_core::{InputFormat, LuaProfile, ObjectRef, OfficialChunkCursor, Value};
use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::StateAllocator;

use crate::alloc::{AllocationCharge, AllocationCharges, AllocationLedger, FailPoint,
    reserve_state_vec_host};
use crate::vm::{RuntimeError, RuntimeErrorKind};
use crate::host::{HostLoadJob, LoadBudgetState};
use crate::string::ByteString;
use crate::{ObjectKind, RootId, RootKind, Vm, VmError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoadBuiltin {
    Load {
        environment: ObjectRef,
    },
    LoadFile {
        environment: ObjectRef,
    },
    DoFile {
        environment: ObjectRef,
    },
    Require {
        cell: ObjectRef,
    },
    PreloadSearcher {
        cell: ObjectRef,
    },
    SearchPath,
    LuaSearcher {
        cell: ObjectRef,
        environment: ObjectRef,
    },
    NativeSearcher {
        cell: ObjectRef,
        environment: ObjectRef,
        root: bool,
    },
}

impl LoadBuiltin {
    pub(crate) const fn owner(self) -> Option<ObjectRef> {
        match self {
            Self::Load { environment }
            | Self::LoadFile { environment }
            | Self::DoFile { environment } => Some(environment),
            Self::Require { cell }
            | Self::PreloadSearcher { cell }
            | Self::LuaSearcher { cell, .. }
            | Self::NativeSearcher { cell, .. } => Some(cell),
            Self::SearchPath => None,
        }
    }

    pub(crate) const fn environment(self) -> Option<ObjectRef> {
        match self {
            Self::LuaSearcher { environment, .. } | Self::NativeSearcher { environment, .. } => {
                Some(environment)
            }
            _ => None,
        }
    }
}

#[doc(hidden)]
pub struct LoadBuffer {
    bytes: AllocVec<u8, StateAllocator>,
    ledger: AllocationLedger,
    owner: Option<LoadBufferCharges>,
    last_failure: Option<VmError>,
}

struct LoadBufferCharges {
    main: AllocationCharge,
    excess: Option<AllocationCharge>,
}

pub(crate) struct LoadReaderState {
    pub(crate) reader: Value,
    pub(crate) environment: Value,
    pub(crate) source: LoadBuffer,
    pub(crate) chunkname: LoadBuffer,
    pub(crate) mode: LoadMode,
    pub(crate) profile: LuaProfile,
    pub(crate) chunks: usize,
    pub(crate) piece: Option<LoadReaderPiece>,
    pub(crate) eof: bool,
    pub(crate) prefix: [u8; 6],
    pub(crate) prefix_len: usize,
    pub(crate) prefix_offset: usize,
    pub(crate) format: Option<InputFormat>,
    pub(crate) job: Option<HostLoadJob>,
    pub(crate) budget: Option<LoadBudgetState>,
    pub(crate) official_cursor: Option<OfficialChunkCursor>,
    pub(crate) official_minimum_total: usize,
    pub(crate) official_scanned: usize,
    reader_root: Option<RootId>,
    environment_root: Option<RootId>,
    previous_object: Option<ObjectRef>,
    previous_root: Option<RootId>,
}

pub(crate) enum LoadReaderPieceBytes {
    String(ByteString),
    Number { bytes: [u8; 128], len: usize },
}

impl LoadReaderPieceBytes {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::String(string) => string.as_bytes(),
            Self::Number { bytes, len } => &bytes[..*len],
        }
    }
}

pub(crate) struct LoadReaderPiece {
    pub(crate) bytes: LoadReaderPieceBytes,
    pub(crate) offset: usize,
    pub(crate) object: Option<ObjectRef>,
    pub(crate) root: Option<RootId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequirePhase {
    LoadedRead,
    SearchersRead,
    SearcherCall,
    LoaderCall,
    LoadedAfterNilRead,
    LoadedWrite,
    LoadedFinalRead,
}

#[derive(Clone, Copy)]
pub(crate) enum RequireRef {
    Package = 0,
    Loaded = 1,
    Name = 2,
    Key = 3,
    Searchers = 4,
    Loader = 5,
    Data = 6,
}

pub(crate) struct RequireState {
    refs: [Value; 7],
    roots: [Option<RootId>; 7],
    pub(crate) phase: RequirePhase,
    pub(crate) search_index: usize,
    pub(crate) diagnostics: LoadBuffer,
}

pub(crate) struct PreloadState {
    pub(crate) key: ObjectRef,
    root: Option<RootId>,
}

pub(crate) struct PathSearcherState {
    pub(crate) package: Value,
    pub(crate) environment: ObjectRef,
    pub(crate) name: ObjectRef,
    pub(crate) path_key: ObjectRef,
    roots: [Option<RootId>; 4],
}

impl PathSearcherState {
    pub(crate) fn new(
        vm: &mut Vm,
        package: Value,
        environment: ObjectRef,
        name: ObjectRef,
        path_key: ObjectRef,
    ) -> Result<Self, VmError> {
        let mut state = Self {
            package,
            environment,
            name,
            path_key,
            roots: [None; 4],
        };
        state.restore_roots(vm)?;
        Ok(state)
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for root in self.roots.iter_mut().rev() {
            if let Some(root) = root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        let values = [
            self.package,
            Value::Object(self.environment),
            Value::Object(self.name),
            Value::Object(self.path_key),
        ];
        for (slot, value) in values
            .iter()
            .copied()
            .enumerate()
        {
            if self.roots[slot].is_none() {
                let Value::Object(object) = value else { continue };
                match vm.add_root_with_borrowed_roots(RootKind::Temporary, object, &values) {
                    Ok(root) => self.roots[slot] = Some(root),
                    Err(error) => {
                        self.clear_roots(vm)?;
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for value in [
            self.package,
            Value::Object(self.environment),
            Value::Object(self.name),
            Value::Object(self.path_key),
        ] {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        Ok(())
    }
}

impl PreloadState {
    pub(crate) fn new(vm: &mut Vm, key: ObjectRef) -> Result<Self, VmError> {
        Ok(Self {
            key,
            root: Some(vm.add_root(RootKind::Temporary, key)?),
        })
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if self.root.is_none() {
            self.root = Some(vm.add_root(RootKind::Temporary, self.key)?);
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        visit(self.key)
    }
}

impl RequireState {
    pub(crate) fn new(
        vm: &mut Vm,
        package: Value,
        loaded: ObjectRef,
        name: Value,
        key: Value,
    ) -> Result<Self, VmError> {
        let mut state = Self {
            refs: [
                package,
                Value::Object(loaded),
                name,
                key,
                Value::Nil,
                Value::Nil,
                Value::Nil,
            ],
            roots: [None; 7],
            phase: RequirePhase::LoadedRead,
            search_index: 1,
            diagnostics: LoadBuffer::new(vm),
        };
        state.restore_roots(vm)?;
        Ok(state)
    }

    pub(crate) fn get(&self, reference: RequireRef) -> Value {
        self.refs[reference as usize]
    }

    pub(crate) fn set(
        &mut self,
        vm: &mut Vm,
        reference: RequireRef,
        value: Value,
    ) -> Result<(), VmError> {
        let index = reference as usize;
        let root = if let Value::Object(object) = value {
            Some(vm.add_root(RootKind::Temporary, object)?)
        } else {
            None
        };
        if let Some(old) = core::mem::replace(&mut self.roots[index], root) {
            vm.remove_root(old)?;
        }
        self.refs[index] = value;
        Ok(())
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for root in self.roots.iter_mut().rev() {
            if let Some(root) = root.take() {
                vm.remove_root(root)?;
            }
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        for index in 0..self.refs.len() {
            if self.roots[index].is_none() {
                if let Value::Object(object) = self.refs[index] {
                    match vm.add_root_with_borrowed_roots(RootKind::Temporary, object, &self.refs) {
                        Ok(root) => self.roots[index] = Some(root),
                        Err(error) => {
                            self.clear_roots(vm)?;
                            return Err(error);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        for value in self.refs {
            if let Value::Object(object) = value {
                visit(object)?;
            }
        }
        Ok(())
    }
}

impl LoadReaderState {
    pub(crate) fn new(
        vm: &mut Vm,
        reader: Value,
        environment: Value,
        chunkname: LoadBuffer,
        mode: LoadMode,
    ) -> Result<Self, VmError> {
        let mut state = Self {
            reader,
            environment,
            source: LoadBuffer::new(vm),
            chunkname,
            mode,
            profile: vm.language_profile(),
            chunks: 0,
            piece: None,
            eof: false,
            prefix: [0; 6],
            prefix_len: 0,
            prefix_offset: 0,
            format: None,
            job: None,
            budget: Some(LoadBudgetState::metered(
                vm.load_limits().max_work_units,
                vm.load_limits().max_temporary_bytes,
                vm.allocation_ledger().clone(),
            ).with_module_limit(vm.load_limits().max_module_allocation_bytes)),
            official_cursor: None,
            official_minimum_total: 1,
            official_scanned: 0,
            reader_root: None,
            environment_root: None,
            previous_object: None,
            previous_root: None,
        };
        state.restore_roots(vm)?;
        Ok(state)
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.piece.as_mut().and_then(|piece| piece.root.take()) {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.previous_root.take() {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.environment_root.take() {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.reader_root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        let piece = self.piece.as_ref().and_then(|piece| piece.object).map(Value::Object)
            .unwrap_or(Value::Nil);
        let previous = self.previous_object.map(Value::Object).unwrap_or(Value::Nil);
        let borrowed = [self.reader, self.environment, piece, previous];
        if self.reader_root.is_none() {
            if let Value::Object(reader) = self.reader {
                self.reader_root = Some(vm.add_root_with_borrowed_roots(
                    RootKind::Temporary, reader, &borrowed,
                )?);
            }
        }
        if self.environment_root.is_none() {
            if let Value::Object(environment) = self.environment {
                match vm.add_root_with_borrowed_roots(
                    RootKind::Temporary, environment, &borrowed,
                ) {
                    Ok(root) => self.environment_root = Some(root),
                    Err(error) => {
                        self.clear_roots(vm)?;
                        return Err(error);
                    }
                }
            }
        }
        if self.previous_root.is_none() {
            if let Some(previous) = self.previous_object {
                match vm.add_root_with_borrowed_roots(
                    RootKind::Temporary, previous, &borrowed,
                ) {
                    Ok(root) => self.previous_root = Some(root),
                    Err(error) => { self.clear_roots(vm)?; return Err(error); }
                }
            }
        }
        let piece_object = self.piece.as_ref().and_then(|piece| {
            if piece.root.is_none() { piece.object } else { None }
        });
        if let Some(object) = piece_object {
            match vm.add_root_with_borrowed_roots(RootKind::Temporary, object, &borrowed) {
                Ok(root) => {
                    if let Some(piece) = self.piece.as_mut() { piece.root = Some(root); }
                }
                Err(error) => { self.clear_roots(vm)?; return Err(error); }
            }
        }
        Ok(())
    }

    pub(crate) fn release_previous(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.previous_root.take() {
            vm.remove_root(root)?;
        }
        self.previous_object = None;
        Ok(())
    }

    pub(crate) fn borrowed_roots(&self) -> [Value; 4] {
        [
            self.reader,
            self.environment,
            self.previous_object.map(Value::Object).unwrap_or(Value::Nil),
            self.piece.as_ref().and_then(|piece| piece.object)
                .map(Value::Object).unwrap_or(Value::Nil),
        ]
    }

    pub(crate) fn finish_piece(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if self.piece.is_none() { return Ok(()); }
        if self.profile == LuaProfile::Lua54 {
            self.release_previous(vm)?;
        }
        let Some(mut piece) = self.piece.take() else { return Ok(()); };
        if self.profile == LuaProfile::Lua54 {
            self.previous_object = piece.object;
            self.previous_root = piece.root.take();
        } else if let Some(root) = piece.root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn trace_children(
        &self,
        mut visit: impl FnMut(ObjectRef) -> Result<(), VmError>,
    ) -> Result<(), VmError> {
        if let Value::Object(reader) = self.reader {
            visit(reader)?;
        }
        if let Value::Object(environment) = self.environment {
            visit(environment)?;
        }
        if let Some(object) = self.previous_object {
            visit(object)?;
        }
        if let Some(object) = self.piece.as_ref().and_then(|piece| piece.object) {
            visit(object)?;
        }
        Ok(())
    }
}

pub(crate) struct ModuleCharge {
    charges: AllocationCharges,
}

impl ModuleCharge {
    #[cfg(test)]
    pub(crate) fn empty() -> Self {
        Self {
            charges: AllocationCharges::new(),
        }
    }

    pub(crate) fn from_charges(charges: AllocationCharges) -> Self {
        Self { charges }
    }

    pub(crate) fn take(&mut self) -> AllocationCharges {
        self.charges.take_preserving_allocator()
    }
}

impl LoadBuffer {
    pub(crate) fn new(vm: &Vm) -> Self {
        let ledger = vm.allocation_ledger().clone();
        Self { bytes: AllocVec::new_in(ledger.backing_allocator()), ledger, owner: None,
            last_failure: None }
    }

    #[doc(hidden)]
    pub fn planned_growth(&self, incoming: usize) -> Result<Option<usize>, RuntimeError> {
        let needed = self.bytes.len().checked_add(incoming).ok_or(VmError::ArithmeticOverflow)?;
        if needed <= self.bytes.capacity() { return Ok(None); }
        Ok(Some(self.bytes.capacity().max(1).checked_mul(2).unwrap_or(needed).max(needed)))
    }

    #[doc(hidden)]
    pub fn uses_allocator(&self, allocator: &StateAllocator) -> bool {
        self.bytes.allocator().same_binding(allocator)
    }

    #[doc(hidden)]
    pub fn reserve_for_append(&mut self, incoming: usize) -> Result<(), RuntimeError> {
        let result = self.reserve_for_append_inner(incoming);
        if let Err(RuntimeError { kind: RuntimeErrorKind::Heap(error), .. }) = result {
            self.last_failure = Some(error);
        } else if result.is_ok() {
            self.last_failure = None;
        }
        result
    }

    fn reserve_for_append_inner(&mut self, incoming: usize) -> Result<(), RuntimeError> {
        let Some(target) = self.planned_growth(incoming)? else { return Ok(()); };
        let allocator = self.bytes.allocator().clone();
        let mut replacement = AllocVec::new_in(allocator.clone());
        let main = reserve_state_vec_host(&self.ledger, &mut replacement, target, FailPoint::WorkReserve)?;
        let excess = replacement.capacity().checked_sub(target).ok_or(VmError::LedgerInvariant)?;
        let extra = if excess == 0 { None } else {
            Some(self.ledger.reserve_host_vec(excess, FailPoint::WorkReserve, allocator.is_lua())?)
        };
        let owner = LoadBufferCharges {
            main: main.commit_charge()?,
            excess: extra.map(|ticket| ticket.commit_charge()).transpose()?,
        };
        replacement.extend_from_slice(&self.bytes);
        let old = core::mem::replace(&mut self.bytes, replacement);
        drop(old);
        self.owner = Some(owner);
        Ok(())
    }

    #[doc(hidden)]
    pub fn last_failure(&self) -> Option<VmError> { self.last_failure }

    #[doc(hidden)]
    pub fn append(&mut self, input: &[u8], limit: usize) -> Result<(), RuntimeError> {
        let next = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        if next > limit {
            return Err(RuntimeError::new(RuntimeErrorKind::HostLoadBudget));
        }
        self.reserve_for_append(input.len())?;
        self.bytes.extend_from_slice(input);
        Ok(())
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[doc(hidden)]
    pub fn copy_work(&self, incoming: usize) -> Result<usize, RuntimeError> {
        let needed = self
            .bytes
            .len()
            .checked_add(incoming)
            .ok_or(VmError::ArithmeticOverflow)?;
        Ok(
            incoming.saturating_add(if needed > self.bytes.capacity() {
                self.bytes.len()
            } else {
                0
            }),
        )
    }

    /// 編譯後端短暫獨占來源與其原配置帳款，留下同配置器的空替身。
    #[doc(hidden)]
    pub fn take_compile_source(&mut self) -> Self {
        let allocator = self.bytes.allocator().clone();
        let replacement = Self { bytes: AllocVec::new_in(allocator), ledger: self.ledger.clone(),
            owner: None, last_failure: None };
        core::mem::replace(self, replacement)
    }
}

impl AsRef<[u8]> for LoadBuffer {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

pub(crate) fn is_function(vm: &Vm, value: Value) -> Result<bool, RuntimeError> {
    if let Value::CFunction(function) = value {
        return if function.vm() == vm.id() {
            Ok(true)
        } else {
            Err(VmError::WrongVm.into())
        };
    }
    let Value::Object(object) = value else {
        return Ok(false);
    };
    Ok(matches!(
        vm.object_kind(object)?,
        ObjectKind::Closure | ObjectKind::CClosure | ObjectKind::Builtin
    ))
}

#[derive(Clone, Copy)]
pub(crate) struct LoadMode {
    pub(crate) text: bool,
    pub(crate) binary: bool,
}

pub(crate) fn mode_work(vm: &Vm, value: Value) -> Result<usize, RuntimeError> {
    match value {
        Value::Nil => Ok(0),
        Value::Integer(_) | Value::Float(_) => {
            let (_, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            Ok(len)
        }
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            Ok(vm.with_byte_string(object, |string| string.len())?)
        }
        _ => Err(RuntimeError::new(RuntimeErrorKind::LoadArgument)),
    }
}

pub(crate) fn mode(vm: &Vm, value: Value) -> Result<LoadMode, RuntimeError> {
    let mut result = LoadMode {
        text: true,
        binary: true,
    };
    let mut invalid_upper_b = false;
    match value {
        Value::Nil => return Ok(result),
        Value::Integer(_) | Value::Float(_) => {
            let (bytes, len) = crate::vm::basic_number_bytes(value, vm.language_profile())?;
            let bytes = bytes[..len].split(|byte| *byte == 0).next().unwrap_or(&[]);
            result.text = bytes.contains(&b't');
            result.binary = bytes.contains(&b'b');
            invalid_upper_b = bytes.contains(&b'B');
        }
        Value::Object(object) if vm.object_kind(object)? == ObjectKind::ByteString => {
            vm.with_byte_string(object, |string| {
                let bytes = string
                    .as_bytes()
                    .split(|byte| *byte == 0)
                    .next()
                    .unwrap_or(&[]);
                result.text = bytes.contains(&b't');
                result.binary = bytes.contains(&b'b');
                invalid_upper_b = bytes.contains(&b'B');
            })?;
        }
        _ => return Err(RuntimeError::new(RuntimeErrorKind::LoadArgument)),
    }
    if invalid_upper_b && vm.language_profile() == LuaProfile::Lua55 {
        return Err(RuntimeError::new(RuntimeErrorKind::LoadMode));
    }
    Ok(result)
}
