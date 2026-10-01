//! 受宿主能力控制的 chunk 與 package 狀態。

use rivetlua_core::{LuaProfile, ObjectRef, Value};

use crate::alloc::AllocationLedger;
use crate::stdlib::string::Buffer;
use crate::vm::{RuntimeError, RuntimeErrorKind};
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
        package: ObjectRef,
    },
    PreloadSearcher,
    LuaSearcher {
        package: ObjectRef,
        environment: ObjectRef,
    },
    NativeSearcher {
        package: ObjectRef,
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
            Self::Require { package }
            | Self::LuaSearcher { package, .. }
            | Self::NativeSearcher { package, .. } => Some(package),
            Self::PreloadSearcher => None,
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

pub(crate) struct LoadBuffer {
    buffer: Buffer,
}

pub(crate) struct LoadReaderState {
    pub(crate) reader: Value,
    pub(crate) environment: Value,
    pub(crate) source: LoadBuffer,
    pub(crate) chunkname: LoadBuffer,
    pub(crate) mode: LoadMode,
    pub(crate) chunks: usize,
    reader_root: Option<RootId>,
    environment_root: Option<RootId>,
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
    pub(crate) package: ObjectRef,
    pub(crate) environment: ObjectRef,
    pub(crate) name: ObjectRef,
    pub(crate) path_key: ObjectRef,
    roots: [Option<RootId>; 4],
}

impl PathSearcherState {
    pub(crate) fn new(
        vm: &mut Vm,
        package: ObjectRef,
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
        for (slot, object) in [self.package, self.environment, self.name, self.path_key]
            .into_iter()
            .enumerate()
        {
            if self.roots[slot].is_none() {
                match vm.add_root(RootKind::Temporary, object) {
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
        for object in [self.package, self.environment, self.name, self.path_key] {
            visit(object)?;
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
        package: ObjectRef,
        loaded: ObjectRef,
        name: Value,
        key: Value,
    ) -> Result<Self, VmError> {
        let mut state = Self {
            refs: [
                Value::Object(package),
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
        for (index, value) in self.refs.iter().enumerate() {
            if self.roots[index].is_none() {
                if let Value::Object(object) = value {
                    match vm.add_root(RootKind::Temporary, *object) {
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
            chunks: 0,
            reader_root: None,
            environment_root: None,
        };
        state.restore_roots(vm)?;
        Ok(state)
    }

    pub(crate) fn clear_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if let Some(root) = self.environment_root.take() {
            vm.remove_root(root)?;
        }
        if let Some(root) = self.reader_root.take() {
            vm.remove_root(root)?;
        }
        Ok(())
    }

    pub(crate) fn restore_roots(&mut self, vm: &mut Vm) -> Result<(), VmError> {
        if self.reader_root.is_none() {
            if let Value::Object(reader) = self.reader {
                self.reader_root = Some(vm.add_root(RootKind::Temporary, reader)?);
            }
        }
        if self.environment_root.is_none() {
            if let Value::Object(environment) = self.environment {
                match vm.add_root(RootKind::Temporary, environment) {
                    Ok(root) => self.environment_root = Some(root),
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
        if let Value::Object(reader) = self.reader {
            visit(reader)?;
        }
        if let Value::Object(environment) = self.environment {
            visit(environment)?;
        }
        Ok(())
    }
}

pub(crate) struct ModuleCharge {
    ledger: AllocationLedger,
    bytes: usize,
}

impl ModuleCharge {
    pub(crate) fn new(vm: &Vm, bytes: usize) -> Self {
        Self {
            ledger: vm.allocation_ledger().clone(),
            bytes,
        }
    }

    pub(crate) fn take(&mut self) -> usize {
        core::mem::replace(&mut self.bytes, 0)
    }
}

impl Drop for ModuleCharge {
    fn drop(&mut self) {
        self.ledger.refund_on_drop(self.bytes);
    }
}

impl LoadBuffer {
    pub(crate) fn new(vm: &Vm) -> Self {
        Self {
            buffer: Buffer::empty(vm),
        }
    }

    pub(crate) fn append(&mut self, input: &[u8], limit: usize) -> Result<(), RuntimeError> {
        let next = self
            .buffer
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or(VmError::ArithmeticOverflow)?;
        if next > limit {
            return Err(RuntimeError::new(RuntimeErrorKind::HostLoadBudget));
        }
        self.buffer.append(input)
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buffer.bytes
    }

    pub(crate) fn copy_work(&self, incoming: usize) -> Result<usize, RuntimeError> {
        let needed = self
            .buffer
            .bytes
            .len()
            .checked_add(incoming)
            .ok_or(VmError::ArithmeticOverflow)?;
        Ok(
            incoming.saturating_add(if needed > self.buffer.bytes.capacity() {
                self.buffer.bytes.len()
            } else {
                0
            }),
        )
    }
}

pub(crate) fn is_function(vm: &Vm, value: Value) -> Result<bool, RuntimeError> {
    let Value::Object(object) = value else {
        return Ok(false);
    };
    Ok(matches!(
        vm.object_kind(object)?,
        ObjectKind::Closure | ObjectKind::Builtin
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
