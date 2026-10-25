//! P05 驗證後的官方來源資料；不屬於 RVLU_V2 wire，也不是執行快照。

use alloc::vec::Vec;
use rivetlua_alloc::{AllocationRecovery, ReserveError, StateAllocator};

use core::mem::size_of;

use super::official::{OfficialChunk, OfficialPrototype};
use super::codec::{BytecodeVec, RetainedVec, Scratch};
use super::official_translation::OfficialPcMap;
use super::{LuaProfile, ProtoId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModuleOrigin {
    NativeRvlu,
    OfficialImport,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfficialRvluPc {
    /// 沒有對應官方指令，例如呼叫 frame 的參數搬移。
    Prologue,
    /// 官方指令所產生的第一條 RVLU 指令；資料 PC 不會有 anchor。
    Anchor(u32),
    /// 同一官方指令展開的後續 helper、close 或一般 RVLU 指令。
    Expanded(u32),
}

impl OfficialRvluPc {
    pub fn source_pc(self) -> Option<u32> {
        match self {
            Self::Prologue => None,
            Self::Anchor(pc) | Self::Expanded(pc) => Some(pc),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct OfficialArtifact {
    chunk: OfficialChunk,
    pc_mappings: RetainedVec<OfficialPcMap>,
    source_owners: RetainedVec<Option<ProtoId>>,
    allocated_bytes: usize,
}

fn fill_source_owners(chunk: &OfficialChunk, owners: &mut [Option<ProtoId>]) -> Option<()> {
    if chunk.main != ProtoId(0) || owners.len() != chunk.prototypes.len() {
        return None;
    }
    for (index, prototype) in chunk.prototypes.iter().enumerate() {
        let id = ProtoId(u32::try_from(index).ok()?);
        let source = if prototype.source.is_some() { Some(id) } else { owners[index] };
        owners[index] = source;
        for child in &prototype.children {
            let slot = owners.get_mut(child.0 as usize)?;
            *slot = source;
        }
    }
    Some(())
}

impl OfficialArtifact {
    pub(crate) fn rehome<R: AllocationRecovery>(
        &mut self,
        recovery: &mut R,
    ) -> Result<(), ReserveError<R::Error>> {
        self.chunk.rehome(recovery)?;
        if let Some(maps) = self.pc_mappings.global_mut() {
            for map in maps {
                map.rehome(recovery)?;
            }
        } else if !self.pc_mappings.is_state_for(&recovery.allocator()) {
            return Err(ReserveError::AllocatorMismatch);
        }
        self.pc_mappings.rehome(recovery)?;
        self.source_owners.rehome(recovery)?;
        self.allocated_bytes = self.state_allocated_bytes().ok_or(ReserveError::AllocationFailed)?;
        Ok(())
    }

    fn state_allocated_bytes(&self) -> Option<usize> {
        let mut bytes = StateAllocator::shared_block_size::<Self>()
            .checked_add(self.chunk.retained_backing_bytes()?)?
            .checked_add(self.pc_mappings.retained_bytes()?)?
            .checked_add(self.source_owners.retained_bytes()?)?;
        for map in &self.pc_mappings {
            bytes = bytes.checked_add(map.allocated_bytes()?)?;
        }
        Some(bytes)
    }

    pub fn profile(&self) -> LuaProfile {
        self.chunk.profile
    }

    pub fn chunk(&self) -> &OfficialChunk {
        &self.chunk
    }

    pub fn pc_mappings(&self) -> &[OfficialPcMap] {
        &self.pc_mappings
    }

    pub fn pc_map(&self, prototype: ProtoId) -> Option<&OfficialPcMap> {
        self.pc_mappings
            .get(prototype.0 as usize)
            .filter(|map| map.prototype() == prototype)
    }

    pub fn prototype(&self, prototype: ProtoId) -> Option<&OfficialPrototype> {
        self.chunk.prototype(prototype)
    }

    pub fn effective_source(&self, prototype: ProtoId) -> Option<&[u8]> {
        let owner = (*self.source_owners.get(prototype.0 as usize)?)?;
        self.chunk.prototype(owner)?.source.as_deref()
    }

    pub fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    pub(crate) fn new(
        chunk: OfficialChunk,
        chunk_bytes: usize,
        pc_mappings: Vec<OfficialPcMap>,
        max_bytes: usize,
    ) -> Option<Self> {
        let mut source_owners = Vec::new();
        source_owners.try_reserve_exact(chunk.prototypes.len()).ok()?;
        source_owners.resize(chunk.prototypes.len(), None);
        fill_source_owners(&chunk, &mut source_owners)?;
        let mut total = chunk_bytes
            .checked_add(size_of::<Self>())?
            .checked_add(2 * size_of::<usize>())?
            .checked_add(
                pc_mappings
                    .capacity()
                    .checked_mul(size_of::<OfficialPcMap>())?,
            )?
            .checked_add(source_owners.capacity().checked_mul(size_of::<Option<ProtoId>>())?)?;
        for map in &pc_mappings {
            total = total.checked_add(map.allocated_bytes()?)?;
        }
        if total > max_bytes {
            return None;
        }
        Some(Self {
            chunk,
            pc_mappings: pc_mappings.into(),
            source_owners: source_owners.into(),
            allocated_bytes: total,
        })
    }

    pub(crate) fn new_with_recovery<R: AllocationRecovery>(
        chunk: OfficialChunk,
        chunk_bytes: usize,
        pc_mappings: BytecodeVec<OfficialPcMap>,
        max_bytes: usize,
        scratch: &mut Scratch<'_, R>,
    ) -> Result<Option<Self>, ()> {
        let mut source_owners = scratch.vec();
        scratch.reserve_exact(&mut source_owners, chunk.prototypes.len())?;
        source_owners.resize(chunk.prototypes.len(), None);
        if fill_source_owners(&chunk, &mut source_owners).is_none() {
            return Ok(None);
        }
        let mut total = match chunk_bytes
            .checked_add(size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(2 * size_of::<usize>()))
            .and_then(|bytes| bytes.checked_add(pc_mappings.capacity().checked_mul(size_of::<OfficialPcMap>())?))
            .and_then(|bytes| bytes.checked_add(source_owners.capacity().checked_mul(size_of::<Option<ProtoId>>())?))
        {
            Some(total) => total,
            None => return Ok(None),
        };
        for map in &pc_mappings {
            total = match total.checked_add(map.allocated_bytes().unwrap_or(usize::MAX)) {
                Some(total) => total,
                None => return Ok(None),
            };
        }
        if total > max_bytes {
            return Ok(None);
        }
        let pc_mappings = scratch.retain(pc_mappings)?;
        let source_owners = scratch.retain(source_owners)?;
        let mut artifact = Self { chunk, pc_mappings, source_owners, allocated_bytes: total };
        if scratch.recovery().allocator().is_lua() {
            let Some(actual) = artifact.state_allocated_bytes() else {
                return Ok(None);
            };
            if actual > max_bytes {
                return Ok(None);
            }
            artifact.allocated_bytes = actual;
        }
        Ok(Some(artifact))
    }
}
