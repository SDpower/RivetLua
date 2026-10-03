//! P05 驗證後的官方來源資料；不屬於 RVLU_V2 wire，也不是執行快照。

use core::mem::size_of;

use super::official::{OfficialChunk, OfficialPrototype};
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

#[derive(Debug, PartialEq)]
pub struct OfficialArtifact {
    chunk: OfficialChunk,
    pc_mappings: Vec<OfficialPcMap>,
    allocated_bytes: usize,
}

impl OfficialArtifact {
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
        fn visit<'a>(
            node: &'a OfficialPrototype,
            target: usize,
            next: &mut usize,
        ) -> Option<&'a OfficialPrototype> {
            let own = *next;
            *next = next.checked_add(1)?;
            if own == target {
                return Some(node);
            }
            for child in &node.children {
                if let Some(found) = visit(child, target, next) {
                    return Some(found);
                }
            }
            None
        }
        visit(&self.chunk.main, prototype.0 as usize, &mut 0)
    }

    pub fn effective_source(&self, prototype: ProtoId) -> Option<&[u8]> {
        fn visit<'a>(
            node: &'a OfficialPrototype,
            target: usize,
            next: &mut usize,
            inherited: Option<&'a [u8]>,
        ) -> Option<Option<&'a [u8]>> {
            let own = *next;
            *next = next.checked_add(1)?;
            let source = node.source.as_deref().or(inherited);
            if own == target {
                return Some(source);
            }
            for child in &node.children {
                if let Some(found) = visit(child, target, next, source) {
                    return Some(found);
                }
            }
            None
        }
        visit(&self.chunk.main, prototype.0 as usize, &mut 0, None).flatten()
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
        let mut total = chunk_bytes
            .checked_add(size_of::<Self>())?
            .checked_add(2 * size_of::<usize>())?
            .checked_add(
                pc_mappings
                    .capacity()
                    .checked_mul(size_of::<OfficialPcMap>())?,
            )?;
        for map in &pc_mappings {
            total = total.checked_add(map.allocated_bytes()?)?;
        }
        if total > max_bytes {
            return None;
        }
        Some(Self {
            chunk,
            pc_mappings,
            allocated_bytes: total,
        })
    }
}
