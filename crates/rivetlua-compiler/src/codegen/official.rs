//! 官方 chunk 轉譯的既有 compiler API；canonical P05 實作位於 core。

pub use rivetlua_core::bytecode::official_translation::{
    OfficialFixedBuiltin, OfficialFrameInput, OfficialFrameInputSource, OfficialInternalCall,
    OfficialPcMap, OfficialRootBinding, OfficialRootBindingSource, OfficialRvluPc,
    OfficialTranslation, OfficialTranslationError, OfficialUpvalueMap, OfficialWorkBudget,
    translate_official_chunk, translate_official_chunk_with_work,
};
