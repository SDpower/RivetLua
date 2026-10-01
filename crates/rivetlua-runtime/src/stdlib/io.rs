//! 封閉宿主檔案能力的 Lua 入口。

use rivetlua_core::ObjectRef;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IoBuiltin {
    Open,
    Close,
    Flush,
    Input,
    Output,
    Lines,
    Read,
    Write,
    Type,
    TmpFile,
    POpen,
    FileClose,
    FileFlush,
    FileLines,
    FileRead,
    FileWrite,
    FileSeek,
    FileSetVBuf,
    FileToString,
    FileGc,
    LinesIterator {
        file: ObjectRef,
        formats: ObjectRef,
        count: usize,
        auto_close: bool,
    },
}
