use super::{CompileLimits, LanguageProfile, SourcePosition};

pub(in crate::lexer) struct Cursor<'input> {
    input: &'input [u8],
    #[allow(dead_code)]
    profile: LanguageProfile,
    offset: usize,
    line: usize,
    column: usize,
}

impl<'input> Cursor<'input> {
    pub(super) fn new(input: &'input [u8], profile: LanguageProfile) -> Self {
        Self {
            input,
            profile,
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    pub(super) fn peek(&self) -> Option<u8> {
        self.input.get(self.offset).copied()
    }

    pub(super) fn peek_n(&self, distance: usize) -> Option<u8> {
        self.offset
            .checked_add(distance)
            .and_then(|offset| self.input.get(offset))
            .copied()
    }

    pub(super) fn offset(&self) -> usize {
        self.offset
    }

    pub(super) fn profile(&self) -> LanguageProfile {
        self.profile
    }

    pub(super) fn position(&self) -> SourcePosition {
        SourcePosition {
            line: self.line,
            column: self.column,
        }
    }

    pub(super) fn advance(&mut self, limits: &CompileLimits) -> Result<(), &'static str> {
        let Some(byte) = self.peek() else {
            return Ok(());
        };
        if matches!(byte, b'\n' | b'\r') {
            let next = self.input.get(self.offset + 1).copied();
            self.offset = self.offset.checked_add(1).ok_or("byte offset 溢位")?;
            if matches!((byte, next), (b'\n', Some(b'\r')) | (b'\r', Some(b'\n'))) {
                self.offset = self.offset.checked_add(1).ok_or("byte offset 溢位")?;
            }
            self.line = self.line.checked_add(1).ok_or("行數溢位")?;
            if self.line > limits.max_lines {
                return Err("行數超過編譯限制");
            }
            self.column = 1;
        } else {
            self.offset = self.offset.checked_add(1).ok_or("byte offset 溢位")?;
            self.column = self.column.checked_add(1).ok_or("欄位溢位")?;
        }
        Ok(())
    }
}
