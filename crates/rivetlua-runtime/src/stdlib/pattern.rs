//! Lua bytes pattern 的有限深度 matcher；搜尋及回溯共用同一 fuel 計數。

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PatternError {
    Malformed,
    TooComplex,
    Exhausted,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Capture {
    pub start: usize,
    pub end: Option<usize>,
    pub position: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct Found {
    pub start: usize,
    pub end: usize,
    pub captures: [Capture; 32],
    pub count: usize,
}

#[derive(Clone, Copy)]
struct State {
    captures: [Capture; 32],
    count: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            captures: [Capture::default(); 32],
            count: 0,
        }
    }
}

pub(crate) struct Matcher<'a> {
    source: &'a [u8],
    pattern: &'a [u8],
    limit: u64,
    steps: u64,
}

impl<'a> Matcher<'a> {
    pub(crate) fn new(source: &'a [u8], pattern: &'a [u8], limit: u64) -> Self {
        Self {
            source,
            pattern,
            limit,
            steps: 0,
        }
    }

    pub(crate) fn steps(&self) -> u64 {
        self.steps
    }

    fn step(&mut self) -> Result<(), PatternError> {
        if self.steps >= self.limit {
            return Err(PatternError::Exhausted);
        }
        self.steps += 1;
        Ok(())
    }

    pub(crate) fn search(
        &mut self,
        start: usize,
        anchor: bool,
        last: Option<usize>,
    ) -> Result<Option<Found>, PatternError> {
        let pattern_start = usize::from(anchor);
        if start > self.source.len() {
            return Ok(None);
        }
        for position in start..=self.source.len() {
            self.step()?;
            let mut state = State::default();
            if let Some(end) = self.match_at(position, pattern_start, &mut state, 0)? {
                if Some(end) != last {
                    return Ok(Some(Found {
                        start: position,
                        end,
                        captures: state.captures,
                        count: state.count,
                    }));
                }
            }
            if anchor {
                break;
            }
        }
        Ok(None)
    }

    pub(crate) fn at(&mut self, start: usize, anchor: bool) -> Result<Option<Found>, PatternError> {
        if start > self.source.len() {
            return Ok(None);
        }
        self.step()?;
        let mut state = State::default();
        let Some(end) = self.match_at(start, usize::from(anchor), &mut state, 0)? else {
            return Ok(None);
        };
        Ok(Some(Found {
            start,
            end,
            captures: state.captures,
            count: state.count,
        }))
    }

    pub(crate) fn plain_find(&mut self, start: usize) -> Result<Option<Found>, PatternError> {
        if start > self.source.len() {
            return Ok(None);
        }
        if self.pattern.len() > self.source.len() - start {
            return Ok(None);
        }
        for position in start..=self.source.len() - self.pattern.len() {
            self.step()?;
            let mut equal = true;
            for offset in 0..self.pattern.len() {
                self.step()?;
                if self.source[position + offset] != self.pattern[offset] {
                    equal = false;
                    break;
                }
            }
            if equal {
                return Ok(Some(Found {
                    start: position,
                    end: position + self.pattern.len(),
                    captures: [Capture::default(); 32],
                    count: 0,
                }));
            }
        }
        Ok(None)
    }

    fn class_end(&mut self, p: usize) -> Result<usize, PatternError> {
        self.step()?;
        match self.pattern.get(p) {
            Some(b'%') if p + 1 < self.pattern.len() => Ok(p + 2),
            Some(b'%') => Err(PatternError::Malformed),
            Some(b'[') => {
                let mut cursor = p + 1;
                if self.pattern.get(cursor) == Some(&b'^') {
                    cursor += 1;
                }
                loop {
                    self.step()?;
                    let byte = *self.pattern.get(cursor).ok_or(PatternError::Malformed)?;
                    cursor += 1;
                    if byte == b'%' && cursor < self.pattern.len() {
                        cursor += 1;
                    }
                    if self.pattern.get(cursor) == Some(&b']') {
                        return Ok(cursor + 1);
                    }
                }
            }
            Some(_) => Ok(p + 1),
            None => Err(PatternError::Malformed),
        }
    }

    fn class(byte: u8, symbol: u8) -> bool {
        let hit = match symbol.to_ascii_lowercase() {
            b'a' => byte.is_ascii_alphabetic(),
            b'c' => byte.is_ascii_control(),
            b'd' => byte.is_ascii_digit(),
            b'g' => byte.is_ascii_graphic(),
            b'l' => byte.is_ascii_lowercase(),
            b'p' => byte.is_ascii_punctuation(),
            b's' => matches!(byte, b'\t' | b'\n' | 0x0b | 0x0c | b'\r' | b' '),
            b'u' => byte.is_ascii_uppercase(),
            b'w' => byte.is_ascii_alphanumeric(),
            b'x' => byte.is_ascii_hexdigit(),
            b'z' => byte == 0,
            _ => return byte == symbol,
        };
        if symbol.is_ascii_lowercase() {
            hit
        } else {
            !hit
        }
    }

    fn bracket(&mut self, byte: u8, start: usize, end: usize) -> Result<bool, PatternError> {
        let mut p = start + 1;
        let positive = if self.pattern.get(p) == Some(&b'^') {
            p += 1;
            false
        } else {
            true
        };
        while p < end - 1 {
            self.step()?;
            let candidate = self.pattern[p];
            if candidate == b'%' && p + 1 < end - 1 {
                if Self::class(byte, self.pattern[p + 1]) {
                    return Ok(positive);
                }
                p += 2;
            } else if p + 2 < end - 1 && self.pattern[p + 1] == b'-' {
                if candidate <= byte && byte <= self.pattern[p + 2] {
                    return Ok(positive);
                }
                p += 3;
            } else {
                if byte == candidate {
                    return Ok(positive);
                }
                p += 1;
            }
        }
        Ok(!positive)
    }

    fn single(&mut self, s: usize, p: usize, end: usize) -> Result<bool, PatternError> {
        self.step()?;
        let Some(&byte) = self.source.get(s) else {
            return Ok(false);
        };
        Ok(match self.pattern[p] {
            b'.' => true,
            b'%' => Self::class(byte, self.pattern[p + 1]),
            b'[' => self.bracket(byte, p, end)?,
            literal => byte == literal,
        })
    }

    fn match_at(
        &mut self,
        mut s: usize,
        mut p: usize,
        state: &mut State,
        depth: usize,
    ) -> Result<Option<usize>, PatternError> {
        if depth >= 200 {
            return Err(PatternError::TooComplex);
        }
        loop {
            self.step()?;
            if p >= self.pattern.len() {
                return Ok(Some(s));
            }
            match self.pattern[p] {
                b'(' => {
                    if state.count == 32 {
                        return Err(PatternError::Malformed);
                    }
                    let position = self.pattern.get(p + 1) == Some(&b')');
                    state.captures[state.count] = Capture {
                        start: s,
                        end: position.then_some(s),
                        position,
                    };
                    state.count += 1;
                    p += if position { 2 } else { 1 };
                    continue;
                }
                b')' => {
                    let Some(index) = (0..state.count)
                        .rev()
                        .find(|&i| state.captures[i].end.is_none())
                    else {
                        return Err(PatternError::Malformed);
                    };
                    state.captures[index].end = Some(s);
                    p += 1;
                    continue;
                }
                b'$' if p + 1 == self.pattern.len() => {
                    return Ok((s == self.source.len()).then_some(s));
                }
                b'%' => {
                    let code = *self.pattern.get(p + 1).ok_or(PatternError::Malformed)?;
                    match code {
                        b'b' => {
                            let open = *self.pattern.get(p + 2).ok_or(PatternError::Malformed)?;
                            let close = *self.pattern.get(p + 3).ok_or(PatternError::Malformed)?;
                            if self.source.get(s) != Some(&open) {
                                return Ok(None);
                            }
                            let mut level = 1_usize;
                            s += 1;
                            while s < self.source.len() {
                                self.step()?;
                                if self.source[s] == close {
                                    level -= 1;
                                    if level == 0 {
                                        s += 1;
                                        break;
                                    }
                                } else if self.source[s] == open {
                                    level += 1;
                                }
                                s += 1;
                            }
                            if level != 0 {
                                return Ok(None);
                            }
                            p += 4;
                            continue;
                        }
                        b'f' => {
                            let class = p + 2;
                            if self.pattern.get(class) != Some(&b'[') {
                                return Err(PatternError::Malformed);
                            }
                            let end = self.class_end(class)?;
                            let previous = if s == 0 { 0 } else { self.source[s - 1] };
                            let current = self.source.get(s).copied().unwrap_or(0);
                            if self.bracket(previous, class, end)?
                                || !self.bracket(current, class, end)?
                            {
                                return Ok(None);
                            }
                            p = end;
                            continue;
                        }
                        b'0'..=b'9' => {
                            let index =
                                usize::from(code.checked_sub(b'1').ok_or(PatternError::Malformed)?);
                            let capture = state
                                .captures
                                .get(index)
                                .filter(|_| index < state.count)
                                .ok_or(PatternError::Malformed)?;
                            let end = capture.end.ok_or(PatternError::Malformed)?;
                            if capture.position {
                                return Ok(None);
                            }
                            if end < capture.start {
                                return Err(PatternError::Malformed);
                            }
                            let length = end - capture.start;
                            if s.saturating_add(length) > self.source.len() {
                                return Ok(None);
                            }
                            for offset in 0..length {
                                self.step()?;
                                if self.source[s + offset] != self.source[capture.start + offset] {
                                    return Ok(None);
                                }
                            }
                            s += length;
                            p += 2;
                            continue;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            let end = self.class_end(p)?;
            let matched = self.single(s, p, end)?;
            match self.pattern.get(end) {
                Some(b'?') => {
                    if matched {
                        let saved = *state;
                        if let Some(found) = self.match_at(s + 1, end + 1, state, depth + 1)? {
                            return Ok(Some(found));
                        }
                        *state = saved;
                    }
                    p = end + 1;
                }
                Some(b'*' | b'+' | b'-') => {
                    let modifier = self.pattern[end];
                    if modifier == b'+' && !matched {
                        return Ok(None);
                    }
                    let first = if modifier == b'+' { s + 1 } else { s };
                    if modifier == b'-' {
                        let mut candidate = first;
                        loop {
                            let saved = *state;
                            if let Some(found) =
                                self.match_at(candidate, end + 1, state, depth + 1)?
                            {
                                return Ok(Some(found));
                            }
                            *state = saved;
                            if !self.single(candidate, p, end)? {
                                return Ok(None);
                            }
                            self.step()?;
                            candidate += 1;
                        }
                    }
                    let mut last = first;
                    while self.single(last, p, end)? {
                        last += 1;
                    }
                    for candidate in (first..=last).rev() {
                        self.step()?;
                        let saved = *state;
                        if let Some(found) = self.match_at(candidate, end + 1, state, depth + 1)? {
                            return Ok(Some(found));
                        }
                        *state = saved;
                    }
                    return Ok(None);
                }
                _ => {
                    if !matched {
                        return Ok(None);
                    }
                    s += 1;
                    p = end;
                }
            }
        }
    }
}

pub(crate) fn special(pattern: &[u8]) -> bool {
    pattern.iter().any(|byte| b"^$*+?.([%-".contains(byte))
}
