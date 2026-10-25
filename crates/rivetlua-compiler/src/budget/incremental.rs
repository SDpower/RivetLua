use allocator_api2::vec::Vec as AllocVec;
use rivetlua_alloc::{AllocationRecovery, ReserveError, StateAllocator, try_reserve_exact_with};

use crate::lexer::incremental::{ByteAvailability, ByteInput, LexProgress, LexerState};
use crate::lexer::{NumericBudget, NumericCharge, ScanError};
use crate::parser::{ParseError, ParseProgress, ParserState};
use crate::resolve::meaning::{MeaningMeter, MeaningState};
use crate::{CompileLimits, Diagnostic, DiagnosticCode, LanguageProfile, SourcePosition, Span};

use super::{
    BudgetedCompileError, BudgetedFrontend, CompileBudgetSink, PullCompileError, PullCompileInput,
    PullParseMeter, PullRefill, PULL_BYTE_WORK, add, compile_frontend_with_budget, lex_admission,
    lexed_allocation_bytes, mul, parse_admission_from_bounds, ast_allocation_bytes,
    numeric_conversion_work,
};

pub trait CompileSource {
    type Source: AsRef<[u8]>;

    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, sink: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>>;
    fn take_source(&mut self) -> Self::Source;
}

pub struct BorrowedSource<'a> { source: &'a [u8], admitted: usize }

impl<'a> BorrowedSource<'a> {
    pub fn new(source: &'a [u8]) -> Self { Self { source, admitted: 0 } }
}

impl<'a> CompileSource for BorrowedSource<'a> {
    type Source = &'a [u8];
    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, _: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        if self.source.get(self.admitted) != Some(&byte) {
            return Err(BudgetedCompileError::AdmissionUnderestimated);
        }
        self.admitted += 1;
        Ok(())
    }
    fn take_source(&mut self) -> Self::Source { self.source }
}

pub struct StreamSource { bytes: AllocVec<u8, StateAllocator> }

impl StreamSource {
    pub fn new(allocator: StateAllocator) -> Self { Self { bytes: AllocVec::new_in(allocator) } }
    pub fn bytes(&self) -> &[u8] { &self.bytes }
}

impl CompileSource for StreamSource {
    type Source = AllocVec<u8, StateAllocator>;

    fn accept<S: CompileBudgetSink>(&mut self, byte: u8, sink: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        if !self.bytes.allocator().same_binding(&sink.state_allocator()) {
            return Err(BudgetedCompileError::AllocationFailed);
        }
        if self.bytes.len() == self.bytes.capacity() {
            let target = self.bytes.capacity().saturating_mul(2).max(8);
            let additional = target.checked_sub(self.bytes.len())
                .ok_or(BudgetedCompileError::AdmissionOverflow)?;
            sink.claim_temporary(additional).map_err(BudgetedCompileError::Budget)?;
            try_reserve_exact_with(&mut self.bytes, additional, &mut super::SinkNumericBudget(sink))
                .map_err(|error| match error {
                    ReserveError::Recovery(error) => error,
                    _ => BudgetedCompileError::AllocationFailed,
                })?;
            let extra = self.bytes.capacity().checked_sub(target)
                .ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
            if extra != 0 {
                sink.claim_temporary(extra).map_err(BudgetedCompileError::Budget)?;
            }
        }
        self.bytes.push(byte);
        Ok(())
    }

    fn take_source(&mut self) -> Self::Source {
        let allocator = self.bytes.allocator().clone();
        core::mem::replace(&mut self.bytes, AllocVec::new_in(allocator))
    }
}

struct DiscardSource;

impl CompileSource for DiscardSource {
    type Source = &'static [u8];
    fn accept<S: CompileBudgetSink>(&mut self, _: u8, _: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> { Ok(()) }
    fn take_source(&mut self) -> Self::Source { b"" }
}

pub enum CompileProgress {
    NeedInput { minimum_total: usize },
    Complete(rivetlua_core::VerifiedModule),
}

pub struct CompileAdvance {
    pub consumed: usize,
    pub progress: CompileProgress,
}

enum FrontendProgress {
    NeedInput { minimum_total: usize },
    Complete(BudgetedFrontend),
}

struct FrontendAdvance {
    consumed: usize,
    progress: FrontendProgress,
}

struct LexMeter {
    initialized: bool,
    admitted_len: usize,
    work: usize,
    temporary: usize,
}

impl LexMeter {
    fn new() -> Self { Self { initialized: false, admitted_len: 0, work: 0, temporary: 0 } }

    fn admit<S: CompileBudgetSink>(&mut self, len: usize, limits: &CompileLimits, sink: &mut S)
        -> Result<(), BudgetedCompileError<S::Error>> {
        if self.initialized && len <= self.admitted_len { return Ok(()); }
        let (base_work, temporary) = lex_admission(len, limits)?;
        let work = add(base_work, mul(add(len, 1)?, PULL_BYTE_WORK)?)?;
        let work_delta = work.checked_sub(self.work).ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
        let temp_delta = temporary.checked_sub(self.temporary).ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
        sink.spend_work(work_delta).map_err(BudgetedCompileError::Budget)?;
        sink.claim_temporary(temp_delta).map_err(BudgetedCompileError::Budget)?;
        self.initialized = true;
        self.admitted_len = len;
        self.work = work;
        self.temporary = temporary;
        Ok(())
    }
}

struct Feed<'a, A: CompileSource, S: CompileBudgetSink> {
    available: &'a [u8],
    eof: bool,
    consumed: usize,
    consumed_total: &'a mut usize,
    source: &'a mut A,
    sink: &'a mut S,
    lex: &'a mut LexMeter,
    limits: &'a CompileLimits,
}

impl<A: CompileSource, S: CompileBudgetSink> AllocationRecovery for Feed<'_, A, S> {
    type Error = BudgetedCompileError<S::Error>;
    fn allocator(&self) -> StateAllocator { self.sink.state_allocator() }
    fn recover_after_refusal(&mut self, before: u64) -> Result<bool, Self::Error> {
        self.sink.recover_allocator_refusal(before).map_err(BudgetedCompileError::Budget)
    }
}

impl<A: CompileSource, S: CompileBudgetSink> MeaningMeter for Feed<'_, A, S> {
    fn admit_meaning(&mut self, work: usize, temporary: usize) -> Result<(), Self::Error> {
        if work != 0 {
            self.sink.spend_work(work).map_err(BudgetedCompileError::Budget)?;
        }
        if temporary != 0 {
            self.sink.claim_temporary(temporary).map_err(BudgetedCompileError::Budget)?;
        }
        Ok(())
    }
}

impl<A: CompileSource, S: CompileBudgetSink> NumericBudget for Feed<'_, A, S> {
    fn before_conversion(&mut self, charge: NumericCharge) -> Result<(), Self::Error> {
        let work = numeric_conversion_work(charge)?;
        self.sink.spend_work(work).map_err(BudgetedCompileError::Budget)
    }
}

impl<A: CompileSource, S: CompileBudgetSink> ByteInput for Feed<'_, A, S> {
    fn next_byte(&mut self) -> Result<ByteAvailability, Self::Error> {
        let Some(byte) = self.available.get(self.consumed).copied() else {
            if self.eof { return Ok(ByteAvailability::Eof); }
            let minimum_total = self.lex.admitted_len.checked_add(1)
                .ok_or(BudgetedCompileError::AdmissionOverflow)?;
            return Ok(ByteAvailability::NeedInput(minimum_total));
        };
        let required = self.lex.admitted_len.checked_add(1)
            .ok_or(BudgetedCompileError::AdmissionOverflow)?;
        if required > self.limits.max_source_bytes {
            return Err(BudgetedCompileError::Frontend(Diagnostic {
                code: DiagnosticCode::CompileLimit,
                span: Span { start_byte: self.lex.admitted_len, end_byte: self.lex.admitted_len },
                start: SourcePosition { line: 1, column: 1 },
                end: SourcePosition { line: 1, column: 1 },
                message: "來源超過編譯限制",
            }));
        }
        self.lex.admit(required, self.limits, &mut *self.sink)?;
        self.source.accept(byte, &mut *self.sink)?;
        *self.consumed_total = required;
        self.consumed += 1;
        Ok(ByteAvailability::Byte(byte))
    }
}

pub struct CompileJob {
    profile: LanguageProfile,
    compile_limits: CompileLimits,
    ir_limits: rivetlua_core::IrLimits,
    verify_limits: rivetlua_core::VerifyLimits,
    lexer: LexerState,
    parser: Option<ParserState<'static>>,
    meaning: Option<MeaningState>,
    allocator: Option<StateAllocator>,
    lex_meter: LexMeter,
    parse_meter: PullParseMeter,
    consumed_total: usize,
    completed: bool,
    official_failure: Option<crate::official_failure::OfficialFailure>,
}

impl CompileJob {
    pub fn new(profile: LanguageProfile, compile_limits: CompileLimits,
        ir_limits: rivetlua_core::IrLimits, verify_limits: rivetlua_core::VerifyLimits) -> Self {
        Self { profile, compile_limits, ir_limits, verify_limits, lexer: LexerState::new(profile),
            parser: None, meaning: None, allocator: None, lex_meter: LexMeter::new(),
            parse_meter: PullParseMeter::new(), consumed_total: 0, completed: false,
            official_failure: None }
    }

    pub fn consumed_total(&self) -> usize { self.consumed_total }

    #[doc(hidden)]
    pub fn official_failure(&self) -> Option<&crate::official_failure::OfficialFailure> {
        self.official_failure.as_ref()
    }

    pub fn advance<A: CompileSource, S: CompileBudgetSink>(
        &mut self, available: &[u8], eof: bool, source: &mut A, chunk_name: &[u8], sink: &mut S,
    ) -> Result<CompileAdvance, BudgetedCompileError<S::Error>> {
        let result = self.advance_frontend(available, eof, source, sink)?;
        match result.progress {
            FrontendProgress::NeedInput { minimum_total } => Ok(CompileAdvance {
                consumed: result.consumed, progress: CompileProgress::NeedInput { minimum_total },
            }),
            FrontendProgress::Complete(frontend) => {
                let source_bytes = source.take_source();
                if source_bytes.as_ref().len() != frontend.lexed.source_len {
                    return Err(BudgetedCompileError::AdmissionUnderestimated);
                }
                let module = compile_frontend_with_budget(frontend, source_bytes.as_ref(), chunk_name,
                    self.profile, &self.compile_limits, &self.ir_limits, &self.verify_limits,
                    sink, Some(&mut self.official_failure))?;
                Ok(CompileAdvance { consumed: result.consumed, progress: CompileProgress::Complete(module) })
            }
        }
    }

    fn advance_frontend<A: CompileSource, S: CompileBudgetSink>(
        &mut self, available: &[u8], eof: bool, source: &mut A, sink: &mut S,
    ) -> Result<FrontendAdvance, BudgetedCompileError<S::Error>> {
        if self.completed { return Err(BudgetedCompileError::AdmissionUnderestimated); }
        let result = self.advance_frontend_inner(available, eof, source, sink);
        if result.is_err() {
            self.official_failure = self.parser.as_mut()
                .and_then(ParserState::take_official_failure)
                .or_else(|| self.meaning.as_mut().and_then(MeaningState::take_official_failure))
                .or_else(|| self.lexer.take_official_failure());
            self.completed = true;
            self.parser = None;
            self.meaning = None;
            self.lexer = LexerState::new(self.profile);
        }
        result
    }

    fn advance_frontend_inner<A: CompileSource, S: CompileBudgetSink>(
        &mut self, available: &[u8], eof: bool, source: &mut A, sink: &mut S,
    ) -> Result<FrontendAdvance, BudgetedCompileError<S::Error>> {
        let allocator = sink.state_allocator();
        if self.allocator.as_ref().is_some_and(|old| !old.same_binding(&allocator)) {
            return Err(BudgetedCompileError::AllocationFailed);
        }
        self.lex_meter.admit(0, &self.compile_limits, sink)?;
        if self.parser.is_none() {
            self.parser = Some(ParserState::owned(self.profile, self.compile_limits, allocator.clone()));
            self.meaning = Some(MeaningState::new(self.profile, self.compile_limits, allocator.clone()));
            self.allocator = Some(allocator);
        }
        let mut feed = Feed { available, eof, consumed: 0, consumed_total: &mut self.consumed_total, source, sink,
            lex: &mut self.lex_meter, limits: &self.compile_limits };
        let ast = loop {
            let parser = self.parser.as_mut().ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
            let meaning = self.meaning.as_mut().ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
            match parser.advance(meaning, &mut feed).map_err(parse_error)? {
                ParseProgress::Complete(ast) => break ast,
                ParseProgress::NeedToken => match self.lexer.next_token(&self.compile_limits, &mut feed)
                    .map_err(scan_error)? {
                    LexProgress::NeedInput(minimum_total) => return Ok(FrontendAdvance {
                        consumed: feed.consumed, progress: FrontendProgress::NeedInput { minimum_total },
                    }),
                    LexProgress::Token(token) => {
                        let count = parser.token_count().checked_add(1)
                            .ok_or(BudgetedCompileError::AdmissionOverflow)?;
                        if count > self.compile_limits.max_tokens {
                            return Err(BudgetedCompileError::Frontend(Diagnostic {
                                code: DiagnosticCode::CompileLimit, span: token.span,
                                start: token.start, end: token.end,
                                message: "token 數超過編譯限制",
                            }));
                        }
                        self.parse_meter.admit_token(&token, count, &self.compile_limits, &mut *feed.sink)?;
                        parser.push_token(token, &mut feed).map_err(parse_error)?;
                    }
                },
            }
        };
        let consumed = feed.consumed;
        drop(feed);
        let parser = self.parser.take().ok_or(BudgetedCompileError::AdmissionUnderestimated)?;
        self.meaning = None;
        let ast_nodes = parser.nodes();
        let lexed = parser.into_lexed(self.lexer.offset()).map_err(BudgetedCompileError::Frontend)?;
        if lexed_allocation_bytes(&lexed)? > self.lex_meter.temporary {
            return Err(BudgetedCompileError::AdmissionUnderestimated);
        }
        let (_, _, local_limits) = parse_admission_from_bounds(
            lexed.tokens.len(), &self.parse_meter.bounds, &self.compile_limits)?;
        if ast_nodes > local_limits.max_ast_nodes || ast_allocation_bytes(&ast)? > self.parse_meter.temporary {
            return Err(BudgetedCompileError::AdmissionUnderestimated);
        }
        self.completed = true;
        Ok(FrontendAdvance { consumed, progress: FrontendProgress::Complete(BudgetedFrontend { lexed, ast, ast_nodes }) })
    }
}

fn parse_error<E>(error: ParseError<BudgetedCompileError<E>>) -> BudgetedCompileError<E> {
    match error {
        ParseError::Diagnostic(error) => BudgetedCompileError::Frontend(error),
        ParseError::Recovery(error) => error,
        ParseError::AllocationFailed => BudgetedCompileError::AllocationFailed,
    }
}

fn scan_error<E>(error: ScanError<BudgetedCompileError<E>>) -> BudgetedCompileError<E> {
    match error {
        ScanError::Diagnostic(error) => BudgetedCompileError::Frontend(error),
        ScanError::Budget(error) => error,
        ScanError::AllocationFailed => BudgetedCompileError::AllocationFailed,
    }
}

fn pull_frontend<I: PullCompileInput>(
    input: &mut I, job: &mut CompileJob,
) -> Result<BudgetedFrontend, PullCompileError<I::Error>> {
    let mut source = DiscardSource;
    let mut offset = 0usize;
    let mut eof = false;
    let mut window = [0u8; 1024];
    loop {
        let len = input.bytes().len();
        if offset < len {
            let end = len.min(offset.saturating_add(window.len()));
            let count = end - offset;
            window[..count].copy_from_slice(&input.bytes()[offset..end]);
            let result = job.advance_frontend(&window[..count], false, &mut source, input)
                .map_err(PullCompileError::Compile)?;
            offset = offset.checked_add(result.consumed)
                .ok_or(PullCompileError::Compile(BudgetedCompileError::AdmissionOverflow))?;
            match result.progress {
                FrontendProgress::Complete(frontend) => return Ok(frontend),
                FrontendProgress::NeedInput { .. } => {
                    if result.consumed != count {
                        return Err(PullCompileError::Compile(BudgetedCompileError::AdmissionUnderestimated));
                    }
                }
            }
        } else if eof {
            let result = job.advance_frontend(&[], true, &mut source, input)
                .map_err(PullCompileError::Compile)?;
            return match result.progress {
                FrontendProgress::Complete(frontend) => Ok(frontend),
                FrontendProgress::NeedInput { .. } =>
                    Err(PullCompileError::Compile(BudgetedCompileError::AdmissionUnderestimated)),
            };
        } else {
            let required = offset.checked_add(1)
                .ok_or(PullCompileError::Compile(BudgetedCompileError::AdmissionOverflow))?;
            match input.refill(required).map_err(PullCompileError::Refill)? {
                PullRefill::Appended if input.bytes().len() <= len =>
                    return Err(PullCompileError::Compile(BudgetedCompileError::AdmissionUnderestimated)),
                PullRefill::Appended => {},
                PullRefill::Eof => eof = true,
            }
        }
    }
}



pub(super) fn compile_with_budget_pull<I: PullCompileInput>(
    input: &mut I, chunk_name: &[u8], profile: LanguageProfile, compile_limits: &CompileLimits,
    ir_limits: &rivetlua_core::IrLimits, verify_limits: &rivetlua_core::VerifyLimits,
) -> Result<rivetlua_core::VerifiedModule, PullCompileError<I::Error>> {
    let mut job = CompileJob::new(profile, *compile_limits, *ir_limits, *verify_limits);
    let frontend = pull_frontend(input, &mut job)?;
    let source_len = input.bytes().len();
    if source_len != frontend.lexed.source_len {
        return Err(PullCompileError::Compile(BudgetedCompileError::AdmissionUnderestimated));
    }
    let source = input.take_source();
    if source.as_ref().len() != source_len {
        return Err(PullCompileError::Compile(BudgetedCompileError::AdmissionUnderestimated));
    }
    compile_frontend_with_budget(frontend, source.as_ref(), chunk_name, profile,
        compile_limits, ir_limits, verify_limits, input, None).map_err(PullCompileError::Compile)
}


