use std::cell::Cell;
use std::rc::Rc;

use rivetlua::{
    Engine, FileOperation, FileReadFormat, FileSeekOrigin, HostCloseResult, HostDeadline,
    HostFileLease, HostIo, HostOs, HostOsOperation, HostOsValue, HostResourceError,
    HostResourceErrorKind, HostServices, LuaProfile, ResourceBudget, ResourceCapability,
    RunOutcome, Value,
};

fn run(profile: LuaProfile, source: &[u8], services: HostServices) -> RunOutcome {
    let engine = Engine::new(profile);
    let module = engine.compile(source).unwrap();
    let mut vm = engine.new_vm_with_services(services).unwrap();
    vm.load_module(&module).unwrap().run().unwrap()
}

fn assert_true_in_both_profiles(source: &[u8]) {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        assert_eq!(
            run(profile, source, HostServices::deny_all()),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
    }
}

#[test]
fn sdk_global_environment_is_the_chunk_environment_in_both_profiles() {
    assert_true_in_both_profiles(b"return _G == _ENV");
}

#[test]
fn sdk_math_atan_y_x_preserves_all_quadrants_in_both_profiles() {
    assert_true_in_both_profiles(
        b"local p=math.pi; local e=1e-12; \
          return math.abs(math.atan(1,1)-p/4)<e and \
            math.abs(math.atan(1,-1)-3*p/4)<e and \
            math.abs(math.atan(-1,-1)+3*p/4)<e and \
            math.abs(math.atan(-1,1)+p/4)<e",
    );
}

#[test]
fn sdk_coroutine_close_omitted_argument_follows_profile_rules() {
    assert_eq!(
        run(
            LuaProfile::Lua55,
            b"local co=coroutine.create(function() coroutine.close() end); \
              local ok=coroutine.resume(co); return ok and coroutine.status(co)=='dead'",
            HostServices::deny_all(),
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    assert_eq!(
        run(
            LuaProfile::Lua54,
            b"return not pcall(coroutine.close)",
            HostServices::deny_all(),
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
}

#[test]
fn sdk_debug_setcstacklimit_matches_lua54_fixed_limit_only() {
    assert_eq!(
        run(
            LuaProfile::Lua54,
            b"local ok,err=pcall(debug.setcstacklimit,{}); \
              return debug.setcstacklimit(0)==200 and \
                debug.setcstacklimit(3.0)==200 and \
                debug.setcstacklimit('3')==200 and \
                not ok and err=='E_DEBUG_ARGUMENT'",
            HostServices::deny_all(),
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
    assert_eq!(
        run(
            LuaProfile::Lua55,
            b"return debug.setcstacklimit==nil",
            HostServices::deny_all(),
        ),
        RunOutcome::Returned(vec![Value::Boolean(true)])
    );
}

#[test]
fn sdk_io_close_wrapper_closes_a_successful_mock_tmpfile() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let closed = Rc::new(Cell::new(0));
        let services = HostServices::deny_all().and_resource(
            ResourceCapability::deny_all()
                .and_io(MockIo {
                    tmpfile_closes: Rc::clone(&closed),
                })
                .and_deadline(MockDeadline),
        );
        assert_eq!(
            run(
                profile,
                b"local file=io.tmpfile(); return io.type(io.stderr)=='file' and \
                  io.type(file)=='file' and io.close(file)",
                services,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
        assert_eq!(closed.get(), 1, "{profile:?}");
    }
}

#[test]
fn sdk_os_remove_and_rename_use_successful_mock_operations() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        let calls = Rc::new(Cell::new(0));
        let services = HostServices::deny_all().and_resource(
            ResourceCapability::deny_all()
                .and_os(MockOs {
                    successful_operations: Rc::clone(&calls),
                })
                .and_deadline(MockDeadline),
        );
        assert_eq!(
            run(
                profile,
                b"return os.remove('mock:remove')==true and \
                  os.rename('mock:old','mock:new')==true",
                services,
            ),
            RunOutcome::Returned(vec![Value::Boolean(true)]),
            "{profile:?}"
        );
        assert_eq!(calls.get(), 2, "{profile:?}");
    }
}

fn unsupported() -> HostResourceError {
    HostResourceError::new(
        HostResourceErrorKind::Unsupported,
        b"mock operation unsupported".to_vec(),
    )
}

struct MockDeadline;

impl HostDeadline for MockDeadline {
    fn check(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)
    }
}

struct MockFileLease {
    closes: Rc<Cell<usize>>,
    closed: bool,
}

impl MockFileLease {
    fn new(
        closes: Rc<Cell<usize>>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.claim_retained(std::mem::size_of::<Self>())?;
        Ok(Box::new(Self {
            closes,
            closed: false,
        }))
    }
}

impl Drop for MockFileLease {
    fn drop(&mut self) {
        if !self.closed {
            self.closes.set(self.closes.get() + 1);
            self.closed = true;
        }
    }
}

impl HostFileLease for MockFileLease {
    fn authorize(
        &mut self,
        operation: FileOperation,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        match operation {
            FileOperation::Close => Ok(()),
            _ => Err(unsupported()),
        }
    }

    fn read(
        &mut self,
        _format: FileReadFormat,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError> {
        Ok(None)
    }

    fn write(
        &mut self,
        bytes: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError> {
        Ok(bytes.len())
    }

    fn seek(
        &mut self,
        _origin: FileSeekOrigin,
        _offset: i64,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError> {
        Ok(0)
    }

    fn flush(&mut self, _budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        Ok(())
    }

    fn close(
        mut self: Box<Self>,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError> {
        self.closed = true;
        self.closes.set(self.closes.get() + 1);
        Ok(HostCloseResult::File)
    }
}

struct MockIo {
    tmpfile_closes: Rc<Cell<usize>>,
}

impl HostIo for MockIo {
    fn authorize_path(
        &mut self,
        _path: &[u8],
        _mode: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        Err(unsupported())
    }

    fn open(
        &mut self,
        _path: &[u8],
        _mode: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Err(unsupported())
    }

    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        MockFileLease::new(Rc::new(Cell::new(0)), budget)
    }

    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        MockFileLease::new(Rc::new(Cell::new(0)), budget)
    }

    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        MockFileLease::new(Rc::new(Cell::new(0)), budget)
    }

    fn tmpfile(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        MockFileLease::new(Rc::clone(&self.tmpfile_closes), budget)
    }
}

struct MockOs {
    successful_operations: Rc<Cell<usize>>,
}

impl HostOs for MockOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        match operation {
            HostOsOperation::Remove(_) | HostOsOperation::Rename(_, _) => Ok(()),
            _ => Err(unsupported()),
        }
    }

    fn authorize_path(
        &mut self,
        path: &[u8],
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        if path == b"mock:remove" || path == b"mock:old" || path == b"mock:new" {
            Ok(())
        } else {
            Err(HostResourceError::new(
                HostResourceErrorKind::PathDenied,
                b"mock path denied".to_vec(),
            ))
        }
    }

    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        _budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        match operation {
            HostOsOperation::Remove(_) | HostOsOperation::Rename(_, _) => {
                self.successful_operations
                    .set(self.successful_operations.get() + 1);
                Ok(HostOsValue::Boolean(true))
            }
            _ => Err(unsupported()),
        }
    }
}
