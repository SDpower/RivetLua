//! 僅供完成 native grant 預檢的 CLI 使用的宿主 OS／IO adapter。

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use rivetlua::{
    FileOperation, FileReadFormat, FileSeekOrigin, HostCloseResult, HostExitStatus, HostFileLease,
    HostIo, HostOs, HostOsOperation, HostOsValue, HostResourceError, HostResourceErrorKind,
    PathEncoding, ResourceBudget, ResourceCapability, ResourceLimits,
};

use super::{CliOs, CliResourceDeadline, os_bytes, os_from_bytes};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static CHILD_STARTED: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static CHILD_REAPED: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static CHILD_NATURAL_EXIT: AtomicU64 = AtomicU64::new(0);

fn denied() -> HostResourceError {
    HostResourceError::new(HostResourceErrorKind::PolicyDenied, Vec::new())
}

fn failure(error: io::Error, budget: &mut ResourceBudget<'_>) -> HostResourceError {
    const MESSAGE: &[u8] = b"host I/O failed";
    if let Err(error) = budget.claim_temporary(MESSAGE.len()) {
        return error;
    }
    HostResourceError::io_failure(
        MESSAGE.to_vec(),
        i64::from(error.raw_os_error().unwrap_or(0)),
    )
}

fn path(bytes: &[u8]) -> Result<PathBuf, HostResourceError> {
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(denied());
    }
    #[cfg(not(unix))]
    std::str::from_utf8(bytes).map_err(|_| {
        HostResourceError::new(HostResourceErrorKind::PlatformDifference, Vec::new())
    })?;
    Ok(PathBuf::from(os_from_bytes(bytes)))
}

fn shell(command: &[u8]) -> Result<Command, HostResourceError> {
    if command.contains(&0) {
        return Err(denied());
    }
    let mut process = Command::new("/bin/sh");
    process.arg("-c").arg(super::os_from_bytes(command));
    Ok(process)
}

fn status(status: std::process::ExitStatus) -> HostExitStatus {
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal: Option<i32> = None;
    HostExitStatus {
        success: status.success(),
        signaled: signal.is_some(),
        code: i64::from(status.code().or(signal).unwrap_or(-1)),
    }
}

fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    if child.wait().is_ok() {
        #[cfg(test)]
        CHILD_REAPED.fetch_add(1, Ordering::Relaxed);
    }
}

fn wait_child(
    child: &mut Child,
    expires_at: Option<Instant>,
    budget: &mut ResourceBudget<'_>,
) -> Result<HostExitStatus, HostResourceError> {
    loop {
        if let Err(error) = budget.spend_work(1) {
            kill_and_wait(child);
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(result)) => {
                #[cfg(test)]
                {
                    CHILD_REAPED.fetch_add(1, Ordering::Relaxed);
                    if result.success() {
                        CHILD_NATURAL_EXIT.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return Ok(status(result));
            }
            Ok(None) => {}
            Err(error) => {
                kill_and_wait(child);
                return Err(failure(error, budget));
            }
        }
        if !expires_at.is_some_and(|deadline| Instant::now() < deadline) {
            kill_and_wait(child);
            return Err(HostResourceError::new(
                HostResourceErrorKind::Deadline,
                Vec::new(),
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn finish_child_on_drop(child: &mut Child, expires_at: Option<Instant>) {
    loop {
        match child.try_wait() {
            Ok(Some(result)) => {
                #[cfg(test)]
                {
                    CHILD_REAPED.fetch_add(1, Ordering::Relaxed);
                    if result.success() {
                        CHILD_NATURAL_EXIT.fetch_add(1, Ordering::Relaxed);
                    }
                }
                return;
            }
            Ok(None) => {}
            Err(_) => {
                kill_and_wait(child);
                return;
            }
        }
        if !expires_at.is_some_and(|deadline| Instant::now() < deadline) {
            kill_and_wait(child);
            return;
        }
        thread::sleep(Duration::from_millis(2));
    }
}

fn temp_path_in(directory: &Path) -> PathBuf {
    directory.join(format!(
        "rivetlua-{}-{}",
        std::process::id(),
        NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
    ))
}

fn temp_path() -> PathBuf {
    temp_path_in(&std::env::temp_dir())
}

fn tmpname_path() -> PathBuf {
    #[cfg(unix)]
    {
        Path::new("/tmp").join(format!(
            "rivetlua_{}_{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ))
    }
    #[cfg(not(unix))]
    {
        temp_path()
    }
}

fn temp_options(read: bool) -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(read).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

pub(super) fn capability(deadline: CliResourceDeadline) -> ResourceCapability {
    let expires_at = deadline.expires_at;
    let capability = ResourceCapability::deny_all()
        .and_os(TrustedOs { expires_at })
        .and_io(TrustedIo { expires_at })
        .and_deadline(deadline)
        .with_limits(ResourceLimits {
            max_work_units: 8_000_000,
            ..ResourceLimits::default()
        });
    #[cfg(unix)]
    let capability = capability.with_path_encoding(PathEncoding::RawBytes);
    capability
}

struct TrustedOs {
    expires_at: Option<Instant>,
}

impl HostOs for TrustedOs {
    fn authorize(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        match operation {
            HostOsOperation::Clock
            | HostOsOperation::Exit(_)
            | HostOsOperation::Time(None)
            | HostOsOperation::Locale(_, _) => CliOs.authorize(operation, budget),
            HostOsOperation::GetEnv(_)
            | HostOsOperation::Execute(_)
            | HostOsOperation::TmpName
            | HostOsOperation::Remove(_)
            | HostOsOperation::Rename(_, _) => budget.spend_work(1),
            _ => Err(denied()),
        }
    }

    fn authorize_path(
        &mut self,
        value: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(value.len().saturating_add(1))?;
        path(value).map(|_| ())
    }

    fn perform(
        &mut self,
        operation: HostOsOperation<'_>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostOsValue, HostResourceError> {
        budget.spend_work(1)?;
        match operation {
            HostOsOperation::Clock
            | HostOsOperation::Exit(_)
            | HostOsOperation::Time(None)
            | HostOsOperation::Locale(_, _) => CliOs.perform(operation, budget),
            HostOsOperation::GetEnv(name) => {
                let name = std::str::from_utf8(name).map_err(|_| denied())?;
                if name.contains('=') || name.contains('\0') {
                    return Err(denied());
                }
                match std::env::var_os(name) {
                    Some(value) => {
                        budget.spend_work(value.len())?;
                        budget.claim_temporary(value.len())?;
                        let bytes = os_bytes(&value);
                        budget.claim_temporary(bytes.capacity().saturating_sub(value.len()))?;
                        Ok(HostOsValue::Bytes(bytes))
                    }
                    None => Ok(HostOsValue::Nil),
                }
            }
            HostOsOperation::Execute(None) => {
                Ok(HostOsValue::Boolean(Path::new("/bin/sh").is_file()))
            }
            HostOsOperation::Execute(Some(command)) => {
                budget.spend_work(command.len())?;
                budget.claim_temporary(command.len())?;
                let mut child = shell(command)?
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|error| failure(error, budget))?;
                #[cfg(test)]
                CHILD_STARTED.fetch_add(1, Ordering::Relaxed);
                wait_child(&mut child, self.expires_at, budget).map(HostOsValue::Exit)
            }
            HostOsOperation::TmpName => {
                for _ in 0..128 {
                    budget.spend_work(1)?;
                    let candidate = tmpname_path();
                    match temp_options(false).open(&candidate) {
                        Ok(file) => {
                            drop(file);
                            let output = (|| {
                                let size = candidate.as_os_str().len();
                                budget.spend_work(size)?;
                                budget.claim_temporary(size)?;
                                let bytes = os_bytes(candidate.as_os_str());
                                budget.claim_temporary(bytes.capacity().saturating_sub(size))?;
                                Ok(bytes)
                            })();
                            let bytes = match output {
                                Ok(bytes) => bytes,
                                Err(error) => {
                                    let _ = fs::remove_file(&candidate);
                                    return Err(error);
                                }
                            };
                            return Ok(HostOsValue::Bytes(bytes));
                        }
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                        Err(error) => return Err(failure(error, budget)),
                    }
                }
                Err(HostResourceError::new(
                    HostResourceErrorKind::Budget,
                    Vec::new(),
                ))
            }
            HostOsOperation::Remove(value) => {
                let path = path(value)?;
                let metadata =
                    fs::symlink_metadata(&path).map_err(|error| failure(error, budget))?;
                if metadata.file_type().is_dir() {
                    fs::remove_dir(&path).map_err(|error| failure(error, budget))?;
                } else {
                    fs::remove_file(&path).map_err(|error| failure(error, budget))?;
                }
                Ok(HostOsValue::Boolean(true))
            }
            HostOsOperation::Rename(from, to) => {
                let from = path(from)?;
                fs::rename(from, path(to)?).map_err(|error| failure(error, budget))?;
                Ok(HostOsValue::Boolean(true))
            }
            _ => Err(denied()),
        }
    }
}

struct TrustedIo {
    expires_at: Option<Instant>,
}

impl TrustedIo {
    fn reserve_lease(budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.claim_retained(std::mem::size_of::<TrustedLease>())?;
        Ok(())
    }

    fn lease(&self, kind: LeaseKind) -> Box<dyn HostFileLease> {
        Box::new(TrustedLease {
            kind: Some(kind),
            unread: [0; 3],
            unread_len: 0,
            expires_at: self.expires_at,
            buffer: Vec::new(),
            buffer_mode: BufferMode::None,
        })
    }
}

impl HostIo for TrustedIo {
    fn authorize_path(
        &mut self,
        value: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(value.len().saturating_add(mode.len()).saturating_add(1))?;
        path(value).map(|_| ())
    }

    fn open(
        &mut self,
        value: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Self::reserve_lease(budget)?;
        let mut options = OpenOptions::new();
        let plus = mode.contains(&b'+');
        match mode.first() {
            Some(b'r') => {
                options.read(true).write(plus);
            }
            Some(b'w') => {
                options.write(true).read(plus).create(true).truncate(true);
            }
            Some(b'a') => {
                options.append(true).read(plus).create(true);
            }
            _ => return Err(denied()),
        }
        let file = options
            .open(path(value)?)
            .map_err(|error| failure(error, budget))?;
        Ok(self.lease(LeaseKind::File(file)))
    }

    fn stdin(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Self::reserve_lease(budget)?;
        Ok(self.lease(LeaseKind::Stdin))
    }

    fn stdout(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Self::reserve_lease(budget)?;
        Ok(self.lease(LeaseKind::Stdout))
    }

    fn stderr(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Self::reserve_lease(budget)?;
        Ok(self.lease(LeaseKind::Stderr))
    }

    fn tmpfile(
        &mut self,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        Self::reserve_lease(budget)?;
        for _ in 0..128 {
            budget.spend_work(1)?;
            let name = temp_path();
            match temp_options(true).open(&name) {
                Ok(file) => {
                    fs::remove_file(&name).map_err(|error| failure(error, budget))?;
                    return Ok(self.lease(LeaseKind::File(file)));
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(failure(error, budget)),
            }
        }
        Err(HostResourceError::new(
            HostResourceErrorKind::Budget,
            Vec::new(),
        ))
    }

    fn authorize_process(
        &mut self,
        command: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(command.len().saturating_add(1))?;
        if command.contains(&0) || !matches!(mode, b"r" | b"w") {
            return Err(denied());
        }
        Ok(())
    }

    fn popen(
        &mut self,
        command: &[u8],
        mode: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Box<dyn HostFileLease>, HostResourceError> {
        budget.spend_work(1)?;
        Self::reserve_lease(budget)?;
        budget.claim_temporary(command.len())?;
        let mut process = shell(command)?;
        let kind = if mode == b"r" {
            let mut child = process
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|error| failure(error, budget))?;
            #[cfg(test)]
            CHILD_STARTED.fetch_add(1, Ordering::Relaxed);
            let Some(stdout) = child.stdout.take() else {
                kill_and_wait(&mut child);
                return Err(HostResourceError::new(
                    HostResourceErrorKind::PlatformDifference,
                    Vec::new(),
                ));
            };
            LeaseKind::ProcessRead(child, stdout)
        } else if mode == b"w" {
            let mut child = process
                .stdin(Stdio::piped())
                .spawn()
                .map_err(|error| failure(error, budget))?;
            #[cfg(test)]
            CHILD_STARTED.fetch_add(1, Ordering::Relaxed);
            let Some(stdin) = child.stdin.take() else {
                kill_and_wait(&mut child);
                return Err(HostResourceError::new(
                    HostResourceErrorKind::PlatformDifference,
                    Vec::new(),
                ));
            };
            LeaseKind::ProcessWrite(child, stdin)
        } else {
            return Err(denied());
        };
        Ok(self.lease(kind))
    }
}

enum LeaseKind {
    File(File),
    Stdin,
    Stdout,
    Stderr,
    ProcessRead(Child, ChildStdout),
    ProcessWrite(Child, ChildStdin),
}

#[derive(Clone, Copy)]
enum BufferMode {
    None,
    Full,
    Line,
}

struct TrustedLease {
    kind: Option<LeaseKind>,
    unread: [u8; 3],
    unread_len: usize,
    expires_at: Option<Instant>,
    buffer: Vec<u8>,
    buffer_mode: BufferMode,
}

impl Drop for TrustedLease {
    fn drop(&mut self) {
        // FilePayload 的 GC／VM 收尾會直接釋放 lease；已接受的檔案寫入須先落盤。
        if matches!(
            self.kind.as_ref(),
            Some(LeaseKind::File(_) | LeaseKind::Stdout | LeaseKind::Stderr)
        ) {
            let _ = self.flush_buffer();
            match self.kind.as_mut() {
                Some(LeaseKind::File(file)) => {
                    let _ = file.flush();
                }
                Some(LeaseKind::Stdout) => {
                    let _ = io::stdout().flush();
                }
                Some(LeaseKind::Stderr) => {
                    let _ = io::stderr().flush();
                }
                _ => {}
            }
        }
        let process_write_flushed =
            if matches!(self.kind.as_ref(), Some(LeaseKind::ProcessWrite(_, _))) {
                self.flush_buffer().is_ok()
                    && match self.kind.as_mut() {
                        Some(LeaseKind::ProcessWrite(_, writer)) => writer.flush().is_ok(),
                        _ => false,
                    }
            } else {
                false
            };
        match self.kind.take() {
            Some(LeaseKind::ProcessRead(mut child, reader)) => {
                drop(reader);
                finish_child_on_drop(&mut child, self.expires_at);
            }
            Some(LeaseKind::ProcessWrite(mut child, writer)) => {
                drop(writer);
                if process_write_flushed {
                    finish_child_on_drop(&mut child, self.expires_at);
                } else {
                    kill_and_wait(&mut child);
                }
            }
            _ => {}
        }
    }
}

impl TrustedLease {
    fn put_back(&mut self, byte: u8) -> Result<(), HostResourceError> {
        if self.unread_len == self.unread.len() {
            return Err(HostResourceError::new(
                HostResourceErrorKind::PlatformDifference,
                Vec::new(),
            ));
        }
        self.unread.copy_within(..self.unread_len, 1);
        self.unread[0] = byte;
        self.unread_len += 1;
        Ok(())
    }

    fn next(&mut self, budget: &mut ResourceBudget<'_>) -> Result<Option<u8>, HostResourceError> {
        budget.spend_work(1)?;
        self.read_one().map_err(|error| failure(error, budget))
    }

    fn read_one(&mut self) -> io::Result<Option<u8>> {
        if self.unread_len != 0 {
            let byte = self.unread[0];
            self.unread.copy_within(1..self.unread_len, 0);
            self.unread_len -= 1;
            return Ok(Some(byte));
        }
        let mut byte = [0u8; 1];
        let n = match self.kind.as_mut() {
            Some(LeaseKind::File(file)) => file.read(&mut byte),
            Some(LeaseKind::Stdin) => io::stdin().read(&mut byte),
            Some(LeaseKind::ProcessRead(_, reader)) => reader.read(&mut byte),
            _ => return Err(io::Error::other("file not readable")),
        }?;
        Ok((n != 0).then_some(byte[0]))
    }

    fn read_chunk(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.unread_len != 0 {
            bytes[0] = self.unread[0];
            self.unread.copy_within(1..self.unread_len, 0);
            self.unread_len -= 1;
            return Ok(1);
        }
        match self.kind.as_mut() {
            Some(LeaseKind::File(file)) => file.read(bytes),
            Some(LeaseKind::Stdin) => io::stdin().read(bytes),
            Some(LeaseKind::ProcessRead(_, reader)) => reader.read(bytes),
            _ => Err(io::Error::other("file not readable")),
        }
    }

    fn read_number(
        &mut self,
        result: &mut Vec<u8>,
        budget: &mut ResourceBudget<'_>,
        maximum: usize,
    ) -> Result<bool, HostResourceError> {
        let mut scanned = 0usize;
        let mut too_long = false;
        let mut number_byte = |result: &mut Vec<u8>, byte: u8| {
            scanned = scanned
                .checked_add(1)
                .ok_or_else(|| HostResourceError::new(HostResourceErrorKind::Budget, Vec::new()))?;
            if scanned > maximum {
                return Err(HostResourceError::new(
                    HostResourceErrorKind::Budget,
                    Vec::new(),
                ));
            }
            if scanned > 200 {
                too_long = true;
            } else {
                result.push(byte);
            }
            Ok(())
        };
        let first = loop {
            match self.next(budget)? {
                Some(byte) if byte.is_ascii_whitespace() => budget.spend_work(1)?,
                other => break other,
            }
        };
        let Some(mut first) = first else {
            return Ok(false);
        };
        if matches!(first, b'+' | b'-') {
            number_byte(result, first)?;
            let Some(next) = self.next(budget)? else {
                return Ok(false);
            };
            first = next;
        }
        let mut hexadecimal = false;
        if first == b'0' {
            number_byte(result, first)?;
            if let Some(next) = self.next(budget)? {
                if matches!(next, b'x' | b'X') {
                    hexadecimal = true;
                    number_byte(result, next)?;
                } else {
                    self.put_back(next)?;
                }
            }
        } else {
            self.put_back(first)?;
        }
        let mut digits = usize::from(first == b'0' && !hexadecimal);
        let mut dot = false;
        let mut malformed = false;
        loop {
            let Some(byte) = self.next(budget)? else {
                break;
            };
            if (hexadecimal && byte.is_ascii_hexdigit()) || (!hexadecimal && byte.is_ascii_digit())
            {
                number_byte(result, byte)?;
                digits += 1;
            } else if byte == b'.' && !dot {
                dot = true;
                number_byte(result, byte)?;
            } else if digits > 0
                && ((hexadecimal && matches!(byte, b'p' | b'P'))
                    || (!hexadecimal && matches!(byte, b'e' | b'E')))
            {
                let next = self.next(budget)?;
                let (sign, digit) = match next {
                    Some(sign @ (b'+' | b'-')) => (Some(sign), self.next(budget)?),
                    other => (None, other),
                };
                match digit {
                    Some(digit) if digit.is_ascii_digit() => {
                        number_byte(result, byte)?;
                        if let Some(sign) = sign {
                            number_byte(result, sign)?;
                        }
                        number_byte(result, digit)?;
                        while let Some(next) = self.next(budget)? {
                            if next.is_ascii_digit() {
                                number_byte(result, next)?;
                            } else {
                                self.put_back(next)?;
                                break;
                            }
                        }
                    }
                    other => {
                        if let Some(next) = other {
                            self.put_back(next)?;
                        }
                        number_byte(result, byte)?;
                        if let Some(sign) = sign {
                            number_byte(result, sign)?;
                        }
                        malformed = true;
                    }
                }
                break;
            } else {
                self.put_back(byte)?;
                break;
            }
        }
        if digits == 0 || too_long || malformed {
            result.clear();
            return Ok(false);
        }
        Ok(true)
    }

    fn write_raw(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self.kind.as_mut() {
            Some(LeaseKind::File(file)) => file.write(bytes),
            Some(LeaseKind::Stdout) => io::stdout().write(bytes),
            Some(LeaseKind::Stderr) => io::stderr().write(bytes),
            Some(LeaseKind::ProcessWrite(_, writer)) => writer.write(bytes),
            _ => Err(io::Error::other("file not writable")),
        }
    }

    fn flush_buffer(&mut self) -> io::Result<()> {
        let mut bytes = std::mem::take(&mut self.buffer);
        let mut written = 0;
        while written < bytes.len() {
            let n = match self.write_raw(&bytes[written..]) {
                Ok(n) => n,
                Err(error) => {
                    bytes.drain(..written);
                    self.buffer = bytes;
                    return Err(error);
                }
            };
            if n == 0 {
                bytes.drain(..written);
                self.buffer = bytes;
                return Err(io::Error::new(io::ErrorKind::WriteZero, "zero write"));
            }
            written += n;
        }
        bytes.clear();
        self.buffer = bytes;
        Ok(())
    }
}

impl HostFileLease for TrustedLease {
    fn authorize(
        &mut self,
        operation: FileOperation,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        let allowed = match (self.kind.as_ref(), operation) {
            (Some(LeaseKind::File(_)), _) => true,
            (
                Some(LeaseKind::Stdin | LeaseKind::ProcessRead(_, _)),
                FileOperation::Read | FileOperation::Close | FileOperation::SetVBuf,
            ) => true,
            (
                Some(LeaseKind::Stdout | LeaseKind::Stderr | LeaseKind::ProcessWrite(_, _)),
                FileOperation::Write
                | FileOperation::Flush
                | FileOperation::Close
                | FileOperation::SetVBuf,
            ) => true,
            _ => false,
        };
        if allowed { Ok(()) } else { Err(denied()) }
    }

    fn read(
        &mut self,
        format: FileReadFormat,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<Option<Vec<u8>>, HostResourceError> {
        let maximum = ResourceLimits::default().max_read_bytes;
        if matches!(format, FileReadFormat::Bytes(n) if n > maximum) {
            return Err(HostResourceError::new(
                HostResourceErrorKind::Budget,
                Vec::new(),
            ));
        }
        let capacity = match format {
            FileReadFormat::Bytes(n) => n.min(maximum),
            _ => maximum,
        };
        budget.claim_temporary(capacity.max(1))?;
        let mut result = Vec::new();
        result
            .try_reserve_exact(capacity)
            .map_err(|_| HostResourceError::new(HostResourceErrorKind::Budget, Vec::new()))?;
        if result.capacity() > capacity.max(1) {
            return Err(HostResourceError::new(
                HostResourceErrorKind::Budget,
                Vec::new(),
            ));
        }
        let mut saw_input = false;
        match format {
            FileReadFormat::Bytes(0) => {
                let Some(byte) = self.next(budget)? else {
                    return Ok(None);
                };
                self.put_back(byte)?;
                saw_input = true;
            }
            FileReadFormat::Bytes(n) => {
                let mut chunk = [0u8; 4096];
                while result.len() < n {
                    let amount = (n - result.len()).min(chunk.len());
                    budget.spend_work(amount)?;
                    let read = self
                        .read_chunk(&mut chunk[..amount])
                        .map_err(|error| failure(error, budget))?;
                    if read == 0 {
                        break;
                    }
                    result.extend_from_slice(&chunk[..read]);
                    saw_input = true;
                }
            }
            FileReadFormat::Line { keep_newline } => {
                while result.len() < maximum {
                    let Some(byte) = self.next(budget)? else {
                        break;
                    };
                    saw_input = true;
                    if byte == b'\n' {
                        if keep_newline {
                            result.push(byte);
                        }
                        break;
                    }
                    result.push(byte);
                }
                if result.len() == maximum {
                    return Err(HostResourceError::new(
                        HostResourceErrorKind::Budget,
                        Vec::new(),
                    ));
                }
            }
            FileReadFormat::All => {
                let mut chunk = [0u8; 4096];
                while result.len() < maximum {
                    let amount = (maximum - result.len()).min(chunk.len());
                    budget.spend_work(amount)?;
                    let read = self
                        .read_chunk(&mut chunk[..amount])
                        .map_err(|error| failure(error, budget))?;
                    if read == 0 {
                        break;
                    }
                    result.extend_from_slice(&chunk[..read]);
                    saw_input = true;
                }
                if result.len() == maximum && self.next(budget)?.is_some() {
                    return Err(HostResourceError::new(
                        HostResourceErrorKind::Budget,
                        Vec::new(),
                    ));
                }
            }
            FileReadFormat::Number => {
                saw_input = self.read_number(&mut result, budget, maximum)?;
            }
        }
        if !saw_input && !matches!(format, FileReadFormat::All) {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    fn write(
        &mut self,
        bytes: &[u8],
        budget: &mut ResourceBudget<'_>,
    ) -> Result<usize, HostResourceError> {
        budget.spend_work(bytes.len().saturating_add(1))?;
        let flush_now = match self.buffer_mode {
            BufferMode::None => true,
            BufferMode::Full => false,
            BufferMode::Line => bytes.contains(&b'\n'),
        };
        if !matches!(self.buffer_mode, BufferMode::None)
            && bytes.len() <= self.buffer.capacity().saturating_sub(self.buffer.len())
        {
            self.buffer.extend_from_slice(bytes);
            if flush_now {
                self.flush_buffer()
                    .map_err(|error| failure(error, budget))?;
            }
            return Ok(bytes.len());
        }
        self.flush_buffer()
            .map_err(|error| failure(error, budget))?;
        let mut written = 0;
        while written < bytes.len() {
            match self.write_raw(&bytes[written..]) {
                Ok(0) => {
                    budget.claim_temporary(b"host I/O failed".len())?;
                    return Err(HostResourceError::write_failure(
                        b"host I/O failed".to_vec(),
                        0,
                        written,
                    ));
                }
                Ok(n) => written += n,
                Err(error) => {
                    budget.claim_temporary(b"host I/O failed".len())?;
                    return Err(HostResourceError::write_failure(
                        b"host I/O failed".to_vec(),
                        i64::from(error.raw_os_error().unwrap_or(0)),
                        written,
                    ));
                }
            }
        }
        Ok(written)
    }

    fn seek(
        &mut self,
        origin: FileSeekOrigin,
        offset: i64,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<u64, HostResourceError> {
        budget.spend_work(1)?;
        self.flush_buffer()
            .map_err(|error| failure(error, budget))?;
        let previous = i64::try_from(self.unread_len).map_err(|_| denied())?;
        let seek = match origin {
            FileSeekOrigin::Set => SeekFrom::Start(u64::try_from(offset).map_err(|_| denied())?),
            FileSeekOrigin::Current => {
                SeekFrom::Current(offset.checked_sub(previous).ok_or_else(denied)?)
            }
            FileSeekOrigin::End => SeekFrom::End(offset),
        };
        match self.kind.as_mut() {
            Some(LeaseKind::File(file)) => {
                let result = file.seek(seek).map_err(|error| failure(error, budget))?;
                self.unread_len = 0;
                Ok(result)
            }
            _ => Err(denied()),
        }
    }

    fn flush(&mut self, budget: &mut ResourceBudget<'_>) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        self.flush_buffer()
            .map_err(|error| failure(error, budget))?;
        match self.kind.as_mut() {
            Some(LeaseKind::File(file)) => file.flush(),
            Some(LeaseKind::Stdout) => io::stdout().flush(),
            Some(LeaseKind::Stderr) => io::stderr().flush(),
            Some(LeaseKind::ProcessWrite(_, writer)) => writer.flush(),
            _ => return Err(denied()),
        }
        .map_err(|error| failure(error, budget))
    }

    fn close(
        mut self: Box<Self>,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<HostCloseResult, HostResourceError> {
        budget.spend_work(1)?;
        self.flush_buffer()
            .map_err(|error| failure(error, budget))?;
        match self.kind.take() {
            Some(LeaseKind::ProcessRead(mut child, reader)) => {
                drop(reader);
                let result = wait_child(&mut child, self.expires_at, budget)?;
                Ok(HostCloseResult::Process {
                    success: result.success,
                    signaled: result.signaled,
                    code: result.code,
                })
            }
            Some(LeaseKind::ProcessWrite(mut child, writer)) => {
                drop(writer);
                let result = wait_child(&mut child, self.expires_at, budget)?;
                Ok(HostCloseResult::Process {
                    success: result.success,
                    signaled: result.signaled,
                    code: result.code,
                })
            }
            Some(LeaseKind::File(mut file)) => {
                file.flush().map_err(|error| failure(error, budget))?;
                Ok(HostCloseResult::File)
            }
            Some(LeaseKind::Stdout) => {
                io::stdout()
                    .flush()
                    .map_err(|error| failure(error, budget))?;
                Ok(HostCloseResult::File)
            }
            Some(LeaseKind::Stderr) => {
                io::stderr()
                    .flush()
                    .map_err(|error| failure(error, budget))?;
                Ok(HostCloseResult::File)
            }
            Some(LeaseKind::Stdin) => Ok(HostCloseResult::File),
            None => Err(denied()),
        }
    }

    fn setvbuf(
        &mut self,
        mode: &[u8],
        size: usize,
        budget: &mut ResourceBudget<'_>,
    ) -> Result<(), HostResourceError> {
        budget.spend_work(1)?;
        self.flush_buffer()
            .map_err(|error| failure(error, budget))?;
        let next_mode = match mode {
            b"no" => BufferMode::None,
            b"full" => BufferMode::Full,
            b"line" => BufferMode::Line,
            _ => return Err(denied()),
        };
        if !matches!(next_mode, BufferMode::None) {
            let previous = self.buffer.capacity();
            let additional = size.saturating_sub(previous);
            budget.claim_retained(additional)?;
            self.buffer
                .try_reserve_exact(size.saturating_sub(self.buffer.len()))
                .map_err(|_| HostResourceError::new(HostResourceErrorKind::Budget, Vec::new()))?;
            if self.buffer.capacity() > previous.saturating_add(additional) {
                budget.claim_retained(self.buffer.capacity() - previous - additional)?;
            }
        }
        self.buffer_mode = next_mode;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use rivetlua::{Engine, HostServices, LuaProfile, RunOutcome, RuntimeErrorKind};

    use super::{CliResourceDeadline, capability};

    fn profile() -> LuaProfile {
        if cfg!(feature = "native-lua55") {
            LuaProfile::Lua55
        } else {
            LuaProfile::Lua54
        }
    }

    fn run(source: &[u8], expires_at: Instant) -> RunOutcome {
        let engine = Engine::new(profile());
        let module = engine.compile(source).unwrap();
        let mut vm = engine
            .new_vm_with_services(HostServices::deny_all().and_resource(capability(
                CliResourceDeadline {
                    expires_at: Some(expires_at),
                },
            )))
            .unwrap();
        vm.load_module(&module).unwrap().run().unwrap()
    }

    #[test]
    fn p17_host_os_process_and_grant_boundary() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let source = br#"
assert(os.execute() == true)
local ok, why, code = os.execute('exit 0')
assert(ok == true and why == 'exit' and code == 0)
local failed, reason, result = os.execute('exit 7')
assert(failed == nil and reason == 'exit' and result == 7)
assert(type(os.getenv('PATH')) == 'string')
return true
"#;
        assert!(
            matches!(run(source, deadline), RunOutcome::Returned(values) if values == [rivetlua::Value::Boolean(true)])
        );
        let engine = Engine::new(profile());
        let module = engine.compile(b"return os.execute()").unwrap();
        let mut vm = engine
            .new_vm_with_services(HostServices::deny_all().and_resource(
                super::super::cli_resource_capability(CliResourceDeadline {
                    expires_at: Some(Instant::now() + Duration::from_secs(5)),
                }),
            ))
            .unwrap();
        let RunOutcome::LuaError(error) = vm.load_module(&module).unwrap().run().unwrap() else {
            panic!("無 grant 應拒絕 Execute(None)");
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostPolicyOs);
    }

    #[test]
    fn p17_host_file_and_pipe_lifecycle() {
        let source = br#"
local path = os.tmpname()
local reserved = assert(io.open(path, 'r'))
assert(reserved:close())
local f = assert(io.open(path, 'w+b'))
assert(f:setvbuf('full', 16))
assert(f:write('12\nxy'))
assert(f:seek('set', 0) == 0)
assert(f:read(0) == '')
assert(f:read('*n') == 12)
assert(f:read('*l') == '')
assert(f:read('*a') == 'xy')
assert(f:close())
local cursor_path = os.tmpname()
local n = assert(io.open(cursor_path, 'w+b'))
assert(n:write('1e+x'))
assert(n:seek('set', 0) == 0)
assert(n:read('*n') == nil)
assert(n:seek('cur', 0) == 3)
assert(n:seek('set', 0) == 0)
assert(n:read('*n') == nil)
local seek_ok, seek_result = pcall(n.seek, n, 'set', -1)
assert(not seek_ok or seek_result == nil)
assert(n:read('*a') == 'x')
assert(n:close())
assert(os.remove(cursor_path))
local valid = assert(io.tmpfile())
assert(valid:write('12.5q'))
assert(valid:seek('set', 0) == 0)
assert(valid:read('*n') == 12.5 and valid:read(1) == 'q')
assert(valid:close())
local hexadecimal = assert(io.tmpfile())
assert(hexadecimal:write('0x10p+1q'))
assert(hexadecimal:seek('set', 0) == 0)
assert(hexadecimal:read('*n') == 32 and hexadecimal:read(1) == 'q')
assert(hexadecimal:close())
local invalid_hex = assert(io.tmpfile())
assert(invalid_hex:write('0xq'))
assert(invalid_hex:seek('set', 0) == 0)
assert(invalid_hex:read('*n') == nil and invalid_hex:read(1) == 'q')
assert(invalid_hex:close())
local long_number = assert(io.tmpfile())
assert(long_number:write(string.rep('7', 201) .. 'q'))
assert(long_number:seek('set', 0) == 0)
assert(long_number:read('*n') == nil and long_number:read(1) == 'q')
assert(long_number:close())
local a = assert(io.open(path, 'a+b'))
assert(a:write('!'))
assert(a:seek('set', 0) == 0)
assert(a:read('*L') == '12\n')
assert(a:read('*a') == 'xy!')
assert(a:close())
local moved = path .. '.moved'
assert(os.rename(path, moved))
local r = assert(io.open(moved, 'r'))
assert(r:read('*a') == '12\nxy!')
assert(r:close())
assert(os.remove(moved))
local missing, message, errno = io.open(moved, 'r')
assert(missing == nil and type(message) == 'string' and type(errno) == 'number')
local removed, remove_error, remove_errno = os.remove(moved)
assert(removed == nil and type(remove_error) == 'string' and type(remove_errno) == 'number')
local t = assert(io.tmpfile())
assert(t:write('z'))
assert(t:seek('set', 0) == 0)
assert(t:read(1) == 'z')
assert(t:close())
local p = assert(io.popen("printf 'abc\\n'", 'r'))
assert(p:read('*l') == 'abc')
assert(p:close())
local w = assert(io.popen('cat >/dev/null', 'w'))
assert(w:write('abc'))
assert(w:close())
assert(io.stdin ~= nil and io.stdout ~= nil and io.stderr ~= nil)
return true
"#;
        assert!(
            matches!(run(source, Instant::now() + Duration::from_secs(5)), RunOutcome::Returned(values) if values == [rivetlua::Value::Boolean(true)])
        );

        let marker_path = super::temp_path();
        let marker_literal = format!("{:?}", marker_path.to_string_lossy());
        let tmpname_source = format!(
            r#"
local path = os.tmpname()
local marker = assert(io.open({marker}, 'wb'))
assert(marker:write(path))
assert(marker:close())
local reserved = assert(io.open(path, 'r'))
assert(reserved:close())
return true
"#,
            marker = marker_literal,
        );
        let tmpname_outcome = run(
            tmpname_source.as_bytes(),
            Instant::now() + Duration::from_secs(5),
        );
        let tmpname_bytes = std::fs::read(&marker_path).expect("讀取 tmpname 路徑 marker");
        std::fs::remove_file(&marker_path).expect("移除 tmpname 路徑 marker");
        let tmpname = std::path::PathBuf::from(super::os_from_bytes(&tmpname_bytes));
        let _metadata = std::fs::metadata(&tmpname).expect("tmpname 應保留已預約檔案");
        #[cfg(unix)]
        let (tmpname_in_posix_tmp, tmpname_mode) = {
            use std::os::unix::fs::PermissionsExt;

            (
                tmpname.parent() == Some(std::path::Path::new("/tmp")),
                _metadata.permissions().mode() & 0o777,
            )
        };
        std::fs::remove_file(&tmpname).expect("移除 tmpname 預約檔案");
        #[cfg(unix)]
        {
            assert!(tmpname_in_posix_tmp);
            assert_eq!(tmpname_mode, 0o600);
            let filename = tmpname.file_name().unwrap().to_str().unwrap();
            assert!(!filename.contains('-'));
            assert!(!filename.contains('.'));
        }
        assert!(
            matches!(
                &tmpname_outcome,
                RunOutcome::Returned(values) if values == &[rivetlua::Value::Boolean(true)]
            ),
            "tmpname 子案例失敗：{tmpname_outcome:?}"
        );

        let dropped_path = super::temp_path();
        let dropped_source = format!(
            "local f = assert(io.open({:?}, 'w')); assert(f:setvbuf('full', 32)); assert(f:write('drop-flush')); return true",
            dropped_path.to_string_lossy()
        );
        assert!(matches!(
            run(dropped_source.as_bytes(), Instant::now() + Duration::from_secs(5)),
            RunOutcome::Returned(values) if values == [rivetlua::Value::Boolean(true)]
        ));
        assert_eq!(std::fs::read(&dropped_path).unwrap(), b"drop-flush");
        std::fs::remove_file(&dropped_path).unwrap();

        let collected_path = super::temp_path();
        let collected_source = format!(
            "local p = {:?}; do local f = assert(io.open(p, 'w')); assert(f:setvbuf('full', 32)); assert(f:write('gc-flush')) end; collectgarbage('collect'); local r = assert(io.open(p, 'r')); assert(r:read('*a') == 'gc-flush'); assert(r:close()); assert(os.remove(p)); return true",
            collected_path.to_string_lossy()
        );
        assert!(matches!(
            run(collected_source.as_bytes(), Instant::now() + Duration::from_secs(5)),
            RunOutcome::Returned(values) if values == [rivetlua::Value::Boolean(true)]
        ));

        for (content, collect) in [("pipe-gc", true), ("pipe-vm-drop", false)] {
            let output = super::temp_path();
            let quoted_path = output.to_string_lossy().replace('\'', "'\\''");
            let command = format!("/bin/cat > '{quoted_path}'");
            let write_source = format!(
                "local w = assert(io.popen({command:?}, 'w')); assert(w:setvbuf('full', 32)); assert(w:write({content:?}))"
            );
            let source = if collect {
                format!("do {write_source} end; collectgarbage('collect'); return true")
            } else {
                format!("{write_source}; return true")
            };
            let started = super::CHILD_STARTED.load(super::Ordering::Relaxed);
            let reaped = super::CHILD_REAPED.load(super::Ordering::Relaxed);
            let succeeded = super::CHILD_NATURAL_EXIT.load(super::Ordering::Relaxed);
            let outcome = run(source.as_bytes(), Instant::now() + Duration::from_secs(5));
            assert!(
                matches!(&outcome, RunOutcome::Returned(values) if values == &[rivetlua::Value::Boolean(true)]),
                "管線 GC／VM 收尾失敗：{outcome:?}"
            );
            assert_eq!(
                super::CHILD_STARTED.load(super::Ordering::Relaxed),
                started + 1
            );
            assert_eq!(
                super::CHILD_REAPED.load(super::Ordering::Relaxed),
                reaped + 1
            );
            assert_eq!(
                super::CHILD_NATURAL_EXIT.load(super::Ordering::Relaxed),
                succeeded + 1
            );
            assert_eq!(std::fs::read(&output).unwrap(), content.as_bytes());
            std::fs::remove_file(&output).unwrap();
        }

        let empty_dir = super::temp_path();
        std::fs::create_dir(&empty_dir).unwrap();
        let remove_dir_source = format!(
            "assert(os.remove({:?})); return true",
            empty_dir.to_string_lossy()
        );
        assert!(matches!(
            run(remove_dir_source.as_bytes(), Instant::now() + Duration::from_secs(5)),
            RunOutcome::Returned(values) if values == [rivetlua::Value::Boolean(true)]
        ));
        assert!(!empty_dir.exists());

        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::PermissionsExt;

            let protected = super::temp_path();
            let file = super::temp_options(false).open(&protected).unwrap();
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
            drop(file);
            std::fs::remove_file(&protected).unwrap();

            let mut raw = super::os_bytes(super::temp_path().as_os_str());
            raw.push(0xff);
            assert_eq!(super::path(&raw).unwrap().as_os_str().as_bytes(), raw);
            let escaped: String = raw.iter().map(|byte| format!("\\{byte:03}")).collect();
            let raw_path_source = format!(
                "local p = '{escaped}'; local f, _, errno = io.open(p, 'w'); if not f then return errno or -1 end; if not f:write('raw') then return 2 end; if not f:close() then return 3 end; if not os.remove(p) then return 4 end; return 0"
            );
            let outcome = run(
                raw_path_source.as_bytes(),
                Instant::now() + Duration::from_secs(5),
            );
            assert!(
                matches!(&outcome, RunOutcome::Returned(values)
                    if values == &[rivetlua::Value::Integer(0)]
                        || (cfg!(target_os = "macos")
                            && values == &[rivetlua::Value::Integer(92)])),
                "非 UTF-8 路徑須保留原位元組：{outcome:?}"
            );
        }
    }

    #[test]
    fn p17_host_child_timeout_cleanup() {
        let source = br#"return os.execute('exec /bin/cat /dev/zero >/dev/null')"#;
        let engine = Engine::new(profile());
        let module = engine.compile(source).unwrap();
        let started = super::CHILD_STARTED.load(super::Ordering::Relaxed);
        let reaped = super::CHILD_REAPED.load(super::Ordering::Relaxed);
        let mut vm = engine
            .new_vm_with_services(HostServices::deny_all().and_resource(capability(
                CliResourceDeadline {
                    expires_at: Some(Instant::now() + Duration::from_millis(250)),
                },
            )))
            .unwrap();
        let outcome = vm.load_module(&module).unwrap().run().unwrap();
        let RunOutcome::LuaError(error) = outcome else {
            panic!("逾時程序必須失敗並完成 kill/wait: {outcome:?}");
        };
        assert_eq!(error.kind, RuntimeErrorKind::HostDeadline);
        assert_eq!(
            super::CHILD_STARTED.load(super::Ordering::Relaxed),
            started + 1
        );
        assert_eq!(
            super::CHILD_REAPED.load(super::Ordering::Relaxed),
            reaped + 1
        );
    }
}
