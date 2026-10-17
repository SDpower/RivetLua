#![cfg(unix)]

use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CHILD_TIMEOUT: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const PROTECTED_LOOP: &str = "local ok,err=pcall(function() print(12); while true do end end); assert(not ok and string.find(err,'interrupted!',1,true)); print(42)";
const UNPROTECTED_LOOP: &str = "print(12); while true do end";
const NATIVE_PATTERN: &str = "print(15); string.find(string.rep('a', 100000), '.*b')";

#[derive(Clone, Copy)]
enum Stream {
    Stdout,
    Stderr,
}

struct Chunk {
    stream: Stream,
    bytes: Vec<u8>,
}

fn read_pipe<R: Read + Send + 'static>(
    mut pipe: R,
    stream: Stream,
    sender: Sender<Chunk>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        loop {
            let length = pipe.read(&mut buffer)?;
            if length == 0 {
                return Ok(());
            }
            if sender
                .send(Chunk {
                    stream,
                    bytes: buffer[..length].to_vec(),
                })
                .is_err()
            {
                return Ok(());
            }
        }
    })
}

struct CliChild {
    child: Child,
    chunks: Receiver<Chunk>,
    readers: Vec<JoinHandle<io::Result<()>>>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exited: bool,
    deadline: Instant,
}

impl CliChild {
    fn spawn(profile: &str, source: &str) -> Self {
        let mut child = Command::new("/bin/sh")
            .arg("-c")
            .arg("trap '' INT; exec \"$@\"")
            .arg("rivetlua-ctrl-c-test")
            .arg(env!("CARGO_BIN_EXE_rivetlua"))
            .arg("--profile")
            .arg(profile)
            .arg("-e")
            .arg(source)
            .env_remove("LUA_INIT")
            .env_remove("LUA_INIT_5_4")
            .env_remove("LUA_INIT_5_5")
            .env_remove("LUA_PATH")
            .env_remove("LUA_PATH_5_4")
            .env_remove("LUA_PATH_5_5")
            .env_remove("LUA_CPATH")
            .env_remove("LUA_CPATH_5_4")
            .env_remove("LUA_CPATH_5_5")
            .env_remove("RIVETLUA_NATIVE_MANIFEST")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("啟動受測 CLI 子程序");

        let stdout = child.stdout.take().expect("取得 CLI stdout 管線");
        let stderr = child.stderr.take().expect("取得 CLI stderr 管線");
        let (sender, chunks) = mpsc::channel();
        let readers = vec![
            read_pipe(stdout, Stream::Stdout, sender.clone()),
            read_pipe(stderr, Stream::Stderr, sender),
        ];

        Self {
            child,
            chunks,
            readers,
            stdout: Vec::new(),
            stderr: Vec::new(),
            exited: false,
            deadline: Instant::now() + CHILD_TIMEOUT,
        }
    }

    fn record(&mut self, chunk: Chunk) {
        match chunk.stream {
            Stream::Stdout => self.stdout.extend_from_slice(&chunk.bytes),
            Stream::Stderr => self.stderr.extend_from_slice(&chunk.bytes),
        }
    }

    fn drain_chunks(&mut self) {
        while let Ok(chunk) = self.chunks.try_recv() {
            self.record(chunk);
        }
    }

    fn poll_status(&mut self) -> Option<ExitStatus> {
        let status = self.child.try_wait().expect("查詢受測 CLI 狀態");
        if status.is_some() {
            self.exited = true;
        }
        status
    }

    fn receive_briefly(&mut self) {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "受測 CLI 超過八秒期限；stdout={:?} stderr={:?}",
            self.stdout,
            self.stderr
        );
        match self.chunks.recv_timeout(remaining.min(POLL_INTERVAL)) {
            Ok(chunk) => self.record(chunk),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => {}
        }
    }

    fn wait_for_stdout(&mut self, expected: &[u8]) {
        loop {
            self.drain_chunks();
            if self.stdout.starts_with(expected) {
                return;
            }
            assert!(
                expected.starts_with(&self.stdout),
                "CLI 的準備輸出不符；stdout={:?}",
                self.stdout
            );
            if let Some(status) = self.poll_status() {
                panic!(
                    "CLI 在準備輸出前結束：{status:?}；stdout={:?} stderr={:?}",
                    self.stdout, self.stderr
                );
            }
            self.receive_briefly();
        }
    }

    fn assert_alive(&mut self) {
        self.drain_chunks();
        assert!(
            self.poll_status().is_none(),
            "CLI 應仍在執行；stdout={:?} stderr={:?}",
            self.stdout,
            self.stderr
        );
    }

    fn send_interrupt(&self) {
        let status = Command::new("/bin/kill")
            .arg("-INT")
            .arg(self.child.id().to_string())
            .status()
            .expect("向自己的 CLI 子程序傳送 INT");
        assert!(status.success(), "向自己的 CLI 子程序傳送 INT 失敗");
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            reader
                .join()
                .expect("管線讀者執行緒結束")
                .expect("讀取 CLI 管線");
        }
        self.drain_chunks();
    }

    fn finish(mut self) -> (ExitStatus, Vec<u8>, Vec<u8>) {
        loop {
            self.drain_chunks();
            if let Some(status) = self.poll_status() {
                self.join_readers();
                return (
                    status,
                    std::mem::take(&mut self.stdout),
                    std::mem::take(&mut self.stderr),
                );
            }
            self.receive_briefly();
        }
    }
}

impl Drop for CliChild {
    fn drop(&mut self) {
        if !self.exited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }
}

#[test]
fn p17_ctrl_c_protected_loop_recovers_after_first_signal() {
    for profile in ["lua55", "lua54"] {
        let mut child = CliChild::spawn(profile, PROTECTED_LOOP);
        child.wait_for_stdout(b"12\n");
        child.assert_alive();
        child.send_interrupt();
        let (status, stdout, stderr) = child.finish();
        assert_eq!(status.code(), Some(0), "{profile}: CLI 應成功結束");
        assert_eq!(stdout, b"12\n42\n", "{profile}: pcall 應恢復執行");
        assert!(stderr.is_empty(), "{profile}: stderr={stderr:?}");
    }
}

#[test]
fn p17_ctrl_c_unprotected_loop_reports_interrupt() {
    for profile in ["lua55", "lua54"] {
        let mut child = CliChild::spawn(profile, UNPROTECTED_LOOP);
        child.wait_for_stdout(b"12\n");
        child.assert_alive();
        child.send_interrupt();
        let (status, stdout, stderr) = child.finish();
        assert!(
            matches!(status.code(), Some(code) if code != 0),
            "{profile}: 未受保護的錯誤應以非零代碼結束；status={status:?}"
        );
        assert_eq!(stdout, b"12\n", "{profile}: stdout 不符");
        assert!(
            stderr
                .windows(b"interrupted!".len())
                .any(|part| part == b"interrupted!"),
            "{profile}: stderr 應包含 interrupted!；stderr={stderr:?}"
        );
    }
}

#[test]
fn p17_ctrl_c_native_pattern_exits_after_second_signal() {
    for profile in ["lua55", "lua54"] {
        let mut child = CliChild::spawn(profile, NATIVE_PATTERN);
        child.wait_for_stdout(b"15\n");
        thread::sleep(Duration::from_secs(1));
        child.assert_alive();
        child.send_interrupt();
        thread::sleep(Duration::from_millis(100));
        child.assert_alive();
        child.send_interrupt();
        let (status, stdout, _stderr) = child.finish();
        assert_eq!(status.code(), Some(130), "{profile}: 第二次 INT 應結束 CLI");
        assert_eq!(stdout, b"15\n", "{profile}: stdout 不符");
    }
}
