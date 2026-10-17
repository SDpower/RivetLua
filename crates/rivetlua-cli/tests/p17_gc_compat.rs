use std::io::{self, Read};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CHILD_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(20);

const LUA54_BASIC_SOURCE: &str = r#"
local oldmode = collectgarbage("incremental")
assert(collectgarbage("generational") == "incremental")
assert(collectgarbage("generational") == "generational")
assert(collectgarbage("incremental") == "generational")
assert(collectgarbage("incremental") == "incremental")
do
  local a = collectgarbage("setpause", 200)
  local b = collectgarbage("setstepmul", 200)
  local t = {0, 2, 10, 90, 500, 5000, 30000, 0x7ffffffe}
  for i = 1, #t do
    local p = t[i]
    for j = 1, #t do
      local m = t[j]
      collectgarbage("setpause", p)
      collectgarbage("setstepmul", m)
      collectgarbage("step", 0)
      collectgarbage("step", 10000)
    end
  end
  collectgarbage("setpause", a)
  collectgarbage("setstepmul", b)
  collectgarbage()
end
print("p17-gc-lua54-basic-ok")
"#;

const WEAK_LONG_STRING_SOURCE: &str = r#"
collectgarbage(); collectgarbage()
local m = collectgarbage("count")
local a = setmetatable({}, {__mode = "kv"})
a[string.rep("a", 2^22)] = 25
a[string.rep("b", 2^22)] = {}
a[{}] = 14
collectgarbage()
local k, v = next(a)
assert(k == string.rep("a", 2^22) and v == 25)
assert(next(a, k) == nil)
assert(a[string.rep("b", 2^22)] == nil)
a[k] = nil
k = nil
collectgarbage()
assert(next(a) == nil)
assert(a[string.rep("b", 100)] == nil)
assert(collectgarbage("count") <= m + 1)
print("p17-gc-weak-long-strings-ok")
"#;

fn read_pipe<R: Read + Send + 'static>(mut pipe: R) -> JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        pipe.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

struct CliProcess {
    child: Child,
    stdout_reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
    stderr_reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
    reaped: bool,
}

impl CliProcess {
    fn spawn(profile: &str, source: &str) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_rivetlua"))
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
            .arg("--profile")
            .arg(profile)
            .arg("-e")
            .arg(source)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("啟動受測 CLI 子程序");
        let mut process = Self {
            child,
            stdout_reader: None,
            stderr_reader: None,
            reaped: false,
        };
        let stdout = process.child.stdout.take().expect("取得 CLI stdout 管線");
        process.stdout_reader = Some(read_pipe(stdout));
        let stderr = process.child.stderr.take().expect("取得 CLI stderr 管線");
        process.stderr_reader = Some(read_pipe(stderr));
        process
    }

    fn finish(mut self, status: ExitStatus) -> Output {
        let stdout = self
            .stdout_reader
            .take()
            .expect("stdout 讀者應存在")
            .join()
            .expect("stdout 讀者執行緒結束")
            .expect("讀取 CLI stdout");
        let stderr = self
            .stderr_reader
            .take()
            .expect("stderr 讀者應存在")
            .join()
            .expect("stderr 讀者執行緒結束")
            .expect("讀取 CLI stderr");
        Output {
            status,
            stdout,
            stderr,
        }
    }
}

impl Drop for CliProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }
}

fn run_lua(profile: &str, source: &str) -> Output {
    let mut process = CliProcess::spawn(profile, source);
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if let Some(status) = process.child.try_wait().expect("查詢受測 CLI 狀態") {
            process.reaped = true;
            return process.finish(status);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "{profile}: CLI 超過六十秒期限");
        thread::sleep(remaining.min(POLL_INTERVAL));
    }
}

fn assert_output(output: &Output, expected_stdout: &[u8], profile: &str) {
    assert_eq!(
        output.status.code(),
        Some(0),
        "{profile}: CLI 應成功結束；stderr={:?}",
        output.stderr
    );
    assert_eq!(
        output.stdout.as_slice(),
        expected_stdout,
        "{profile}: stdout 不符"
    );
    assert!(output.stderr.is_empty(), "{profile}: stderr 不應有內容");
}

#[test]
fn p17_gc_lua54_basic_mode_and_parameters() {
    let output = run_lua("lua54", LUA54_BASIC_SOURCE);
    assert_output(&output, b"p17-gc-lua54-basic-ok\n", "lua54");
}

#[test]
fn p17_gc_weak_long_string_keys_are_collected() {
    for profile in ["lua55", "lua54"] {
        let output = run_lua(profile, WEAK_LONG_STRING_SOURCE);
        assert_output(&output, b"p17-gc-weak-long-strings-ok\n", profile);
    }
}
