#![cfg(all(unix, any(feature = "native-lua55", feature = "native-lua54")))]

#[cfg(all(feature = "native-lua55", feature = "native-lua54"))]
compile_error!("P17 REPL 每個測試 binary 只能選一個 Lua ABI profile");

use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(feature = "native-lua55")]
const PROFILE: &str = "lua55";
#[cfg(feature = "native-lua54")]
const PROFILE: &str = "lua54";

const MULTILINE_INPUT: &[u8] = br#"

--
function

f

(

x

)




local

a

=

[[
xuxu
]]




local

b

=

"\
xuxu\n"




if

x

==

11

then

return

1

+

12

,

2

+

20

end



--[[

test

multiple

returns

]]




return

x

+

1




--\\
end
return(

f(

100

)

)
assert(

a

==

b

)
do

return

f(

11

)

end



"#;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("系統時間晚於 Unix epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "rivetlua-p17-repl-{PROFILE}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("建立隔離 REPL 測試目錄");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run_repl(arguments: &[&str], stdin: &[u8]) -> Output {
    let scratch = Scratch::new();
    let cli = PathBuf::from(env!("CARGO_BIN_EXE_rivetlua"));
    let mut child = Command::new(cli)
        .args(arguments)
        .current_dir(&scratch.0)
        .env_clear()
        .env("TMPDIR", &scratch.0)
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("啟動 Cargo 編譯的 rivetlua CLI");
    child
        .stdin
        .take()
        .expect("REPL 子程序 stdin 已設定為 pipe")
        .write_all(stdin)
        .expect("寫入 REPL stdin");
    child.wait_with_output().expect("等待 rivetlua CLI 結束")
}

#[test]
fn p17_repl_stringifies_non_string_prompt_for_each_input_and_eof() {
    let output = run_repl(
        &[
            "-e",
            "local C = 0; _PROMPT=setmetatable({},{__tostring = function () C = C + 1; return C end})",
            "-i",
        ],
        b" --\na = 2\n",
    );

    assert!(
        output.status.success(),
        "{PROFILE}: exit={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{PROFILE}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("RivetLua "), "{PROFILE}: stdout={stdout:?}");
    let (_, transcript) = stdout
        .split_once('\n')
        .expect("REPL stdout 包含版本列與提示字串");
    assert_eq!(transcript, "1 --\n2a = 2\n3\n", "{PROFILE}: stdout={stdout:?}");
}

#[test]
fn p17_repl_multiline_chunks_allow_arbitrary_whitespace() {
    let output = run_repl(&["-e", "_PROMPT='' _PROMPT2=''", "-i"], MULTILINE_INPUT);

    assert!(
        output.status.success(),
        "{PROFILE}: exit={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{PROFILE}: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("101\n"), "{PROFILE}: stdout={stdout:?}");
    assert!(stdout.contains("13\t22\n"), "{PROFILE}: stdout={stdout:?}");
}

#[test]
fn p17_repl_non_eof_syntax_error_reports_and_recovers() {
    let output = run_repl(
        &["-e", "_PROMPT='' _PROMPT2=''", "-i"],
        b")\nprint('P17_REPL_AFTER_NON_EOF_SYNTAX_ERROR')\n",
    );

    assert!(
        output.status.success(),
        "{PROFILE}: exit={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("編譯失敗"), "{PROFILE}: stderr={stderr:?}");
    assert!(
        !stderr.contains("未完成的 REPL 輸入"),
        "{PROFILE}: stderr={stderr:?}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout
            .lines()
            .any(|line| line == "P17_REPL_AFTER_NON_EOF_SYNTAX_ERROR"),
        "{PROFILE}: stdout={stdout:?}"
    );
}

#[test]
fn p17_repl_eof_prefix_waits_for_continuation() {
    let output = run_repl(&["-e", "_PROMPT='' _PROMPT2=''", "-i"], b"a.\n");

    assert!(
        output.status.success(),
        "{PROFILE}: exit={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("未完成的 REPL 輸入"),
        "{PROFILE}: stderr={stderr:?}"
    );
    assert!(
        !stderr.contains("編譯失敗"),
        "{PROFILE}: stderr={stderr:?}"
    );
}
