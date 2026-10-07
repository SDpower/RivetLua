pub(super) struct Parsed {
    pub assertion_count: usize,
    pub panic_count: usize,
    pub crash_count: usize,
    pub error_count: usize,
    pub skip_messages: Vec<String>,
    pub final_ok: bool,
    pub starting_tests: bool,
    pub provisional_pass: bool,
}

pub(super) fn parse(stdout: &[u8], stderr: &[u8], exit_code: Option<i32>) -> Parsed {
    let mut result = Parsed {
        assertion_count: 0,
        panic_count: 0,
        crash_count: 0,
        error_count: 0,
        skip_messages: Vec::new(),
        final_ok: false,
        starting_tests: false,
        provisional_pass: false,
    };
    for (stream, bytes) in [("stdout", stdout), ("stderr", stderr)] {
        for line in String::from_utf8_lossy(bytes).lines() {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            result.final_ok |= trimmed == "final OK !!!";
            result.starting_tests |= trimmed == "Starting Tests";
            if lower.contains("assertion failed") || lower.contains("assertion failure") {
                result.assertion_count += 1;
            }
            if lower.contains("panic:")
                || lower.contains("panicked at")
                || lower.starts_with("panic ")
            {
                result.panic_count += 1;
            }
            if lower.contains("crashed")
                || lower.contains("segmentation fault")
                || lower.contains("abort trap")
            {
                result.crash_count += 1;
            }
            if lower.starts_with("error:")
                || lower.contains(": error:")
                || lower.contains("stack traceback:")
            {
                result.error_count += 1;
            }
            if lower.contains("not performed")
                || lower.contains("skipped")
                || lower.starts_with("skip:")
            {
                result.skip_messages.push(format!("{stream}:{trimmed}"));
            }
        }
    }
    result.provisional_pass = exit_code == Some(0)
        && result.starting_tests
        && result.final_ok
        && result.assertion_count == 0
        && result.panic_count == 0
        && result.crash_count == 0
        && result.error_count == 0
        && result.skip_messages.is_empty();
    result
}
