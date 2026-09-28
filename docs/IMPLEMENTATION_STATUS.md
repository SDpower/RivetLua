# RivetLua implementation status

English | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | [한국어](IMPLEMENTATION_STATUS.ko.md) | [日本語](IMPLEMENTATION_STATUS.ja.md)

Updated: 2026-09-28. This page lists what is implemented in the repository and what remains. A checked item means that its stated scope has passed tests. An unchecked item has not been implemented. A specification or test fixture alone does not mean the corresponding runtime feature exists.

## Implemented and verified

- [x] **Project foundation and governance:** The Cargo workspace contains core and compiler libraries plus a verification tool. The project has MIT or Apache-2.0 licensing, contribution, security, and governance documents.
- [x] **Rust build baseline:** Development uses the system default Rust stable toolchain. Cargo declares Rust 1.94.1 as the minimum supported version (MSRV). Builds and tests use `Cargo.lock` with `--locked`.
- [x] **Official Lua reference material:** The repository contains verified source archives, separate test archives, and license snapshots for Lua 5.5.1 and 5.4.9. Versions and SHA-256 hashes are checked. These archives are reference material and are not linked into the Rust product.
- [x] **Compatibility data and test tooling:** The [compatibility inventory](../spec/compatibility.csv), separate settings for the two Lua versions, a case runner, parseable reports, and deliberate failure cases are in place.
- [x] **Foundation gate:** Automated checks cover required files, the Rust version, upstream hashes, runner cases, offline reruns, and product artifacts. Only fully passing results satisfy the gate.
- [x] **C ABI risk boundary:** Safe C control-flow cases were run. A `longjmp` that skips a Rust frame holding resources is rejected by design. The [experiment record](../tests/abi/REPORT.md) does not claim that a production C API exists.
- [x] **Core value model:** Rust APIs distinguish nil, booleans, 64-bit integers, double-precision floats, and opaque object references.
- [x] **Numeric rules:** Centralized operations cover arithmetic, floor division, remainder, integer wrapping, bitwise operations, conversions, and precise integer-to-float comparisons. Tests cover large integers, NaN, signed zero, and shift boundaries.
- [x] **Errors and truthiness:** Division by zero and invalid operands return inspectable core errors. Only nil and false are false; `and` and `or` preserve the selected operand. The [core API](../crates/rivetlua-core/src/lib.rs) and external integration tests pass.
- [x] **Lua lexical analysis:** The [compiler API](../crates/rivetlua-compiler/src/lib.rs) tokenizes raw bytes for Lua 5.5 and 5.4, preserving spans, positions, literals, and bounded diagnostics. Lua 5.5 treats `global` as a keyword under the strict manual grammar. Both profiles pass the P02 gate.
- [x] **Lua syntax analysis:** The [compiler API](../crates/rivetlua-compiler/src/lib.rs) parses P02 tokens into an owned AST, preserving expression precedence, parentheses, calls, declarations, and spans. Both profiles pass the P03 gate. This stage verifies syntax structure only.
- [x] **Lua scope and name resolution:** The [compiler API](../crates/rivetlua-compiler/src/lib.rs) resolves bindings, nested upvalues, read-only names, jumps, close paths, and Lua 5.5 explicit global declarations into an owned resolved AST. Both profiles pass the P04 gate. This stage does not generate bytecode or execute Lua.
- [x] **Intermediate representation and bytecode verification:** The [compiler API](../crates/rivetlua-compiler/src/lib.rs) lowers resolved AST into typed register IR and RivetLua's RVLU_V2 bytecode. Its module-owned format version, signature/vararg and close metadata, numeric-for instructions, and canonical static effects are verified by the [core verifier](../crates/rivetlua-core/src/bytecode/codec.rs); v1 and unknown versions are rejected. Both profiles pass the P05 gate. This is not a Lua binary chunk.
- [x] **Heap, roots, host handles, and allocation failure:** The [runtime crate](../crates/rivetlua-runtime/src/lib.rs) provides stable object identity, six root classes, RAII host handles, quota accounting, rollback on failure, and a reclaiming mark/sweep collector. P06 passes locally with 29 gate checks and eight HEAP cases for each profile. Its gate reruns P01 and P05. This stage does not execute bytecode or Lua source.
- [x] **Minimal virtual machine:** The runtime accepts only verified RVLU_V2 modules and executes the P07 subset for numeric values, local assignment, conditionals, loops, numeric-for, fuel limits, and terminal outcomes; unsupported instructions and constants are rejected. The local P07 gate passed 30/30 checks and produced 20 unique VM case reports, ten per profile. VM-005/007 compile the exact source `while true do end`, emit a verified module, and pass that compiler-produced module to the VM. Compiler codegen appends an implicit terminal `Return(Fixed(0))` for function fallthrough; fuel exhaustion and terminal-state assertions exercise the compiler output.
- [x] **Byte strings and raw tables:** The runtime supports arbitrary byte strings including NUL, array/hash raw tables, canonical keys, raw reads/writes/removal, byte length, valid table borders, GC tracing, and allocation-failure rollback. The local P08 gate passed 33/33 checks and produced 24 unique TAB-001–012 reports, 12 per profile. TAB-010 verifies both insertion orders and the same field set in an internal runtime test; no public iteration library is provided. P08 does not implement metamethods or standard libraries.
- [x] **Functions, closures, upvalues, varargs, multiple returns, and tail calls:** The runtime uses explicit call frames, preserves captured locals through open/closed upvalues, adjusts fixed and vararg arguments and multiple results, supports Lua 5.5 named vararg tables, rejects that syntax in Lua 5.4, reuses frames for eligible tail calls, and limits non-tail call depth. The local P09 gate passed 29/29 checks and produced 24 unique CALL-001–013 reports: 12 for `lua55-i64f64` (CALL-001–011/013) and 12 for `lua54-i64f64` (CALL-001–010/012/013). CALL-013 verifies retention of pending ClosePath, no tail-frame reuse, the result count, and actual LIFO `__close` execution.
- [x] **Metatables and resumable operations:** The runtime applies raw fast paths, `__index`/`__newindex`, callable-table and operator events, bounded event chains, and resumable PendingOps through P09 call frames with their roots. The local P10 gate passed 26/26 checks and produced 20 unique META-001–010 reports, ten per profile.
- [x] **Lua errors, coroutines, and closing values:** P11 preserves the original error `Value` identity across protected boundaries, supports yield/resume plus `coroutine.close`/`wrap`, and executes `<close>` and generic-for closing values in LIFO order on applicable exits. Hard abort remains a terminal host outcome, outside normal Lua error and close completion. Only VM builtins needed by the P11 cases are installed. The local P11 gate passed with 366 checks and produced 32 unique ERR-001–005, COR-001–006, and CLOSE-001–005 reports (16 per profile; category counts 5/6/5).

Value, numeric, lexical, and syntax tests call Rust APIs directly. **RivetLua currently executes the supported P11 Lua subset; full Lua compatibility has not been verified.** Only VM builtins needed by the P11 cases are installed. Table/string standard libraries and public `pairs`/`next` wrappers remain unimplemented; P12 GC extensions and weak references, general standard libraries and module loading planned for P13, and full Lua compatibility remain future work.

## Remaining work

- [ ] Implement table/string standard libraries and public `pairs`/`next` wrappers.

- [ ] Implement P12 garbage-collection extensions, weak references, and memory-pressure handling.
- [ ] Implement general standard libraries and module loading (P13).
- [ ] Provide a public Rust SDK, module serialization, and command-line tools.
- [ ] Pass the official Lua Basic test suite compatibility gate.
- [ ] Implement the production C API/ABI and native module support.
- [ ] Pass the official Lua Complete test suite compatibility gate.
- [ ] Verify LuaRocks, Moonrocks, LuaUnit, and Busted workflows.
- [ ] Complete the Lua 5.4.9 compatibility configuration and regression checks.
- [ ] Evaluate and implement applicable interpreter optimizations and JIT support.
- [ ] Evaluate and implement AOT, cross-platform, and MCU support.
- [ ] Build sandboxing, private-process, and data-leak protections.
- [ ] Add fuzzing, fault injection, and performance verification.
- [ ] Complete package publication, third-party adoption, and 1.0 release checks.

## Reproduce the verification

Run these commands from the repository root with the system default Rust stable toolchain:

```sh
cargo fmt --all -- --check
cargo test --locked --workspace -- --test-threads=1
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
cargo run --locked -p rivetlua-xtask -- gate P06
cargo run --locked -p rivetlua-xtask -- gate P07
cargo run --locked -p rivetlua-xtask -- gate P08
cargo run --locked -p rivetlua-xtask -- gate P09
cargo run --locked -p rivetlua-xtask -- gate P10
cargo run --locked -p rivetlua-xtask -- gate P11
```

`gate P00` checks the project foundation; `gate P01` checks core values and numbers; `gate P02` checks the lexer; `gate P03` checks the parser; `gate P04` checks scope and name resolution; `gate P05` checks bytecode and reruns earlier gates; `gate P06` checks heap and handle contracts and reruns P01/P05; `gate P07` checks the minimal VM and reruns P01/P05/P06; `gate P08` validates earlier gate reports, byte-string/raw-table cases, and both profiles; `gate P09` validates prior reports, the CALL case matrix, and function/closure behavior for both profiles; `gate P10` validates P00–P09 reports and both profiles of the META case matrix; `gate P11` validates P00–P10 prerequisites and both profiles of the ERR/COR/CLOSE case matrix. No local planning documents are needed to run them. On 2026-09-22, formatting and workspace tests passed with Rust 1.98.1. The foundation, core, lexer, parser, resolver, and bytecode gates passed 22/22, 35/35, 29/29, 25/25, 23/23, and 24/24 checks respectively; P05 includes eight cases for each profile. On 2026-09-24, Rust 1.98.1 passed the P06 gate with 29/29 checks, including 16 unique case reports (eight per profile), 17 runtime unit tests, 19 crate-external contract tests per profile, and two doctests per profile, including one compile-fail doctest each. P07 passed locally with 30/30 checks, 20 unique case reports (ten per profile), 48 runtime unit tests, and 27 crate-external contract tests per profile. VM-005/007 now compile the exact input `while true do end`, emit the verified RVLU_V2 module, and execute that compiler-produced module; its codegen appends an implicit terminal `Return(Fixed(0))` for fallthrough. P08 passed locally with 33/33 checks and 24 unique TAB reports, 12 per profile. TAB-001–009 and TAB-011/012 come from runtime contract tests; TAB-010 comes from an internal raw traversal unit test, with both insertion orders combined into one report per profile. CLI negative tests covered missing/duplicate cases, wrong profiles, damaged fixtures, incorrect expected values, missing/malformed CSV columns and mappings, missing or FAIL P07 reports, and a failing test subprocess; each returned nonzero with parseable FAIL JSON, restored fixtures with `cmp -s`, and preserved the working-tree status. On 2026-09-27, the P00–P09 gates passed locally with 22/37/29/25/25/33/29/30/33/29 aggregate checks. P09 produced 24 unique CALL reports, 12 per profile. The workspace passed (including xtask CLI 18/18), and formatting passed. Its serial CLI negative tests checked invalid fixture and profile mappings, malformed or incomplete CSV, missing/FAIL/invalid P08 prerequisite reports, and a failing child; each failure returned nonzero with parseable FAIL JSON, and the fixture, CSV bytes, and working-tree status were restored. On 2026-09-28, the local P00–P10 gates passed in order with 22/37/29/25/25/33/29/30/33/29/26 checks and 20 unique META reports, ten per profile. The workspace passed with exit 0, including xtask unit tests 46/46, CLI tests 21/21, and full `p10_contracts` tests 16/16 for each profile; formatting and `git diff --check` passed. Final local verification on 2026-09-28 passed: P00–P11 gate checks were 22/37/29/25/25/33/29/30/33/29/26/366; P08/P09/P10/P11 produced 24/24/20/32 unique PASS case reports. The workspace passed with 498 passed and 0 failed across 26 test summaries (xtask unit 51/51, CLI 23/23, P11 contracts 48/48). P11 produced 32 unique reports, 16 per profile (ERR/COR/CLOSE counts 5/6/5). A clean isolated worktree rebuilt and passed P00–P11 with the same gate counts. Remote GitHub CI has not been run. P12 GC extensions, P13 general standard libraries/module loading, and full Lua compatibility remain future work. Reports are generated under `target/rivetlua-reports/`; that directory is not committed and can be recreated with the commands above. Cargo still declares Rust 1.94.1 as the MSRV.


## Review fixes and revalidation (2026-09-28)

- The preceding 498-passed/0-failed workspace result (xtask unit 51/51, CLI 23/23, P11 contracts 48/48) is the pre-review snapshot and is superseded by this entry. The fixes preserve adjacency between a dynamic tail call's open-result producer and consumer while closing caller upvalues after argument evaluation; dispatch built-in functions used as metamethods through the normal protected and coroutine paths; and add deterministic `source_digest` values to P00–P11 reports so P08–P11 reject missing, malformed, or stale prerequisite evidence before starting runtime children.
- Before this documentation edit, `DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --workspace -- --test-threads=1` passed: 509 tests passed, 0 failed across 26 summaries; xtask unit 52/52, CLI 24/24, and P11 contracts 50/50. Core review checks also passed: compiler unit 16/16, runtime unit 131/131, and in each profile P05 7/7, P09 11/11, P10 19/19, and P11 50/50. Formatting and `git diff --check` passed.
- Before this documentation edit, P00–P11 gates passed in order with 22/37/29/25/25/33/29/30/33/29/26/366 checks, and P08–P11 produced 24/24/20/32 unique PASS case reports. Their shared `source_digest` was `6b94e337b2ee097266b505ea5e01f3064620f2aaa41586b0a13fdef5df2a4670` for that tested source state. This edit invalidates that digest because it includes the public status files. Final reports must be rebuilt from the finalized source and their `source_digest` values compared; the definitive final verification result is recorded in the primary agent’s acceptance record. Remote GitHub CI has not been run. P12 GC extensions, P13 general standard libraries/module loading, and full Lua compatibility remain future work.
