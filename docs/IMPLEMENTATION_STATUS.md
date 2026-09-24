# RivetLua implementation status

English | [繁體中文](IMPLEMENTATION_STATUS.zh-TW.md) | [한국어](IMPLEMENTATION_STATUS.ko.md) | [日本語](IMPLEMENTATION_STATUS.ja.md)

Updated: 2026-09-25. This page lists what is implemented in the repository and what remains. A checked item means that its stated scope has passed tests. An unchecked item has not been implemented. A specification or test fixture alone does not mean the corresponding runtime feature exists.

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

Value, numeric, lexical, and syntax tests call Rust APIs directly. **RivetLua executes only the supported P07 subset; full Lua language compatibility has not been verified.**

## Remaining work

- [ ] Implement strings and raw table operations.
- [ ] Implement functions, closures, multiple returns, and tail calls.
- [ ] Implement metatables and related operations.
- [ ] Implement Lua errors, coroutines, and to-be-closed resources.
- [ ] Implement full garbage collection, weak references, and memory-pressure handling.
- [ ] Implement standard libraries and module loading.
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
cargo test --locked --workspace
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
cargo run --locked -p rivetlua-xtask -- gate P06
cargo run --locked -p rivetlua-xtask -- gate P07
```

`gate P00` checks the project foundation; `gate P01` checks core values and numbers; `gate P02` checks the lexer; `gate P03` checks the parser; `gate P04` checks scope and name resolution; `gate P05` checks bytecode and reruns earlier gates; `gate P06` checks heap and handle contracts and reruns P01/P05; `gate P07` checks the minimal VM and reruns P01/P05/P06. No local planning documents are needed to run them. On 2026-09-22, formatting and workspace tests passed with Rust 1.98.1. The foundation, core, lexer, parser, resolver, and bytecode gates passed 22/22, 35/35, 29/29, 25/25, 23/23, and 24/24 checks respectively; P05 includes eight cases for each profile. On 2026-09-24, Rust 1.98.1 passed the P06 gate with 29/29 checks, including 16 unique case reports (eight per profile), 17 runtime unit tests, 19 crate-external contract tests per profile, and two doctests per profile, including one compile-fail doctest each. P07 passed locally with 30/30 checks, 20 unique case reports (ten per profile), 48 runtime unit tests, and 27 crate-external contract tests per profile. VM-005/007 now compile the exact input `while true do end`, emit the verified RVLU_V2 module, and execute that compiler-produced module; its codegen appends an implicit terminal `Return(Fixed(0))` for fallthrough. The xtask CLI verified missing, duplicate, and wrong-profile P07 cases, a damaged P07 fixture, and a failed P01 prerequisite; each produced nonzero exit and parseable FAIL JSON. Modified fixtures were restored and compared with `cmp -s`, and the working-tree status matched before and after injections. This records local verification; no remote GitHub CI run is claimed. Reports are generated under `target/rivetlua-reports/`; that directory is not committed and can be recreated with the commands above. Cargo still declares Rust 1.94.1 as the MSRV.
