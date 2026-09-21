# RivetLua

English | [繁體中文](README.zh-TW.md) | [한국어](README.ko.md) | [日本語](README.ja.md)

RivetLua is an independent open-source project in the planning stage. It aims to build a Lua compiler and execution engine in pure Rust for embedding in other applications.

## Current status

The Rust SDK, execution engine, and command-line tools have not been implemented yet. Compatibility and test results have not been verified.

## Planned direction

- Compile Lua source code or AST into verified bytecode and execute it in a virtual machine.
- Provide a Rust SDK for host applications, resource controls, and optional execution capabilities.
- Validate Lua compatibility in stages and evaluate JIT/AOT on suitable platforms.

## License

This project is dual-licensed. You may choose either license:

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) © [@SteveLuo](https://github.com/sdpower)
