# RivetLua

English | [繁體中文](README.zh-TW.md) | [한국어](README.ko.md) | [日本語](README.ja.md)

RivetLua is an independent open-source project in early development. It aims to build a Lua compiler and execution engine in pure Rust for embedding in other applications.

It has no dependency on a parent project, account, database, model service, system Lua, telemetry, or background network access.

## Current status

RivetLua can compile and execute the Lua subset verified through P11. The P08–P11 acceptance cases pass for the Lua 5.5 and Lua 5.4 profiles. Full Lua compatibility and the public Rust SDK are not complete.

See the [implementation status checklist](docs/IMPLEMENTATION_STATUS.md) for implemented features, remaining work, and verification commands.

## Build baseline

Development uses the system default Rust `stable` toolchain. The minimum supported Rust version (MSRV) is `1.94.1`; changing that support baseline requires a compatibility decision. Build and test commands use `--locked`.

## Planned direction

- Compile Lua source code or AST into verified bytecode and execute it in a virtual machine.
- Provide a Rust SDK for host applications, resource controls, and optional execution capabilities.
- Validate Lua compatibility in stages and evaluate JIT/AOT on suitable platforms.

## License

This project is dual-licensed. You may choose either license:

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) © [@SteveLuo](https://github.com/sdpower)
