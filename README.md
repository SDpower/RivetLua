# RivetLua

RivetLua 是規劃中的獨立開源專案，目標是以純 Rust 建立 Lua 編譯器與執行引擎，供其他應用程式嵌入使用。

## 目前狀態

專案目前處於規劃階段。Rust SDK、執行引擎、命令列工具，以及相容性與測試結果，均尚未完成。

## 計畫方向

- 將 Lua 原始碼或 AST 編譯為經驗證的 bytecode，並由虛擬機器執行。
- 提供宿主應用程式使用的 Rust SDK、資源控制及可選的執行能力。
- 依計畫逐階段驗證 Lua 相容性，並在合適的平台評估 JIT／AOT。

## License

本專案採雙授權，使用者可擇一遵循：

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) © [@SteveLuo](https://github.com/sdpower)
