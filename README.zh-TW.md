# RivetLua

[English](README.md) | 繁體中文 | [한국어](README.ko.md) | [日本語](README.ja.md)

RivetLua 是處於早期開發階段的獨立開源專案，目標是以純 Rust 建立 Lua 編譯器與執行引擎，供其他應用程式嵌入使用。

專案不依賴母專案、帳號、資料庫、模型服務、系統 Lua、自動遙測或背景網路存取。

## 目前狀態

專案已有 Rust 工作區、官方 Lua 對照資料、測試執行器，以及處理核心值、數值與錯誤的 Rust API。Rust SDK 與 Lua 執行引擎尚未實作；尚不能執行 Lua 原始碼，也尚未驗證語言相容性。

已實作功能、待辦事項與驗證命令見[實作狀態清單](docs/IMPLEMENTATION_STATUS.zh-TW.md)。

## 建置基準

開發使用系統預設 Rust `stable` 工具鏈。最低支援 Rust 版本（MSRV）為 `1.94.1`；變更此基準須另作相容性決策。建置與測試命令使用 `--locked`。

## 計畫方向

- 將 Lua 原始碼或 AST 編譯為經驗證的 bytecode，並由虛擬機器執行。
- 提供宿主應用程式使用的 Rust SDK、資源控制及可選的執行能力。
- 依計畫逐階段驗證 Lua 相容性，並在合適的平台評估 JIT／AOT。

## 授權

本專案採雙授權，使用者可擇一遵循：

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE) © [@SteveLuo](https://github.com/sdpower)
