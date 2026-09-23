# RivetLua 實作狀態

[English](IMPLEMENTATION_STATUS.md) | 繁體中文 | [한국어](IMPLEMENTATION_STATUS.ko.md) | [日本語](IMPLEMENTATION_STATUS.ja.md)

更新日期：2026-09-22。本頁列出專案中已實作與待實作的功能。勾選代表所述範圍已通過測試；未勾選代表尚未實作。規格文件或測試資料存在，不代表對應的執行功能已完成。

## 已實作並驗收

- [x] **專案骨架與治理**：Cargo 工作區包含核心、編譯器程式庫和驗證工具；專案具有 MIT 或 Apache-2.0 雙授權，以及貢獻、安全與治理文件。
- [x] **Rust 建置基準**：開發使用系統預設 Rust stable。Cargo 宣告最低支援版本（MSRV）為 1.94.1，建置與測試使用 `Cargo.lock` 及 `--locked`。
- [x] **官方 Lua 對照資料**：保存 Lua 5.5.1 與 5.4.9 的官方原始碼、各自的獨立測試包及授權快照，並驗證版本與 SHA-256。這些資料只供對照，不連入正式 Rust 產物。
- [x] **相容性資料與測試工具**：建立[相容性清單](../spec/compatibility.csv)、兩個 Lua 版本各自的設定、案例執行器、可解析報告及故意失敗案例。
- [x] **基礎驗收**：自動檢查必要檔案、Rust 版本、上游雜湊、執行器案例、離線重跑與正式產物；只有所有必要項目通過才算成功。
- [x] **C ABI 風險邊界**：執行安全的 C 控制流程案例。設計上拒絕讓 `longjmp` 跳過持有資源的 Rust 呼叫框架。[實驗紀錄](../tests/abi/REPORT.md) 不代表正式 C API 已完成。
- [x] **核心值模型**：Rust API 可區分 nil、布林值、64 位元整數、雙精度浮點數與不透明物件參照。
- [x] **數值規則**：集中處理算術、向下整除、餘數、整數環繞、位元運算、轉換及精確的整數／浮點比較。測試涵蓋大整數、NaN、正負零與位移邊界。
- [x] **錯誤與真假規則**：零除與無效操作數會回傳可檢查的核心錯誤。只有 nil 和 false 為假；`and`／`or` 保留所選操作數。[核心 API](../crates/rivetlua-core/src/lib.rs) 與 crate 外整合測試已通過。
- [x] **Lua 詞法分析**：[編譯器 API](../crates/rivetlua-compiler/src/lib.rs) 以原始 bytes 辨識 Lua 5.5 與 5.4 的 token，保留 span、行列、literal 與受控診斷；5.5 的 `global` 採手冊嚴格語法。兩個 profile 的 P02 gate 已通過。
- [x] **Lua 語法分析**：[編譯器 API](../crates/rivetlua-compiler/src/lib.rs) 將 P02 token 解析為擁有資料的 AST，保留運算式優先序、括號、呼叫、宣告與 span；兩個 profile 的 P03 gate 已通過。此階段只驗證語法結構。
- [x] **Lua 作用域與名稱解析**：[編譯器 API](../crates/rivetlua-compiler/src/lib.rs) 將 binding、巢狀 upvalue、唯讀名稱、跳轉、關閉路徑及 Lua 5.5 明確全域宣告解析為擁有資料的 AST；兩個 profile 的 P04 gate 已通過。此階段不產生 bytecode，也不執行 Lua。
- [x] **中介表示與 bytecode 驗證**：[編譯器 API](../crates/rivetlua-compiler/src/lib.rs) 將 resolved AST 降為具型別的暫存器 IR 與 RVLU_V2 bytecode。module 自帶格式版本、signature/vararg、ClosePath、numeric-for 專用指令與 canonical static effects，均由[核心驗證器](../crates/rivetlua-core/src/bytecode/codec.rs)檢查；v1 與未知版明確拒絕。兩個 profile 的 P05 gate 已通過。此格式不是 Lua binary chunk，也**不能執行 Lua**；P06+ 仍為 `NOT_IMPLEMENTED`。

值、數值、詞法與語法測試直接呼叫 Rust API。**RivetLua 尚不能執行 Lua 原始碼，也尚未驗證完整的 Lua 語言相容性。**

## 待實作

- [ ] 管理 heap 物件、root、handle 與配置失敗。
- [ ] 建立能執行控制流程與指派的最小虛擬機。
- [ ] 實作字串與原始 table 操作。
- [ ] 實作函式、閉包、多重回傳與尾呼叫。
- [ ] 實作 metatable 及相關操作。
- [ ] 實作 Lua 錯誤、協程與待關閉資源。
- [ ] 實作完整垃圾回收、弱參照與記憶體壓力處理。
- [ ] 實作標準函式庫與模組載入。
- [ ] 提供公開 Rust SDK、模組序列化與命令列工具。
- [ ] 通過官方 Lua Basic 測試套件相容性驗收。
- [ ] 實作正式 C API／ABI 與原生模組支援。
- [ ] 通過官方 Lua Complete 測試套件相容性驗收。
- [ ] 驗證 LuaRocks、Moonrocks、LuaUnit 與 Busted 的使用流程。
- [ ] 完成 Lua 5.4.9 相容配置與回歸檢查。
- [ ] 評估並實作適用的直譯最佳化與 JIT 支援。
- [ ] 評估並實作 AOT、跨平台與 MCU 支援。
- [ ] 建立沙箱、私人程序與防資料外洩機制。
- [ ] 加入 fuzzing、故障注入與效能驗證。
- [ ] 完成套件發布、第三方採用與 1.0 發布驗收。

## 重新執行驗證

在專案根目錄使用系統預設 Rust stable 執行：

```sh
cargo fmt --all -- --check
cargo test --locked --workspace
cargo run --locked -p rivetlua-xtask -- gate P00
cargo run --locked -p rivetlua-xtask -- gate P01
cargo run --locked -p rivetlua-xtask -- gate P02
cargo run --locked -p rivetlua-xtask -- gate P03
cargo run --locked -p rivetlua-xtask -- gate P04
cargo run --locked -p rivetlua-xtask -- gate P05
```

`gate P00` 檢查專案基礎；`gate P01` 檢查核心值與數值；`gate P02` 檢查 lexer；`gate P03` 檢查 parser；`gate P04` 檢查作用域與名稱解析；`gate P05` 檢查 bytecode 並包含前階段回歸。這些命令不需要本機規劃文件。2026-09-22 使用 Rust 1.98.1 驗證：格式與工作區測試通過；基礎、核心、詞法、語法、解析與 bytecode 驗收分別為 22/22、35/35、29/29、25/25、23/23、24/24，P05 兩個 profile 各包含八個案例。報告產生於 `target/rivetlua-reports/`；該目錄不納入 Git，可用上述命令重建。Cargo 宣告的 MSRV 仍為 1.94.1。
