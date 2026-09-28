# RivetLua 實作狀態

[English](IMPLEMENTATION_STATUS.md) | 繁體中文 | [한국어](IMPLEMENTATION_STATUS.ko.md) | [日本語](IMPLEMENTATION_STATUS.ja.md)

更新日期：2026-09-28。本頁列出專案中已實作與待實作的功能。勾選代表所述範圍已通過測試；未勾選代表尚未實作。規格文件或測試資料存在，不代表對應的執行功能已完成。

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
- [x] **中介表示與 bytecode 驗證**：[編譯器 API](../crates/rivetlua-compiler/src/lib.rs) 將 resolved AST 降為具型別的暫存器 IR 與 RVLU_V2 bytecode。module 自帶格式版本、signature/vararg、ClosePath、numeric-for 專用指令與 canonical static effects，均由[核心驗證器](../crates/rivetlua-core/src/bytecode/codec.rs)檢查；v1 與未知版明確拒絕。兩個 profile 的 P05 gate 已通過。此格式不是 Lua binary chunk。
- [x] **Heap、root、宿主 handle 與配置失敗**：[runtime crate](../crates/rivetlua-runtime/src/lib.rs) 提供穩定物件身分、六類 root、RAII 宿主 handle、額度計帳、失敗回復及可實際回收物件的 mark/sweep。P06 本機 gate 29 項檢查通過，兩個 profile 各有八個 HEAP 案例；gate 會重跑 P01 與 P05。此階段不執行 bytecode 或 Lua 原始碼。
- [x] **最小虛擬機**：runtime 僅接受已驗證 RVLU_V2 module，並執行 P07 支援的數值、local 指派、條件、迴圈、numeric-for、fuel 限制與終結狀態；未支援的指令與常數會明確拒絕。P07 本機 gate 30/30 項檢查通過，產生 20 份唯一 VM 案例報告（每個 profile 十份）。VM-005/007 編譯精確來源 `while true do end`、輸出已驗證 module，再把 compiler 產物交給 VM 執行。compiler codegen 會在函式可落尾時補上隱式終端 `Return(Fixed(0))`；fuel 耗盡與終結狀態斷言都使用這份 compiler 產物。
- [x] **Byte string 與 raw table**：runtime 支援含 NUL 的任意 bytes 字串、array/hash raw table、canonical key、raw 讀寫與移除、byte 長度、合法 table 邊界、GC trace 及配置失敗回復。P08 本機 gate 33/33 項檢查通過，TAB-001～012 共 24 份唯一案例報告（每個 profile 12 份）；TAB-010 由 runtime 內部測試驗證兩種插入順序及相同欄位集合，不提供公開遍歷標準庫。P08 未實作 metamethod 或標準函式庫。
- [x] **函式、閉包、upvalue、vararg、多重回傳與尾呼叫**：runtime 使用明確的呼叫 frame，以 open／closed upvalue 保留捕捉的 local，處理固定參數與 vararg、多重結果調整、Lua 5.5 具名 vararg table；Lua 5.4 會拒絕該語法。runtime 也支援合法尾呼叫的 frame 重用與非尾呼叫深度限制。P09 本機 gate 29/29 項檢查通過，CALL-001～013 共 24 份唯一報告：`lua55-i64f64` 12 份（CALL-001～011／013），`lua54-i64f64` 12 份（CALL-001～010／012／013）。CALL-013 驗證保留 Pending ClosePath、不重用尾呼叫 frame、結果數量，並實際依 LIFO 執行 `__close`。
- [x] **Metatable 與可續行操作**：runtime 支援 raw fast path、`__index`／`__newindex`、table `__call` 與 operator event、受限事件鏈，以及透過 P09 call frame 與 roots 續行的 PendingOp。P10 本機 gate 26/26 項檢查通過，META-001～010 共 20 份唯一報告，每個 profile 十份。
- [x] **Lua 錯誤、協程與關閉值**：P11 在 protected boundary 間保留原始錯誤 `Value` 身分，支援 yield/resume、`coroutine.close`／`wrap`，並在適用出口依 LIFO 執行 `<close>` 與 generic-for closing value。Hard abort 維持終結的宿主結果，不轉成一般 Lua 錯誤或正常 close 結果。只安裝 P11 案例所需的 VM 內建入口。本機 P11 gate 通過 366 項檢查，產生 ERR-001～005、COR-001～006、CLOSE-001～005 共 32 份唯一報告（每個 profile 16 份；各類 5/6/5）。

值、數值、詞法與語法測試直接呼叫 Rust API。**RivetLua 目前執行 P11 驗證過的 Lua 子集；完整 Lua 相容性尚未驗證。**P11 只安裝正式案例所需的 VM 內建入口。table/string 標準函式庫與公開 `pairs`／`next` 包裝仍未實作；P12 GC 擴充與弱參照、P13 一般標準函式庫與模組載入，以及完整 Lua 相容性仍待後續。

## 待實作

- [ ] 實作 table/string 標準函式庫與公開 `pairs`／`next` 包裝。

- [ ] 實作 P12 GC 擴充、弱參照與記憶體壓力處理。
- [ ] 實作 P13 一般標準函式庫與模組載入。
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

`gate P00` 檢查專案基礎；`gate P01` 檢查核心值與數值；`gate P02` 檢查 lexer；`gate P03` 檢查 parser；`gate P04` 檢查作用域與名稱解析；`gate P05` 檢查 bytecode 並重跑前階段；`gate P06` 檢查 heap 與 handle 契約並重跑 P01/P05；`gate P07` 檢查最小 VM 並重跑 P01/P05/P06；`gate P08` 驗證前置 gate 報告、byte string/raw table 案例與兩個 profile；`gate P09` 驗證前置報告、CALL 案例與兩個 profile 的函式／閉包行為；`gate P10` 驗證 P00～P09 前置報告與兩個 profile 的 META 案例；`gate P11` 驗證 P00～P10 前置條件與兩個 profile 的 ERR/COR/CLOSE 案例。這些命令不需要本機規劃文件。2026-09-22 使用 Rust 1.98.1 驗證：格式與工作區測試通過；基礎、核心、詞法、語法、解析與 bytecode 驗收分別為 22/22、35/35、29/29、25/25、23/23、24/24，P05 兩個 profile 各包含八個案例。2026-09-24 使用 Rust 1.98.1 執行 P06 gate，29/29 項檢查通過，含 16 份唯一案例報告（每個 profile 八份）、runtime unit 17 項、每個 profile 19 項 crate 外契約測試，以及每個 profile 各兩個 doctest（其中一個為 compile-fail）。P07 本機 gate 30/30 項檢查通過，產生 20 份唯一案例報告（每個 profile 十份）、runtime unit 48 項，以及每個 profile 27 項 crate 外契約測試。VM-005/007 現在會編譯精確輸入 `while true do end`、輸出已驗證 RVLU_V2 module，並執行 compiler 產物；compiler codegen 會在函式可落尾時補上隱式終端 `Return(Fixed(0))`。P08 本機 gate 33/33 項檢查通過，產生 24 份唯一 TAB 案例報告（每個 profile 12 份）；TAB-001～009、011～012 由 runtime contract tests 驗證，TAB-010 由 runtime 內部 raw traversal unit test 驗證並合併兩種插入順序成每個 profile 一份報告。CLI 負向測試涵蓋缺少/重複案例、錯誤 profile、損壞 fixture、錯 expected、CSV 缺欄/錯映射、缺少或 FAIL 的 P07 報告及測試子命令失敗；均驗證非零退出與可解析 FAIL JSON，fixture 以 `cmp -s` 還原且工作區狀態一致。2026-09-27 本機 P00～P09 gates 全部通過，aggregate checks 依序為 22/37/29/25/25/33/29/30/33/29。P09 產生 24 份唯一 CALL 案例報告，每個 profile 12 份。`cargo test --locked --workspace -- --test-threads=1` 通過（xtask CLI 18/18），格式檢查通過。P09 serial CLI 負向測試涵蓋無效 fixture/profile、損壞或欄位不完整的 CSV、P08 前置報告缺少／FAIL／非法 JSON，以及失敗的 child command；各情況均得到非零退出與可解析的 FAIL JSON，並逐位元組還原 fixture、CSV 與工作區狀態。2026-09-28 本機 P00～P10 gates 依序全通過，checks 為 22/37/29/25/25/33/29/30/33/29/26；產生 20 份唯一 META 報告（每個 profile 十份）。完整 workspace 測試 exit 0，xtask unit 46/46、CLI 21/21，完整 `p10_contracts` 兩 profile 各 16/16；fmt 與 `git diff --check` 通過。本機最終驗收於 2026-09-28 通過：P00～P11 gate checks 依序為 22/37/29/25/25/33/29/30/33/29/26/366；P08/P09/P10/P11 產生 24/24/20/32 份唯一 PASS 案例報告。完整 workspace 測試共 26 個摘要、498 passed／0 failed，xtask unit 51/51、CLI 23/23、P11 contracts 48/48。P11 產生 32 份唯一報告，每個 profile 16 份（ERR/COR/CLOSE 為 5/6/5）。隔離乾淨 worktree 重建並重跑 P00～P11，結果與 checks 相同。遠端 GitHub CI 尚未執行；P12 GC 擴充、P13 一般標準函式庫／模組載入及完整 Lua 相容性仍待後續。報告位於 `target/rivetlua-reports/`，不納入 Git，可依上述命令重建。Cargo 宣告的 MSRV 仍為 1.94.1。


## Review 修正與重新驗證（2026-09-28）

- 上一節記錄的 workspace 498 passed／0 failed（xtask unit 51/51、CLI 23/23、P11 contracts 48/48）是 review 修正前的快照，已由本節結果取代。修正保留動態尾呼叫 open 多重結果 producer／consumer 相鄰，並在引數求值後關閉 caller upvalue；讓 Builtin 可作 metamethod，沿一般 protected 與 coroutine 路徑分派；P00～P11 報告加入確定性 `source_digest`，P08～P11 在啟動 runtime child 前拒絕缺少、格式錯誤或過期的前置證據。
- 文件修改前，`DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --workspace -- --test-threads=1` 通過：26 個摘要共 509 passed、0 failed；xtask unit 52/52、CLI 24/24、P11 contracts 50/50。核心修復檢查亦通過：compiler unit 16/16、runtime unit 131/131；每個 profile 的 P05 7/7、P09 11/11、P10 19/19、P11 50/50。格式檢查與 `git diff --check` 通過。
- 文件修改前，P00～P11 gates 依序通過，checks 為 22/37/29/25/25/33/29/30/33/29/26/366；P08～P11 產生 24/24/20/32 份唯一 PASS 案例報告。當時 12 份報告共用 `source_digest` `6b94e337b2ee097266b505ea5e01f3064620f2aaa41586b0a13fdef5df2a4670`。此 digest 涵蓋公開狀態文件，因此本次編修會使舊 digest 失效。最終報告須由定稿來源重建並比對 `source_digest`；最終驗收結果以主代理驗收紀錄為準。遠端 GitHub CI 未執行；P12 GC 擴充、P13 一般標準函式庫／模組載入及完整 Lua 相容性仍待後續。
