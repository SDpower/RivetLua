# RivetLua 實作狀態

[English](IMPLEMENTATION_STATUS.md) | 繁體中文 | [한국어](IMPLEMENTATION_STATUS.ko.md) | [日本語](IMPLEMENTATION_STATUS.ja.md)

更新日期：2026-10-04。本頁列出專案中已實作與待實作的功能。勾選代表所述範圍已通過測試；未勾選代表尚未實作。規格文件或測試資料存在，不代表對應的執行功能已完成。

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
- [x] **增量與分代垃圾回收**：P12 保留非移動 `ObjectId`／slot／generation 與既有 roots，加入完整追蹤及引用寫入入口、增量三色標記與屏障、remembered set、weak table／ephemeron 固定點、`__gc` finalizer／復活及配置失敗回復。P12 本機 gate 經主代理驗收：46/46 checks 通過；GC-001～010 在 Lua 5.5 與 5.4 profile 各有十份唯一 PASS 報告，共 20/20。GC-009 的 yield/error 案例與 reentry unit 合併作為該案例證據。遠端 CI 驗收見下節。
- [x] **P13 基礎標準函式庫與模組載入**：本機 gate 驗證 basic、raw、type、`pairs`／`next`、table、bytes string／Lua pattern／pack、math 與 RNG、utf8，以及受控的 load／package、io／os 和受限 debug 功能。純 Rust `HostServices` 由 VM 個別持有，預設拒絕宿主能力；載入與原生資源操作須明確授權，執行仍接受已驗證的 `VerifiedModule`／RVLU_V2。P13 本機 gate 47/47 項檢查通過，LIB-001～014 在 Lua 5.5 與 5.4 profile 各有 14 份唯一 PASS 報告，共 28/28；遠端 CI 驗收見下節。

值、數值、詞法與語法測試直接呼叫 Rust API。**RivetLua 目前執行 P13 本機驗證過的 Lua 子集；完整 Lua 相容性尚未驗證。**P11 階段只安裝當時正式案例所需的 VM 內建入口；P13 已加入上列受控標準函式庫與模組載入範圍。

## 待實作

- [ ] 完成公開 Rust SDK、模組序列化與命令列工具的 P14 fresh gates 與三平台 CI 驗收（實作及局部測試已完成）。
- [ ] 通過官方 Lua Basic 測試套件相容性驗收。
- [ ] 實作正式 C API／ABI 與原生模組支援。
- [ ] 通過官方 Lua Complete 測試套件相容性驗收。
- [ ] 驗證 LuaRocks、Moonrocks、LuaUnit 與 Busted 的使用流程。
- [ ] 完成 Lua 5.5.1 與 5.4.9 的完整相容配置與回歸檢查。
- [ ] 評估並實作適用的直譯最佳化與 JIT 支援。
- [ ] 評估並實作 AOT、跨平台與 MCU 支援。
- [ ] 建立沙箱、私人程序與防資料外洩機制。
- [ ] 加入 fuzzing、故障注入與效能驗證。
- [ ] 完成套件發布、第三方採用與 1.0 發布驗收。

## 重新執行驗證

在專案根目錄使用系統預設 Rust stable，依序重跑 P00～P14 gates：

```sh
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
cargo run --locked -p rivetlua-xtask -- gate P12
cargo run --locked -p rivetlua-xtask -- gate P13
cargo run --locked -p rivetlua-xtask -- gate P14
```

`gate P12` 驗證 P00～P11 前置 gate 報告、P05 effects／P11 roots 契約、runtime GC 測試，以及 GC-001～010 兩個 profile 的案例。

`gate P13` 驗證 P00～P12 前置 gate 報告與來源 digest，執行 P13 runtime unit 測試（39 項匹配且通過），並檢查 LIB-001～014 兩個 profile 共 28 份唯一案例報告的預期與實際結果、trace 及 source digest。

`gate P14` 要求同一來源 digest 的 P00～P13 PASS 報告，執行 SDK／wrapper／CLI filters、雙 profile 公開 example 及 28 個 SDK-001～008／SDK-NEG-001～006 exact 子測試，再核對固定 marker、測試摘要、案例 JSON 與前置報告於執行後不變。正式結果以本輪 fresh 執行產生的 `target/rivetlua-reports/gate-P14.json` 為準。

`gate P00` 檢查專案基礎；`gate P01` 檢查核心值與數值；`gate P02` 檢查 lexer；`gate P03` 檢查 parser；`gate P04` 檢查作用域與名稱解析；`gate P05` 檢查 bytecode 並重跑前階段；`gate P06` 檢查 heap 與 handle 契約並重跑 P01/P05；`gate P07` 檢查最小 VM 並重跑 P01/P05/P06；`gate P08` 驗證前置 gate 報告、byte string/raw table 案例與兩個 profile；`gate P09` 驗證前置報告、CALL 案例與兩個 profile 的函式／閉包行為；`gate P10` 驗證 P00～P09 前置報告與兩個 profile 的 META 案例；`gate P11` 驗證 P00～P10 前置條件與兩個 profile 的 ERR/COR/CLOSE 案例。這些命令不需要本機規劃文件。2026-09-22 使用 Rust 1.98.1 驗證：格式與工作區測試通過；基礎、核心、詞法、語法、解析與 bytecode 驗收分別為 22/22、35/35、29/29、25/25、23/23、24/24，P05 兩個 profile 各包含八個案例。2026-09-24 使用 Rust 1.98.1 執行 P06 gate，29/29 項檢查通過，含 16 份唯一案例報告（每個 profile 八份）、runtime unit 17 項、每個 profile 19 項 crate 外契約測試，以及每個 profile 各兩個 doctest（其中一個為 compile-fail）。P07 本機 gate 30/30 項檢查通過，產生 20 份唯一案例報告（每個 profile 十份）、runtime unit 48 項，以及每個 profile 27 項 crate 外契約測試。VM-005/007 現在會編譯精確輸入 `while true do end`、輸出已驗證 RVLU_V2 module，並執行 compiler 產物；compiler codegen 會在函式可落尾時補上隱式終端 `Return(Fixed(0))`。P08 本機 gate 33/33 項檢查通過，產生 24 份唯一 TAB 案例報告（每個 profile 12 份）；TAB-001～009、011～012 由 runtime contract tests 驗證，TAB-010 由 runtime 內部 raw traversal unit test 驗證並合併兩種插入順序成每個 profile 一份報告。CLI 負向測試涵蓋缺少/重複案例、錯誤 profile、損壞 fixture、錯 expected、CSV 缺欄/錯映射、缺少或 FAIL 的 P07 報告及測試子命令失敗；均驗證非零退出與可解析 FAIL JSON，fixture 以 `cmp -s` 還原且工作區狀態一致。2026-09-27 本機 P00～P09 gates 全部通過，aggregate checks 依序為 22/37/29/25/25/33/29/30/33/29。P09 產生 24 份唯一 CALL 案例報告，每個 profile 12 份。`cargo test --locked --workspace -- --test-threads=1` 通過（xtask CLI 18/18），格式檢查通過。P09 serial CLI 負向測試涵蓋無效 fixture/profile、損壞或欄位不完整的 CSV、P08 前置報告缺少／FAIL／非法 JSON，以及失敗的 child command；各情況均得到非零退出與可解析的 FAIL JSON，並逐位元組還原 fixture、CSV 與工作區狀態。2026-09-28 本機 P00～P10 gates 依序全通過，checks 為 22/37/29/25/25/33/29/30/33/29/26；產生 20 份唯一 META 報告（每個 profile 十份）。完整 workspace 測試 exit 0，xtask unit 46/46、CLI 21/21，完整 `p10_contracts` 兩 profile 各 16/16；fmt 與 `git diff --check` 通過。本機最終驗收於 2026-09-28 通過：P00～P11 gate checks 依序為 22/37/29/25/25/33/29/30/33/29/26/366；P08/P09/P10/P11 產生 24/24/20/32 份唯一 PASS 案例報告。完整 workspace 測試共 26 個摘要、498 passed／0 failed，xtask unit 51/51、CLI 23/23、P11 contracts 48/48。P11 產生 32 份唯一報告，每個 profile 16 份（ERR/COR/CLOSE 為 5/6/5）。隔離乾淨 worktree 重建並重跑 P00～P11，結果與 checks 相同。遠端 GitHub CI 尚未執行；P12 GC 擴充、P13 一般標準函式庫／模組載入及完整 Lua 相容性仍待後續。報告位於 `target/rivetlua-reports/`，不納入 Git，可依上述命令重建。Cargo 宣告的 MSRV 仍為 1.94.1。


## Review 修正與重新驗證（2026-09-28）

- 上一節記錄的 workspace 498 passed／0 failed（xtask unit 51/51、CLI 23/23、P11 contracts 48/48）是 review 修正前的快照，已由本節結果取代。修正保留動態尾呼叫 open 多重結果 producer／consumer 相鄰，並在引數求值後關閉 caller upvalue；讓 Builtin 可作 metamethod，沿一般 protected 與 coroutine 路徑分派；P00～P11 報告加入確定性 `source_digest`，P08～P11 在啟動 runtime child 前拒絕缺少、格式錯誤或過期的前置證據。
- 文件修改前，`DEVELOPER_DIR=/Library/Developer/CommandLineTools cargo test --locked --workspace -- --test-threads=1` 通過：26 個摘要共 509 passed、0 failed；xtask unit 52/52、CLI 24/24、P11 contracts 50/50。核心修復檢查亦通過：compiler unit 16/16、runtime unit 131/131；每個 profile 的 P05 7/7、P09 11/11、P10 19/19、P11 50/50。格式檢查與 `git diff --check` 通過。
- 文件修改前，P00～P11 gates 依序通過，checks 為 22/37/29/25/25/33/29/30/33/29/26/366；P08～P11 產生 24/24/20/32 份唯一 PASS 案例報告。當時 12 份報告共用 `source_digest` `6b94e337b2ee097266b505ea5e01f3064620f2aaa41586b0a13fdef5df2a4670`。此 digest 涵蓋公開狀態文件，因此本次編修會使舊 digest 失效。最終報告須由定稿來源重建並比對 `source_digest`；最終驗收結果以主代理驗收紀錄為準。這是 2026-09-28 當時的本機驗收紀錄；較新的遠端 CI 結果見下節。P12 GC 擴充、P13 一般標準函式庫／模組載入及完整 Lua 相容性仍待後續。

## GitHub Actions 最終驗收（2026-09-29）

- [GitHub Actions run 36444257299](https://github.com/SDpower/RivetLua/actions/runs/36444257299) 對提交 `badd790cb2d3839c7c105fc1ed084bb859e2818e` 全數通過。三個 matrix job（macOS 15 aarch64、Ubuntu 24.04 x86_64、Ubuntu 24.04 ARM aarch64）均通過格式檢查、`cargo test --locked --workspace`、P00～P11 共 12 個 gate 步驟及 gate report artifact 上傳；每個 job 均有 report artifact。
- P08 TAB 案例 24/24、P09 CALL 案例 24/24、P10 META 案例 20/20、P11 ERR/COR/CLOSE 案例 32/32 均通過。
- 上方 2026-09-28「遠端 CI 尚未執行」的敘述是當時本機驗收的歷史快照，現由本節較新的 CI 結果更新。本節所記錄的文件修訂晚於提交 `badd790` 的 CI，未納入該次驗收。公開狀態文件會納入 `source_digest`；該次 CI 的 digest 不能作為這些後續修訂的證據，修訂後來源的 digest 須另行產生並核對。
- 就提交 `badd790cb2d3839c7c105fc1ed084bb859e2818e` 而言，當時 P12 GC 擴充與 P13 一般標準函式庫／模組載入尚未完成；後續兩節分別記錄本機 P12 與 P13 gate 驗收。完整 Lua 相容性目前仍未完成。

## P12 本機 gate 驗收（2026-09-29）

- P12 已由主代理驗收通過。本機 gate 報告 `target/rivetlua-reports/gate-P12.json` 為 `PASS`、46/46 checks；GC-001～010 兩個 profile 各十份唯一 PASS 報告，共 20/20。Lua 5.5 與 Lua 5.4 各 10/10；GC-009 的正式 yield/error 案例與精確 reentry unit 共同構成驗收證據。gate 及案例報告在本次公開狀態更新前使用 source digest `0b24a52873b780ab5fd198fa872a361962429da9ed92aa208abd70b2aace6152`。
- 此節記錄 2026-09-29 的本機驗收；當時 P12 遠端 CI 尚未執行，P11 的 GitHub Actions run 不包含 P12。P13 本機驗收與較新的遠端 CI 結果見後續各節。
- 當時的 P12 公開狀態更新改變了納入 gate source digest 的文件內容，因此後續報告須按更新後來源重建並驗證。P13 公開狀態更新同樣改變 digest；完整 workspace 與 P00～P13 串行 gates 的後續本機結果見「P13 最終本機整合」。依使用者本次指示，接續以正式提交後的三平台 CI 驗證。

## P13 本機 gate 驗收（2026-10-01）

- 主代理已驗收本機 `gate P13`：報告 `target/rivetlua-reports/gate-P13.json` 為 `PASS`，47/47 checks 通過，其中 P13 runtime unit 測試 39 項匹配且通過。LIB-001～014 共 28 份唯一 PASS 案例報告，`lua55-i64f64` 與 `lua54-i64f64` 各 14 份；逐一核對 schema、expected／actual、trace 及來源 digest。
- LIB-006 記錄巨大 `string.rep` 的 size／fuel 處理差異：Lua 5.5 回傳 `FuelExhausted`，Lua 5.4 回傳 `StringArgument`；allocation budget 情境在兩個 profile 均回傳 `Heap(AllocationFailed)`。LIB-010 記錄 utf8 差異：Lua 5.5 的 offset 情境回傳 `Utf8Sequence`，Lua 5.4 回傳整數 `1`。兩個 profile 的案例均依各自預期驗收。
- gate 驗收時 P00～P13 報告共用 source digest `9279b479be6468e3727f43f6c1ba578829919b6e079e10663703746bbd6d1fdb`。此值是前次 P13 公開狀態更新前的來源快照；更新後的本機重建結果見下節。兩個 profile 的 P13 案例通過，不等於官方完整 Lua 語言、Lua bytecode 或 C API／ABI 相容性驗收。
- debug 限於已核准的檢視、traceback 與 count hook；不支援的操作依明示政策拒絕。io／os、load 與原生能力須由 VM 個別的 `HostServices` 明確提供，預設不取得宿主資源。當時 CI workflow 已加入 P13 gate 配置，但 P12／P13 尚無遠端執行結果；上述 `badd790` 的三平台 P11 CI 不涵蓋 P13 新來源。較新的結果見後節。

## P13 最終本機整合（2026-10-01）

- 在專案根目錄使用系統預設 Rust stable，設定 `CARGO_TARGET_DIR=/tmp/rivetlua-p13-xtask-target-20261001`，依序執行 `cargo fmt --all -- --check`、`cargo test --locked --workspace -- --test-threads=1`、上列 P00～P13 的 14 個 gate 命令及 `git diff --check`，共 17 個命令全部 exit 0。workspace 的 28 個測試摘要合計 875 tests 與 4 doctests，0 failed／0 ignored；包含 xtask unit 59 項、CLI 28 項、runtime unit 216 項、P13 contracts 232 項、compiler unit 16 項及 core unit 35 項。
- 14 個 gate 報告均為 `PASS`，P00～P13 checks 依序為 22/37/29/25/25/33/29/30/33/29/26/366/46/47。主代理核對 P12 的 20 份與 P13 的 28 份唯一案例報告，包括各自的 schema、profile、fixture、expected／actual、trace、exit、command 與 report path；P13 runtime unit 39 項匹配且通過。命令與結果明細保存在 `/tmp/rivetlua-p13-final-20261001/`，報告快照保存在 `/tmp/rivetlua-p13-final-reports-20261001/`。
- 上述本機驗證使用本次文件更新前的同一來源快照，P00～P13 報告的 source digest 均為 `94e29e7e04735b0f4e5debb752d6198be0faec51b34b5ed82c3d7ed3f2ce4154`。本次文件更新會使該摘要失效；正式提交後的 CI 須以新來源重建報告與 digest，不能將此舊摘要當作新提交的驗收結果。
- 隔離來源候選雖已準備，未建立快照提交，也未執行乾淨 checkout 的獨立重建。依使用者本次指示，後續採正式提交、推送及三平台 CI 驗證；此節本機驗收當時尚無 P12／P13 遠端結果，後續結果見下節。

## P12／P13 GitHub Actions 驗收（2026-10-03）

- 主代理於 2026-10-03 核對 [GitHub Actions CI run #11](https://github.com/SDpower/RivetLua/actions/runs/36843092702)：提交 `e2c4190ea627eac7e7f89626b3ae3b885b099496` 的總覽狀態為 `Success`，三個 job 均完成且顯示成功，總耗時 1 小時 26 分 7 秒。
- [CI workflow](../.github/workflows/ci.yml) 使用 macOS 15 aarch64、Ubuntu 24.04 x86_64 與 Ubuntu 24.04 ARM aarch64 三平台矩陣；格式檢查、`cargo test --locked --workspace` 與 P00～P13 gates 均為必要步驟，未設定 `continue-on-error` 或略過這些驗證的條件。結合三個 job 的成功狀態，可確認本次配置的必要檢查在三平台通過。
- run #11 總覽列出三份 gate report artifacts（macos-15 223 KB、ubuntu-24.04 222 KB、ubuntu-24.04-arm 222 KB）。尚未另行下載並逐份核對遠端報告 JSON，因此此處不列遠端案例計數或 source digest；上節的 `94e29e7e04735b0f4e5debb752d6198be0faec51b34b5ed82c3d7ed3f2ce4154` 仍僅代表公開文件最後更新前的本機來源快照。此次 CI 通過不等於官方完整 Lua 語言、Lua bytecode 或 C API／ABI 相容性驗收。
- 主代理於 2026-10-03 核對 [GitHub Actions CI run #12](https://github.com/SDpower/RivetLua/actions/runs/37052657533)：提交 `4acf363` 的總覽狀態為 `Success`，3 個 jobs completed，耗時 1 小時 29 分 7 秒，列出 3 份 artifacts。macOS 15 aarch64、Ubuntu 24.04 x86_64 與 Ubuntu 24.04 ARM aarch64 的 verify jobs 均顯示 `octicon-check-circle-fill color-fg-success`。未下載遠端報告 JSON，故不列遠端案例計數或 source digest；此結果僅適用於 `4acf363`，不代表其後的 P14／P15 變更已驗收。

## P14～P24 規劃與 P14 前置進度（2026-10-03）

- P14～P24 共 11 張工作卡已由主代理複審。工作卡複審只確認任務範圍與驗收方式；表列功能仍屬待實作，不表示任何 P14～P24 gate 或相容性驗收已通過。
- P14 核心前置第 1～7 步已由主代理接受，涵蓋純 Rust Lua 5.4.9／5.5.1 官方 chunk codec／轉譯、固定 Call 語意、artifact、capability-controlled load/dump、callback／resume 與雙向互通。DA-32（官方 chunk→P13）與 DA-33（artifact metadata→P14）已為 `IMPLEMENTED`；DA-20 原 `CONTRACTED` interface 不變。P05 sidecar producer、SDK 第 8～11 步及第 12a／12b adapter 已由主代理接受。SDK-001～008 與 SDK-NEG-001～006 的雙 profile 可執行測試、fixture 和 fail-closed gate 已加入；本地目標與 gate 協定測試通過，完整 P14 gate、workspace、fresh P00～P13、commit／push／CI 尚待最終驗證。P14 整體尚未驗收，P15 尚未解鎖。
- 第 2 步 codec 驗證：`cargo test --locked -p rivetlua-core --test official_chunk_codec -- --nocapture` 為 9 passed、1 個隔離 oracle 測試 ignored；另以 `--ignored` 執行該 oracle 測試為 1/1 passed，使用 Lua 5.5.1／5.4.9 `luac` 核對重讀與重輸出。`cargo test --locked -p rivetlua-core bytecode` 為 22/22，`cargo test --locked -p rivetlua-compiler --test bytecode_contracts` 為 26/26；雙 profile P05 contract tests 各 7/7。第 3 步當時因 core codec 輸入未變而沿用這份驗證結果；codec 證據只驗證 chunk 編解碼，不代表官方 opcode 的 VM 語意或互通已驗收。
- 第 3 步局部驗證：官方 chunk translation tests 19/19、codegen tests 7/7、bytecode tests 26/26，P05 兩個 profile 各 7/7。19 項 translation tests 包含 Lua 5.4.9 的 83 個與 Lua 5.5.1 的 85 個 opcode 結構矩陣；opcode 數是結構覆蓋案例，不等於 VM 語意或雙向互通已通過。macOS 遇到 `dyld` 啟動受阻，改以 SHA 相同的 binary 複本在 repository cwd 執行；第 3 步當時因 core codec 輸入未改而沿用第 2 步結果。第 4 步另行重建並執行 codec 測試，見下方。
- 第 4 步局部驗收已由主代理接受：`official_chunk_runtime` 15/15、`official_chunk_translation` 23/23、core bytecode 22/22、compiler `bytecode_contracts` 26/26，P05 兩個 profile 各 7/7；`official_chunk_codec` 本步重新建置後一般測試 9/9、顯式隔離 oracle 1/1（binary SHA-256 `4d9b1eb04602df7e89d25afe59ae981b7bf47278657fb6c8b8b08dd013a7308c`）。runtime 相關 filters 共 11 項、P13 debug filters 4 項均通過。R1 參數 ABI 已修正；P05 驗證私有、非 wire 執行描述後，四個固定 builtin 經一般 Call 執行。raw 值、guest 可見值與 active varargs 按 frame 隔離。對 root closure vararg pack 的 33 個配置序號及兩次 PackUnpack 的 117 個配置序號逐一注入失敗後，roots／reserved／GC live count 回復基線，重試成功；table、string、closure varargs 經 tail call 與 coroutine 暫停仍保活，解除 root 後可回收。hidden upvalue 的 guest_count 上界阻止讀取隱藏 capture。macOS `dyld` 啟動受阻時，以 SHA-256 相同的 binary 複本在 repository cwd 執行；這些局部結果不代表官方雙向互通或完整 VM 語意相容已通過。
- 第 5 步 artifact metadata／debug 局部驗收已由主代理接受：runtime `official_chunk_runtime` 22/22、core `official_chunk_metadata` 6/6、compiler `official_chunk_translation` 23/23 與 `bytecode_contracts` 26/26、core bytecode 22/22，P05 兩個 profile 各 7/7，P13 五個 filters 各 1/1。core `official_chunk_codec` 本步一般測試 9/9；oracle 專用測試本步未執行，沿用第 4 步 1/1（`decode_official_chunk`／`encode_official_chunk` 未變）。`OfficialArtifact` 為不可變 artifact；`OfficialImport` 與 `NativeRvlu` 的來源信任區分、雙向 PC／行號對應、guest debug 名稱與合成綁定隔離、離線 work／來源與 artifact 雙額度，以及 VM debug 的 fuel／配置計費與清理已有局部驗證，包含 `short_src` 與 traceback 行號。這些結果不代表 P13 load/dump、官方互通或 P14 整體驗收已通過。
- 核心第 1～7 步驗收：pre-DA workspace 33 個 targets 為 1017 passed、17 ignored；另將 16 個 export oracle 與 1 個 codec oracle 實際執行，均通過。P00～P13 pre-DA gates 全 PASS。DA-32／33 改為 `IMPLEMENTED` 後，xtask 60/60 passed，14 個 fresh P00～P13 gates 全 PASS，checks 為 22/37/29/25/25/33/29/30/33/29/26/366/46/47，digest `d32a00ee898ed21d6d93fdcbb97fd7781c77b5bc59ecba5eed81d6622bbcca28`。DA 修訂未改 core／compiler／runtime inputs，因此同 inputs 的 workspace／互通結果沿用。該 digest 僅代表核心與 DA 驗收時點，不是後續 SDK／transport 變更後的全 repo digest，也不代表本輪 P14 整體 gates 已通過。
- SDK 第 8 步及 P05 sidecar producer 已接受。SDK 提供 `Engine`／`Vm`／immutable module／`Root`、安全 values、globals／table／owned bytes、call／callback／resume、VM-local host policy、多值與結構化 error／`Aborted`，含 GC／配置失敗與 retry；21 個 SDK integration tests、README doctest、public-only embed example、fmt／diff 均通過。Native metadata 提供 `source_name()`／`main_line_range()`；原生 Lua 的 `debug.getinfo("S")` 支援仍限於 `OfficialArtifact`，此既有邊界不代表 SDK 基本功能失敗。RVAS v1 為獨立 opaque sidecar，不改 RVLU wire；`None` 還原一般 RVLU，官方來源重新轉譯並核對完整 canonical RVLU bytes，`NativeDebug` 候選重新驗證並重算 storage／close groups。分段掃描、work、temporary／retained admission、metadata 平方 CPU 成本及實際容量均納入檢查。
- sidecar consumer／SDK 驗證：core transport 16/16、core lib 61/61、runtime transport 3/3；codec 一般 10/10 與 oracle 1/1、metadata 6/6、compiler translation 23/23、P05 雙 profile 各 7/7、runtime `official_chunk_runtime` 25/25、SDK 21 tests 與 README doctest 1/1 亦通過。codec／metadata 等沿用的證據之後，僅 transport math／tests 有變，其餘相關 inputs 未變；fmt／diff check 通過。這些分項結果不取代 SDK-001～008 完整雙 profile、negative controls 或全 P14 驗收。
- 前置契約檢查通過：`cargo test --locked -p rivetlua-xtask phase_dependency_graph -- --nocapture` 為 2/2 unit tests；`cargo test --locked -p rivetlua-xtask csv_ -- --nocapture` 為 18/18 unit tests 與 P08／P10／P12 三個 CLI gates 通過（共 21 項，exit 0）。`cargo fmt --all -- --check` 與 `git diff --check` 亦通過。這些結果只驗證契約圖與 CSV／既有 gate 相容性，不代表 codec 或 P14 功能已完成。
- 文件收尾提交 `4acf3633afc06832bcee56f143bd1ab234902a9f` 已推送。該提交的乾淨 detached worktree 依序通過格式檢查、workspace、P00～P13 gates 與 `git diff --check` 共 17 個命令；workspace 為 879 passed（875 個一般測試、4 個 doctests），0 failed／0 ignored。14 個 gates 全 PASS，checks 依序為 22/37/29/25/25/33/29/30/33/29/26/366/46/47；P12 20 與 P13 28 份唯一案例報告均通過雙 profile、expected／actual、exit 與 source digest 稽核。該乾淨重建 digest 為 `80c1ae86ae4a4d0fc20c74ecbf6b5c7700737b6d2d866a823fe45588848039d5`，僅代表提交 `4acf363` 的來源，不適用於其後 P14 契約同步或本次文件更新。完整命令、退出碼與報告稽核索引保存在主代理本機 `/tmp/rivetlua-p13-doc-closeout-evidence-4acf363/verification-index.md`。
- GitHub Actions run #12 對應 `4acf363`，三平台已成功（詳見上方 CI 紀錄）。該提交的 clean 驗收與 CI 結果均不涵蓋其後 P14／P15 的修改；不得將其作為後續階段的通過證據。
- `spec/acceptance-waivers.toml` 列出六項 `USER_WAIVED`：PLAT-003、PLAT-004、DOWN-007、REL-007、R10-006、R10-007，只豁免指定 Cortex-M 條件的實板燒錄、啟動、執行或硬體量測。`counts_as_test_pass` 與 `counts_as_hardware_evidence` 均為 false；所有建置、runtime-only、AOT、數值、profile、安全、非實板 target 與發布驗收仍須通過，豁免不能標成實測 PASS。
