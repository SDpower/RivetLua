# P20-B02：Cranelift 0.134.2 後端工程評估

本文件保留 P20-B02 時的 Cranelift 工程評估快照及後續採用狀態；後續實作已改變部分現況，應以「對後續 P20 工作的結論」與目前採用方案段為準。P20-B01～B04 實作與整合已完成，採用可移除的 `crates/rivetlua-native`、codegen／frontend 0.134.2、鎖定的 libc，且不採用 `cranelift-jit`。當前產品基線中 native executed 為 0，沒有 JIT 加速證據；測試與階段驗收已依使用者指示取消。`unsafe` 僅限 native ABI／execmem 薄層，逐處附安全理由與檢查；core、compiler、runtime 維持 safe。P20-B01 直譯基線不代表 JIT 編譯延遲或原生產物大小。

## 現有邊界

- `Cargo.lock` 沒有 Cranelift／Wasmtime 依賴。離線 Cargo source cache 僅有 `cranelift-codegen 0.134.2`，沒有同版 `cranelift-jit` 或 `cranelift-module`；未下載、安裝或修改依賴。
- `rivetlua-core` 的 VerifiedModule 與 static effects、runtime 的 VM／fuel／GC 介面可提供後端輸入和回退語意；後端仍須由 P05 驗證後的 RVLU_V2 輸入與完整 effects 決定資格，不得代替 Lua 語意。`rivetlua-runtime` 和公開 SDK 均禁止 `unsafe`。
- 現有 `native-lua54`／`native-lua55` 是 C module 載入路徑；`crates/rivetlua-capi/src/native/platform.c` 只有 `dlopen`／`dlsym`／`dlclose` 等原生模組與 worker 操作，沒有 `MAP_JIT`、可執行頁配置、寫入保護或指令快取同步。它不能授權或代替 JIT 執行介面。

| 項目 | 0.134.2 靜態發現 | 採用前須解決的邊界 |
| --- | --- | --- |
| ISA／Rust target | `cranelift-codegen` 的架構 feature 包含 x86-64、AArch64、s390x、RISC-V 64；實際 ISA 可因編譯 feature 而缺席。`JITBuilder::new/with_flags` 選本機 ISA，`with_isa` 文件主要供測試。cached codegen manifest 宣告 Rust 1.94.0，workspace MSRV 為 1.94.1。 | 對要部署的 target triple、CPU features、ABI 與實際啟用的 feature 逐一核對；架構列於 API 不代表 macOS ARM64 或 Linux 目標已完成建置／執行驗證。`jit`／`module` 及其遞迴依賴的 MSRV 和建置鏈尚未核對。 |
| Relocation／符號 | `JITModule::finalize_definitions` 修補 relocation；AArch64 遠距呼叫使 JIT builder 關閉 colocated libcall。浮點合法化或 stack probe 可引入外部 libcall。JIT builder 預設把程序 `dlsym` 放進查找鏈；找不到必要 symbol 時，source 中有 `panic!` 路徑。 | 原生入口只能使用經批准的符號與 libcall；在執行前驗證全部 relocation、目標距離與 ABI。不能把預設程序符號搜尋視為封閉 guest 邊界，也不能假設 `finalize_definitions` 的所有錯誤都以 `Result` 回傳。 |
| Unwind／錯誤 | codegen 有 `unwind` feature，JIT module 另有條件式 exception metadata；這些不是 RivetLua 的 LuaError、Aborted、yield 或 close 狀態。JIT module API 也不承諾 `UnwindSafe`。 | 原生函式必須以明確狀態回到既有 VM 安全點；panic、Lua error 與宿主例外不得未定義地跨原生／Rust 呼叫邊界展開。deopt 要保存下一個未執行指令和 fuel，已完成副作用不得重播。 |
| 可執行記憶體 | `JITMemoryProvider` 要求 `allocate/finalize/unsafe free_memory`，builder 未設定時使用 `SystemMemoryProvider`。Apple 說明 Hardened Runtime 的 `MAP_JIT` 需要 `com.apple.security.cs.allow-jit`；Apple silicon 還須處理寫入保護、允許清單與執行前的指令快取失效。 | 在碰可執行頁前確認宿主的簽章、entitlement、target、`MAP_JIT` 與寫入保護能力；不足時直接回退直譯。不能由 Cranelift 的預設 provider 推定其符合本產品的 macOS 部署政策。新增記憶體／函式指標薄層和任何 `unsafe` 均需另行明確授權。 |
| Cache／生命週期 | `JITModule::get_finalized_function` 回傳原始指標；`free_memory` 為 `unsafe`，官方要求模組內無函式正在執行，也不得再呼叫舊指標。預設 `SystemMemoryProvider` 為保留指標有效而不自動釋放記憶體。 | artifact 須綁定 VM、module/function/code version、profile、numeric config、ISA/CPU 與後端版本；分開限制 code／metadata 容量。失效後從新入口移除，待所有活躍呼叫離開安全點才退役；不能以無界保留取代可回收設計。 |
| 建置／維護成本 | codegen 0.134.2 本身有 `build.rs`，且後端需配套多個同版 crate；目前僅 source 層級核對。 | 建置延遲、最終 binary 增量、每函式 JIT 編譯時間、原生碼大小與維護成本**未量測**。未核對完整依賴啟動鏈前不得執行建置；不能用直譯基線推算。 |

## 對後續 P20 工作的結論

目前採用方案為獨立 native crate，P20-B01～B04 實作與整合已完成。JIT 只接納受限數值／控制流程，使用 128-instruction quantum；guard/deopt 保留下一個未執行 pc 與 fuel，並沿既有 cleanup 路徑返回，不重播已完成副作用。artifact 綁定 VM 身分，code／metadata 以有界 FIFO 退役；mac arena 採保守重複計費。原生執行比例只計實際機器碼，不能把回退直譯算作原生執行。

**目前採用方案：** 使用可移除的 `crates/rivetlua-native`，固定 `cranelift-codegen`／`cranelift-frontend` 0.134.2、沿用 `Cargo.lock` 已鎖定的 `libc`，不使用 `cranelift-jit` 的預設 `dlsym`／`SystemMemoryProvider`。`unsafe` 僅在 native crate 的 ABI／execmem 薄層；每處附安全理由與檢查，core／compiler／runtime 維持 safe。使用者 2026-10-17 指示續行並移除額外的 unsafe 明確授權條件；此採用狀態覆寫前文待授權建議，研究表與來源引文保留，永久工具禁令不變。平台能力不足時在執行前回退直譯。目前產品 interpreter 與 `--jit` 基線各有 6 scenarios／36 raw；此環境未具 JIT entitlement，整數 while 因 `Platform` 回退，float／table 因 `UnsupportedInstruction` 回退，native executed 為 0，不宣稱 JIT 加速。Linux aarch64 能力未確認，維持保守 fallback。

P20-B01～B04 實作與整合已完成，必要 xtask build、SDK `--lib`／`--features jit` check exit 0；`p20_jit` 測試來源僅編譯，未執行。產品基線 interpreter 與 `--jit` 各涵蓋 6 scenarios／36 raw，native executed 為 0。所有測試、Basic／Complete、gate 與 CI acceptance 及驗收紀錄均已取消。本階段提交包含此進度更新；P21～P24 未開始。未宣稱完整 Lua／上游相容、機器碼實際執行或 JIT 效能提升。

## 一手資料

- [Cranelift codegen 0.134.2 ISA API](https://docs.rs/cranelift-codegen/0.134.2/cranelift_codegen/isa/)、[固定版 codegen crate](https://docs.rs/cranelift-codegen/0.134.2/cranelift_codegen/)；架構 features／MSRV 另依本機已快取的 `cranelift-codegen-0.134.2/Cargo.toml` 靜態核對。
- [Cranelift JIT 0.134.2 API](https://docs.rs/cranelift-jit/0.134.2/cranelift_jit/)、[JITBuilder API 與預設符號搜尋](https://docs.rs/cranelift-jit/0.134.2/cranelift_jit/struct.JITBuilder.html)、[JITModule 指標與釋放條件](https://docs.rs/cranelift-jit/0.134.2/cranelift_jit/struct.JITModule.html)、[JITMemoryProvider](https://docs.rs/cranelift-jit/0.134.2/cranelift_jit/trait.JITMemoryProvider.html)、[固定版 JIT backend source](https://docs.rs/cranelift-jit/0.134.2/src/cranelift_jit/backend.rs.html)。
- Apple：[JIT entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.allow-jit)、[Apple silicon JIT 移植與寫入保護](https://developer.apple.com/documentation/apple-silicon/porting-just-in-time-compilers-to-apple-silicon)。
