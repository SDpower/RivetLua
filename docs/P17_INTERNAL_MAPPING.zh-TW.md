# P17-B02 Internal 對照範圍

本文件與 `tests/p17/internal/mapping.json` 記錄 Lua 5.5.1、5.4.9 官方測試器中需要 Rust 可觀察替代驗證的項目。Mapping 的四欄是原始項目、依賴理由、Rust 不變量、替代案例；B02 gate 另依 `case_id` 補入實際執行結果。這份盤點本身不宣告任何替代案例已 PASS。

## 固定來源與盤點方式

| profile | 官方測試器來源 | `ltests.c` SHA-256 | `ltests.h` SHA-256 |
| --- | --- | --- | --- |
| `lua55-i64f64` | `vendor/lua55/lua-5.5.1-tests/ltests/` | `62a7015b036d366addd131e4f046f38557d66b8f48aae120e8aad992f3d90199` | `6d2e3db39c58bdadc3a0aaf3ded12873e0b56ad898ce11a872717da72efb4829` |
| `lua54-i64f64` | `vendor/lua54/lua-5.4.9-tests/ltests/` | `69837abb3adbdc1cc6e7d2a0bac5fa94d53fb1a811fbd5bedc0214d2d045b6cb` | `1477d1a70ce07f5c645379924b20e6264c5f273ac39d9339421d3c29667bc725` |

每筆 `original.c_source_sha256` 綁定實作該 helper 或命令的 `ltests.c`；每個 Lua 引用另綁定該 suite 檔案的 SHA-256 與 1-based 行號。盤點逐一比對兩版 `tests_funcs` 註冊、對應 C 函式與 suite 的實際 `T.<symbol>` 呼叫；`runC` 中會讀取私有配置記帳或 C stack layout 的命令另外列成獨立項。若同一 Lua 行出現多個不同 symbol，各自保留該行引用。

沒有引用的項目只保留仍註冊的私有 helper：Lua 5.5.1 是 `T.limits`、`T.sizes`、`T.printcode`、`T.listabslineinfo`、`T.listlocals`、`T.printallstack`、`T.tracegc`、`T.pobj`、`T.gcquery`、`runC:printstack`；Lua 5.4.9 是 `T.pobj`、`T.hash`、`T.trick`、`runC:printstack`。其他映射列出的 Lua 行均是 suite 中實際引用。兩版 `runC:alloccount` 命令並不對稱：5.5.1 的 suite 在 `api.lua` 的 panic 腳本中使用該命令；5.4.9 的 `ltests.c` 沒有註冊此命令，因此沒有虛構 5.4.9 對應列。

一般 C API 包裝（例如 `T.ref`、`T.upvalue`、`T.newuserdata`，以及 `lua_gettop`、`lua_pushvalue`、`lua_settop` 等 `testC` 命令）不探測 Lua 私有 layout，不列為本份 internal mapping 的原始項；需要替代驗證時，應由對應公開 API 案例涵蓋，不以 private layout 作為判定。`T.d2s`／`T.s2d` 是 C double 位元組轉換測試工具；`T.nonblock` 使用輔助函式庫的 `luaL_Stream` 及 POSIX `fcntl`；它們也不讀取 Lua core 私有物件布局。普通 Lua table 的 `t.foo` 欄位不會被當成 `T.foo` 測試器引用。已核對 `all.lua` 捕獲的 `T`、`api.lua` 的 `require "T"` alias 都指向測試器模組；`events.lua` 的區域 `T` 是 metamethod 收到的值，只比較值而沒有存取同名欄位。

## Mapping 覆蓋

`mapping.json` 共 49 筆：Lua 5.5.1 有 32 筆、153 個 Lua 引用行；Lua 5.4.9 有 17 筆、117 個 Lua 引用行。14 筆沒有 suite 引用，均是上表列出的未呼叫私有 helper。四欄逐筆保留，不合併不同 profile、C 函式或 `runC` 私有命令。

| 替代案例族 | 對照的內部面向 |
| --- | --- |
| `allocation-ledger` | 私有 allocator 計數、記憶體圖核對與配置失敗 |
| `gc-roots` | GC 顏色／世代／相位、物件可達性及 trace 狀態 |
| `table-string` | Table array/hash node、字串 intern table 與雜湊位置 |
| `verified-code` | Proto 指令、常數、行號與私有 opcode 上限 |
| `c-stack-errors` | CallInfo、stack 容量、frame／root 收尾 |
| `upvalue-debug` | Proto 區域名稱 debug metadata |
| `gc-parameters` | Lua 5.5 GC 百分比編碼及有界比例應用誤差 |
| `external-strings` | Lua 5.5 外部字串 owner 與釋放 callback |
| `native-modules` | ltests 次狀態載入 helper 與固定 native-module 載入證據 |

`T.loadlib` 的用途是在測試器新建的 `lua_State` 開啟標準庫及 `package`；B01 的 `native-modules` 證據則是實際五個官方 C module 分別經 CAPI host 與 CLI 載入。B01 report `target/rivetlua-reports/gate-P17-B01.json` 的 SHA-256 為 `f915bb587d537f703c4d4ec1093b14163122af3fa73f0af9e9caf7f1cf6a7c77`；兩版各有 `capi-driver-load`、`cli-native-load` 兩項 `module-load` PASS。此證據確認公開 module-load 行為，不宣稱複製 ltests 私有第二 state 的建立與標準庫配置細節。

## 公開缺口與刻意不複製的細節

除 Lua 5.5 的 `T.codeparam`、`T.applyparam` 兩列外，其餘 mapping 的 `public_gap` 為空字串。這兩列的 `gc-parameters` 替代案例只檢查 GC 百分比編碼及套用的有界近似，不保證公開 `collectgarbage("param", ...)` 對實際 GC 排程與工作量的行為；該公開行為須由公開 API 案例另行驗收。盤點到的其他布局差異（`sizeof`、Table 容量與 node 排列、TString bucket/hash、GC 顏色與世代、Lua C bytecode listing、CallInfo 數量）都不是本專案承諾的公開語言或 C ABI 行為。替代測試應檢查各列 `rust_invariant` 所述可觀察不變量，不能以 Rust 結構大小、table 配置、GC 標籤或 private dump 相等作為通過條件。

映射替代案例 ID 是 selector，不是測試結果。本文件只盤點範圍，不宣告個別替代案例 PASS；實際匹配、命令、profile、通過／失敗數及 B01 依賴以已完成的 B02 report 為準（SHA-256 `87e66ca8005bc01e2af1b07a804623573ffd689b7ee899d17ad5a247dc160d30`）。
