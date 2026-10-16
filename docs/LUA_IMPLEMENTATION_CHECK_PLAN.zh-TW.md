# Lua 5.5.1／5.4.9 實作與測試檢查計畫

## 啟動條件與範圍

此工作只能在 P16–P24 已授權工作依序整合、各階段 commit 完成，且 P24 commit 已完成後開始。它是逐項確認既有 Lua 實作與有效測試的後續工程工作，不是 release/package/registry、phase gate、CI 或重新啟用的階段驗收；不建立驗收 records，不宣稱 `1.0` ready、正式 registry 權利、硬體支援或尚未執行的測試。本計畫不授權新增 commit；修正先留待檢視，commit 需另有明確授權。

版本基準固定為 Lua 5.5.1 與 Lua 5.4.9，各自維持 profile。使用[上游來源索引](../spec/upstream-sources.md)所列的 source/test 快照與 SHA-256；不以系統 Lua、網路下載或未核實的新版替代。從[相容性索引](../spec/compatibility.csv)起步，但目前索引只有 P00–P14 項目，其舊 `PASS` 欄不能當作本次結果，也不能表示目前完整相容。bytecode 依 P05 的 `VerifiedModule.format_version()` 判定；crate SemVer、Lua profile/numeric、RVLU 格式、C ABI、native artifact/platform identity 分開核對。

檢查範圍依既定 Lua 版本與專案契約逐項盤點：語言語意、標準函式庫、公開 C API、官方 chunk 與 RVLU bytecode、VM、GC、coroutine，以及資源額度、錯誤與中止行為。每項均標示兩個 profile 各自的規格來源、實作位置、能實際驗證該行為的測試與結果；未列入專案支援範圍的功能明確標示為未支援或有意限制，不從測試數量推論完整相容。

## 執行批次

### 批次一：建立項目到實作與有效測試的映射

- 逐項整理兩個 profile 的既定規格、相容性索引、現有階段契約與測試 ID；涵蓋語言、標準庫、公開 C API、bytecode/VM、GC/coroutine、錯誤與資源限制。
- 對每個項目記錄：profile、規格或契約來源、實作模組／符號、能檢查預期行為的測試 ID／斷言、目前缺口。只讀索引或 source 沒有對應有效測試時標為「無測試」，不能算已驗證。
- 重用一份簡潔映射表，不另建多層 receipts。發現規格互相矛盾時先標記衝突與適用來源，不自行改寫契約。

### 批次二：修正已確認的實作缺口

- 僅修正批次一確認的功能錯誤、明確契約缺口或失效測試；先加入能區分正確與錯誤行為的最小回歸案例，再修正實作。
- 沒有契約、狀態、錯誤清理或檔案相依，且檔案／符號 ownership 不重疊的工作，才可平行處理；一般切片用 `plan_implementer`，非 VM 核心但深度耦合者用 `complex_implementer`。VM、bytecode、GC、coroutine、資源生命週期或跨層錯誤路徑有耦合時，由同一 `vm_core_implementer` 順序完成實作與測試。
- 不以弱化斷言、隱藏錯誤、停用 GC 或擴大不受支援行為來消除失敗；對已確認且可在授權範圍內修正的問題自行修正，不等待額外提問。

### 批次三：兩 profile 的必要功能驗證

- 執行前逐層靜態確認每個測試、runner、wrapper、formatter（包括 `rustfmt`、`cargo fmt`）及其子程序的完整啟動鏈、參數、環境與下游工具。永久禁止 `xcrun`、`/usr/bin` 的 `cc`、`clang`、`ar`、`nm`、`otool`、`git` launcher shims，以及 debugger、process attach、Developer Tools 對話框鏈；啟動鏈不明或無法確認安全的檢查不得執行，標為 `BLOCKED`，不可要求繞過禁令。
- 只執行映射表中能有效覆蓋各 Lua 項目的必要功能測試，Lua 5.5.1 與 5.4.9 分開驗證。適用的上游測試只使用來源索引所列、雜湊確認的離線版本；不把未執行的上游套件列為通過。
- 相關程式、測試、輸入、設定與執行條件均可證明未變時，重用已有有效結果；其餘只跑受影響檢查。每項明確記錄 `PASS`、`FAIL`、`NOT_RUN` 或 `BLOCKED`、實際命令與測試數；零匹配測試不是 `PASS`，一個 profile 的結果不能代表另一個。

### 批次四：覆蓋閉合、修正後重測與交付

- 檢查所有映射項目都有規格、實作及有效測試；缺任一項都保留為未完成／未驗證，不以匯總成功掩蓋。修正失敗後只重測受變更影響的範圍及必要跨層互動。
- 清除本次建立且已不需要的 task-owned 暫存輸入／輸出；不刪除使用者資料、來源測試、必要 fixture 或其他工作使用的共享快取。
- 提交簡短結果摘要，列出兩 profile 已覆蓋項目、實際測試結果、已修正缺口、仍未驗證／阻擋項目及原因；不建立 phase acceptance、release evidence 或繁複 receipts，不新增 commit。

## 完成判準

只有在每個列入範圍的 Lua 項目於 Lua 5.5.1 與 Lua 5.4.9 均有明確實作映射和至少一項有效行為測試，必要測試已在安全啟動鏈下實際執行，且修正後受影響測試通過時，才可報告「已實作並有測試覆蓋」。未支援項目、無測試項目、零匹配、未執行檢查、工具鏈禁令阻擋或上游 oracle 未提供的情況，須分別列出，不宣稱完整 Lua 相容或全面通過。
