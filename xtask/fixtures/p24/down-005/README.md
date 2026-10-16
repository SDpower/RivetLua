# DOWN-005：runtime-only RVLU consumer

- 狀態：SOURCE fixture；consumer 與 producer 均尚未建置或執行。
- consumer 只直接依賴 p24-stage registry 的 rivetlua-core 與 rivetlua-runtime，兩者皆關閉 default features；沒有 compiler、parser 或 SDK 依賴，並以 panic=abort 符合 runtime 的 no_std 設定。
- 獨立的 `producer/` 套件只使用公開 core encoder 建立最小 RVLU_V2、i64/f64 模組；profile 由 argv 明確指定為 54 或 55。producer 未執行，目錄沒有 `.rvlu` bytes、hash 或產物證據。
- 若日後獲准執行，producer 與 consumer 都依序接收 profile（54 或 55）及 artifact 路徑；相同 profile 的 producer 輸出交給 consumer 時，預期 stdout 為 `41` 後接一個換行、exit code 為 0。
- consumer 透過公開 `decode_module` → `VerifiedModule` → `Vm::load`／`Execution::run` 路徑檢查固定結果 41、相反 Lua profile、RVLU format 不符及零 fuel 受控中止。首次執行 fuel 上限為 1024；VM logical heap 上限為 8 MiB；輸入最多讀取並接受 1 MiB，超出即拒絕。
- 所有 package、registry、clean-consumer、build、runtime 與驗收檢查均未執行；此目錄不含封存 artifact 或驗收紀錄。
