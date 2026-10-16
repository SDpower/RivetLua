# P24 REL009：母 repo path dependency 負例 SOURCE

- 狀態：SOURCE 負例；尚未建置或執行。
- 此獨立 fixture 刻意以相對 path 依賴母 repo 的 `crates/rivetlua`；這是唯一刻意使用母 repo path dependency 的 SOURCE 負例。
- clean-consumer preflight 預期在解析或讀取母 repo 前拒絕此依賴。母 repo 路徑目前存在、Cargo 能解析或 workspace 建置成功，都不能算作負例通過。
- 不得用母 repo 內容滿足 consumer，也不得改寫為 registry、網路或全域 cache fallback。
- 未執行 clean-consumer、build、consumer、test 或 gate；沒有結果、artifact 或驗收紀錄。
