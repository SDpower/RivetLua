# P24 REL009：未封存依賴負例 SOURCE

- 狀態：SOURCE 負例；尚未建置或執行。
- 刻意依賴 p24-stage registry 中 public7 closure 之外的具名套件 `rivetlua-xtask = 0.0.0`；此 package 只列在 workspace 工具範圍，不屬於公開七套件閉包。
- 預期由 closure、clean-consumer preflight 或 registry 的受控政策拒絕。不得 fallback 到 crates.io、網路、全域 cache 或母 repo。
- dependency/registry/closure 缺失或 resolver 意外成功都不能單獨算作預期負例通過；需由日後明確授權的檢查確認拒絕來源。
- 未執行 package、registry、clean-consumer、build、consumer、test 或 gate；沒有結果、artifact 或驗收紀錄。
