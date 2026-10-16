# P24 REL009：私有欄位負例 SOURCE

- 狀態：SOURCE 負例；尚未建置或執行。
- 僅依賴 p24-stage registry 的 `rivetlua = 0.0.0`，入口先透過公開 SDK 建立 `Module`，再刻意讀取私有欄位 `Module::verified`。
- 前置條件：p24-stage 中有可解析的精確 `rivetlua = 0.0.0` 封存套件。前置條件滿足後，預期以明確私有欄位存取錯誤（Rust `E0616`）拒絕。
- registry、套件或封存缺失屬前置條件失敗，不得算作此私有 API 負例通過；不得以母 repo、其他 registry、網路或全域 cache 補足。
- 未執行 package、registry、clean-consumer、build、consumer、test 或 gate；沒有結果、artifact 或驗收紀錄。
