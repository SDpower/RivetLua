# Moonrocks 1.3.0 localtest fixtures

這些檔案是固定 release protocol 的靜態輸入，不是 HTTP server 或已下載的上游資料。

- `response-version.json` 對應 `GET /api/tool_version?current=1.3.0`；`response-force-update.json` 表示強制更新。
- `response-status.json` 與 `response-invalid-key.json` 對應 `GET /api/1/<key>/status` 的成功與錯誤回應。`<key>` 只是路徑佔位，檔案不含憑證。本機 adapter 另驗證成功回應中的 `namespace` 欄位，這是本機授權規則，並非 Moonrocks release 的必要欄位。
- `response-check-new.json` 與 `response-check-existing.json` 對應 `GET /api/1/<key>/check_rockspec?package=...&version=...`。
- `response-upload.json` 對應帶 `rockspec_file` 的 multipart `POST /api/1/<key>/upload`。
- `manifest.lua` 是 Lua repository 表，供 `outdated` 的 host adapter 將原版固定 manifest URL 導向 loopback fixture。

測試 endpoint 固定為 `http://127.0.0.1:18018`。CLI 的 `<token-env>` 是環境變數名稱，token 不放在 argv 或這些檔案中。原版 client 使用固定 HTTPS/API 與 manifest URL；需由 host adapter 導向本地 fixture。本資料不表示原版支援 `--server` 改寫 URL，也不會連線或下載上游。

自有 rockspec 使用保留的 `example.invalid` Git URL 與 tag，不宣稱上游版本或來源 hash；Closure index 的 `source` 欄應指向已備妥的 `tests/p18/fixtures` source root（不是本 `moonrocks` 目錄），以便 `source/example_pure.lua` 重用既有檔案，不需複製或另行產生來源。此流程只上傳 rockspec（`skip-pack`），不下載或建置該來源。
