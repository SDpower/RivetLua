# P24 發布準備狀態

目前版本仍為 0.x；部署狀態僅能依既有證據標為 `Experimental` 或 `BuildOnly`，尚非 1.0-ready。本階段只提供手動工具與只讀證據審核的來源碼。暫存 registry、封裝、乾淨 consumer、audit、checklist、測試與驗收均未執行；沒有可據以發布的套件閉包或正式 registry 權利證據。

`xtask/p24/release.py` 的手動入口依序提供 `topology`、`init`、`mirror`、`stage`、`inspect`、`index`、`consumer`、`closure` 與 `recipe`。`serve` 只允許手動在 loopback 提供暫存資料；本階段沒有啟動。工具只接受 task-owned 暫存目錄及離線、與 production `Cargo.lock` 精確一致的第三方輸入；正式 workspace lock 不改寫。stage 只把內部 path 依賴轉為 `p24-stage` 精確版本，並複製核准的授權、NOTICE 與 C header。建立 index 前必須有外部 resolver 產生且符合既有鎖定來源的 staging lock、實際 archive 及內容核對。`consumer` 產生的空 `main` 僅是 compile smoke 來源，不能當作任何下游案例通過。`closure` 只回報 `STATIC_ONLY`；沒有每包實際乾淨 consumer 結果便不構成完整閉包。

`recipe` 固定回報 `BLOCKED_CHAIN` 與待查的 Cargo、編譯器、linker、archiver、SDK、build script 與轉遞子程序。任何執行者都須先獨立完成既有永久工具禁令要求的完整啟動鏈靜態核實；recipe 不提供已核准的執行器，也不讀取權杖或發布。`release-identity identity --rvlu … --profile lua54|lua55 --crate-version …` 只從 P05 `VerifiedModule` 投影 bytecode 版本與 profile；C ABI、native artifact 與平台版本沒有獨立 producer 證據時為 `null`，結果明列 `release_ready:false`。

`xtask/p24/evidence.py` 的 `audit_release(evidence, expected_inputs, waiver_doc)` 是純資料函式。`expected_inputs` 以個別 `DOWN-001`～`007`、`REL-001`～`010`、`R10-001`～`009` 對應該案例相關 scope 的 SHA-256；不相關文件或全域 digest 變動不會讓其他案例失效。每筆來源證據須有有效報告摘要、公開來源、非零 matched count、全部通過且無未解高風險項；缺漏、過期、零案例與非 `PASS` 均回 `BLOCKED`。`REL-001`～`007` 另依相應 `DOWN`；`REL-010` 與 `R10-009` 需要七個正式 package name、owner、publish rights 及第三方授權、NOTICE、安全聯絡方式的公開來源，暫存 registry 不能取代正式權利。`R10-008` 需要兩個 profile 的獨立版本 producer 與升級策略；0.x、未知 ABI/native/platform 版本不滿足 1.0 判定。

輸入中的 `evidence.version` 固定為 1；`cases[case_id]` 各含 `status`、`inputs`、`matched`、`passed`、`failed`、`report_sha256`、`source`、`unresolved_high_risk`。`expected_inputs[case_id]` 至少列一個相關 scope；實板與 R10 關鍵案例還有 `evidence.py` 固定的必要 scope。輸出只有公開狀態碼、案例 ID、阻塞清單及四個適用子條件的豁免狀態，不複製來源報告或私有錯誤內容。

`waiver_doc` 僅接受唯讀 `spec/acceptance-waivers.toml` 的六筆既定記錄；P24 只在 `DOWN-007`、`REL-007`、`R10-006`、`R10-007` 附加精確實板子條件的 `USER_WAIVED`。這不是測試通過或實板證據，不能豁免封裝、artifact、交叉建置、公開 consumer、license、notice、安全或權利；沒有實板證據不得標 `Supported`。證據審核不連網、不讀 token、不核准 publish，且只能檢查提供的資料一致性，不能代替原始 producer 的獨立驗證。
