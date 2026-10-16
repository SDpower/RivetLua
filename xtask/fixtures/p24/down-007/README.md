# DOWN-007：Cortex-M runtime-only SOURCE consumer

- 狀態：SOURCE fixture；尚未建置、交叉編譯或執行。
- no_std library 的一般依賴只有 p24-stage registry 的 rivetlua-core 與 rivetlua-runtime，兩者都關閉 default features；它接受 caller 提供的 RVLU bytes，不含 allocator、board startup 或 unsafe code。最終板端執行檔仍須自行提供 allocator 與 panic handler。
- host example 以 argv 明確選擇 Lua profile 54 或 55，透過公開 P21 target API 確認 `thumbv7em-none-eabi` 是 BuildOnly，並以公開 core/runtime API source-assert 指定 profile 的 RVLU_V2、相反 profile/format 拒絕、固定回傳值 41 及零 fuel 受控中止。首次執行 fuel 上限為 1024；VM logical heap 上限為 8 MiB；輸入最多讀取並接受 1 MiB，超出即拒絕。host example 的 target query dependency 僅列在 dev-dependencies，不屬於 runtime-only library dependency graph。
- `CORTEX_M_TRIPLE` 是 target identity source；沒有建立 artifact、hash、provenance 或 board descriptor 證據。
- `spec/acceptance-waivers.toml` 的 DOWN-007 USER_WAIVED 只豁免實板啟動、執行與量測，不代表測試 PASS 或 hardware evidence，也不授權 Supported 狀態。其餘交叉建置、artifact、dependency、identity 與主機驗證仍未執行。
- 沒有封存 artifact、驗收紀錄或實板結果；目前內容只可視為 SOURCE fixture。
