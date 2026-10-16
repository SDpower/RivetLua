# DOWN-006：公開 C API host source

- 狀態：SOURCE fixture；C source 尚未編譯、連結或執行。
- Cargo driver 只透過 p24-stage registry 依賴 rivetlua-capi，feature 預設選擇 lua55，也可單選 lua54；Rust compile-time 檢查會拒絕零個或兩個 profile feature。Lua 5.4 配對方式為 cargo check --manifest-path xtask/fixtures/p24/down-006/Cargo.toml --no-default-features --features lua54。C host source 預設引用 Lua 5.5 公開 headers；定義 P24_LUA54 時改用 Lua 5.4 headers，封存 library 與 Cargo driver 必須採用相同 profile。
- `capi_host.c` 先比較 headers 產生的預期 identity 與封存 library 回報的 identity，成功後才建立 state；接著確認 callback 副作用恰一次、受保護執行回傳 error 並留下單一 stack error object。
- error 由 VM 執行 Lua 算術錯誤產生；C callback 不呼叫 `lua_error`，不要求 longjmp 穿越 Rust frame。
- 預期 C host 成功時 exit code 為 0，stdout/stderr 皆空。C source 不在此 fixture 中連結或執行。
- `artifacts/README.md` 列出封存 artifact 提供的 header 與 library 路徑；此目錄沒有複製母 repo headers、library binary、hash 或驗收紀錄。
- package、registry、C compile/link/run、clean-consumer 與驗收檢查均未執行。
