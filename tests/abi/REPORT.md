# P00 C ABI 風險證據

原始風險實驗平台：macOS arm64。編譯器：`cc`。當時 Rust toolchain：1.94.1。`gate P00` 在執行主機重新編譯並執行安全案例，產物寫入 `target/rivetlua-abi/`；各平台的實際結果須以該次 gate 報告為準。

| Case | 命令與旗標 | 預期與實際控制流 | 退出碼 |
|---|---|---|---|
| P00-ABI-001 | `cc tests/abi/nested_callback.c -o target/rivetlua-abi/nested_callback` | `main → callback → callback → main`；兩次正常 C 返回後比較結果為 2。 | 0 |
| P00-ABI-002 | `cc tests/abi/c_only_longjmp.c -o target/rivetlua-abi/c_only_longjmp` | `main/setjmp → nested_callback → longjmp → main/setjmp`；跳轉只跨 C frame。 | 0 |

兩項命令的實際退出碼由 gate 以 process exit status 記入報告；非零即失敗。

`longjmp` 跨越持有 Rust `Drop` 資源的 frame 是拒絕設計。此倉庫不建立、編譯或執行該路徑；未來 C API 必須在 C 隔離層轉換錯誤，讓 foreign `longjmp` 不進入或不越過 Rust frame。正式 C API 仍為 `NOT_IMPLEMENTED`。
