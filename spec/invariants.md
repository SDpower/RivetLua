# 不變量

- `lua55` 與 `lua54` 必須明確指定，不能互相代替。
- 外部 bytecode 必須先驗證；P00 尚未實作驗證器。
- 每個 VM 的 heap、global 與 registry 在未來保持分離。
- 正式產物與依賴不得含官方 Lua engine。
- P00 不實作正式 C API；foreign `longjmp` 不得進入或越過持有 Rust 資源的 frame。
