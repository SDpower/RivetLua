# P00 上游來源清單

取得日期：2026-09-22（Asia/Taipei）。所有包先下載到隔離的 `tmp/`，以 SHA-256 驗證、解壓並依上游 Makefile 建置後，才複製為本目錄的離線快照。它們的角色均為 `development_test`，不可成為正式 crate 依賴或發行產物。

| Profile | 內容 | 版本 | 官方 URL | SHA-256 | 本地路徑 | 授權位置 |
|---|---|---|---|---|---|---|
| `lua55` | source | Lua 5.5.1 | https://www.lua.org/ftp/lua-5.5.1.tar.gz | `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce` | `vendor/lua55/source.tar.gz`、`vendor/lua55/lua-5.5.1/` | `vendor/lua55/lua-5.5.1/README` 與 `doc/readme.html` |
| `lua55` | tests | Lua 5.5.1 | https://www.lua.org/tests/lua-5.5.1-tests.tar.gz | `da07b543872dc0bb2ff12aabd0c248578d78df3eb6b67efdc537a46d455c7f31` | `vendor/lua55/tests.tar.gz`、`vendor/lua55/lua-5.5.1-tests/` | 同版本 source 快照的 Lua 授權資訊 |
| `lua54` | source | Lua 5.4.9 | https://www.lua.org/ftp/lua-5.4.9.tar.gz | `2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6` | `vendor/lua54/source.tar.gz`、`vendor/lua54/lua-5.4.9/` | `vendor/lua54/lua-5.4.9/README` 與 `doc/readme.html` |
| `lua54` | tests | Lua 5.4.9 | https://www.lua.org/tests/lua-5.4.9-tests.tar.gz | `7d971845f545ffc09fbb3128a86b2c6524161c70d0fdf0154a16e8c00c343fca` | `vendor/lua54/tests.tar.gz`、`vendor/lua54/lua-5.4.9-tests/` | 同版本 source 快照的 Lua 授權資訊 |

本次參考程式在 macOS arm64 以各原始碼包的 `make macosx` 建置。`lua55` 的 `src/lua -v` 回報 Lua 5.5.1；`lua54` 的 `src/lua -v` 回報 Lua 5.4.9。gate 在離線模式由上述 tarball 重建，不能呼叫系統 Lua 或下載其他引擎。

目前 runner 依執行平台選擇上游 Makefile 目標：macOS 使用 `macosx`，Linux 使用 `linux`。雜湊工具分別使用 `shasum -a 256` 與 `sha256sum`；兩者都核對同一組固定 SHA-256。Linux 的實際通過狀態須以 CI 執行結果判定。
