# 官方 chunk 測試輸入

固定來源為 `vendor/lua55/source.tar.gz`（Lua 5.5.1，SHA-256 `1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce`）與 `vendor/lua54/source.tar.gz`（Lua 5.4.9，SHA-256 `2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6`）。在隔離暫存目錄解壓並執行各版本 `make -C lua-X.Y.Z/src generic`，不要修改 vendor 或把官方 runtime 納入產品。

從專案根目錄、以各版暫存 `lua`／`luac` 執行：

```sh
luac55 -o crates/rivetlua-core/tests/official_chunk_fixtures/lua55-debug.luac crates/rivetlua-core/tests/official_chunk_fixture.lua
luac55 -s -o crates/rivetlua-core/tests/official_chunk_fixtures/lua55-strip.luac crates/rivetlua-core/tests/official_chunk_fixture.lua
luac54 -o crates/rivetlua-core/tests/official_chunk_fixtures/lua54-debug.luac crates/rivetlua-core/tests/official_chunk_fixture.lua
luac54 -s -o crates/rivetlua-core/tests/official_chunk_fixtures/lua54-strip.luac crates/rivetlua-core/tests/official_chunk_fixture.lua
lua55 crates/rivetlua-core/tests/official_chunk_closure_fixture.lua crates/rivetlua-core/tests/official_chunk_fixtures/lua55-closure.luac
lua54 crates/rivetlua-core/tests/official_chunk_closure_fixture.lua crates/rivetlua-core/tests/official_chunk_fixtures/lua54-closure.luac
```

上述 `luac55`、`luac54`、`lua55`、`lua54` 是隔離建置後二進位的示意名稱；實際驗證使用 `/tmp/rivetlua-official-codec-oracle-4acf363/lua55/lua-5.5.1/src/{lua,luac}` 與對應 `lua54/lua-5.4.9/src/{lua,luac}`。`lua55-closure`／`lua54-closure` 是 `string.dump` 非主函式，root upvalue 描述為 `in_stack=0`。

六份產物的 SHA-256：

| 檔案 | SHA-256 |
| --- | --- |
| lua55-debug.luac | `0f99904d2488fb27868cff66af0be09d1ef64b00c59201bf16456ae9cb05ab7a` |
| lua55-strip.luac | `1fc3dc232f26d69669e9efa0497ab15a0cd00341d4ed10d93109d9bdd00ef7a2` |
| lua55-closure.luac | `1224eeb61b9a11fd6763d4d24845f3f6f36c1588bd7019b498225182fa26afcf` |
| lua54-debug.luac | `df15b0baa436f80b7f4325e9bfea73c469769ab5083c5f30632fc393a5a34d68` |
| lua54-strip.luac | `43bba279e76f316bcccd086c5ac3f2146ef1762759e98c08c8bc4fed087f7308` |
| lua54-closure.luac | `8f49ed293d46f9029972d7b8cf8420aa61f69c141c2dad394a081851cb725bf0` |

官方互讀測試需設定 `RIVETLUA_LUA55_LUAC`、`RIVETLUA_LUA54_LUAC`、`RIVETLUA_OFFICIAL_ORACLE_OUTPUT_DIR`，然後執行 `cargo test --locked -p rivetlua-core --test official_chunk_codec official_oracle_accepts_reencoded_debug_strip_and_nested_closure -- --ignored --nocapture`。測試會讓各版官方 `luac -p` 讀取重編碼產物，再由官方 `luac -s` 重新 strip。
