# RivetLua 命令列工具

`rivetlua` 與 `rivetluac` 是 `rivetlua-cli` 套件提供的兩個 Rust VM 工具。預設使用 Lua 5.5.1；`--profile lua54` 可選擇 Lua 5.4.9。兩個工具都只透過公開 SDK 編譯、匯入與保存模組，不會啟動系統 Lua、C 模組或外部 runtime。

`rivetlua` 可執行檔案、stdin／pipe，或用 `-e` 執行程式文字；沒有檔名且 stdin 是 pipe 時會執行 stdin，互動 terminal 則進入 REPL。`-l` 透過 `require` 載入模組，接受 `g=module` 指定全域名稱；`-i` 在前置執行後進入 REPL，`-v` 印出 profile 版本，`--` 停止剖析選項。檔名後的參數全部交給 script，並以 Lua `arg` table 和 root chunk varargs 傳入。

```sh
rivetlua --profile lua54 -e "print('hello')"
rivetlua -lmath -e "print(math.type(42))" script.lua first second
rivetlua script.lua < input.txt
```

執行順序固定為環境初始化、依命令列順序執行 `-e`／`-l`、執行 script／file／stdin，最後才依 `-i` 進入 REPL。互動輸入先嘗試 expression，再回退到 statement；Lua 5.4 接受 `=expression`，Lua 5.5 不接受。Expression 回傳的所有值（包含中間 `nil`）會在同一次呼叫中交給 VM 當下的全域 `print`，因此遵循 Lua 的數值格式、`__tostring` 與 guest 對 `print` 的替換。REPL 會在錯誤後繼續處理輸入，但若本次互動曾出錯，結束狀態仍為非零。

環境變數範圍固定：profile 專屬 `LUA_INIT_5_4`／`LUA_INIT_5_5` 優先於 `LUA_INIT`；值以 `@` 開頭時讀該檔案，否則作為程式文字。package path 同樣使用 `LUA_PATH_5_4`／`LUA_PATH_5_5` 優先於 `LUA_PATH`，cpath 使用 `LUA_CPATH_5_4`／`LUA_CPATH_5_5` 優先於 `LUA_CPATH`。`;;` 會插入預設 Lua path `./?.lua;./?/init.lua`，預設 cpath 為空。`-E` 只略過這些明定的 init 與 path 環境來源。

CLI VM 明確啟用 stdout、SDK source compiler、受控 file/stdin reader 與 package source／raw RVLU／official chunk repository；P05 classifier 負責 raw 與 official chunk 格式。CLI 直接輸入可由 SDK 完整解碼 RVCT；`loadfile` 與 `require` 的動態 reader／repository 僅支援 source、raw RVLU 與 official chunk，不接受 RVCT。其他服務維持 SDK 預設拒絕，包括 native module、process、debug 與未設定的 host service。`loadfile`／`require` 使用獨立的有限 load policy：來源上限 4 MiB、encoded 上限 64 MiB、module allocation 上限 64 MiB、work 上限 16 Mi 單位、module 候選路徑最多 4096 bytes、候選搜尋上限 512；reader／repository 會在配置、讀取、路徑處理及來源正規化前向 `LoadBudget` 預付工作與暫存額度，並核對實際容量。CLI 直接讀取的 file／stdin 上限為 16 MiB，編譯仍受 Engine 的 compiler／IR／verifier 預設限額約束。超限、編譯、解碼或執行錯誤都會產生非零狀態。

`rivetluac` 一次接受一個檔案或 stdin；沒有檔名時使用 stdin。`-p` 只驗證，不產生輸出；`-l` 僅列出公開 `Module` 的 profile、格式版本、origin、source name 與 main line range，不反組譯 bytecode。預設輸出為 `rivetluac.out`，`-o path` 指定輸出檔，`-o -` 將已完整生成的 RVCT bytes 寫至 stdout；`-o` 不可與 `-l` 或 `-p` 同時使用。`-v` 顯示 profile 版本，`--` 結束選項剖析。多個輸入、無效 profile、語法錯誤、損壞的 RVCT 或輸出錯誤都會以非零狀態回報。

所有二進位輸入交由 SDK／P05 驗證；成功的 `rivetluac` 二進位輸出一律使用 SDK `Engine::save_module` 產生 RVCT。檔案輸出先在目標目錄完整建立暫存檔，再以 rename 替換目標，寫入或 rename 失敗時移除暫存檔並保留原目標。安裝只建立 `rivetlua` 與 `rivetluac` 名稱，不建立或覆寫 `lua`／`luac` 別名。

P14 正式 CLI 案例會在隔離 prefix 執行 `cargo install --path crates/rivetlua-cli --root <prefix> --locked --offline`，再用安裝後的 `rivetluac` 產生 RVCT 並交給安裝後的 `rivetlua` 執行；prefix 內預先放置的 `lua`／`luac` sentinel 必須保持逐位元組相同。負向測試另將可執行的 `lua`／`luac` decoy 放在 `PATH` 最前面，驗證 source、raw RVLU、官方 chunk 與 RVCT 路徑均沒有呼叫系統 Lua。這些是驗收配置，不改變 CLI 預設的 host capability。
