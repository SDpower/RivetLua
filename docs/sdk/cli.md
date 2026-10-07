# RivetLua 命令列工具

`rivetlua` 與 `rivetluac` 是 `rivetlua-cli` 套件提供的兩個 Rust VM 工具。預設 build 使用 Lua 5.5.1；以 `cargo build -p rivetlua-cli --features default-lua54` 建置時，兩個工具的預設 profile 都改為 Lua 5.4.9。`--profile lua54`／`--profile lua55` 仍可明確選擇 profile，優先於編譯期預設。Feature 只設定 parser 的預設值，不插入命令列參數，也不改變 script 的 `arg` 索引或 varargs。兩個工具都只透過公開 SDK 編譯、匯入與保存模組，不會啟動系統 Lua、C 模組或外部 runtime。

`rivetlua` 為 `math.randomseed()` 的無參數呼叫明確提供作業系統 entropy：Unix 平台每次開啟 `/dev/urandom` 並讀取 8 bytes；開啟、短讀或讀取失敗會回報 `E_HOST_ENTROPY_FAILED`。目前只有 Unix 提供真實 OS entropy；非 Unix 平台上的該呼叫會以相同錯誤失敗，不會改用固定 seed 或時間值。顯式傳入 seed 不需要 OS entropy。此權限只由 CLI 注入，SDK 預設的 deny-all host services 不變。

CLI 只啟用受限的作業系統能力：`os.clock()` 回傳程序 CPU 使用秒數，不代表牆上時鐘；Unix 與 Windows 使用原生 CPU 計時，其他平台回報 `E_HOST_UNSUPPORTED`。`os.time()` 僅接受無參數呼叫並回傳 Unix epoch 整秒，超出平台可表示的 `i64` 範圍時回報平台差異錯誤。CLI 的 locale backend 固定為 C locale：`os.setlocale()`、`os.setlocale(nil)` 與六個合法 category 的查詢回傳 `C`；明確選擇 `C` 也回傳 `C`。其他 locale 名稱（包含空字串）回傳 nil，查詢仍為 `C`。這是 VM-local 的固定 backend，不呼叫程序全域 locale，也不表示支援原生的非 C locale。CLI VM 使用的 host services 建立時會起算一小時 deadline；期限只檢查 host resource operations，到期時相關呼叫回報 `E_HOST_DEADLINE`，不會限制整段 guest 執行的 wall-clock 時間。CLI 另外為每個 top-level Execution 透過 SDK `Execution::set_fuel` 設定有限的 8,000,000,000 fuel，涵蓋 root module、`-l` require 與 REPL 自訂 `print`；SDK/runtime 預設的每次 Execution 1,000,000 fuel 不變。其他 OS 操作（包含 `os.time(table)`、日期格式、環境查詢、程序與路徑操作）維持拒絕；SDK 預設 host services 仍為 deny-all。

`rivetlua` 可執行檔案、stdin／pipe，或用 `-e` 執行程式文字；沒有檔名且 stdin 是 pipe 時會執行 stdin，互動 terminal 則進入 REPL。`-l` 透過 `require` 載入模組，接受 `g=module` 指定全域名稱；`-i` 在前置執行後進入 REPL，`-v` 印出 profile 版本，`--` 停止剖析選項。檔名後的參數全部交給 script，並以 Lua `arg` table 和 root chunk varargs 傳入。

```sh
rivetlua --profile lua54 -e "print('hello')"
rivetlua -lmath -e "print(math.type(42))" script.lua first second
rivetlua script.lua < input.txt
```

執行順序固定為環境初始化、依命令列順序執行 `-e`／`-l`、執行 script／file／stdin，最後才依 `-i` 進入 REPL。互動輸入先嘗試 expression，再回退到 statement；Lua 5.4 接受 `=expression`，Lua 5.5 不接受。Expression 回傳的所有值（包含中間 `nil`）會在同一次呼叫中交給 VM 當下的全域 `print`，因此遵循 Lua 的數值格式、`__tostring` 與 guest 對 `print` 的替換。REPL 會在錯誤後繼續處理輸入，但若本次互動曾出錯，結束狀態仍為非零。

環境變數範圍固定：profile 專屬 `LUA_INIT_5_4`／`LUA_INIT_5_5` 優先於 `LUA_INIT`；值以 `@` 開頭時讀該檔案，否則作為程式文字。package path 同樣使用 `LUA_PATH_5_4`／`LUA_PATH_5_5` 優先於 `LUA_PATH`，cpath 使用 `LUA_CPATH_5_4`／`LUA_CPATH_5_5` 優先於 `LUA_CPATH`。`;;` 會插入預設 Lua path `./?.lua;./?/init.lua`，預設 cpath 為空。`-E` 只略過這些明定的 init 與 path 環境來源。

CLI VM 明確啟用 stdout、SDK source compiler、受控 file/stdin reader 與 package source／raw RVLU／official chunk repository；P05 classifier 負責 raw 與 official chunk 格式。CLI 直接輸入可由 SDK 完整解碼 RVCT；`load`、`loadfile` 與 `require` 的動態編譯／reader／repository 僅支援 source、raw RVLU 與 official chunk，不接受 RVCT。其他服務維持 SDK 預設拒絕，包括 native module、process 與未設定的 host service。動態 host load 使用獨立且有限的 policy：來源上限 4 MiB、encoded 上限 64 MiB、module allocation 上限 64 MiB、temporary 上限 256 MiB、work 上限 2 Gi 單位、module 候選路徑最多 4096 bytes、reader chunks 與候選搜尋各上限 512；reader／repository 會在配置、讀取、路徑處理及來源正規化前向 `LoadBudget` 預付工作與暫存額度，並核對實際容量。CLI 直接讀取的 file／stdin 上限為 16 MiB，編譯仍受 Engine 的 compiler／IR／verifier 預設限額約束。超限、編譯、解碼或執行錯誤都會產生非零狀態。

CLI 的 debug capability 開放官方 Lua 5.5.1／5.4.9 測試實際使用、且 runtime 已實作的權限：`debug.getinfo` 與 stack 查詢、local 讀寫、upvalue 讀寫與身分操作、registry 與 uservalue 讀寫、`debug.traceback`、`debug.gethook`／`debug.sethook`，以及受支援物件的 `debug.getmetatable`。`debug.setmetatable` 仍只允許 table；即使原 metatable 設有受保護的 `__metatable` 欄位，也可替換或以 `nil` 清除。CLI File userdata 沒有 uservalue 槽，對它呼叫 `debug.getuservalue`／`debug.setuservalue` 會回傳 `nil`。metatable 讀取僅支援 runtime 可驗證的 table、file 與 string metatable；debug 操作遇到 runtime 不支援的物件或資訊仍會回報 `E_HOST_POLICY_DEBUG`。非 table 的數字、boolean、nil 作為 `debug.setmetatable` 參數會以 `E_DEBUG_ARGUMENT` 拒絕，string、function、coroutine 等非 table 物件會以 `E_HOST_POLICY_DEBUG` 拒絕。`debug.debug` 不授權，呼叫時回報 `E_HOST_POLICY_DEBUG`；`debug.setcstacklimit` 僅 Lua 5.4 profile 會提供，但不授權而回報 `E_HOST_POLICY_DEBUG`，Lua 5.5 profile 不提供此欄位。SDK/runtime 預設 `DebugCapability` 維持 deny-all。

CLI 允許 `string.dump` 輸出目前 Lua profile 的官方 bytecode，並支援 `strip` 參數；每次輸出受限於 512 Mi 單位 work、4 MiB temporary 與 1 MiB encoded bytes。輸出包含所選函式 prototype，並依 `strip` 保留或移除 debug 資訊；不序列化閉包捕獲值、VM stack 或 host resource 狀態。SDK/runtime 預設的 `DumpCapability` 仍為 deny-all。

`rivetluac` 一次接受一個檔案或 stdin；沒有檔名時使用 stdin。`-p` 只驗證，不產生輸出；`-l` 僅列出公開 `Module` 的 profile、格式版本、origin、source name 與 main line range，不反組譯 bytecode。預設輸出為 `rivetluac.out`，`-o path` 指定輸出檔，`-o -` 將已完整生成的 RVCT bytes 寫至 stdout；`-o` 不可與 `-l` 或 `-p` 同時使用。`-v` 顯示 profile 版本，`--` 結束選項剖析。多個輸入、無效 profile、語法錯誤、損壞的 RVCT 或輸出錯誤都會以非零狀態回報。

所有二進位輸入交由 SDK／P05 驗證；成功的 `rivetluac` 二進位輸出一律使用 SDK `Engine::save_module` 產生 RVCT。檔案輸出先在目標目錄完整建立暫存檔，再以 rename 替換目標，寫入或 rename 失敗時移除暫存檔並保留原目標。安裝只建立 `rivetlua` 與 `rivetluac` 名稱，不建立或覆寫 `lua`／`luac` 別名。

P14 正式 CLI 案例會在隔離 prefix 執行 `cargo install --path crates/rivetlua-cli --root <prefix> --locked --offline`，再用安裝後的 `rivetluac` 產生 RVCT 並交給安裝後的 `rivetlua` 執行；prefix 內預先放置的 `lua`／`luac` sentinel 必須保持逐位元組相同。負向測試另將可執行的 `lua`／`luac` decoy 放在 `PATH` 最前面，驗證 source、raw RVLU、官方 chunk 與 RVCT 路徑均沒有呼叫系統 Lua。這些是驗收配置，不改變 CLI 預設的 host capability。
