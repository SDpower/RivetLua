# RivetLua Rust SDK

SDK 以明確的 Lua 5.4 或 Lua 5.5 profile 編譯並執行程式。`Engine` 持有 lexer/parser/resolver、IR 與 RVLU verifier 各自的 limits；`compile_named` 會把來源名稱交給 P05 native-debug verifier。`Module` 私下持有不可變的 `VerifiedModule`，可由多個 VM 共用；`source_name` 與 `main_line_range` 只讀查詢 P05 驗證過的 root debug metadata。每個 `Vm` 仍有自己的 globals、heap、callback registry、coroutine 與宿主服務。

```rust
use rivetlua::{ContainerLimits, Engine, LuaProfile, RunOutcome, SdkError, TransportBudget, Value};

let engine = Engine::new(LuaProfile::Lua55);
let budget = TransportBudget::new(ContainerLimits::default());
let module = engine.compile_named(b"return function() return {} end", b"example.lua")?;
let container = engine.save_module(&module, &budget)?;
let module = engine.load_module(&container, &budget)?;
let mut vm = engine.new_vm()?;

let function_value = match vm
    .load_module(&module)?
    .run()
    .map_err(SdkError::Runtime)?
{
    RunOutcome::Returned(values) => values[0],
    other => return Err(format!("預期回傳函式，得到 {other:?}").into()),
};
let function = vm.root(function_value)?;

let table_value = match vm
    .call(&function, &[])?
    .run()
    .map_err(SdkError::Runtime)?
{
    RunOutcome::Returned(values) => values[0],
    other => return Err(format!("預期回傳表格，得到 {other:?}").into()),
};
let table = vm.root(table_value)?;
vm.collect()?;
assert!(matches!(table.value(&vm)?, Value::Object(_)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

`Value` 是可複製的值分類；其中的 heap 物件身分包含 VM 與世代資訊，本身不保活物件。執行回傳的物件值須在 Execution 結束後、下一次配置或 GC 前呼叫 `Vm::root`。`Root` 以 runtime `HostHandle` 實作，驗證 VM 身分及物件世代；`try_clone` 會向同一 VM 建立獨立 root。`Root::value` 回傳可複製的 `Value`，但取得後不會因原 `Root` 借用而延長物件生命；若要跨越配置或 GC 保活，應持有 `Root`。SDK 的 globals/table 操作沿用 runtime 驗證；ByteString 讀取會複製成宿主擁有的 bytes，不會借出 heap 參照。

`Engine::save_module` 與 `Engine::load_module` 以 RVCT v1 保存／還原 P05 已驗證的 immutable module artifact。`Module::clone` 只共享 `Arc<VerifiedModule>` 與不可變 metadata；每個 `Vm` 仍有自己的 globals、package registry／require cache、heap、coroutine 與宿主服務。使用 `TransportBudget::new(ContainerLimits::default())` 建立可重用的單次操作額度；可分別設定總容器 bytes、peak 配置、work 及 P05 transport limits。load 先驗證 RVCT header、長度與 CRC，再把兩段 opaque payload 交給 P05 重建及驗證；SDK 不自行解讀 RVLU 或 RVAS。錯誤以 `ContainerError` 回報，失敗不會交出部分 module。此格式只保存 module 與驗證 metadata，不保存 VM heap、closure capture、stack、coroutine 或 host resource。

`Vm::new` 與 `Engine::new_vm` 會安裝 runtime 已有的標準函式庫，並以 `HostServices::deny_all()` 建立 VM。需要 I/O、載入、entropy、debug 或其他宿主能力時，應明確建立對應的 `HostServices` 並傳入 `with_host_services`／`new_vm_with_services`。`set_allocation_limit` 設定包含目前 committed bytes 的 VM 總邏輯配置上限；唯讀 `allocation_snapshot` 可檢查目前帳本，`inject_next_allocation_failure` 可用來驗證一次性失敗後的清理與重試。SDK 不借出 runtime 的可變 VM 參照。

`Vm::get_global`／`set_global` 與 rooted table 的 `table_raw_get`／`table_raw_set` 使用 runtime 現有的驗證操作。由 lookup 得到的物件值要跨越配置或 GC 時仍須呼叫 `Vm::root`；`read_byte_string` 回傳宿主擁有的位元組複本。`Module` 上的 metadata 查詢不會改變 Lua `debug.getinfo` 的能力；Lua `S` 欄位仍遵循 runtime 目前對 official artifact 的支援範圍。

`Vm::register_callback` 接受明確的 Lua capture 值，runtime 會驗證其 VM 所屬並在登錄期間追蹤物件捕獲。回呼只能透過 `CallbackContext` 回傳、丟出錯誤、呼叫、續跑或 yield 動作；它不會取得第二個 VM 借用。

`Execution::set_fuel` 設定單次執行額度，`run` 回傳 runtime 的 `RunOutcome`。`Returned`、`LuaError`、`Aborted` 與 `PendingClose` 各自保留原有語意，不合併成單一錯誤結果。可執行的公開 API 範例位於 [`examples/embed.rs`](examples/embed.rs)。
