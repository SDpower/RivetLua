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

## VM 政策與輸出

以 `HostServices::deny_all().and_policy(...)` 在建構 VM 前固定 `VmPolicy::Compatibility`、`VmPolicy::Sandbox` 或 `VmPolicy::PrivateService`；guest 沒有政策 setter。`Compatibility` 預設拒絕可選宿主服務，只有明確注入才開放；未設輸出額度時保留既有無限制語意，明設額度後則照常計量。`Sandbox` 與 `PrivateService` 預設使用有限輸出額度（64 KiB、1,024 events、depth 8、100,000 work units），並限制敏感 debug／dump 及不可信 native／bytecode 能力。自訂額度可這樣傳入：

```rust
use rivetlua::{Engine, HostServices, LuaProfile, OutputBudget, VmPolicy};

let engine = Engine::new(LuaProfile::Lua55);
let services = HostServices::deny_all()
    .and_policy(VmPolicy::Sandbox)
    .and_output_budget(OutputBudget {
        max_bytes: 64 * 1024,
        max_events: 1024,
        max_depth: 8,
        max_work_units: 100_000,
    });
let mut vm = engine.new_vm_with_services(services)?;
```

輸出額度是同一 VM 的累積帳本，不會在不同 `Execution` 間重設；callback、`print`、錯誤輸出與 module export 共用。scalar 深度為 0，每個 return tuple 算一個 event；數字按 Lua 顯示形式計 bytes，字串按原始 bytes 計。受限輸出不接受 table、closure 或 opaque 資料；錯誤診斷以 `RunOutcome::SafeDiagnostic(diagnostic)` 回傳，`diagnostic` 只含 `public_code` 與 `correlation_id`，超額則為 `RunOutcome::Aborted(AbortReason::OutputLimit)`。

私密服務只在 `PrivateService` 政策、以 `and_policy_capabilities` 注入同 VM 的 `PolicyCapabilities` issuer，並以 `and_policy_clock` 注入單調遞增 `PolicyClock` 時授權；缺少 clock 時 fail closed，且 `now >= expires_at` 即失效。`OpaqueServiceHandle` 與 `CapabilityGrant` 不會成為 Lua 值或可序列化資料。Module export 預設拒絕；只有 `Compatibility`、以 `and_export_policy(ExportPolicy::OwnerModules)` 開啟、有效 issuer 及同 VM 已載入的 module 才可輸出。授權結果是 RVLU 主體，不含 debug sidecar、source map 或 AST，也不能還原 private service、closure 或 VM state；宿主主動輸出自己已持有的資料不在此保證內。

CLI 的 `--vm-policy compatibility|sandbox|private-service` 預設為 `Compatibility`；限制政策只接受 `-e` 或 stdin，並在開啟前拒絕腳本檔與 native manifest。C ABI 的 `rivetlua_capi_newstate_with_policy_b22(int)` 使用 `RIVETLUA_VM_POLICY_COMPATIBILITY`（0）、`RIVETLUA_VM_POLICY_SANDBOX`（1）或 `RIVETLUA_VM_POLICY_PRIVATE_SERVICE`（2）在建立 state 時固定政策。此 state policy 選擇本身不授予 C native execution；OS worker 是獨立的 RVWK/1 路徑，缺少 OS isolation evidence 時 fail closed。

P22 OS worker 的 host-side Rust API 是 unsafe `rivetlua_capi::worker::run_worker_with_policy`（[API source](../rivetlua-capi/src/worker/process.rs)）；module exports 與 worker entry 可參考 [worker module](../rivetlua-capi/src/worker/mod.rs) 和 [native worker binary](../rivetlua-capi/src/bin/rivetlua-native-worker.rs)。Host 必須明確核准 worker binary、每個 native artifact 及其 `CNoUnwind` 保證。受限政策的 worker request 共用 1,000,000 fuel，Compatibility 沿用原行為。

同 VM 的 native internal objects 只驗證 owner／generation，並計入 event／work；SDK host callbacks、對外 export 與 RPC 仍採嚴格限制。RVWK/1 的一般成功 RPC 回覆只攜帶有界 scalar／bytes，錯誤回覆帶 public code；codec 沒有獨立 correlation 欄位。輸出政策與平台條件詳見 [P22 安全政策矩陣](../../docs/SECURITY_POLICY.zh-TW.md)。

平台限制尚未經 OS 實測：Linux 僅有 root＋same-executable 模式的有限能力，Linux adapter 未 cross-compile；macOS 需要 same-Team-signed worker、App Sandbox 與實際 fork／exec denial 證據，private `sandbox_check` ABI 尚未經 OS 驗證；Windows Unsupported。native worker 未執行，因此這些內容不構成 OS 隔離或安全保證。

`Vm::get_global`／`set_global` 與 rooted table 的 `table_raw_get`／`table_raw_set` 使用 runtime 現有的驗證操作。由 lookup 得到的物件值要跨越配置或 GC 時仍須呼叫 `Vm::root`；`read_byte_string` 回傳宿主擁有的位元組複本。`Module` 上的 metadata 查詢不會改變 Lua `debug.getinfo` 的能力；Lua `S` 欄位仍遵循 runtime 目前對 official artifact 的支援範圍。

`Vm::register_callback` 接受明確的 Lua capture 值，runtime 會驗證其 VM 所屬並在登錄期間追蹤物件捕獲。回呼只能透過 `CallbackContext` 回傳、丟出錯誤、呼叫、續跑或 yield 動作；它不會取得第二個 VM 借用。

`Execution::set_fuel` 設定單次執行額度，`run` 回傳 runtime 的 `RunOutcome`。`Returned`、`LuaError`、`Aborted` 與 `PendingClose` 各自保留原有語意，不合併成單一錯誤結果。可執行的公開 API 範例位於 [`examples/embed.rs`](examples/embed.rs)。

## Runtime 與 AOT

`rivetlua-runtime` 預設使用 `std`；以 `--no-default-features` 建置時採 `no_std + alloc`，嵌入端須提供 allocator、`panic=abort`、程式入口，並確認目標支援 pointer atomics。runtime 的 `aot` feature 提供 AOT artifact 載入；SDK 的 `aot` 僅提供載入，`aot-builder` 才提供建置與載入。SDK 預設仍包含 source compiler，因此 SDK 依賴圖不能稱為 runtime-only；runtime 的 AOT normal dependency graph 不含 compiler 或 Cranelift。使用 `Module::build_aot` 建置，再由 `Vm::install_aot` 驗證及載入：

```rust
let artifact = module.build_aot(&target, proto_index, entry_pc)?;
vm.install_aot(
    &module,
    artifact.bytes(),
    &target,
    &artifact.trusted_build(),
)?;
```

載入前會核對 trusted-build digest 與完整 target／profile／module／entry identity，再映射 bytes。若以 unsafe external attestation 載入外部 artifact，必須由帶外流程保證它來自正確 builder；檔案自帶的 hash 只能核對內容，不能建立信任。macOS entitlement 不足、Linux AArch64 instruction-cache 條件不滿足，或 Windows native backend 尚不支援時，應拒絕載入或回退 interpreter；目前不宣稱已在目標平台執行 AOT native code。

xtask 的 platform matrix、resources 與 runtime-audit 可盤點 target metadata、邏輯配置資源及 normal dependency／symbol；這些資料不代表實板執行能力或實體 RAM 峰值。
