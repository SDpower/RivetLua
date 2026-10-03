# SDK 模組傳輸容器

`Engine::save_module` 與 `Engine::load_module` 以 RVCT v1 封裝、還原已通過 P05 驗證的 immutable `Module`。`Module::clone` 只共享 `Arc<VerifiedModule>` 和不可變 metadata；globals、package loaded/preload registry、heap、coroutine 與 host services 均屬各自的 `Vm`。宿主可重用 `TransportBudget`，每次操作會建立新的 work budget，並以配置帳本暫時 escrow 峰值上界；成功或失敗都會釋放 escrow。回傳的 `Vec<u8>` 由宿主持有，帳本不把它當成跨操作累積的 resident allocation。

`Engine::compile_named`／`compile_named_with_budget` 共用 compiler 的同一條 `compile_with_budget` pipeline；後者接受可重用 `CompileBudget`，由 `CompileBudgetLimits` 限制每次編譯的 work 與 peak allocation，配置採 768 MiB 預設上限。每次呼叫重新計量，結束時釋放暫時 escrow；`allocation_snapshot`、`allocation_trace` 與 `fail_once_at_ordinal` 可供宿主觀察和驗證清理。`Engine` 也明確實作 runtime `HostLoadCompiler`：必須把 `engine.clone()` 傳入 `LoadCapability::and_compiler` 才能啟用 Lua `load()` 編譯，`new_vm()` 預設仍是 deny-all。SDK 不建立第二條 parser pipeline，也不把 compiler 直接產出的未驗證資料包成 `Module`。

`Engine::load_binary_module(bytes, &TransportBudget)` 由 Core `classify_input` 區分裸 RVLU、官方 chunk、source 與不支援的 binary。SDK 只負責既有 RVCT magic 的外層分流；其餘格式分類、scan、preflight、decode、verify 與 official translation 交回 Core。每次 decode 先支付 input scan work，再支付 preflight 的 work／temporary／retained 上界；裸 RVLU 經 P05 私有 none sidecar 驗證，不會推測 native debug 或 private plan。`Vm::load_module_with_args` 可把宿主值傳給 root chunk，舊 `load_module` 等價於空參數；參數依 VM 身分、root 與 GC 生命週期規則驗證。

相同 `Module`、clone 或 RVCT 還原結果載入不同 VM，只重建相同 module 定義，不會共用 VM-local 執行狀態。宿主若明確把同一外部 provider 傳給多個 VM，該 provider 自己管理的狀態可以共享；`Module` 本身不攜帶或傳播 host service 的授權或 execution state。

```rust,no_run
use rivetlua::{ContainerLimits, Engine, LuaProfile, TransportBudget};

let engine = Engine::new(LuaProfile::Lua55);
let budget = TransportBudget::new(ContainerLimits::default());
let module = engine.compile_named(b"return 42", b"example.lua")?;
let bytes = engine.save_module(&module, &budget)?;
let restored = engine.load_module(&bytes, &budget)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

RVCT 固定 40-byte little-endian header：`0..4` 為 `RVCT` magic，`4..6` 為 version 1，`6..8` 為零 flags，`8..16` 為含 header 的 total length，`16..24` 為 RVLU 長度，`24..32` 為 sidecar 長度，`32..36` 為 CRC32，`36..40` 為零 reserved 欄位。其後依序放入 RVLU 和 sidecar 的 opaque bytes。CRC32 使用 RFC 1952 §8 的 reflected CRC-32，涵蓋 header `[0..32]`、reserved 欄位及完整 payload，略過 CRC 欄位本身；CRC 只檢查傳輸完整性，不建立 payload 信任。

Load 先驗證 RVCT 自身的 magic、版本、flags、reserved、checked lengths、輸入長度與 policy，再預付並掃描 checksum。只有 checksum 正確後，SDK 才對 borrowed payload 執行 P05 scan／preflight、配置 escrow，並呼叫 P05 transport decoder。SDK 不剖析 RVLU_V2 的欄位或 opcode，也不解析 RVAS sidecar；最終 `Module` 只由 P05 decoder 提供的 `VerifiedModule` 建立。profile 不符或 payload 結構錯誤由 P05 拒絕。

`ContainerLimits` 提供容器總 bytes、單次峰值配置、總 work 與 P05 `TransportLimits`。`TransportBudget` 的 `allocation_snapshot` 和 `allocation_trace` 可供宿主觀察／測試帳本；`fail_once_at_ordinal` 可注入一次配置失敗，確認 reservation 回滾後可重試。超限與額度不足在配置或讀取 payload 前拒絕；完整輸入的外層錯誤與 checksum 失敗不進入帳本。由於 peak escrow 是保守上界，靠近限制時可能拒絕實際容量較小的操作。

錯誤以 `ContainerError` 回傳，類別包含格式、版本、完整性、限額、配置與 P05 payload 驗證錯誤。失敗不交出部分 bytes 或 `Module`，也不改變既有 VM。容器只攜帶 module／immutable artifact metadata；closure capture、heap、stack、coroutine、root、callback 和其他 host resource 不屬於可保存狀態。即使同一 module 同時載入多個 VM，重新載入只重建 module 定義，不會還原執行中的 closure、已 yield coroutine 或 VM-local registry entry。

P14 正式 `SDK-008` 以改壞 RVLU_V2 prototype 記錄長度驗證 section 不能跨越父 section 或侵入相鄰 section；P05 的 RVLU_V2 使用逐段 length-prefix，沒有 offset directory。負向案例另改壞 opcode，要求 P05 提供結構化 `payload_kind` 與 byte offset；RVCT 本身只回報外層分類，不解析 payload。配置注入失敗後同一 budget 可重試，帳本不保留已撤銷的 reservation。
