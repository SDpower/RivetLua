# 安全政策與公開入口（版本 1）

本文件對照 P22 的 SEC-001～SEC-010 與 B01～B03 已實作的程式碼契約。它描述公開入口的准入規則與威脅邊界，不是安全驗收紀錄。B03 的 macOS host／共用來源已完成必要編譯，Linux 隔離 adapter 未跨平台編譯；安全測試、OS 隔離探測、gate 與 CI 驗收均未執行，不能據此宣稱平台隔離已獲實測證明。

## 威脅模型與政策

受限 guest 可能猜測 ID、呼叫 Lua／C API、構造序列化或輸出資料，並提交不可信 C 模組。政策在 VM 建立及首次配置前固定；能力由宿主明確核發，guest 不能自行建立 issuer、授權或 OS 隔離證據。宿主若已持有資料、明確授權讀取並提供任意輸出通道，或具有本機最高權限，均不在 VM 能保證隔離的範圍內（SEC-007、SEC-010）。字串編碼與格式轉換不會建立讀取或匯出權限。

| `VmPolicy` | 准入 | 拒絕 |
| --- | --- | --- |
| `Compatibility` | 使用宿主明確配置的服務；只有 explicit issuer、`ExportPolicy::OwnerModules`、本 VM 擁有且可匯出的模組，才能匯出經驗證的 RVLU 主體。 | 私有服務的 Host `Invoke` 不適用；任意 closure、執行狀態、source map、AST 或其他 VM 資源不能藉模組匯出 API 外送。 |
| `Sandbox` | 一般 Lua 執行及已配置的受額度限制輸出；不可信 native 僅能走取得真實 OS 證據的獨立 worker。 | 預設拒絕私有服務 `Invoke`、模組匯出，以及未配置的檔案／網路／native 宿主服務。 |
| `PrivateService` | 僅由可信 issuer 註冊的私有服務，可在 owner、generation、scope、期限、額度及 audience 均符合時，以授予 Host 的 `Invoke` 能力呼叫。 | 模組匯出及其他未授權公開入口；guest 不得自行取得服務 handle 或 grant。 |

上述模組匯出與私有服務互不代替：同一 VM 內受保護的 native 載入／模組初始化橋接是內部作業，不是授權 Host 匯出，也不開放 guest 的 public registry。SDK 原有的 issuer、owner、resource class 與目的地檢查仍逐項適用。主要實作位於 `crates/rivetlua-runtime/src/{policy,heap}.rs`、`crates/rivetlua/src/lib.rs`。

## 公開入口對照

| 入口 | 受限政策下的規則與實作位置 |
| --- | --- |
| SDK／Host callback | 建立 VM 時固定 `VmPolicy` 與 `HostServices`；私有呼叫檢查完整 grant，模組匯出檢查 issuer／owner／類別／目的地；受限政策的輸出先扣共用額度。`crates/rivetlua/src/lib.rs`、`crates/rivetlua-runtime/src/heap.rs`。 |
| CLI | `--vm-policy` 選擇三種政策；受限模式僅配置指定的輸出／警告服務，診斷只回公開碼與 correlation ID。`crates/rivetlua-cli/src/lib.rs`。 |
| Lua 基本函式、print、error | 可處理原本可讀的值；受限 `tostring` 不顯示 lightuserdata 位址或物件 ID；受限 `print` 需輸出 sink 並扣共用額度，對外錯誤走安全診斷。`crates/rivetlua-runtime/src/stdlib/basic.rs` 及政策／輸出接點。 |
| C API、debug、registry、upvalue | `rivetlua_capi_newstate_with_policy_b22` 在配置前固定政策；公開檔案載入、registry、debug、dump 與 upvalue 敏感操作僅 `Compatibility` 可准入。受限 native 初始化的私有橋接不解除公開限制。`crates/rivetlua-capi/src/stack.rs`。 |
| dump、serializer、模組匯出 | 受限公開 dump 拒絕；SDK 僅在 `Compatibility` 的明確授權下匯出本 VM 可匯出模組的 RVLU 主體，不附帶 debug sidecar、source map 或 AST；額度不足先拒絕。`crates/rivetlua/src/lib.rs`、`crates/rivetlua-capi/src/stack.rs`。 |
| Base64、slice、編碼、格式化、回呼 | 這些轉換不提升可讀取範圍，也不取代匯出授權；資料進入 Host 輸出／回呼時使用相同政策與輸出額度。已獲授權讀取並輸出的資料屬宿主授權風險。 |
| 不可信 native／worker RPC | 保留原 `run_worker` 的可信 `Compatibility` 行為；`run_worker_with_policy` 的受限路徑在 native request 前要求 parent／child OS 證據，缺證據回 `E_POLICY_DENIED` 並清理程序群組。RPC 僅傳有界 scalar／bytes，不傳 host VM state、private closure 或 service handle；成功回覆可含有界 scalar／bytes，失敗只回公開錯誤碼，codec 沒有獨立 correlation 欄位。`crates/rivetlua-capi/src/worker/process.rs`、`codec.rs` 與 `isolation/`。 |

受限政策的輸出使用共用 meter；預設上限為 64 KiB、1,024 個事件、深度 8、100,000 個工作單位。`Compatibility` 未明確設定額度時保留原有無上限行為。受限 worker 每個 request 的 VM fuel 上限為 1,000,000，另有 RPC 長度、deadline 與 OS 資源限制。超額時停止並回公開錯誤；OS CPU／時間限制不能代替 VM fuel。已准入後的 crash、deadline、資源或協定失敗保留其故障分類，不偽裝為政策拒絕。

## SEC 契約與限制

| 編號 | 已實作的防線或明確邊界 |
| --- | --- |
| SEC-001 | 私有服務、closure、執行狀態、source map 與 AST 不屬安全模組匯出的正向類別；不符回 `E_EXPORT_DENIED`，不產出部分 RVLU。 |
| SEC-002 | 私有服務依 owner／slot／generation／scope 與 grant 查核，拒絕對外走安全診斷；存在性相關的時間與計數等價尚未實測，不宣稱等時性。 |
| SEC-003 | 受限 C API 的公開 registry／debug／upvalue 入口受政策阻擋；私有 native 初始化橋接不暴露給 guest 或其他 VM。 |
| SEC-004 | CLI 對外使用公開錯誤碼與 correlation ID；受限 worker 的 RPC 失敗只回公開錯誤碼，避免在該邊界輸出私有路徑、位址、來源片段或值。 |
| SEC-005 | Base64／slice／格式化／table 遍歷與回呼不授予讀取或匯出權限；實際 Host 輸出仍受准入與共用額度約束，不能靠字串過濾宣稱保密。 |
| SEC-006 | 受限 print、回傳、error、callback 與 RPC 的輸出／協定邊界採 byte、event、depth 或工作量上限；超額以受控錯誤呈現，不回傳私密 payload。 |
| SEC-007 | 宿主明確授權秘密讀取及任意輸出時，外洩屬宿主授權風險；VM 不宣稱可阻止宿主主動公開資料。 |
| SEC-008 | 合法 owner 仍需 `Compatibility`、explicit issuer、`OwnerModules`、正確模組身分及輸出額度，才能匯出自己的可匯出模組；不能藉此匯出其他 VM 或私有狀態。 |
| SEC-009 | 不可信 C/native 需獨立 worker 與實際平台隔離證據；缺必要權限、probe 或限制時，native 載入前回 `E_POLICY_DENIED`。同權限程序或單一 seccomp 證據不足。 |
| SEC-010 | 惡意宿主、已持資料的宿主及本機最高權限行為不在 guest sandbox 的保證範圍；平台實際隔離尚未執行驗證。 |

## 平台隔離狀態

| 平台 | 程式碼要求與目前限制 |
| --- | --- |
| macOS arm64 | 要求宿主簽名的指定 worker、最小 App Sandbox entitlement、非 uid 0、Team／identifier／CDHash／檔案身分綁定，並在 parent 與 child 查核實際程序及 kernel deny probe；`process-fork` 與 `process-exec` 兩者都必須實際遭拒。`sandbox_check` 是私有 ABI；相容性與真實拒絕結果尚未經 OS 執行驗證。缺簽名、entitlement、probe 或可用的受限 artifact 路徑即拒絕，不自行簽名或改系統權限。 |
| Linux GNU x86-64／AArch64 | 要求 root 啟動、與宿主相同的 worker 映像身分、私有 mount／唯讀 artifact／暫存區、隔離網路與身份、capability drop、架構對應 seccomp、資源限制及 parent／child probe。獨立 worker binary 尚無身分證明契約，正向路徑未支援；缺 root／OS 能力即拒絕。artifact 在 child 再驗 digest，載入使用驗證後保留的 staged bytes。這些 OS 保證尚未實測。 |
| Windows | 現有 C API 與 worker 隔離未支援；明確拒絕，不宣稱 AppContainer／LPAC 已實作。 |

政策規則來自上述程式碼；目前僅 macOS host／共用來源有必要編譯結果，Linux 隔離 adapter 未跨平台編譯，且沒有執行安全測試、worker 或 OS 探測。版本 1 的平台敘述因此是實作要求及已知限制，不是部署安全認證。
