# API、SemVer 與遷移指引

本頁整理目前 source 中可確認的公開介面與升級檢查方式，不構成穩定 API、完整 Lua 相容性或 release-ready 承諾。workspace 的套件版本目前是 `0.0.0`、MSRV 是 Rust `1.94.1`；不據此宣稱已發布、完成 SemVer 封存或準備好 `1.0`。

| 範圍 | 升級時檢查 | 不相符時的處置 |
| --- | --- | --- |
| Rust SDK API | `Engine`、`Module`、`Vm`、`Root`、`IntoValue`、`FromValue`、`CompileBudget`、`TransportBudget` 都是公開介面。固定套件版本與 feature 組合，使用至少 Rust `1.94.1`，並重新編譯 consumer；不要假設 `0.0.0` 提供 SemVer 相容保證。 | trait 方法、函式簽章或 enum variants 變更可能需要修改實作與 `match`。對錯誤 enum 保留 wildcard 分支，避免依賴 `Display` 文字作為機器協定。 |
| Features 與 runtime | SDK features 為 `jit`、`aot`、`aot-builder`、`native-lua54`、`native-lua55`；SDK 仍含 source compiler。`rivetlua-runtime` 預設使用 `std`，`--no-default-features` 為 `no_std + alloc`，需要宿主 allocator、`panic=abort` 與 pointer atomics。 | feature 或目標組合不同時，重新建置並核對產物功能；`no_std` 不適用於 `panic=unwind` 或不支援 pointer atomics 的目標。 |
| Lua profile 與數值 | 明確選擇 `LuaProfile::Lua54` 或 `LuaProfile::Lua55`；目前數值設定為 `RVLU_NUMERIC_I64_F64`。不要依賴 CLI 預設 profile。 | VM 與 module profile 不符時 SDK 會回報 `ProfileMismatch`。以相符 profile 重新編譯來源或重新載入可驗證的 module，不要改 header 或套件版本來代替。 |
| RVLU 與 module 傳輸 | Bytecode 版本以 P05 `VerifiedModule::format_version()` 為準，目前可驗證的語言格式是 `RVLU_V2`。SDK 保存使用的 `RVCT v1` 是外層容器；profile、numeric config、RVLU 格式各自檢查。 | 未支援版本、損壞資料或驗證失敗必須由 loader 拒絕，不交出部分 module。需遷移時從來源重新編譯，或使用明確支援該輸入的 loader；不要由 crate SemVer、C header、CLI 版本或 P14 wrapper 推定 RVLU 格式。 |
| 編譯、載入與執行錯誤 | 保留 `CompileError`、`ContainerError`、`SdkError` 等結構化錯誤分類。執行結果分別處理 `Returned`、`LuaError`、`Aborted`、`PendingClose`；輸出額度錯誤與 fuel 耗盡屬 abort。 | 不要把 abort 當成 Lua error 或成功結果。`FuelExhausted` 是終結狀態，不能靠重新執行或補 fuel 恢復；依 abort reason 停止並回報宿主。 |
| CLI | 腳本與自動化明確傳入 `--profile lua54|lua55` 及 `--vm-policy compatibility|sandbox|private-service`。`--compatibility [--gaps]` 是相容性資料查詢，不是完整 Lua 相容聲明。 | parser 拒絕不支援或衝突的選項；升級後核對 CLI 用法與退出結果，再更新呼叫端。 |
| C ABI | `rivetlua_abi_identity_v1` 比對 ABI revision、profile、numeric config、pointer width、endianness、target、header hashes 與 layout。header 固定 Lua 5.5.1 或 5.4.9、i64f64、little-endian、64-bit pointer，並只列出指定 target。 | identity 不符即拒絕；以配對的 Lua headers、RivetLua library 與 host extension 一起重建。C ABI identity 不代表 crate SemVer 或 RVLU bytecode 版本。 |
| VM policy、root 與序列化 | `Compatibility`、`Sandbox`、`PrivateService` 在建立 VM 時固定；限制政策須明確設定；`HostServices::deny_all()` 預設仍拒絕非 table／userdata 值的型別共用 metatable 存取，宿主要啟用時須分別明確授權 `DebugPermission::TypeMetatableRead` 或 `DebugPermission::TypeMetatableWrite`。`DebugPermission::TableMetatableWrite` 仍只授權 table 與一般 userdata 各自的 metatable，不授予型別共用 metatable 權限。`Root` 綁定所屬 VM 與物件世代。module 傳輸只保存已驗證 module，不保存 VM heap、closure、stack、coroutine 或宿主服務；private handle／grant 不是 Lua 值，也不可序列化。 | 權限、owner 或 generation 不符時拒絕操作。不要把 module 傳輸當成 VM checkpoint，也不要跨 VM 重用 root、private handle 或 grant。 |
| Native／AOT artifact 與平台 | Native artifact 有自己的 backend/code 身分；AOT manifest 另列 schema、RVLU/profile/numeric、target、backend/code、runtime/compiler version 與 build provenance。artifact 身分須由 producer 證據支持；未知或空白欄位保持未知。 | 身分、provenance 或 target 不符時拒絕載入；重建並重新核對 producer 證據。不得從 crate、header、CLI 版本或 artifact digest 單獨推定相容性。 |

C ABI identity v1 的 frozen header set 僅含 `lua.h`、`lauxlib.h`、`luaconf.h`；新增的公開 `lualib.h` 由 SDK 產物檔案雜湊覆蓋，不屬於該三份 header hash。

## 已知能力邊界

- Lua 5.5 的 `luaL_openselectedlibs` 與兩版標準庫 opener 已實作；Lua 5.4 與 Lua 5.5 兩個 profile 的 C 功能測試皆已通過（詳見[檢查結果](LUA_IMPLEMENTATION_CHECK.csv)及[實作計畫](LUA_IMPLEMENTATION_CHECK_PLAN.zh-TW.md)）；不得宣稱完整 Lua 5.4／5.5 相容。
- P20 的 native executed 數為 0；沒有 JIT 加速證據。
- P21 desktop 為 `Experimental`、Thumb 為 `BuildOnly`、RV32 為 `Unsupported`；沒有 `Supported` target 或已驗證實板、RAM、RSS 證據。
- P22 worker 尚未執行，Linux adapter 尚未 cross-compile，OS 隔離尚未實測；Windows 為 `Unsupported`。

版本判斷須分開處理：crate SemVer、Lua profile/numeric config、P05 `VerifiedModule.format_version()`、C ABI identity，以及 native artifact/platform identity 是不同契約。任何一項都不能替其他項背書。
