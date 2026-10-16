# P23-B03 動態工具手動工作契約

本文件只定義適用範圍與未來手動工作的證據條件，不啟動工具、CI 或驗收。`xtask/src/p23/tools.rs` 的 `job_registry()` 是工作目錄；`assess_scope()` 只判斷靜態適用性，回傳 `NOT_RUN`／`BLOCKED`，不產生 `PASS`。`xtask/fixtures/p23/tool_jobs.toml` 只含惰性的 argv 模板；其中 `VERIFIED_*`、`TASK_OWNED_*` 和 `APPROVED_*_REQUIRED` 都不是可直接執行的程式或已核准工作。目前沒有已核准的替代工作，`alternative` 均為空。實際執行前須逐段靜態驗證工具、launcher、參數、環境、設定、相依檔與後續子程序；Miri 的 `VERIFIED_NIGHTLY_CARGO` 須指向釘選 nightly 的實體 Cargo，cargo-miri、driver、sysroot 與其子程序亦須驗證，不能經未知 shim。未知或可能觸發 macOS Developer Tools 授權對話框的鏈一律不得執行。

| 手動工作 | 適用範圍 | 負例與判定條件 |
|---|---|---|
| `P23-MIRI-PURE` | Miri，僅純 Rust core/runtime | 指定 `rivetlua-core` 的 `p01_value` 與 `rivetlua-runtime` 的 `gc_controls` 單一測試；`xtask/fixtures/p23/miri_negative.rs` 須當獨立 Rust 來源執行，不建置 xtask。其故意 assert 只校準工作有執行並能回報失敗，不證明 Miri 的 UB 偵測能力。狀態 `NOT_RUN`；僅沿用來源 commit `ecf3b86c7a3774bafa2f68f57c4f4d82b0005d35` 與 `nightly-2026-09-21` 規劃，不表示工具已安裝或重新查核。 |
| `P23-ASAN-FFI`、`P23-ASAN-NATIVE` | FFI／native thin layer | `xtask/fixtures/p23/sanitizer_negative.c` 預設分支故意寫出 1 byte heap 範圍，獨立受監督 job 必須因 ASan 報告而失敗，且產品碼需同樣受 instrument。 |
| `P23-UBSAN-FFI`、`P23-UBSAN-NATIVE` | FFI／native thin layer | 同一負例以 `P23_NEGATIVE_UBSAN` 分支觸發執行期有號整數溢位，獨立 job 必須因 UBSan 報告而失敗。 |
| `P23-TSAN-SHARED` | native 共享狀態 | `xtask/fixtures/p23/race_negative.c` 中兩執行緒無同步寫入同一計數器；獨立 job 必須報 data race。這不代表所有 Rust 共享狀態已被覆蓋。 |
| `P23-JIT-INSTRUMENTED` | JIT native/generated code | guard-page、ISA、fuel、GC/deopt 與 interpreter differential 的負例與受 instrument 的 generated code 工作尚待核准；未 instrument generated code 時一律不得宣稱 JIT clean。 |
| `P23-WORKER-POLICY-DENY` | OS worker | 只規劃以 `VmPolicy::Sandbox` 做受限政策否決，並核對 native load 前的 OS isolation evidence；沒有受核准的實際 OS job，保持 `BLOCKED`，不能以模擬拒絕代替 OS 證據。 |
| `P23-FZ006-CAPI` | 外部 C API fuzz | 引用現有 `xtask/fixtures/p23/capi_sequence.c`；外部 job 的工具／啟動鏈尚未驗證，保持 `BLOCKED`。`cargo-fuzz` 0.13.2 僅為既有計畫參考版本，不表示已安裝或執行。 |

每個手動工作須記錄 profile、target、工具與 instrumented binary 的版本及雜湊、精確命令與啟動鏈、負例失敗證據、正例涵蓋範圍、退出碼、finding 與去識別 artifact。缺工具、核准、負例、可驗證啟動鏈或實際覆蓋時記 `BLOCKED`／`NOT_RUN`；`NOT_APPLICABLE` 僅能伴隨確實核准且有證據的替代工作。Miri 結果不得外推至 FFI、native、JIT 或 OS worker，sanitizer/race 負例也不構成產品路徑安全證明。

若需 suppression，逐筆必填 issue、owner、到期日與 regression case；空白批准、無期限 ignorelist 與把 skip 算成通過均不接受。所有輸入與輸出遵守 P22 去識別規則，crash artifact、日誌與 corpus 不保存私密 payload、source、address、capability 或憑證。
