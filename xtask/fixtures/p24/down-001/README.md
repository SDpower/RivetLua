# DOWN-001

## 預期輸出

`lua54` 或 `lua55` profile 均讀得 `enabled=true`、`retries=3`，並由 table 內的函式回傳 `3`；程式輸出 `DOWN-001 <profile> enabled=true retries=3 call=3`。

## 限制

不合法來源必須編譯失敗；`max_work=0` 的 compile budget 必須拒絕編譯。只使用公開 `rivetlua` SDK。
