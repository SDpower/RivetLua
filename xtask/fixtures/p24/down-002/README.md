# DOWN-002

## 預期輸出

`lua54` 或 `lua55` profile 下，`compute(20, 22)` 回傳 `42`，host log 收到一次 `42`，compute side effect 僅一次；`Throw(77)` 產生 `Thrown` 錯誤與 payload `77`。程式輸出 `DOWN-002 <profile> compute=42 log=42 throw=77`。

## 限制

VM 使用明確 Sandbox policy 與 deny-all HostServices；只注入 fixture 需要的 log、compute 與 throw callbacks，不啟用其他宿主服務。
