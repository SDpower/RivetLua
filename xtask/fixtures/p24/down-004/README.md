# DOWN-004

## 預期輸出

兩個同 profile VM 各自保留 tenant global、table state、callback handle 與 output：A 為 `11/4/101`，B 為 `22/9/202`；兩個 output sink 分別只收到 `11\n` 與 `22\n`。foreign Root 由公開 API 拒絕。程式輸出 `DOWN-004 <profile> A=11/4/101 B=22/9/202`。

## 限制

只使用公開 SOURCE 與 VM-local roots/callbacks；兩 VM 採 Sandbox policy 及 deny-all HostServices，各自只注入獨立 output sink。不傳遞跨 VM payload。
