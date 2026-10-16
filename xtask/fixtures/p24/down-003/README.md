# DOWN-003：公開 CLI consumer

- 狀態：SOURCE fixture；尚未建置或執行。
- 套件只透過 p24-stage registry 依賴 rivetlua-cli，入口呼叫公開的 `rivetlua_standalone_main()`。
- 執行時將 `fixtures/hello.lua` 指定為輸入；預期 stdout 為 `p24-down-003` 後接一個換行、stderr 為空、exit code 為 0。
- 此 consumer 不安裝、呼叫或覆寫系統 Lua。
- 尚未執行 registry、clean-consumer、建置、CLI 或驗收檢查；此目錄不含封存產物或驗收紀錄。
