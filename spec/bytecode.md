# Bytecode 邊界

RivetLua 使用自有 RVLU_V2 bytecode 格式。module 自帶 `format_version`，encoder 僅輸出 v2，decode/verify 明確拒絕 v1 與未知版；外部資料必須在載入前通過驗證，且不宣稱與 Lua chunk 格式相容。V2 有 20 個 typed opcode、prototype signature/vararg metadata、ClosePath、numeric-for 專用 instruction 與每條 instruction 的 canonical static effect flags；effect 不是 GC heap-edge graph，也不代表可執行 runtime。
