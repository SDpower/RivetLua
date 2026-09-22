# 架構

RivetLua 將採純 Rust 的暫存器式 bytecode VM。正式 runtime 不連結、啟動或轉呼叫官方 Lua；官方 Lua 僅為開發與測試的參考環境。

P00 只建立 workspace 骨架，尚未實作 compiler、VM、GC 或語言語意。
