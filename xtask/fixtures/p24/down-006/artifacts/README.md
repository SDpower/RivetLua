# DOWN-006 外部 artifact 輸入契約

本 SOURCE fixture 不含 headers 或 library binary。stage 封存 artifact 須提供：

- include/rivetlua/lua54/{lua.h,lauxlib.h,luaconf.h} 或 include/rivetlua/lua55/{lua.h,lauxlib.h,luaconf.h}
- include/rivetlua/rivetlua_abi.h
- lib/librivetlua_capi.a

headers 應來自專案 canonical `include/rivetlua/` 同版封存內容；CAPI static library 應來自 p24-stage 封存 crate artifact，並與選用的 Lua profile 相符。不得以母 repo include 路徑、workspace/path dependency 或未封存 binary 代替。
