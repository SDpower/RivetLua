package = "rivetlua-example-reject-system-lua"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/reject-system-lua.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example input that links against system Lua and must be rejected",
   detailed = "This fixture deliberately requests the system lua.h and -llua.",
   license = "MIT",
}

dependencies = { "lua >= 5.4, < 5.6" }
supported_platforms = { "linux", "macosx" }

external_dependencies = {
   LUA = {
      header = "lua.h",
      library = "lua",
   },
}

-- LuaRocks 將 libraries = { "lua" } 轉為系統 -llua 連結。
build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.reject_system_lua"] = {
         sources = { "source/reject_system_lua.c" },
         incdirs = { "$(LUA_INCDIR)" },
         libdirs = { "$(LUA_LIBDIR)" },
         libraries = { "lua" },
      },
   },
}
