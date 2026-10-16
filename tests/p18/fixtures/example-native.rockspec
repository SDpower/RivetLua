package = "rivetlua-example-native"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/example-native.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example native module linked against the RivetLua SDK",
   detailed = "The external dependency names the RivetLua SDK and its public Lua C API header.",
   license = "MIT",
}

supported_platforms = { "linux", "macosx" }

external_dependencies = {
   RIVETLUA = {
      header = "lua.h",
   },
}

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.native"] = {
         sources = { "source/example_native.c" },
         defines = { "RIVETLUA_SDK=1" },
         incdirs = { "$(RIVETLUA_INCDIR)" },
      },
   },
}
