package = "rivetlua-example-pure"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/example-pure.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example pure Lua module for RivetLua packaging input",
   detailed = "A local fixture demonstrating a pure Lua module and installation data.",
   license = "MIT",
}

dependencies = { "lua >= 5.4, < 5.6" }
build_dependencies = { "lua >= 5.4, < 5.6" }
test_dependencies = { "busted >= 2.3.0-1" }
supported_platforms = { "linux", "macosx" }

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.pure"] = "source/example_pure.lua",
   },
   install = {
      conf = { "source/example-pure.conf" },
   },
}
