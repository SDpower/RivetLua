package = "localtest-rivetlua-example"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/localtest-rivetlua-example.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example localtest package for Moonrocks protocol fixtures",
   detailed = "A self-owned example rockspec; no upstream release or source hash is claimed.",
   license = "MIT",
}

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.pure"] = "source/example_pure.lua",
   },
}
