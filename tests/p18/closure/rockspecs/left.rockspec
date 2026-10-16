package = "rivetlua-example-closure-left"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/package-closure-left.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example left branch for package dependency closure",
   license = "MIT",
}

dependencies = { "rivetlua-example-closure-leaf >= 1.0-1" }

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.closure_left"] = "source/left.lua",
   },
}
