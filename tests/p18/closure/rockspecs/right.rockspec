package = "rivetlua-example-closure-right"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/package-closure-right.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example right branch for package dependency closure",
   license = "MIT",
}

dependencies = { "rivetlua-example-closure-leaf >= 1.0-1" }

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.closure_right"] = "source/right.lua",
   },
}
