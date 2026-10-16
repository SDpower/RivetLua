package = "rivetlua-example-closure-leaf"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/package-closure-leaf.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example shared leaf for package dependency closure",
   license = "MIT",
}

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.closure_leaf"] = "source/leaf.lua",
   },
}
