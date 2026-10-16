package = "rivetlua-example-closure-leaf"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/package-closure-leaf.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example cyclic dependency input for package closure",
   license = "MIT",
}

dependencies = { "rivetlua-example-closure-root >= 1.0-1" }

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.closure_leaf"] = "source/leaf.lua",
   },
}
