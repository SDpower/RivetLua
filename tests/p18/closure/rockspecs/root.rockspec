package = "rivetlua-example-closure-root"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/package-closure-root.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example package dependency-closure root",
   detailed = "Small local fixture for runtime, build, and test dependency resolution.",
   license = "MIT",
}

dependencies = {
   "rivetlua-example-closure-left >= 1.0-1",
   "rivetlua-example-closure-right >= 1.0-1",
}
build_dependencies = {
   "rivetlua-example-closure-left >= 1.0-1",
   "rivetlua-example-closure-right >= 1.0-1",
}
test_dependencies = {
   "rivetlua-example-closure-left >= 1.0-1",
   "rivetlua-example-closure-right >= 1.0-1",
}

build = {
   type = "builtin",
   modules = {
      ["rivetlua_example.closure_root"] = "source/root.lua",
   },
}
