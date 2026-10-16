package = "rivetlua-example-none"
version = "1.0-1"

source = {
   url = "git+https://example.invalid/rivetlua/example-none.git",
   tag = "v1.0.0",
   dir = ".",
}

description = {
   summary = "Example package with file-only installation",
   detailed = "Installs the existing pure Lua module and configuration without a build step.",
   license = "MIT",
}

build = {
   type = "none",
   install = {
      lua = {
         ["rivetlua_example.none"] = "source/example_pure.lua",
      },
      conf = { "source/example-pure.conf" },
   },
}
