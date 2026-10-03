local function f() end
local info = debug.getinfo(f, "S")
return info.source, info.short_src
