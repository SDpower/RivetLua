local x = 11
local function make(a)
  return function(b)
    return x + a + b
  end
end
local f = make(2)
local info = debug.getinfo(f, "Suf")
local n1, v1 = debug.getupvalue(f, 1)
local n2, v2 = debug.getupvalue(f, 2)
local trace = debug.traceback("mark")
return info.source, info.linedefined, info.lastlinedefined, info.nups,
  info.nparams, info.isvararg, n1, v1, n2, v2, trace, info.func == f
