local function child()
  local marker = 1
  return debug.traceback("mark")
end
local function parent()
  local trace = child()
  return trace
end
local out = parent()
return out
