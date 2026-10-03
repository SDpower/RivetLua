local t = {11, 22, 33}
local function spread(...)
  local x = {44, ...}
  return x[1], x[2], x[3]
end
local a, b, c = spread(55, 66)
local empty = {}
return t[2], a, b, c, #empty, t[1], t[3]
