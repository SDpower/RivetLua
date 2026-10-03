local function one(a, ...)
  return a, ...
end

local function child(a, b, ...)
  local c, d = ...
  return a, b, c, d, marker
end

local function tail(a, b, ...)
  return child(a, b, ...)
end

local first, second = one(nil, 5)
local a, b, c, d, m = tail(3, nil, 7, 8)
return first, second, a, b, c, d, m
