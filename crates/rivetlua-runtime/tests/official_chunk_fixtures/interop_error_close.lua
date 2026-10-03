local order = 0
local function closer(n)
  return setmetatable({}, {__close = function(_, err)
    order = order * 10 + n
    order = order + host(n, err ~= nil)
  end})
end

local ok = pcall(function()
  local first <close> = closer(1)
  local second <close> = closer(2)
  error("boom")
end)
return ok, order
