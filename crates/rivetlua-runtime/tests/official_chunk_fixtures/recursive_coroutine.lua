local function recurse(n, ... args)
  if n == 0 then
    return args[1], args[2]
  end
  return recurse(n - 1, args[1] + 1, args[2] + 2)
end

local co = coroutine.create(function(... args)
  local before = args[1]
  coroutine.yield(before, args[1])
  args[1] = 99
  return before, args[1], ...
end)

local ok, a, b = coroutine.resume(co, 11, 22)
local ok2, c, d, e = coroutine.resume(co)
local x, y = recurse(3, 1, 2)
return ok, a, b, ok2, c, d, e, x, y
