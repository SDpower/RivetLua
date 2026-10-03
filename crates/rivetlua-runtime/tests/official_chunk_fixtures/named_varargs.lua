local function probe(... args)
  local first = args[1]
  local count = args.n
  args[1] = 99
  local after = args[1]
  return first, count, after, ...
end

local a, b, c, d, e = probe(11, 22)
local f, g, h, i, j = probe(33, 44)
return a, b, c, d, e, f, g, h, i, j
