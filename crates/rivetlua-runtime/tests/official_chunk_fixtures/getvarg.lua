local function read(... args)
  return args[1], args.n, args[1.0], args["1"], args[2]
end

local a, b, c, d, e = read(5, 6)
local f, g, h, i, j = read(7)
return a, b, c, d, e, f, g, h, i, j
