local function inspect(... args)
  return args[1]
end

local name, value = debug.getupvalue(inspect, 1)
return name == nil, value == nil
