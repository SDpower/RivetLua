local order = 0
local function closer(n)
  return setmetatable({}, {__close = function() order = order * 10 + n end})
end

do
  local first <close> = closer(1)
  local second <close> = closer(2)
end

local function make_getter()
  local value = 5
  local function get() return value end
  do
    local guard <close> = closer(3)
    value = value + 4
  end
  return get
end

local get = make_getter()
local sum = 0
for i = 1, 3 do sum = sum + i end
local operand = setmetatable({}, {__add = function() return 7 end})
local result = operand + operand
return order, get(), sum, result, host(result, sum)
