local function receiver(... args)
  coroutine.yield(1)
  local table_value = args[1]
  local text_value = args[2]
  local function_value = args[3]
  return table_value, args[1], table_value[1], text_value, function_value()
end

local function producer()
  local table_value = {41}
  local text_value = "edge"
  local function_value = function() return 43 end
  return receiver(table_value, text_value, function_value)
end

local co = coroutine.create(producer)
local first_ok, parked = coroutine.resume(co)
for _ = 1, 10 do
  local pressure = {}
end
local second_ok, table_value, same_table, number_value, text_value, function_value = coroutine.resume(co)
return first_ok, parked, second_ok, table_value, same_table, number_value, text_value, function_value
