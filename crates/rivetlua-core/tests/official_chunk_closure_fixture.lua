local seed = 7
local function outer()
  local function middle()
    return function(value)
      return seed + value
    end
  end
  return middle()
end
local handle = assert(io.open(arg[1], 'wb'))
assert(handle:write(string.dump(outer(), false)))
assert(handle:close())
