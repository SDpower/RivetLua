local function iter(a, b, ...)
  local t = {a, b, 3, 4, label = "ok", ...}
  t[1] = a
  t.label = "changed"
  local result = t[1] + t.label:len()
  if a == b then result = result + 1 else result = result - 1 end
  if a < b and b <= 10 then result = result * 2 end
  repeat result = result - 1 until result <= 0
  for i = 1, 3 do result = result + i end
  for key, value in pairs(t) do
    if type(value) == "number" then result = result + value end
  end
  local function nested() return result end
  return nested(), ...
end

return iter(2, 3, 4, 5)
