local function probe(... args)
  args.n = 1
  local first, second = ...
  return first, second
end

return probe(7, 8)
