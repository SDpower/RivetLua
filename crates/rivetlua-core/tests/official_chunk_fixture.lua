local captured = 'same-string'
local long_text = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-long'
local function child(a, ...)
  local local_text = 'same-string'
  if a then
    return captured, local_text, long_text, -47, 1.25, ...
  end
  return nil, false, true
end
return child
