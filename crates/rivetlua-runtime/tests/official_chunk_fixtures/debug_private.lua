local function inspect(... args)
  local first = args[1]
  local local_ok, local_error = pcall(debug.getlocal, 1, 1)
  local setlocal_ok, setlocal_error = pcall(debug.setlocal, 1, 1, 99)
  local upvalue_ok, upvalue_error = pcall(debug.getupvalue, inspect, 1)
  local setupvalue_ok, setupvalue_error = pcall(debug.setupvalue, inspect, 1, 99)
  local upvalueid_ok, upvalueid_error = pcall(debug.upvalueid, inspect, 1)
  local upvaluejoin_ok, upvaluejoin_error = pcall(debug.upvaluejoin, inspect, 1, inspect, 1)
  return first, local_ok, local_error, setlocal_ok, setlocal_error,
    upvalue_ok, upvalue_error, setupvalue_ok, setupvalue_error,
    upvalueid_ok, upvalueid_error, upvaluejoin_ok, upvaluejoin_error
end

return inspect(11)
