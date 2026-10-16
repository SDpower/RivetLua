assert(_U == nil, "P17 _U 必須未設定")

local profile
if _VERSION == "Lua 5.5" then
  profile = "lua55-i64f64"
elseif _VERSION == "Lua 5.4" then
  profile = "lua54-i64f64"
else
  error("P17 未支援的 Lua profile：" .. tostring(_VERSION), 0)
end

assert(type(os) == "table", "P17 os table 不存在")
assert(type(os.tmpname) == "function", "P17 os.tmpname 不存在")
assert(type(os.time) == "function", "P17 os.time 不存在")
assert(type(os.execute) == "function", "P17 os.execute 不存在")
assert(type(os.difftime) == "function", "P17 os.difftime 不存在")
assert(type(package) == "table" and type(package.loadlib) == "function",
  "P17 package.loadlib 不存在")

local function check_os_denial(name, operation)
  local ok, diagnostic = pcall(operation)
  assert(not ok, "P17 os." .. name .. " 在逐操作 policy 下未拒絕")
  assert(type(diagnostic) == "string" and
    string.find(diagnostic, "E_HOST_POLICY_OS", 1, true) ~= nil,
    "P17 os." .. name .. " 未回報 E_HOST_POLICY_OS")
  return "E_HOST_POLICY_OS"
end

local tmpname_category = check_os_denial("tmpname", os.tmpname)
local time_ok, time_value = pcall(os.time)
assert(time_ok, "P17 os.time 在逐操作 policy 下應允許")
assert(type(time_value) == "number", "P17 os.time 必須回傳 number")
local time_result_type = type(time_value)
local execute_category = check_os_denial("execute", os.execute)
assert(os.difftime(42, 2) == 40, "P17 os.difftime 純計算結果錯誤")

local opener, native_diagnostic, native_when =
  package.loadlib("libs/lib1.so", "luaopen_lib1_sub")
assert(opener == nil, "P17 無 grant 時 package.loadlib 不得回傳 opener")
assert(type(native_diagnostic) == "string" and #native_diagnostic > 0,
  "P17 package.loadlib 缺少 native-grant 診斷")
assert(string.find(native_diagnostic, "native-grant", 1, true) ~= nil,
  "P17 package.loadlib 診斷缺少 native-grant 類別")
local native_category = string.match(native_diagnostic, "native%-grant: preflight")
assert(native_category ~= nil,
  "P17 package.loadlib 診斷缺少 preflight 類別")
assert(native_when == "open", "P17 package.loadlib 必須在 open 階段拒絕")

local function json_string(value)
  return '"' .. string.gsub(value, '[%z\1-\31\\"]', function(char)
    if char == "\\" then return "\\\\" end
    if char == '"' then return '\\"' end
    return string.format("\\u%04x", string.byte(char))
  end) .. '"'
end

print("P17_B03_CASE {\"case_id\":\"p17_platform_cli\",\"profile\":" ..
  json_string(profile) ..
  ",\"seed\":0,\"iterations\":1,\"outcome\":\"PASS\",\"capabilities\":{\"os_tmpname\":\"denied\",\"os_tmpname_error\":" ..
  json_string(tmpname_category) ..
  ",\"os_time\":\"available\",\"os_time_result_type\":" .. json_string(time_result_type) ..
  ",\"os_execute\":\"denied\",\"os_execute_error\":" ..
  json_string(execute_category) ..
  ",\"os_difftime\":\"available\",\"package_loadlib\":\"denied\",\"package_loadlib_error\":" ..
  json_string(native_category) .. ",\"package_loadlib_when\":" ..
  json_string(native_when) .. "}}")
