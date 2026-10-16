assert(_U == nil, "P17 _U must be unset")
assert(type(arg) == "table" and string.match(arg[0], "cli_native_load%.lua$"))
local profile, nonce = arg[1], arg[2]
assert(profile == "lua55-i64f64" or profile == "lua54-i64f64")
assert(type(nonce) == "string" and string.match(nonce, "^b01%-%w+%-i64f64%-%d+%-%d+$"))
local suite, suite_error = loadfile("all.lua", "t")
assert(type(suite) == "function", suite_error or "P17 suite cwd mismatch")
assert(type(package.loadlib) == "function", "P17 package.loadlib unavailable")

local loaded1, error1 = package.loadlib("libs/lib1.so", "*")
assert(loaded1 == true, error1)
local loaded2, error2 = package.loadlib("libs/lib2.so", "*")
assert(loaded2 == true, error2)
local one = assert(package.loadlib("libs/lib1.so", "onefunction"))
local first, second = one(15, 25)
assert(first == 25 and second == 15)
local another = assert(package.loadlib("libs/lib1.so", "anotherfunc"))
assert(another(10, 20) == "10%20\n")
local linked11 = assert(package.loadlib("libs/lib11.so", "luaopen_lib11"))
assert(linked11() == "exported")

package.cpath = "libs/?.so"
local lib2v2, filename2v2 = require "lib2-v2"
assert(filename2v2 == "libs/lib2-v2.so")
assert(package.loaded["lib2-v2"] == lib2v2)
assert(_G.x == "lib2-v2" and _G.y == filename2v2)
local v2, value = lib2v2.id("x")
assert(v2 == true and value == "x")
if profile == "lua55-i64f64" then
  local external = lib2v2.newstr("P17 external string lifetime")
  assert(external == "P17 external string lifetime")
  external = nil
  collectgarbage("collect")
end

local lib2 = require "lib2"
assert(package.loaded.lib2 == lib2)
assert(_G.x == "lib2" and _G.y == "libs/lib2.so")
local left, right = lib2.id("left", "right")
assert(left == "left" and right == "right")
local lib21 = require "lib21"
assert(package.loaded.lib21 == lib21)
assert(_G.x == "lib21" and _G.y == "libs/lib21.so")
assert(lib21.id("linked") == "linked")

local lib1, filename1 = require "lib1.sub"
assert(filename1 == "libs/lib1.so")
assert(package.loaded["lib1.sub"] == lib1)
assert(_G.x == "lib1.sub" and _G.y == filename1)
assert(lib1.id(45) == 45)
print("P17_NATIVE_FIVE " .. profile .. " " .. nonce .. " PASS")

package.path = "libs/?.lua;libs/?/init.lua"
local p1 = require "P1"
local xuxu = require "P1.xuxu"
assert(type(p1) == "table" and p1.AA == 10)
assert(type(xuxu) == "table" and xuxu.AA == 20)
assert(_G.AA == nil)
print("P17_NATIVE_P1 " .. profile .. " " .. nonce .. " PASS")
