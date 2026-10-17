use rivetlua_compiler::{
    CompileLimits, IrLimits, LanguageProfile, emit_with_native_debug, lex, lower, parse, resolve,
    translate_official_chunk,
};
use rivetlua_core::bytecode::official_export::OfficialExportErrorKind;
use rivetlua_core::bytecode::official_export::emit_official_chunk;
use rivetlua_core::{
    LuaProfile, OfficialChunk, OfficialChunkLimits, OfficialConstant, OfficialDebug,
    OfficialPrototype, OfficialRvluPc, OfficialWorkBudget, ProtoId, Value, VerifiedModule,
    VerifyLimits, decode_official_chunk,
};
use rivetlua_runtime::{DebugCapability, DebugPermission, HostServices, RootKind, RunOutcome, Vm};

// 以下片段逐位元組取自 Lua 官方 5.4.9 與 5.5.1 測試集的 testes/db.lua。
// 5.4.9 的版權聲明見同套測試的 all.lua；5.5.1 見 lua.h：
// https://www.lua.org/source/5.5/lua.h.html
// Copyright (C) 1994-2025 Lua.org, PUC-Rio. (Lua 5.4.9)
// Copyright (C) 1994-2026 Lua.org, PUC-Rio. (Lua 5.5.1)
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
// SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
const DB54_PREFIX_AND_CAPTURES: &[u8] = br##"-- $Id: testes/db.lua $
-- See Copyright Notice in file all.lua

-- testing debug library

local debug = require "debug"

local function dostring(s) return assert(load(s))() end

print"testing debug library and debug information"

do
local a=1
end

assert(not debug.gethook())

local testline = 19         -- line where 'test' is defined
local function test (s, l, p)     -- this must be line 19
  collectgarbage()   -- avoid gc during trace
  local function f (event, line)
    assert(event == 'line')
    local l = table.remove(l, 1)
    if p then print(l, line) end
    assert(l == line, "wrong trace!!")
  end
  debug.sethook(f,"l"); load(s)(); debug.sethook()
  assert(#l == 0)
end


do
  assert(not pcall(debug.getinfo, print, "X"))   -- invalid option
  assert(not pcall(debug.getinfo, 0, ">"))   -- invalid option
  assert(not debug.getinfo(1000))   -- out of range level
  assert(not debug.getinfo(-1))     -- out of range level
  local a = debug.getinfo(print)
  assert(a.what == "C" and a.short_src == "[C]")
  a = debug.getinfo(print, "L")
  assert(a.activelines == nil)
  local b = debug.getinfo(test, "SfL")
  assert(b.name == nil and b.what == "Lua" and b.linedefined == testline and
         b.lastlinedefined == b.linedefined + 10 and
         b.func == test and not string.find(b.short_src, "%["))
  assert(b.activelines[b.linedefined + 1] and
         b.activelines[b.lastlinedefined])
  assert(not b.activelines[b.linedefined] and
         not b.activelines[b.lastlinedefined + 1])
end


--  bug in 5.4.4-5.4.6: activelines in vararg functions
--  without debug information
do
  local func = load(string.dump(load("print(10)"), true))
  local actl = debug.getinfo(func, "L").activelines
  assert(#actl == 0)   -- no line info
end


-- test file and string names truncation
local a = "function f () end"
local function dostring (s, x) return load(s, x)() end
dostring(a)
assert(debug.getinfo(f).short_src == string.format('[string "%s"]', a))
dostring(a..string.format("; %s\n=1", string.rep('p', 400)))
assert(string.find(debug.getinfo(f).short_src, '^%[string [^\n]*%.%.%."%]$'))
dostring(a..string.format("; %s=1", string.rep('p', 400)))
assert(string.find(debug.getinfo(f).short_src, '^%[string [^\n]*%.%.%."%]$'))
dostring("\n"..a)
assert(debug.getinfo(f).short_src == '[string "..."]')
dostring(a, "")
assert(debug.getinfo(f).short_src == '[string ""]')
dostring(a, "@xuxu")
assert(debug.getinfo(f).short_src == "xuxu")
dostring(a, "@"..string.rep('p', 1000)..'t')
assert(string.find(debug.getinfo(f).short_src, "^%.%.%.p*t$"))
dostring(a, "=xuxu")
assert(debug.getinfo(f).short_src == "xuxu")
dostring(a, string.format("=%s", string.rep('x', 500)))
assert(string.find(debug.getinfo(f).short_src, "^x*$"))
dostring(a, "=")
assert(debug.getinfo(f).short_src == "")
_G.a = nil; _G.f = nil;
_G[string.rep("p", 400)] = nil


repeat
  local g = {x = function ()
    local a = debug.getinfo(2)
    assert(a.name == 'f' and a.namewhat == 'local')
    a = debug.getinfo(1)
    assert(a.name == 'x' and a.namewhat == 'field')
    return 'xixi'
  end}
  local f = function () return 1+1 and (not 1 or g.x()) end
  assert(f() == 'xixi')
  g = debug.getinfo(f)
  assert(g.what == "Lua" and g.func == f and g.namewhat == "" and not g.name)

  function f (x, name)   -- local!
    name = name or 'f'
    local a = debug.getinfo(1)
    assert(a.name == name and a.namewhat == 'local')
    return x
  end

  -- breaks in different conditions
  if 3>4 then break end; f()
  if 3<4 then a=1 else break end; f()
  while 1 do local x=10; break end; f()
  local b = 1
  if 3>4 then return math.sin(1) end; f()
  a = 3<4; f()
  a = 3<4 or 1; f()
  repeat local x=20; if 4>3 then f() else break end; f() until 1
  g = {}
  f(g).x = f(2) and f(10)+f(9)
  assert(g.x == f(19))
  function g(x) if not x then return 3 end return (x('a', 'x')) end
  assert(g(f) == 'a')
until 1

test([[if
math.sin(1)
then
  a=1
else
  a=2
end
]], {2,3,4,7})


test([[
local function foo()
end
foo()
A = 1
A = 2
A = 3
]], {2, 3, 2, 4, 5, 6})
_G.A = nil


test([[--
if nil then
  a=1
else
  a=2
end
]], {2,5,6})

test([[a=1
repeat
  a=a+1
until a==3
]], {1,3,4,3,4})

test([[ do
  return
end
]], {2})

test([[local a
a=1
while a<=3 do
  a=a+1
end
]], {1,2,3,4,3,4,3,4,3,5})

test([[while math.sin(1) do
  if math.sin(1)
  then break
  end
end
a=1]], {1,2,3,6})

test([[for i=1,3 do
  a=i
end
]], {1,2,1,2,1,2,1,3})

test([[for i,v in pairs{'a','b'} do
  a=tostring(i) .. v
end
]], {1,2,1,2,1,3})

test([[for i=1,4 do a=1 end]], {1,1,1,1})

_G.a = nil


do   -- testing line info/trace with large gaps in source

  local a = {1, 2, 3, 10, 124, 125, 126, 127, 128, 129, 130,
             255, 256, 257, 500, 1000}
  local s = [[
     local b = {10}
     a = b[1] X + Y b[1]
     b = 4
  ]]
  for _, i in ipairs(a) do
    local subs = {X = string.rep("\n", i)}
    for _, j in ipairs(a) do
      subs.Y = string.rep("\n", j)
      local s = string.gsub(s, "[XY]", subs)
      test(s, {1, 2 + i, 2 + i + j, 2 + i, 2 + i + j, 3 + i + j})
    end
  end
end
_G.a = nil


do   -- testing active lines
  local function checkactivelines (f, lines)
    local t = debug.getinfo(f, "SL")
    for _, l in pairs(lines) do
      l = l + t.linedefined
      assert(t.activelines[l])
      t.activelines[l] = undef
    end
    assert(next(t.activelines) == nil)   -- no extra lines
  end

  checkactivelines(function (...)   -- vararg function
    -- 1st line is empty
    -- 2nd line is empty
    -- 3th line is empty
    local a = 20
    -- 5th line is empty
    local b = 30
    -- 7th line is empty
  end, {4, 6, 8})

  checkactivelines(function (a)
    -- 1st line is empty
    -- 2nd line is empty
    local a = 20
    local b = 30
    -- 5th line is empty
  end, {3, 4, 6})

  checkactivelines(function (a, b, ...) end, {0})

  checkactivelines(function (a, b)
  end, {1})

  for _, n in pairs{0, 1, 2, 10, 50, 100, 1000, 10000} do
    checkactivelines(
      load(string.format("%s return 1", string.rep("\n", n))),
      {n + 1})
  end

end

print'+'

-- invalid levels in [gs]etlocal
assert(not pcall(debug.getlocal, 20, 1))
assert(not pcall(debug.setlocal, -1, 1, 10))


-- parameter names
local function foo (a,b,...) local d, e end
local co = coroutine.create(foo)

assert(debug.getlocal(foo, 1) == 'a')
assert(debug.getlocal(foo, 2) == 'b')
assert(not debug.getlocal(foo, 3))
assert(debug.getlocal(co, foo, 1) == 'a')
assert(debug.getlocal(co, foo, 2) == 'b')
assert(not debug.getlocal(co, foo, 3))

assert(not debug.getlocal(print, 1))


local function foo () return (debug.getlocal(1, -1)) end
assert(not foo(10))


-- varargs
local function foo (a, ...)
  local t = table.pack(...)
  for i = 1, t.n do
    local n, v = debug.getlocal(1, -i)
    assert(n == "(vararg)" and v == t[i])
  end
  assert(not debug.getlocal(1, -(t.n + 1)))
  assert(not debug.setlocal(1, -(t.n + 1), 30))
  if t.n > 0 then
    (function (x)
      assert(debug.setlocal(2, -1, x) == "(vararg)")
      assert(debug.setlocal(2, -t.n, x) == "(vararg)")
     end)(430)
     assert(... == 430)
  end
end

foo()
foo(print)
foo(200, 3, 4)
local a = {}
for i = 1, (_soft and 100 or 1000) do a[i] = i end
foo(table.unpack(a))



do   -- test hook presence in debug info
  assert(not debug.gethook())
  local count = 0
  local function f ()
    assert(debug.getinfo(1).namewhat == "hook")
    local sndline = string.match(debug.traceback(), "\n(.-)\n")
    assert(string.find(sndline, "hook"))
    count = count + 1
  end
  debug.sethook(f, "l")
  local a = 0
  _ENV.a = a
  a = 1
  debug.sethook()
  assert(count == 4)
end
_ENV.a = nil


-- hook table has weak keys
assert(getmetatable(debug.getregistry()._HOOKKEY).__mode == 'k')


a = {}; local L = nil
local glob = 1
local oldglob = glob
debug.sethook(function (e,l)
  collectgarbage()   -- force GC during a hook
  local f, m, c = debug.gethook()
  assert(m == 'crl' and c == 0)
  if e == "line" then
    if glob ~= oldglob then
      L = l-1   -- get the first line where "glob" has changed
      oldglob = glob
    end
  elseif e == "call" then
      local f = debug.getinfo(2, "f").func
      a[f] = 1
  else assert(e == "return")
  end
end, "crl")


function f(a,b)
  collectgarbage()
  local _, x = debug.getlocal(1, 1)
  local _, y = debug.getlocal(1, 2)
  assert(x == a and y == b)
  assert(debug.setlocal(2, 3, "pera") == "AA".."AA")
  assert(debug.setlocal(2, 4, "manga") == "B")
  x = debug.getinfo(2)
  assert(x.func == g and x.what == "Lua" and x.name == 'g' and
         x.nups == 2 and string.find(x.source, "^@.*db%.lua$"))
  glob = glob+1
  assert(debug.getinfo(1, "l").currentline == L+1)
  assert(debug.getinfo(1, "l").currentline == L+2)
end

function foo()
  glob = glob+1
  assert(debug.getinfo(1, "l").currentline == L+1)
end; foo()  -- set L
-- check line counting inside strings and empty lines

local _ = 'alo\
alo' .. [[

]]
--[[
]]
assert(debug.getinfo(1, "l").currentline == L+11)  -- check count of lines


function g (...)
  local arg = {...}
  do local a,b,c; a=math.sin(40); end
  local feijao
  local AAAA,B = "xuxu", "abacate"
  f(AAAA,B)
  assert(AAAA == "pera" and B == "manga")
  do
     local B = 13
     local x,y = debug.getlocal(1,5)
     assert(x == 'B' and y == 13)
  end
end

g()


assert(a[f] and a[g] and a[assert] and a[debug.getlocal] and not a[print])


-- tests for manipulating non-registered locals (C and Lua temporaries)

local n, v = debug.getlocal(0, 1)
assert(v == 0 and n == "(C temporary)")
local n, v = debug.getlocal(0, 2)
assert(v == 2 and n == "(C temporary)")
assert(not debug.getlocal(0, 3))
assert(not debug.getlocal(0, 0))

function f()
  assert(select(2, debug.getlocal(2,3)) == 1)
  assert(not debug.getlocal(2,4))
  debug.setlocal(2, 3, 10)
  return 20
end

function g(a,b) return (a+1) + f() end

assert(g(0,0) == 30)
 
_G.f, _G.g = nil

debug.sethook(nil);
assert(not debug.gethook())


-- minimal tests for setuservalue/getuservalue
do
  assert(not debug.setuservalue(io.stdin, 10))
  local a, b = debug.getuservalue(io.stdin, 10)
  assert(a == nil and not b)
end

-- testing iteraction between multiple values x hooks
do
  local function f(...) return 3, ... end
  local count = 0
  local a = {}
  for i = 1, 100 do a[i] = i end
  debug.sethook(function () count = count + 1 end, "", 1)
  local t = {table.unpack(a)}
  assert(#t == 100)
  t = {table.unpack(a, 1, 3)}
  assert(#t == 3)
  t = {f(table.unpack(a, 1, 30))}
  assert(#t == 31)
end


-- testing access to function arguments

local function collectlocals (level)
  local tab = {}
  for i = 1, math.huge do
    local n, v = debug.getlocal(level + 1, i)
    if not (n and string.find(n, "^[a-zA-Z0-9_]+$")) then
       break   -- consider only real variables
    end
    tab[n] = v
  end
  return tab
end


local X = nil
a = {}
function a:f (a, b, ...) local arg = {...}; local c = 13 end
debug.sethook(function (e)
  assert(e == "call")
  dostring("XX = 12")  -- test dostring inside hooks
  -- testing errors inside hooks
  assert(not pcall(load("a='joao'+1")))
  debug.sethook(function (e, l) 
    assert(debug.getinfo(2, "l").currentline == l)
    local f,m,c = debug.gethook()
    assert(e == "line")
    assert(m == 'l' and c == 0)
    debug.sethook(nil)  -- hook is called only once
    assert(not X)       -- check that
    X = collectlocals(2)
  end, "l")
end, "c")

a:f(1,2,3,4,5)
assert(X.self == a and X.a == 1   and X.b == 2 and X.c == nil)
assert(XX == 12)
assert(not debug.gethook())
_G.XX = nil


-- testing access to local variables in return hook (bug in 5.2)
do
  local X = false

  local function foo (a, b, ...)
    do local x,y,z end
    local c, d = 10, 20
    return
  end

  local function aux ()
    if debug.getinfo(2).name == "foo" then
      X = true   -- to signal that it found 'foo'
      local tab = {a = 100, b = 200, c = 10, d = 20}
      for n, v in pairs(collectlocals(2)) do
        assert(tab[n] == v)
        tab[n] = undef
      end
      assert(next(tab) == nil)    -- 'tab' must be empty
    end
  end

  debug.sethook(aux, "r"); foo(100, 200); debug.sethook()
  assert(X)

end


local function eqseq (t1, t2)
  assert(#t1 == #t2)
  for i = 1, #t1 do
    assert(t1[i] == t2[i])
  end
end


do  print("testing inspection of parameters/returned values")
  local on = false
  local inp, out

  local function hook (event)
    if not on then return end
    local ar = debug.getinfo(2, "ruS")
    local t = {}
    for i = ar.ftransfer, ar.ftransfer + ar.ntransfer - 1 do
      local _, v = debug.getlocal(2, i)
      t[#t + 1] = v 
    end
    if event == "return" then
      out = t
    else
      inp = t
    end
  end

  debug.sethook(hook, "cr")

  on = true; math.sin(3); on = false
  eqseq(inp, {3}); eqseq(out, {math.sin(3)})

  on = true; select(2, 10, 20, 30, 40); on = false
  eqseq(inp, {2, 10, 20, 30, 40}); eqseq(out, {20, 30, 40})

  local function foo (a, ...) return ... end
  local function foo1 () on = not on; return foo(20, 10, 0) end
  foo1(); on = false
  eqseq(inp, {20}); eqseq(out, {10, 0})

  debug.sethook()
end



-- testing upvalue access
local function getupvalues (f)
  local t = {}
  local i = 1
  while true do
    local name, value = debug.getupvalue(f, i)
    if not name then break end
    assert(not t[name])
    t[name] = value
    i = i + 1
  end
  return t
end

local a,b,c = 1,2,3
local function foo1 (a) b = a; return c end
local function foo2 (x) a = x; return c+b end
"##;

const DB55_PREFIX_AND_CAPTURES: &[u8] = br##"-- $Id: testes/db.lua $
-- See Copyright Notice in file lua.h

-- testing debug library

local debug = require "debug"

local function dostring(s) return assert(load(s))() end

print"testing debug library and debug information"

do
local a=1
end

assert(not debug.gethook())

local testline = 19         -- line where 'test' is defined
local function test (s, l, p)     -- this must be line 19
  collectgarbage()   -- avoid gc during trace
  local function f (event, line)
    assert(event == 'line')
    local l = table.remove(l, 1)
    if p then print(l, line) end
    assert(l == line, "wrong trace!!")
  end
  debug.sethook(f,"l"); load(s)(); debug.sethook()
  assert(#l == 0)
end


do
  assert(not pcall(debug.getinfo, print, "X"))   -- invalid option
  assert(not pcall(debug.getinfo, 0, ">"))   -- invalid option
  assert(not debug.getinfo(1000))   -- out of range level
  assert(not debug.getinfo(-1))     -- out of range level
  local a = debug.getinfo(print)
  assert(a.what == "C" and a.short_src == "[C]")
  a = debug.getinfo(print, "L")
  assert(a.activelines == nil)
  local b = debug.getinfo(test, "SfL")
  assert(b.name == nil and b.what == "Lua" and b.linedefined == testline and
         b.lastlinedefined == b.linedefined + 10 and
         b.func == test and not string.find(b.short_src, "%["))
  assert(b.activelines[b.linedefined + 1] and
         b.activelines[b.lastlinedefined])
  assert(not b.activelines[b.linedefined] and
         not b.activelines[b.lastlinedefined + 1])
end


--  bug in 5.4.4-5.4.6: activelines in vararg functions
--  without debug information
do
  local func = load(string.dump(load("print(10)"), true))
  local actl = debug.getinfo(func, "L").activelines
  assert(#actl == 0)   -- no line info
end


-- test file and string names truncation
local a = "function f () end"
local function dostring (s, x) return load(s, x)() end
dostring(a)
assert(debug.getinfo(f).short_src == string.format('[string "%s"]', a))
dostring(a..string.format("; %s\n=1", string.rep('p', 400)))
assert(string.find(debug.getinfo(f).short_src, '^%[string [^\n]*%.%.%."%]$'))
dostring(a..string.format("; %s=1", string.rep('p', 400)))
assert(string.find(debug.getinfo(f).short_src, '^%[string [^\n]*%.%.%."%]$'))
dostring("\n"..a)
assert(debug.getinfo(f).short_src == '[string "..."]')
dostring(a, "")
assert(debug.getinfo(f).short_src == '[string ""]')
dostring(a, "@xuxu")
assert(debug.getinfo(f).short_src == "xuxu")
dostring(a, "@"..string.rep('p', 1000)..'t')
assert(string.find(debug.getinfo(f).short_src, "^%.%.%.p*t$"))
dostring(a, "=xuxu")
assert(debug.getinfo(f).short_src == "xuxu")
dostring(a, string.format("=%s", string.rep('x', 500)))
assert(string.find(debug.getinfo(f).short_src, "^x*$"))
dostring(a, "=")
assert(debug.getinfo(f).short_src == "")
_G.a = nil; _G.f = nil;
_G[string.rep("p", 400)] = nil


repeat
  local g = {x = function ()
    local a = debug.getinfo(2)
    assert(a.name == 'f' and a.namewhat == 'local')
    a = debug.getinfo(1)
    assert(a.name == 'x' and a.namewhat == 'field')
    return 'xixi'
  end}
  local f = function () return 1+1 and (not 1 or g.x()) end
  assert(f() == 'xixi')
  g = debug.getinfo(f)
  assert(g.what == "Lua" and g.func == f and g.namewhat == "" and not g.name)

  function f (x, name)   -- local!
    name = name or 'f'
    local a = debug.getinfo(1)
    assert(a.name == name and a.namewhat == 'local')
    return x
  end

  -- breaks in different conditions
  if 3>4 then break end; f()
  if 3<4 then a=1 else break end; f()
  while 1 do local x=10; break end; f()
  local b = 1
  if 3>4 then return math.sin(1) end; f()
  a = 3<4; f()
  a = 3<4 or 1; f()
  repeat local x=20; if 4>3 then f() else break end; f() until 1
  g = {}
  f(g).x = f(2) and f(10)+f(9)
  assert(g.x == f(19))
  function g(x) if not x then return 3 end return (x('a', 'x')) end
  assert(g(f) == 'a')
until 1

test([[if
math.sin(1)
then
  a=1
else
  a=2
end
]], {2,4,7})


test([[
local function foo()
end
foo()
A = 1
A = 2
A = 3
]], {2, 3, 2, 4, 5, 6})
_G.A = nil


test([[--
if nil then
  a=1
else
  a=2
end
]], {2,5,6})

test([[a=1
repeat
  a=a+1
until a==3
]], {1,3,4,3,4})

test([[ do
  return
end
]], {2})

test([[local a
a=1
while a<=3 do
  a=a+1
end
]], {1,2,3,4,3,4,3,4,3,5})

test([[while math.sin(1) do
  if math.sin(1)
  then break
  end
end
a=1]], {1,2,3,6})

test([[for i=1,3 do
  a=i
end
]], {1,2,1,2,1,2,1,3})

test([[for i,v in pairs{'a','b'} do
  a=tostring(i) .. v
end
]], {1,2,1,2,1,3})

test([[for i=1,4 do a=1 end]], {1,1,1,1})

_G.a = nil


do   -- testing line info/trace with large gaps in source

  local a = {1, 2, 3, 10, 124, 125, 126, 127, 128, 129, 130,
             255, 256, 257, 500, 1000}
  local s = [[
     local b = {10}
     a = b[1] X + Y b[1]
     b = 4
  ]]
  for _, i in ipairs(a) do
    local subs = {X = string.rep("\n", i)}
    for _, j in ipairs(a) do
      subs.Y = string.rep("\n", j)
      local s = string.gsub(s, "[XY]", subs)
      test(s, {1, 2 + i, 2 + i + j, 2 + i, 2 + i + j, 3 + i + j})
    end
  end
end
_G.a = nil


do   -- testing active lines
  local function checkactivelines (f, lines)
    local t = debug.getinfo(f, "SL")
    for _, l in pairs(lines) do
      l = l + t.linedefined
      assert(t.activelines[l])
      t.activelines[l] = undef
    end
    assert(next(t.activelines) == nil)   -- no extra lines
  end

  checkactivelines(function (...)   -- vararg function
    -- 1st line is empty
    -- 2nd line is empty
    -- 3th line is empty
    local a = 20
    -- 5th line is empty
    local b = 30
    -- 7th line is empty
  end, {4, 6, 8})

  checkactivelines(function (a)
    -- 1st line is empty
    -- 2nd line is empty
    local a = 20
    local b = 30
    -- 5th line is empty
  end, {3, 4, 6})

  checkactivelines(function (a, b, ...) end, {0})

  checkactivelines(function (a, b)
  end, {1})

  for _, n in pairs{0, 1, 2, 10, 50, 100, 1000, 10000} do
    checkactivelines(
      load(string.format("%s return 1", string.rep("\n", n))),
      {n + 1})
  end

end

print'+'

-- invalid levels in [gs]etlocal
assert(not pcall(debug.getlocal, 20, 1))
assert(not pcall(debug.setlocal, -1, 1, 10))


-- parameter names
local function foo (a,b,...) local d, e end
local co = coroutine.create(foo)

assert(debug.getlocal(foo, 1) == 'a')
assert(debug.getlocal(foo, 2) == 'b')
assert(not debug.getlocal(foo, 3))
assert(debug.getlocal(co, foo, 1) == 'a')
assert(debug.getlocal(co, foo, 2) == 'b')
assert(not debug.getlocal(co, foo, 3))

assert(not debug.getlocal(print, 1))


local function foo () return (debug.getlocal(1, -1)) end
assert(not foo(10))


-- varargs
local function foo (a, ...)
  local t = table.pack(...)
  for i = 1, t.n do
    local n, v = debug.getlocal(1, -i)
    assert(n == "(vararg)" and v == t[i])
  end
  assert(not debug.getlocal(1, -(t.n + 1)))
  assert(not debug.setlocal(1, -(t.n + 1), 30))
  if t.n > 0 then
    (function (x)
      assert(debug.setlocal(2, -1, x) == "(vararg)")
      assert(debug.setlocal(2, -t.n, x) == "(vararg)")
     end)(430)
     assert(... == 430)
  end
end

foo()
foo(print)
foo(200, 3, 4)
local a = {}
for i = 1, (_soft and 100 or 1000) do a[i] = i end
foo(table.unpack(a))



do   -- test hook presence in debug info
  assert(not debug.gethook())
  local count = 0
  local function f ()
    assert(debug.getinfo(1).namewhat == "hook")
    local sndline = string.match(debug.traceback(), "\n(.-)\n")
    assert(string.find(sndline, "hook"))
    count = count + 1
  end
  debug.sethook(f, "l")
  local a = 0
  _ENV.a = a
  a = 1
  debug.sethook()
  assert(count == 4)
end
_ENV.a = nil


-- hook table has weak keys
assert(getmetatable(debug.getregistry()._HOOKKEY).__mode == 'k')


a = {}; local L = nil
local glob = 1
local oldglob = glob
debug.sethook(function (e,l)
  collectgarbage()   -- force GC during a hook
  local f, m, c = debug.gethook()
  assert(m == 'crl' and c == 0)
  if e == "line" then
    if glob ~= oldglob then
      L = l-1   -- get the first line where "glob" has changed
      oldglob = glob
    end
  elseif e == "call" then
      local f = debug.getinfo(2, "f").func
      a[f] = 1
  else assert(e == "return")
  end
end, "crl")


function f(a,b)
 -- declare some globals to check that they don't interfere with 'getlocal'
  global collectgarbage
  collectgarbage()
  local _, x = debug.getlocal(1, 1)
  global assert, g, string
  local _, y = debug.getlocal(1, 2)
  assert(x == a and y == b)
  assert(debug.setlocal(2, 4, "pera") == "AA".."AA")
  assert(debug.setlocal(2, 5, "manga") == "B")
  x = debug.getinfo(2)
  assert(x.func == g and x.what == "Lua" and x.name == 'g' and
         x.nups == 2 and string.find(x.source, "^@.*db%.lua$"))
  glob = glob+1
  assert(debug.getinfo(1, "l").currentline == L+1)
  assert(debug.getinfo(1, "l").currentline == L+2)
end

function foo()
  glob = glob+1
  assert(debug.getinfo(1, "l").currentline == L+1)
end; foo()  -- set L
-- check line counting inside strings and empty lines

local _ = 'alo\
alo' .. [[

]]
--[[
]]
assert(debug.getinfo(1, "l").currentline == L+11)  -- check count of lines


function g (...)
  local arg = {...}
  do local a,b,c; a=math.sin(40); end
  local feijao
  local AAAA,B = "xuxu", "abacate"
  f(AAAA,B)
  assert(AAAA == "pera" and B == "manga")
  do
     global *
     local B = 13
     global<const> assert
     local x,y = debug.getlocal(1,6)
     assert(x == 'B' and y == 13)
  end
end

g()


assert(a[f] and a[g] and a[assert] and a[debug.getlocal] and not a[print])


-- tests for manipulating non-registered locals (C and Lua temporaries)

local n, v = debug.getlocal(0, 1)
assert(v == 0 and n == "(C temporary)")
local n, v = debug.getlocal(0, 2)
assert(v == 2 and n == "(C temporary)")
assert(not debug.getlocal(0, 3))
assert(not debug.getlocal(0, 0))

function f()
  assert(select(2, debug.getlocal(2,3)) == 1)
  assert(not debug.getlocal(2,4))
  debug.setlocal(2, 3, 10)
  return 20
end

function g(a,b) return (a+1) + f() end

assert(g(0,0) == 30)
 
_G.f, _G.g = nil

debug.sethook(nil);
assert(not debug.gethook())


-- minimal tests for setuservalue/getuservalue
do
  assert(not debug.setuservalue(io.stdin, 10))
  local a, b = debug.getuservalue(io.stdin, 10)
  assert(a == nil and not b)
end

-- testing interaction between multiple values x hooks
do
  local function f(...) return 3, ... end
  local count = 0
  local a = {}
  for i = 1, 100 do a[i] = i end
  debug.sethook(function () count = count + 1 end, "", 1)
  local t = {table.unpack(a)}
  assert(#t == 100)
  t = {table.unpack(a, 1, 3)}
  assert(#t == 3)
  t = {f(table.unpack(a, 1, 30))}
  assert(#t == 31)
end


-- testing access to function arguments

local function collectlocals (level)
  local tab = {}
  for i = 1, math.huge do
    local n, v = debug.getlocal(level + 1, i)
    if not (n and string.find(n, "^[a-zA-Z0-9_]+$") or
            n == "(vararg table)") then
       break   -- consider only real variables
    end
    tab[n] = v
  end
  return tab
end


local X = nil
a = {}
function a:f (a, b, ...) local arg = {...}; local c = 13 end
debug.sethook(function (e)
  assert(e == "call")
  dostring("XX = 12")  -- test dostring inside hooks
  -- testing errors inside hooks
  assert(not pcall(load("a='joao'+1")))
  debug.sethook(function (e, l) 
    assert(debug.getinfo(2, "l").currentline == l)
    local f,m,c = debug.gethook()
    assert(e == "line")
    assert(m == 'l' and c == 0)
    debug.sethook(nil)  -- hook is called only once
    assert(not X)       -- check that
    X = collectlocals(2)
  end, "l")
end, "c")

a:f(1,2,3,4,5)
assert(X.self == a and X.a == 1   and X.b == 2 and X.c == nil)
assert(XX == 12)
assert(not debug.gethook())
_G.XX = nil


-- testing access to local variables in return hook (bug in 5.2)
do
  local X = false

  local function foo (a, b, ...)
    do local x,y,z end
    local c, d = 10, 20
    return
  end

  local function aux ()
    if debug.getinfo(2).name == "foo" then
      X = true   -- to signal that it found 'foo'
      local tab = {a = 100, b = 200, c = 10, d = 20}
      for n, v in pairs(collectlocals(2)) do
        assert(tab[n] == v)
        tab[n] = undef
      end
      assert(next(tab) == nil)    -- 'tab' must be empty
    end
  end

  debug.sethook(aux, "r"); foo(100, 200); debug.sethook()
  assert(X)

end


local function eqseq (t1, t2)
  assert(#t1 == #t2)
  for i = 1, #t1 do
    assert(t1[i] == t2[i])
  end
end


do  print("testing inspection of parameters/returned values")
  local on = false
  local inp, out

  local function hook (event)
    if not on then return end
    local ar = debug.getinfo(2, "ruS")
    local t = {}
    for i = ar.ftransfer, ar.ftransfer + ar.ntransfer - 1 do
      local _, v = debug.getlocal(2, i)
      t[#t + 1] = v 
    end
    if event == "return" then
      out = t
    else
      inp = t
    end
  end

  debug.sethook(hook, "cr")

  on = true; math.sin(3); on = false
  eqseq(inp, {3}); eqseq(out, {math.sin(3)})

  on = true; select(2, 10, 20, 30, 40); on = false
  eqseq(inp, {2, 10, 20, 30, 40}); eqseq(out, {20, 30, 40})

  local function foo (a, ...) return ... end
  local function foo1 () on = not on; return foo(20, 10, 0) end
  foo1(); on = false
  eqseq(inp, {20}); eqseq(out, {10, 0})

  debug.sethook()
end



-- testing upvalue access
local function getupvalues (f)
  local t = {}
  local i = 1
  while true do
    local name, value = debug.getupvalue(f, i)
    if not name then break end
    assert(not t[name])
    t[name] = value
    i = i + 1
  end
  return t
end

local a,b,c = 1,2,3
local function foo1 (a) b = a; return c end
local function foo2 (x) a = x; return c+b end
"##;

const COUNT_SOURCE: &[u8] = br#"local a, active, nested, wrong = 0, false, 0, 0
local function hook(event)
  if event ~= "count" then wrong = wrong + 1 end
  if active then nested = nested + 1 end
  active = true
  a = a + 1
  active = false
end
debug.sethook(hook, "", 1)
a=0; for i=1,1000 do end; local one_ok = 1000 < a and a < 1012
local one = a
debug.sethook(hook, "", 4)
a=0; for i=1,1000 do end; local four_ok = 250 < a and a < 255
local four = a
local _, mask, count = debug.gethook()
debug.sethook(hook, "", 4000)
a=0; for i=1,1000 do end; local many_ok = a == 0
local many = a
debug.sethook()
return one, four, many, mask, count, nested, wrong, one_ok, four_ok, many_ok
"#;

const ORIGINAL_COUNT_BLOCK: &[u8] = br#"local a=0
debug.sethook(function(e) a=a+1 end, "", 1)
a=0; for i=1,1000 do end; assert(1000 < a and a < 1012)
debug.sethook(function(e) a=a+1 end, "", 4)
a=0; for i=1,1000 do end; assert(250 < a and a < 255)
local f,m,c=debug.gethook()
assert(m == "" and c == 4)
debug.sethook(function(e) a=a+1 end, "", 4000)
a=0; for i=1,1000 do end; assert(a == 0)
debug.sethook()
return true
"#;

const BACKWARD_COUNT_CONTEXT: &[u8] = br#"local a, again = 0, false
::before::
if again then
  debug.sethook()
  return a, ...
end
debug.sethook(function() a=a+1 end, "", 1)
a=0; for i=1,1000 do end
again=true
goto before
"#;

const VISIBLE_SOURCE: &[u8] = br#"local sum, last = 0, 0
for i=1,1000 do
  sum = sum + i
  last = i
end
return sum, last
"#;

const COUNT_LOCAL_SOURCE: &[u8] =
    br#"local seen, bad, last, maximum, nested, active = 0, 0, 0, 0, 0, false
debug.sethook(function(event)
  if active then nested = nested + 1 end
  active = true
  if event ~= "count" then bad = bad + 1 end
  for slot=1,32 do
    local name, value = debug.getlocal(2, slot)
    if name == "i" then
      if type(value) ~= "number" or value < 1 or value > 1000 or value < last then
        bad = bad + 1
      end
      last = value
      if type(value) == "number" and value > maximum then maximum = value end
      seen = seen + 1
      break
    end
  end
  active = false
end, "", 1)
for i=1,1000 do end
debug.sethook()
return seen, bad, last, maximum, nested
"#;

const CAPTURE_SOURCE: &[u8] = br#"local closures = {}
for i=1,3 do
  closures[i] = function() return i end
end
return closures[1](), closures[2](), closures[3]()
"#;

const NESTED_CLOSE_SOURCE: &[u8] = br#"local f,g
for i=1,1 do
  do local x=5; f=function() return i,x end end
  local index
  for slot=1,2 do
    local name=debug.getupvalue(f,slot)
    if name=="i" then index=slot; break end
  end
  assert(index~=nil)
  assert(debug.setupvalue(f,index,9)=="i")
  g=function() return i end
end
local vi,vx=f()
return vi,vx,g()
"#;

const ENV_FIELD_SOURCE: &[u8] = br#"local env = _ENV
local setmeta, call, raise = setmetatable, pcall, error
setmeta(env, {__index=function(_, key)
  if key=="missing" then return 17 end
  raise("boom")
end})
local found = missing
local ok = call(function() return absent end)
return found, ok
"#;

const SCOPE_BRANCH_SOURCE: &[u8] = br#"local before = 41
do
  for i=3,1,-1 do
    if i == 2 then break end
    before = before + i
  end
end
local after = before + 1
return before, after
"#;

const COMPARE_ALIAS_TRUE_SOURCE: &[u8] = br#"return (1 < 2) and 9"#;
const COMPARE_ALIAS_FALSE_SOURCE: &[u8] = br#"return (2 < 1) and 9"#;
const COMPARE_ALIAS_ERROR_SOURCE: &[u8] = br#"local ok, message = pcall(function()
  return (1 < 2) and error('rhs', 0)
end)
return ok, message == 'rhs'
"#;
const COMPARE_ALIAS_ARITH_TRUE_SOURCE: &[u8] = br#"local a=1001
return 1000 < a and a + 1
"#;
const COMPARE_ALIAS_ARITH_FALSE_SOURCE: &[u8] = br#"local a=999
return 1000 < a and a + 1
"#;

fn compile(source: &[u8], language: LanguageProfile) -> VerifiedModule {
    let limits = CompileLimits::default();
    let chunk = lex(source, language, &limits).unwrap();
    let syntax = parse(&chunk, language, &limits).unwrap();
    let resolved = resolve(&syntax, &chunk, language, &limits).unwrap();
    let ir = lower(&resolved, &IrLimits::default()).unwrap();
    emit_with_native_debug(
        &ir,
        &resolved,
        source,
        b"@p17-db-count-hook.lua",
        &VerifyLimits::default(),
    )
    .unwrap()
    .verified()
    .clone()
}

fn official(module: &VerifiedModule, profile: LuaProfile) -> VerifiedModule {
    let bytes = emit_official_chunk(
        module,
        ProtoId(0),
        profile,
        false,
        &OfficialChunkLimits::default(),
        &mut OfficialWorkBudget::new(u64::MAX),
    )
    .unwrap();
    let chunk = decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
    translate_official_chunk(&chunk, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn test_abc(opcode: u8, a: u8, b: u8, k: bool) -> u32 {
    u32::from(opcode) | (u32::from(a) << 7) | (u32::from(k) << 15) | (u32::from(b) << 16)
}

fn test_jump(offset: i32) -> u32 {
    56 | (((offset + 16_777_215) as u32) << 7)
}

fn test_official_code(
    profile: LuaProfile,
    code: Vec<u32>,
    constants: Vec<OfficialConstant>,
) -> VerifiedModule {
    let chunk = OfficialChunk {
        profile,
        root_upvalues: 0,
        main: OfficialPrototype {
            source: None,
            line_defined: 0,
            last_line_defined: 0,
            num_params: 0,
            flags: 0,
            max_stack_size: 4,
            code,
            constants,
            upvalues: vec![],
            children: vec![],
            debug: OfficialDebug::default(),
        },
    };
    translate_official_chunk(&chunk, &VerifyLimits::default())
        .unwrap()
        .verified()
        .clone()
}

fn run_with_gc(
    module: VerifiedModule,
    profile: LuaProfile,
    hooks: bool,
    collect_every_allocation: bool,
) -> (Vec<Value>, Option<Vec<u8>>) {
    run_with_gc_permissions(module, profile, hooks, collect_every_allocation, false)
}

fn run_with_gc_permissions(
    module: VerifiedModule,
    profile: LuaProfile,
    hooks: bool,
    collect_every_allocation: bool,
    upvalue_mutation: bool,
) -> (Vec<Value>, Option<Vec<u8>>) {
    let debug = DebugCapability::deny_all()
        .allow(DebugPermission::CountHook)
        .allow(DebugPermission::Info)
        .allow(DebugPermission::StackInspection)
        .allow(DebugPermission::LocalInspection);
    let debug = if upvalue_mutation {
        debug
            .allow(DebugPermission::Upvalues)
            .allow(DebugPermission::UpvalueMutation)
    } else {
        debug
    };
    let mut vm = Vm::new_with_services(profile, HostServices::deny_all().and_debug(debug)).unwrap();
    let environment = vm.allocate_table().unwrap();
    let root = vm.add_root(RootKind::Host, environment).unwrap();
    vm.install_basic_builtins(environment).unwrap();
    if hooks {
        vm.install_debug_builtins(environment).unwrap();
    }
    if collect_every_allocation {
        vm.set_collect_every_allocation(true);
    }
    let outcome = vm
        .load_with_environment(module, Value::Object(environment))
        .unwrap()
        .run()
        .unwrap();
    let RunOutcome::Returned(values) = outcome else {
        let message = if let RunOutcome::LuaError(error) = &outcome {
            if let Value::Object(object) = error.value {
                vm.with_byte_string(object, |text| text.as_bytes().to_vec())
                    .ok()
            } else {
                None
            }
        } else {
            None
        };
        panic!("count hook 測試應正常返回: {outcome:?}; message={message:?}");
    };
    let mask = if hooks && values.len() == 10 {
        let Value::Object(mask) = values[3] else {
            panic!("gethook mask 應為字串: {:?}", values[3]);
        };
        Some(
            vm.with_byte_string(mask, |text| text.as_bytes().to_vec())
                .unwrap(),
        )
    } else {
        None
    };
    vm.remove_root(root).unwrap();
    assert_eq!(vm.ledger_snapshot().reserved, 0);
    (values, mask)
}

fn run(module: VerifiedModule, profile: LuaProfile, hooks: bool) -> (Vec<Value>, Option<Vec<u8>>) {
    run_with_gc(module, profile, hooks, false)
}

#[derive(Debug)]
struct CountObservation {
    _one: i64,
    _four: i64,
    _many: i64,
    mask: Vec<u8>,
    count: i64,
    nested: i64,
    wrong: i64,
    one_ok: bool,
    four_ok: bool,
    many_ok: bool,
}

fn integer(value: Value) -> i64 {
    let Value::Integer(value) = value else {
        panic!("應返回整數: {value:?}");
    };
    value
}

fn boolean(value: Value) -> bool {
    let Value::Boolean(value) = value else {
        panic!("應返回布林值: {value:?}");
    };
    value
}

fn observe(module: VerifiedModule, profile: LuaProfile) -> CountObservation {
    let (values, mask) = run(module, profile, true);
    assert_eq!(values.len(), 10);
    CountObservation {
        _one: integer(values[0]),
        _four: integer(values[1]),
        _many: integer(values[2]),
        mask: mask.unwrap(),
        count: integer(values[4]),
        nested: integer(values[5]),
        wrong: integer(values[6]),
        one_ok: boolean(values[7]),
        four_ok: boolean(values[8]),
        many_ok: boolean(values[9]),
    }
}

#[test]
fn p17_debug_count_hook_empty_numeric_for_matches_official_intervals() {
    let mut failures = Vec::new();
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(COUNT_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let observed = observe(module, profile);
            if !(observed.one_ok
                && observed.four_ok
                && observed.many_ok
                && observed.mask.is_empty()
                && observed.count == 4
                && observed.nested == 0
                && observed.wrong == 0)
            {
                failures.push(format!("{profile:?} {label}: {observed:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn p17_original_db_count_block_assertions_survive_official_roundtrip() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(ORIGINAL_COUNT_BLOCK, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, true);
            assert_eq!(values, vec![Value::Boolean(true)], "{profile:?} {label}");
        }
    }
}

#[test]
fn p17_db_prefix_native_context_preserves_empty_for_count() {
    let mut failures = Vec::new();
    for (language, profile, fixture) in [
        (
            LanguageProfile::Lua54,
            LuaProfile::Lua54,
            DB54_PREFIX_AND_CAPTURES,
        ),
        (
            LanguageProfile::Lua55,
            LuaProfile::Lua55,
            DB55_PREFIX_AND_CAPTURES,
        ),
    ] {
        let lines: Vec<_> = fixture.split_inclusive(|byte| *byte == b'\n').collect();
        let old_captures = if profile == LuaProfile::Lua54 {
            &lines[577..580]
        } else {
            &lines[583..586]
        };
        let prefix_end = if profile == LuaProfile::Lua54 {
            577
        } else {
            583
        };
        // 保留 db.lua 前綴的完整編譯原型，執行時跳過無關的既有斷言與副作用。
        let mut source = b"if false then\n".to_vec();
        for line in &lines[..prefix_end] {
            source.extend_from_slice(line);
        }
        source.extend_from_slice(b"end\n");
        for line in old_captures {
            source.extend_from_slice(line);
        }
        source.extend_from_slice(
            br#"
local a=0
debug.sethook(function (e) a=a+1 end, "", 1)
a=0; for i=1,1000 do end; local one = a
debug.sethook(function (e) a=a+1 end, "", 4)
a=0; for i=1,1000 do end; local four = a
debug.sethook(function (e) a=a+1 end, "", 4000)
a=0; for i=1,1000 do end; local many = a
debug.sethook()
return one, four, many
"#,
        );
        let native = compile(&source, language);
        eprintln!(
            "{profile:?} prototypes={} root_instructions={} root_registers={}",
            native.module().prototypes.len(),
            native.module().prototypes[0].instructions.len(),
            native.module().prototypes[0].register_count
        );
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, true);
            assert_eq!(values.len(), 3, "{profile:?} {label}");
            let counts = (integer(values[0]), integer(values[1]), integer(values[2]));
            eprintln!("{profile:?} {label}: {counts:?}");
            if !(1000 < counts.0
                && counts.0 < 1012
                && 250 < counts.1
                && counts.1 < 255
                && counts.2 == 0)
            {
                failures.push(format!("{profile:?} {label}: {counts:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("; "));
}

#[test]
fn p17_numeric_alias_rejects_backward_entry_to_prior_open_return() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(BACKWARD_COUNT_CONTEXT, language);
        let official = official(&native, profile);
        let (native_values, _) = run(native, profile, true);
        let (official_values, _) = run(official, profile, true);
        assert_eq!(native_values.len(), 1, "{profile:?}");
        assert_eq!(official_values.len(), 1, "{profile:?}");
        let native_count = integer(native_values[0]);
        let official_count = integer(official_values[0]);
        assert!(
            1000 < native_count && native_count < 1020,
            "{profile:?} {native_count}"
        );
        assert!(
            official_count > 2 * native_count,
            "{profile:?} {official_count}"
        );
    }
}

#[test]
fn p17_numeric_for_visible_counter_survives_official_roundtrip() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(VISIBLE_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, false);
            assert_eq!(
                values,
                [Value::Integer(500_500), Value::Integer(1000)],
                "{profile:?} {label}"
            );
        }
    }
}

#[test]
fn p17_count_hook_getlocal_reads_visible_numeric_for_value() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(COUNT_LOCAL_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, true);
            assert_eq!(values.len(), 5, "{profile:?} {label}");
            let observed: Vec<_> = values.into_iter().map(integer).collect();
            assert!(
                observed[0] >= 1000 && observed[0] <= 1012,
                "{profile:?} {label} 應在每輪觀察 i：{observed:?}"
            );
            assert_eq!(&observed[1..], &[0, 1000, 1000, 0], "{profile:?} {label}");
        }
    }
}

#[test]
fn p17_numeric_for_each_iteration_closure_keeps_its_value() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(CAPTURE_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            for pressure in [false, true] {
                let (values, _) = run_with_gc(module.clone(), profile, false, pressure);
                assert_eq!(
                    values,
                    [Value::Integer(1), Value::Integer(2), Value::Integer(3)],
                    "{profile:?} {label} GC={pressure}"
                );
            }
        }
    }
}

#[test]
fn p17_numeric_for_nested_close_preserves_parent_i_capture() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(NESTED_CLOSE_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            for pressure in [false, true] {
                let (values, _) =
                    run_with_gc_permissions(module.clone(), profile, true, pressure, true);
                assert_eq!(
                    values,
                    [Value::Integer(9), Value::Integer(5), Value::Integer(9)],
                    "{profile:?} {label} GC={pressure}"
                );
            }
        }
    }
}

#[test]
fn p17_gettabup_env_metatable_and_error_match_native() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(ENV_FIELD_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, false);
            assert_eq!(
                values,
                [Value::Integer(17), Value::Boolean(false)],
                "{profile:?} {label}"
            );
        }
    }
}

#[test]
fn p17_native_export_preflight_exact_allocation_budget_with_numeric_debug_names() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(COUNT_LOCAL_SOURCE, language);
        let export = |max_allocated_bytes| {
            let limits = OfficialChunkLimits {
                max_allocated_bytes,
                ..OfficialChunkLimits::default()
            };
            emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                false,
                &limits,
                &mut OfficialWorkBudget::new(u64::MAX),
            )
        };
        let mut low = 0usize;
        let mut high = OfficialChunkLimits::default().max_allocated_bytes;
        assert!(export(high).is_ok(), "{profile:?} 預設額度應可匯出");
        while low + 1 < high {
            let middle = low + (high - low) / 2;
            match export(middle) {
                Ok(_) => high = middle,
                Err(error) => {
                    assert_eq!(error.kind, OfficialExportErrorKind::LimitExceeded);
                    low = middle;
                }
            }
        }
        assert_eq!(
            export(low).expect_err("少一 byte 不可匯出").kind,
            OfficialExportErrorKind::LimitExceeded,
            "{profile:?}",
        );
        assert!(
            !export(high).unwrap().is_empty(),
            "{profile:?} 精確足額應可匯出"
        );
    }
}

#[test]
fn p17_numeric_for_negative_step_break_and_following_local() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        let native = compile(SCOPE_BRANCH_SOURCE, language);
        let official = official(&native, profile);
        for (label, module) in [("native", native), ("official", official)] {
            let (values, _) = run(module, profile, false);
            assert_eq!(
                values,
                [Value::Integer(44), Value::Integer(45)],
                "{profile:?} {label}"
            );
        }
    }
}

#[test]
fn p17_official_conditional_jump_and_testset_keep_branch_semantics() {
    for profile in [LuaProfile::Lua54, LuaProfile::Lua55] {
        for (less, k) in [(true, true), (true, false), (false, true), (false, false)] {
            let left_constant = if less { 0 } else { 1 };
            let right_constant = if less { 1 } else { 0 };
            let code = vec![
                3 | (left_constant << 15),
                3 | (1 << 7) | (right_constant << 15),
                test_abc(58, 0, 1, k),
                test_jump(2),
                test_abc(5, 2, 0, false),
                test_jump(1),
                test_abc(7, 2, 0, false),
                test_abc(70, 2, 2, false),
            ];
            let module = test_official_code(
                profile,
                code,
                vec![OfficialConstant::Integer(1), OfficialConstant::Integer(2)],
            );
            let prototype = &module.module().prototypes[0];
            let origins = module
                .official_artifact()
                .unwrap()
                .pc_map(ProtoId(0))
                .unwrap()
                .rvlu_to_official();
            assert!(
                origins
                    .iter()
                    .zip(&prototype.instructions)
                    .any(|(origin, entry)| {
                        *origin == OfficialRvluPc::Expanded(2)
                            && matches!(entry.instruction, rivetlua_core::Instruction::Jump { .. })
                    })
            );
            assert!(
                origins
                    .iter()
                    .zip(&prototype.instructions)
                    .any(|(origin, entry)| {
                        *origin == OfficialRvluPc::Anchor(3)
                            && matches!(entry.instruction, rivetlua_core::Instruction::Jump { .. })
                    })
            );
            // 直接執行的 JMP 保留獨立 Anchor；count hook 依此 Anchor 計數。
            assert!(
                origins
                    .iter()
                    .zip(&prototype.instructions)
                    .any(|(origin, entry)| {
                        *origin == OfficialRvluPc::Anchor(5)
                            && matches!(entry.instruction, rivetlua_core::Instruction::Jump { .. })
                    })
            );
            let (values, _) = run(module, profile, false);
            assert_eq!(
                values,
                vec![Value::Boolean(less == k)],
                "{profile:?} LT {less:?}/{k:?}"
            );
        }
        for (input, k) in [(true, true), (true, false), (false, true), (false, false)] {
            let initial = if input { 7 } else { 5 };
            let code = vec![
                test_abc(initial, 0, 0, false),
                test_abc(66, 0, 0, k),
                test_jump(2),
                test_abc(5, 1, 0, false),
                test_jump(1),
                test_abc(7, 1, 0, false),
                test_abc(70, 1, 2, false),
            ];
            let module = test_official_code(profile, code, vec![]);
            let (values, _) = run(module, profile, false);
            assert_eq!(
                values,
                vec![Value::Boolean(input == k)],
                "{profile:?} TEST {input:?}/{k:?}"
            );

            let sentinel = if input { 5 } else { 7 };
            let code = vec![
                test_abc(initial, 0, 0, false),
                test_abc(sentinel, 1, 0, false),
                test_abc(67, 1, 0, k),
                test_jump(1),
                test_abc(70, 1, 2, false),
                test_abc(70, 1, 2, false),
            ];
            let module = test_official_code(profile, code, vec![]);
            let (values, _) = run(module, profile, false);
            let expected = if input == k { input } else { !input };
            assert_eq!(
                values,
                vec![Value::Boolean(expected)],
                "{profile:?} TESTSET {input:?}/{k:?}"
            );
        }
    }
}

#[test]
fn p17_compare_left_phi_alias_terminal_fallback_preserves_short_circuit() {
    for (language, profile) in [
        (LanguageProfile::Lua54, LuaProfile::Lua54),
        (LanguageProfile::Lua55, LuaProfile::Lua55),
    ] {
        for (label, source, expected) in [
            ("true", COMPARE_ALIAS_TRUE_SOURCE, vec![Value::Integer(9)]),
            (
                "false",
                COMPARE_ALIAS_FALSE_SOURCE,
                vec![Value::Boolean(false)],
            ),
            (
                "arith true",
                COMPARE_ALIAS_ARITH_TRUE_SOURCE,
                vec![Value::Integer(1002)],
            ),
            (
                "arith false",
                COMPARE_ALIAS_ARITH_FALSE_SOURCE,
                vec![Value::Boolean(false)],
            ),
            (
                "rhs error",
                COMPARE_ALIAS_ERROR_SOURCE,
                vec![Value::Boolean(false), Value::Boolean(true)],
            ),
        ] {
            let native = compile(source, language);
            assert_eq!(
                run(native.clone(), profile, false).0,
                expected,
                "{profile:?} {label} native"
            );
            let bytes = emit_official_chunk(
                &native,
                ProtoId(0),
                profile,
                false,
                &OfficialChunkLimits::default(),
                &mut OfficialWorkBudget::new(u64::MAX),
            )
            .unwrap();
            let chunk =
                decode_official_chunk(&bytes, profile, &OfficialChunkLimits::default()).unwrap();
            let clobbers_left = chunk.main.code.windows(2).any(|pair| {
                pair[0] & 0x7f == 5
                    && pair[1] & 0x7f == 58
                    && ((pair[0] >> 7) & 0xff) == ((pair[1] >> 7) & 0xff)
            });
            eprintln!("{profile:?} {label}: fallback 左槽覆寫={clobbers_left}");
            if label == "arith true" {
                eprintln!(
                    "{profile:?} native={:?}",
                    native.module().prototypes[0].instructions
                );
                eprintln!(
                    "{profile:?} official={:?}",
                    chunk
                        .main
                        .code
                        .iter()
                        .map(|word| (word & 0x7f, (word >> 7) & 0xff, (word >> 16) & 0xff))
                        .collect::<Vec<_>>()
                );
            }
            let official = translate_official_chunk(&chunk, &VerifyLimits::default())
                .unwrap()
                .verified()
                .clone();
            assert_eq!(
                run(official, profile, false).0,
                expected,
                "{profile:?} {label} official"
            );
            assert!(
                !clobbers_left,
                "{profile:?} {label}: CMP 前不可覆寫左運算元"
            );
        }
    }
}
