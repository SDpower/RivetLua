local lu = require("luaunit")

TestExampleLuaUnit = {}

function TestExampleLuaUnit:setUp()
   self.value = 40
end

function TestExampleLuaUnit:tearDown()
   self.value = nil
end

function TestExampleLuaUnit:test_adds_two()
   lu.assertEquals(self.value + 2, 42)
end

os.exit(lu.LuaUnit.run())
