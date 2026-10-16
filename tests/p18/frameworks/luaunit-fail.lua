local lu = require("luaunit")

TestExampleLuaUnitFailure = {}

function TestExampleLuaUnitFailure:test_deliberate_failure()
   lu.assertEquals("expected", "actual")
end

os.exit(lu.LuaUnit.run())
