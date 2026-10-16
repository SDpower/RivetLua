local stub = require("luassert.stub")
local spy = require("luassert.spy")

local service = {
   fetch = function()
      return "original"
   end,
}

describe("example Busted package", function()
   setup(function()
      stub.new(service, "fetch").returns("stubbed")
   end)

   teardown(function()
      stub.revert(service, "fetch")
   end)

   context("with a stubbed dependency", function()
      it("records calls and restores the stub after the spec", function()
         local observed = spy.new(function(value)
            return service.fetch(value)
         end)

         assert.are.equal("stubbed", observed("example"))
         assert.spy(observed).was.called_with("example")
         assert.stub(service.fetch).was.called_with("example")
      end)
   end)
end)
