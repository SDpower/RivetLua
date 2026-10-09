/* P17 模組形式探針；P16-1 只編譯，不連結、載入或執行。 */
#include "lua.h"
#include "lauxlib.h"
#include "rivetlua_abi.h"

static int answer(lua_State *L) {
  lua_Integer input = luaL_checkinteger(L, 1);
  lua_pushinteger(L, input + 2);
  return 1;
}

int luaopen_rivetlua_p16_probe(lua_State *L) {
  static const luaL_Reg functions[] = {
    {"answer", answer},
    {NULL, NULL}
  };
  luaL_newlib(L, functions);
  return 1;
}

rivetlua_abi_identity rivetlua_module_abi_identity_v1(void) {
  return rivetlua_expected_abi_identity();
}
