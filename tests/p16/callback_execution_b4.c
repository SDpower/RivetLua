/* P16-2 B4：固定 header 下檢查私有 callback driver 的正常同步呼叫。 */
#include "lua.h"
#include "lauxlib.h"

extern int rivetlua_capi_call_b4(lua_State *state, int nargs, int nresults);
extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);

static int callback_b4(lua_State *state) {
  if (lua_gettop(state) != 1) return 0;
  lua_pushinteger(state, lua_tointeger(state, 1) + 1);
  return 1;
}

static int nested_b4(lua_State *state) {
  if (lua_gettop(state) != 1) return -1;
  lua_pushcfunction(state, callback_b4);
  lua_pushvalue(state, 1);
  if (rivetlua_capi_call_b4(state, 1, 1) != 0) return -1;
  lua_pushinteger(state, lua_tointeger(state, -1) + 1);
  return 1;
}

static int capture_b4(lua_State *state) {
  lua_pushinteger(state,
      lua_tointeger(state, lua_upvalueindex(1)) + lua_tointeger(state, 1));
  return 1;
}

static int lua_bridge_b4(lua_State *state) {
  if (lua_gettop(state) != 1) return -1;
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, callback_b4);
  lua_pushvalue(state, 1);
  if (rivetlua_capi_call_b4(state, 2, 1) != 0) return -1;
  lua_pushinteger(state, lua_tointeger(state, -1) + 1);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  lua_pushcfunction(state, callback_b4);
  lua_pushinteger(state, 41);
  int status = rivetlua_capi_call_b4(state, 1, 1);
  int result = lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42;
  lua_settop(state, 0);
  lua_pushcfunction(state, nested_b4);
  lua_pushinteger(state, 40);
  int nested = rivetlua_capi_call_b4(state, 1, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42;
  lua_settop(state, 0);
  lua_pushinteger(state, 40);
  lua_pushcclosure(state, capture_b4, 1);
  lua_pushinteger(state, 2);
  int capture = rivetlua_capi_call_b4(state, 1, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42;
  lua_settop(state, 0);
  int rejected_selector = rivetlua_capi_test_push_lua_b4(state, 99) == 0 &&
      lua_gettop(state) == 0;
  int fixture = rivetlua_capi_test_push_lua_b4(state, 1) == 1;
  int inner_fixture = rivetlua_capi_test_push_lua_b4(state, 1) == 1;
  lua_pushcclosure(state, lua_bridge_b4, 1);
  lua_pushinteger(state, 40);
  int chain = fixture && inner_fixture && rivetlua_capi_call_b4(state, 2, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42;
  lua_close(state);
  return status == 0 && result && nested && capture && rejected_selector &&
      chain ? 0 : 2;
}
