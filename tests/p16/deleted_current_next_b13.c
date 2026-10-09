/* P16-2 G2-B13：固定 header 的 deleted-current lua_next 回歸。 */
#include "lua.h"
#include "lauxlib.h"
#include <string.h>

static int invalid_next_returned = 0;

static int invalid_key_next(lua_State *state) {
  /* lua_pcall 的 C frame 保護此錯誤入口；不存在的鍵不可正常返回。 */
  (void)lua_next(state, 1);
  invalid_next_returned = 1;
  return 0;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  int result = 0;

  lua_createtable(state, 2, 0);
  lua_pushinteger(state, 1);
  lua_pushinteger(state, 11);
  lua_rawset(state, 1);
  lua_pushinteger(state, 2);
  lua_pushinteger(state, 22);
  lua_rawset(state, 1);
  lua_pushnil(state);
  if (lua_next(state, 1) != 1 || lua_tointeger(state, -2) != 1 ||
      lua_tointeger(state, -1) != 11) {
    result = 2;
    goto done;
  }
  lua_pushvalue(state, -2);
  lua_pushnil(state);
  lua_rawset(state, 1);
  lua_pop(state, 1);
  if (lua_next(state, 1) != 1 || lua_tointeger(state, -2) != 2 ||
      lua_tointeger(state, -1) != 22) {
    result = 3;
    goto done;
  }
  lua_settop(state, 0);

  lua_createtable(state, 0, 4);
  lua_pushboolean(state, 0);
  lua_pushinteger(state, 31);
  lua_rawset(state, 1);
  lua_pushboolean(state, 1);
  lua_pushinteger(state, 32);
  lua_rawset(state, 1);
  lua_pushlightuserdata(state, (void *)&result);
  lua_pushinteger(state, 33);
  lua_rawset(state, 1);
  lua_pushnil(state);
  if (lua_next(state, 1) != 1) {
    result = 4;
    goto done;
  }
  lua_pushvalue(state, -2);
  lua_pushnil(state);
  lua_rawset(state, 1);
  lua_pop(state, 1);
  if (lua_next(state, 1) != 1 || lua_type(state, -1) != LUA_TNUMBER) {
    result = 5;
    goto done;
  }
  lua_settop(state, 1);
  lua_pushcfunction(state, invalid_key_next);
  lua_pushvalue(state, 1);
  lua_pushinteger(state, 999);
  int status = lua_pcall(state, 2, 0, 0);
  if (status != LUA_ERRRUN || invalid_next_returned != 0 ||
      lua_gettop(state) != 2 || lua_type(state, -1) != LUA_TSTRING) {
    result = 6;
    goto done;
  }
  const char *error = lua_tostring(state, -1);
  if (error == NULL || strcmp(error, "E_NEXT_KEY") != 0) {
    result = 6;
    goto done;
  }
  /* 錯誤物件移除後，原 table 與 C stack 仍可再次合法迭代。 */
  lua_settop(state, 1);
  lua_pushnil(state);
  if (lua_next(state, 1) != 1 || lua_type(state, -1) != LUA_TNUMBER) {
    result = 7;
    goto done;
  }
  lua_settop(state, 1);

done:
  lua_close(state);
  return result;
}
