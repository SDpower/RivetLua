/* P16-2 G2-B12：固定 header 的 registry destination 與 replace 展開。 */
#include "lua.h"
#include "lauxlib.h"
#include <string.h>

static int registry_function_b12(lua_State *state) {
  (void)state;
  return 0;
}

int main(void) {
  lua_State *main_state = luaL_newstate();
  if (main_state == NULL) return 1;
  lua_State *child = lua_newthread(main_state);
  if (child == NULL) return 2;

  lua_pushinteger(main_state, 47);
  int main_top = lua_gettop(main_state);
  lua_copy(main_state, -1, LUA_REGISTRYINDEX);
  if (lua_gettop(main_state) != main_top ||
      lua_type(child, LUA_REGISTRYINDEX) != LUA_TNUMBER ||
      lua_tointeger(child, LUA_REGISTRYINDEX) != 47) return 3;

  lua_pushlstring(main_state, "a\0b", 3);
  main_top = lua_gettop(main_state);
  lua_replace(main_state, LUA_REGISTRYINDEX);
  size_t len = 0;
  lua_pushvalue(child, LUA_REGISTRYINDEX);
  const char *bytes = lua_tolstring(child, -1, &len);
  if (lua_gettop(main_state) != main_top - 1 || bytes == NULL || len != 3 ||
      memcmp(bytes, "a\0b", 3) != 0) return 4;
  lua_settop(child, 0);

  lua_pushcfunction(main_state, registry_function_b12);
  lua_copy(main_state, -1, LUA_REGISTRYINDEX);
  if (lua_type(child, LUA_REGISTRYINDEX) != LUA_TFUNCTION ||
      lua_tocfunction(child, LUA_REGISTRYINDEX) != registry_function_b12)
    return 5;
  lua_copy(child, LUA_REGISTRYINDEX, LUA_REGISTRYINDEX);
  if (lua_type(main_state, LUA_REGISTRYINDEX) != LUA_TFUNCTION) return 6;

  lua_createtable(child, 0, 0);
  lua_replace(child, LUA_REGISTRYINDEX);
  if (lua_gettop(child) != 0 ||
      lua_type(main_state, LUA_REGISTRYINDEX) != LUA_TTABLE) return 7;
  lua_pushinteger(child, 99);
  lua_rawseti(child, LUA_REGISTRYINDEX, 17);
  if (lua_rawgeti(main_state, LUA_REGISTRYINDEX, 17) != LUA_TNUMBER ||
      lua_tointeger(main_state, -1) != 99) return 8;

  lua_close(main_state);
  return 0;
}
