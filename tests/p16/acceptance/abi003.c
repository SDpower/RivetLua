#include <stdio.h>

#include "lua.h"
#include "lauxlib.h"

static int collect_ref_userdata(lua_State *state) {
  if (lua_gettop(state) != 2 || lua_tointeger(state, 1) != 41) return 0;
  unsigned char *payload = (unsigned char *)lua_touserdata(state, 2);
  if (payload == NULL || payload[0] != 0x5a) return 0;
  lua_pushvalue(state, 2);
  int reference = luaL_ref(state, LUA_REGISTRYINDEX);
  if (reference < 0 || lua_gc(state, LUA_GCCOLLECT) != 0) return 0;
  if (lua_rawgeti(state, LUA_REGISTRYINDEX, reference) != LUA_TUSERDATA ||
      lua_touserdata(state, -1) != payload || payload[0] != 0x5a) return 0;
  luaL_unref(state, LUA_REGISTRYINDEX, reference);
  lua_pushinteger(state, 42);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  lua_pushcfunction(state, collect_ref_userdata);
  lua_pushinteger(state, 41);
  unsigned char *payload = (unsigned char *)lua_newuserdatauv(state, 32, 0);
  if (payload == NULL) {
    lua_close(state);
    return 2;
  }
  payload[0] = 0x5a;
  int status = lua_pcall(state, 2, 1, 0);
  int passed = status == LUA_OK && lua_gettop(state) == 1 &&
               lua_tointeger(state, -1) == 42;
  lua_close(state);
  if (!passed) return 3;
  puts("P16_C_BODY ABI-003 PASS");
  puts("P16_ASSERT ABI-003 gc=PASS");
  puts("P16_ASSERT ABI-003 parameters=PASS");
  puts("P16_ASSERT ABI-003 refs=PASS");
  puts("P16_ASSERT ABI-003 userdata=PASS");
  return 0;
}
