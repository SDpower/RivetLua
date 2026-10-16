#include "lauxlib.h"
#include "lua.h"

#include <stdio.h>

static void checkpoint(const char *operation) {
  (void)fprintf(stderr, "native-after-%s\n", operation);
  (void)fflush(stderr);
}

static int exit_probe_call(lua_State *L) {
  luaL_checktype(L, 1, LUA_TFUNCTION);
  lua_pushvalue(L, 1);
  lua_call(L, 0, LUA_MULTRET);
  checkpoint("call");
  return lua_gettop(L) - 1;
}

static int exit_probe_pcall(lua_State *L) {
  int status;

  luaL_checktype(L, 1, LUA_TFUNCTION);
  lua_pushvalue(L, 1);
  status = lua_pcall(L, 0, LUA_MULTRET, 0);
  checkpoint("pcall");
  lua_remove(L, 1);
  lua_pushboolean(L, status == LUA_OK);
  lua_insert(L, 1);
  return lua_gettop(L);
}

int luaopen_p17_exit_probe(lua_State *L) {
  static const luaL_Reg functions[] = {
      {"call", exit_probe_call},
      {"pcall", exit_probe_pcall},
      {NULL, NULL},
  };

  luaL_newlib(L, functions);
  return 1;
}
