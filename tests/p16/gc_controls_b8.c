/* P16-2 B8：固定 header 的 lua_gc 變參 ABI 與兩版命令編號。 */
#include "lua.h"
#include "lauxlib.h"
#include <stddef.h>

extern int rivetlua_capi_call_b4(lua_State *, int, int);

static int good_calls_b8;
static int bad_calls_b8;
static int outer_calls_b8;

static int good_finalizer_b8(lua_State *state) {
  good_calls_b8++;
  if (lua_gc(state, LUA_GCISRUNNING) != -1 ||
      lua_gc(state, LUA_GCCOLLECT) != -1 ||
      lua_gc(state, 99) != -1) __builtin_trap();
  return 0;
}

static int bad_finalizer_b8(lua_State *state) {
  bad_calls_b8++;
  luaL_checktype(state, 1, LUA_TNUMBER);
  __builtin_trap();
  return 0;
}

static void push_finalizable_b8(lua_State *state, lua_CFunction callback) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__gc");
  lua_pushcclosure(state, callback, 0);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) __builtin_trap();
  lua_pop(state, 1);
}

static int outer_gc_b8(lua_State *state) {
  outer_calls_b8++;
  push_finalizable_b8(state, bad_finalizer_b8);
  push_finalizable_b8(state, good_finalizer_b8);
  if (lua_gc(state, LUA_GCCOLLECT) != 0) __builtin_trap();
  lua_pushinteger(state, 81);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  if (lua_gc(state, LUA_GCISRUNNING) != 1) return 2;
  if (lua_gc(state, LUA_GCSTOP) != 0) return 3;
  if (lua_gc(state, LUA_GCISRUNNING) != 0) return 4;
  if (lua_gc(state, LUA_GCRESTART) != 0) return 5;
#if LUA_VERSION_NUM < 505
  if (LUA_GCISRUNNING != 9 || LUA_GCGEN != 10 || LUA_GCINC != 11) return 6;
  if (lua_gc(state, LUA_GCSETPAUSE, 200) != 200) return 7;
  if (lua_gc(state, LUA_GCGEN, 20, 100) != LUA_GCGEN) return 8;
  if (lua_gc(state, LUA_GCSTEP, 0) < 0) return 9;
#else
  if (LUA_GCISRUNNING != 6 || LUA_GCGEN != 7 || LUA_GCINC != 8 ||
      LUA_GCPARAM != 9) return 6;
  if (lua_gc(state, LUA_GCPARAM, LUA_GCPSTEPSIZE, -1) != 9600) return 7;
  if (lua_gc(state, LUA_GCGEN) != LUA_GCGEN) return 8;
  if (lua_gc(state, LUA_GCSTEP, (size_t)0) < 0) return 9;
#endif
  if (lua_gc(state, 99) != -1) return 10;
  push_finalizable_b8(state, good_finalizer_b8);
  push_finalizable_b8(state, bad_finalizer_b8);
  if (lua_gc(state, LUA_GCCOLLECT) != 0 ||
      bad_calls_b8 != 1 || good_calls_b8 != 1 || lua_gettop(state) != 0)
    return 11;
  lua_pushcclosure(state, outer_gc_b8, 0);
  if (rivetlua_capi_call_b4(state, 0, 1) != 0 ||
      lua_tointeger(state, -1) != 81 || outer_calls_b8 != 1 ||
      good_calls_b8 != 2 || bad_calls_b8 != 2) return 12;
  lua_settop(state, 0);
  if (lua_gc(state, LUA_GCCOLLECT) != 0 || lua_gettop(state) != 0)
    return 13;
  lua_close(state);
  return 0;
}
