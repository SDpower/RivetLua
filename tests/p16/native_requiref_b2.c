#include <lauxlib.h>
#include <lua.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

extern int rivetlua_capi_requiref_protected_b2(
    lua_State *state, const char *name, lua_CFunction opener, int global);

static int truthy_calls;
static int nil_calls;
static int false_calls;
static int table_calls;

static int open_truthy(lua_State *state) {
  size_t length = 0;
  const char *name = lua_tolstring(state, 1, &length);
  if (name == NULL || length != strlen("native.truthy") ||
      memcmp(name, "native.truthy", length) != 0)
    return luaL_error(state, "wrong module argument");
  truthy_calls++;
  lua_pushinteger(state, 41);
  return 1;
}

static int open_nil(lua_State *state) {
  nil_calls++;
  lua_pushnil(state);
  return 1;
}

static int open_false(lua_State *state) {
  false_calls++;
  lua_pushboolean(state, 0);
  return 1;
}

static int open_table(lua_State *state) {
  table_calls++;
  lua_newtable(state);
  lua_pushinteger(state, 91);
  lua_setfield(state, -2, "value");
  return 1;
}

static int open_error(lua_State *state) {
  return luaL_error(state, "native opener failed");
}

static int call_error(lua_State *state) {
  luaL_requiref(state, "native.error", open_error, 0);
  return 1;
}

static int cached_type(lua_State *state, const char *name) {
  int type;
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  type = lua_getfield(state, -1, name);
  lua_pop(state, 2);
  return type;
}

int main(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  lua_pushinteger(state, 73);

  luaL_requiref(state, "native.truthy", open_truthy, 0);
  CHECK(lua_gettop(state) == 2 && lua_tointeger(state, -1) == 41);
  CHECK(truthy_calls == 1 && cached_type(state, "native.truthy") == LUA_TNUMBER);
  lua_pop(state, 1);
  luaL_requiref(state, "native.truthy", open_truthy, 1);
  CHECK(truthy_calls == 1 && lua_tointeger(state, -1) == 41);
  lua_getglobal(state, "native.truthy");
  CHECK(lua_tointeger(state, -1) == 41);
  lua_pop(state, 2);

  luaL_requiref(state, "native.nil", open_nil, 0);
  CHECK(lua_type(state, -1) == LUA_TNIL);
  CHECK(cached_type(state, "native.nil") == LUA_TNIL);
  lua_pop(state, 1);
  luaL_requiref(state, "native.nil", open_nil, 0);
  CHECK(lua_type(state, -1) == LUA_TNIL && nil_calls == 2);
  lua_pop(state, 1);

  luaL_requiref(state, "native.false", open_false, 0);
  CHECK(lua_type(state, -1) == LUA_TBOOLEAN && !lua_toboolean(state, -1));
  CHECK(cached_type(state, "native.false") == LUA_TBOOLEAN);
  lua_pop(state, 1);
  luaL_requiref(state, "native.false", open_false, 0);
  CHECK(lua_type(state, -1) == LUA_TBOOLEAN && false_calls == 2);
  lua_pop(state, 1);

  luaL_requiref(state, "native.table", open_table, 0);
  CHECK(lua_type(state, -1) == LUA_TTABLE && table_calls == 1);
  lua_gc(state, LUA_GCCOLLECT);
  lua_getfield(state, -1, "value");
  CHECK(lua_tointeger(state, -1) == 91);
  lua_pop(state, 2);

  lua_pushcfunction(state, call_error);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "native opener failed") != NULL);
  lua_pop(state, 1);
  CHECK(cached_type(state, "native.error") == LUA_TNIL);
  CHECK(rivetlua_capi_requiref_protected_b2(
      state, "native.error", open_error, 0) == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "native opener failed") != NULL);
  lua_pop(state, 1);
  luaL_requiref(state, "native.truthy", open_truthy, 0);
  CHECK(lua_gettop(state) == 2 && lua_tointeger(state, 1) == 73);
  CHECK(lua_tointeger(state, 2) == 41 && truthy_calls == 1);

  lua_close(state);
  return 0;
}
