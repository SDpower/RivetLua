#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define CHECK(condition) do { if (!(condition)) return ((__LINE__ - 1) % 255) + 1; } while (0)

extern int rivetlua_capi_test_inject_point_a4a(lua_State *state, int code);
extern int rivetlua_capi_configure_load_limits_b3(
    lua_State *state, size_t source, size_t encoded, size_t module,
    size_t temporary, size_t work, size_t chunks, size_t paths);

static int installer_failure_point;
static int expected_parent_yieldable;
static const char yieldability_query[] =
    "return coroutine.isyieldable(parent), coroutine.isyieldable(), "
    "coroutine.isyieldable(main)";

static int resume_child_from_parent(lua_State *parent) {
  lua_State *child = lua_newthread(parent);
  int nresults = 0;
  if (child == NULL) return luaL_error(parent, "child allocation failed");
  lua_pushthread(parent);
  lua_setglobal(parent, "parent");
  int loaded = luaL_loadstring(child, yieldability_query);
  if (loaded != LUA_OK) {
    return luaL_error(parent, "child chunk failed");
  }
  int status = lua_resume(child, parent, 0, &nresults);
  if (status != LUA_OK || nresults != 3) {
    return luaL_error(parent, "direct child resume failed");
  }
  int parent_value = lua_toboolean(child, 1);
  int child_value = lua_toboolean(child, 2);
  int main_value = lua_toboolean(child, 3);
  if (parent_value != expected_parent_yieldable ||
      !child_value || main_value) {
    return luaL_error(parent, "parent/child/main yieldability mismatch");
  }
  lua_pop(child, 3);
  lua_pushboolean(parent, 1);
  return 1;
}

static int resume_parent_entry(lua_State *parent) {
  if (expected_parent_yieldable) return resume_child_from_parent(parent);
  lua_pushcfunction(parent, resume_child_from_parent);
  lua_call(parent, 0, 1);
  return 1;
}

static int yield_child_under_non_yieldable_parent(lua_State *parent) {
  lua_State *child = lua_newthread(parent);
  int nresults = 0;
  if (child == NULL) return luaL_error(parent, "child allocation failed");
  lua_pushvalue(parent, -1);
  lua_setglobal(parent, "held_child");
  lua_pushthread(parent);
  lua_setglobal(parent, "parent");
  if (luaL_loadstring(child,
        "coroutine.yield(coroutine.isyieldable(parent)); "
        "return coroutine.isyieldable(parent), coroutine.isyieldable()") != LUA_OK)
    return luaL_error(parent, "yielding child chunk failed");
  int status = lua_resume(child, parent, 0, &nresults);
  if (status != LUA_YIELD || nresults != 1 || lua_toboolean(child, 1)) {
    return luaL_error(parent, "child yield under parent boundary failed");
  }
  lua_pop(child, 1);
  return 0;
}

static int resumed_child_uses_new_parent_boundary(lua_State *parent) {
  int nresults = 0;
  lua_pushcfunction(parent, yield_child_under_non_yieldable_parent);
  lua_call(parent, 0, 0);
  if (lua_getglobal(parent, "held_child") != LUA_TTHREAD)
    return luaL_error(parent, "yielded child was lost");
  lua_State *child = lua_tothread(parent, -1);
  int status = lua_resume(child, parent, 0, &nresults);
  if (status != LUA_OK || nresults != 2 ||
      !lua_toboolean(child, 1) || !lua_toboolean(child, 2)) {
    return luaL_error(parent, "resumed child kept stale parent boundary");
  }
  lua_pop(child, 2);
  lua_pushboolean(parent, 1);
  return 1;
}

static int direct_resume_parent_yieldability(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  CHECK(rivetlua_capi_configure_load_limits_b3(
      state, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
      1024 * 1024, 2 * 1000 * 1000, 256, 256) == 1);
  luaL_openlibs(state);
  lua_pushthread(state);
  lua_setglobal(state, "main");
  for (int expected = 0; expected <= 1; expected++) {
    lua_State *parent = lua_newthread(state);
    int nresults = 0;
    CHECK(parent != NULL);
    expected_parent_yieldable = expected;
    lua_pushcfunction(parent, resume_parent_entry);
    int status = lua_resume(parent, state, 0, &nresults);
    CHECK(status == LUA_OK);
    CHECK(nresults == 1 && lua_toboolean(parent, 1));
    lua_pop(state, 1);
  }
  lua_State *parent = lua_newthread(state);
  int nresults = 0;
  CHECK(parent != NULL);
  lua_pushcfunction(parent, resumed_child_uses_new_parent_boundary);
  int status = lua_resume(parent, state, 0, &nresults);
  CHECK(status == LUA_OK);
  CHECK(nresults == 1 && lua_toboolean(parent, 1));
  lua_pop(state, 1);
  lua_State *value_child = lua_newthread(state);
  CHECK(value_child != NULL);
  CHECK(luaL_loadstring(value_child,
        "local value = coroutine.yield(7); return value + 1") == LUA_OK);
  status = lua_resume(value_child, state, 0, &nresults);
  CHECK(status == LUA_YIELD);
  CHECK(nresults == 1 && lua_tointeger(value_child, 1) == 7);
  lua_pop(value_child, 1);
  lua_pushinteger(value_child, 41);
  status = lua_resume(value_child, state, 1, &nresults);
  CHECK(status == LUA_OK);
  CHECK(nresults == 1 && lua_tointeger(value_child, 1) == 42);
  lua_pop(state, 1);
  lua_pushnil(state);
  lua_setglobal(state, "held_child");
  CHECK(lua_gettop(state) == 0);
  lua_close(state);
  return 0;
}

static int nested_yieldability_inner(lua_State *state) {
  lua_pushboolean(state, lua_isyieldable(state));
  return 1;
}

static int nested_yieldability_continuation(
    lua_State *state, int status, lua_KContext context) {
  (void)status;
  (void)context;
  lua_pushboolean(state, lua_isyieldable(state));
  return 1;
}

static int nested_yieldability_outer(lua_State *state) {
  int outer = lua_isyieldable(state);
  lua_pushcfunction(state, nested_yieldability_inner);
  lua_callk(state, 0, 1, 0, NULL);
  int ordinary = lua_toboolean(state, -1);
  lua_pop(state, 1);
  lua_pushcfunction(state, nested_yieldability_inner);
  lua_callk(state, 0, 1, 0, nested_yieldability_continuation);
  int continued = lua_toboolean(state, -1);
  lua_pop(state, 1);
  lua_pushboolean(state, outer);
  lua_pushboolean(state, ordinary);
  lua_pushboolean(state, continued);
  lua_pushboolean(state, lua_isyieldable(state));
  return 4;
}

static int nested_yieldability_public_callbacks(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  lua_State *child = lua_newthread(state);
  CHECK(child != NULL);
  lua_pushcfunction(child, nested_yieldability_outer);
  int nresults = -1;
  int status = lua_resume(child, state, 0, &nresults);
  CHECK(status == LUA_OK && nresults == 4);
  CHECK(lua_toboolean(child, 1) == 1);
  CHECK(lua_toboolean(child, 2) == 0);
  CHECK(lua_toboolean(child, 3) == 1);
  CHECK(lua_toboolean(child, 4) == 1);
  lua_close(state);
  return 0;
}

static int resume_child_from_main_callback(lua_State *main) {
  lua_State *child = lua_newthread(main);
  int nresults = -1;
  if (child == NULL) return luaL_error(main, "main callback child allocation failed");
  lua_pushcfunction(child, nested_yieldability_inner);
  int status = lua_resume(child, main, 0, &nresults);
  if (status != LUA_OK || nresults != 1 || !lua_toboolean(child, 1) ||
      lua_isyieldable(main) != 0) {
    return luaL_error(main, "main callback child resume failed");
  }
  lua_pop(child, 1);
  lua_pop(main, 1);
  lua_pushboolean(main, 1);
  return 1;
}

static int main_callback_resumes_child(void) {
  lua_State *main = luaL_newstate();
  CHECK(main != NULL);
  lua_pushcfunction(main, resume_child_from_main_callback);
  CHECK(lua_pcall(main, 0, 1, 0) == LUA_OK);
  CHECK(lua_toboolean(main, -1) == 1);
  lua_pop(main, 1);
  CHECK(lua_gettop(main) == 0);
  lua_close(main);
  return 0;
}

#if LUA_VERSION_NUM >= 505
static int child_self_close_direct_resume(void) {
  lua_State *parent = luaL_newstate();
  int results = 0;
  lua_State *child;
  CHECK(parent != NULL);
  CHECK(rivetlua_capi_configure_load_limits_b3(
      parent, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
      1024 * 1024, 2 * 1000 * 1000, 256, 256) == 1);
  luaL_openlibs(parent);
  child = lua_newthread(parent);
  CHECK(child != NULL);
  CHECK(lua_gettop(parent) == 1 && lua_tothread(parent, -1) == child);
  CHECK(luaL_loadstring(child,
        "coroutine.close(); error('self close returned')") == LUA_OK);
  int status = lua_resume(child, parent, 0, &results);
  CHECK(status == LUA_OK);
  CHECK(results == 0);
  CHECK(lua_gettop(parent) == 1 && lua_tothread(parent, -1) == child);
  lua_pop(parent, 1);
  CHECK(lua_gettop(parent) == 0);
  lua_gc(parent, LUA_GCCOLLECT, 0);
  CHECK(lua_gettop(parent) == 0);
  lua_close(parent);
  return 0;
}
#endif

static int failing_table_opener(lua_State *state) {
  if (rivetlua_capi_test_inject_point_a4a(state, installer_failure_point) != 1)
    return luaL_error(state, "test injection unavailable");
  return luaopen_table(state);
}

static int call_failing_table(lua_State *state) {
  luaL_requiref(state, LUA_TABLIBNAME, failing_table_opener, 1);
  return 1;
}

typedef struct {
  const char *name;
  lua_CFunction opener;
} Library;

static const Library libraries[] = {
  {LUA_GNAME, luaopen_base},
  {LUA_LOADLIBNAME, luaopen_package},
  {LUA_COLIBNAME, luaopen_coroutine},
  {LUA_TABLIBNAME, luaopen_table},
  {LUA_IOLIBNAME, luaopen_io},
  {LUA_OSLIBNAME, luaopen_os},
  {LUA_STRLIBNAME, luaopen_string},
  {LUA_MATHLIBNAME, luaopen_math},
  {LUA_UTF8LIBNAME, luaopen_utf8},
  {LUA_DBLIBNAME, luaopen_debug}
};

static int broken_opener(lua_State *state) {
  return luaL_error(state, "opener failure");
}

static int type_metatable_tostring(lua_State *state) {
  lua_pushstring(state, "c-type-meta");
  return 1;
}

static int capi_type_metatable_reaches_guest(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  CHECK(rivetlua_capi_configure_load_limits_b3(
      state, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
      1024 * 1024, 2 * 1000 * 1000, 256, 256) == 1);
  luaL_openlibs(state);
  lua_pushinteger(state, 1);
  lua_newtable(state);
  lua_newtable(state);
  lua_pushinteger(state, 81);
  lua_setfield(state, -2, "answer");
  lua_setfield(state, -2, "__index");
  lua_pushcfunction(state, type_metatable_tostring);
  lua_setfield(state, -2, "__tostring");
  CHECK(lua_setmetatable(state, -2) == 1);
  lua_pop(state, 1);
  lua_pushlightuserdata(state, (void *)state);
  lua_newtable(state);
  lua_pushcfunction(state, type_metatable_tostring);
  lua_setfield(state, -2, "__tostring");
  CHECK(lua_setmetatable(state, -2) == 1);
  lua_setglobal(state, "light");
  lua_gc(state, LUA_GCCOLLECT, 0);
  CHECK(luaL_loadstring(state,
        "return (7).answer, tostring(7), tostring(light)") == LUA_OK);
  CHECK(lua_pcall(state, 0, 3, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -3) == 81);
  CHECK(lua_type(state, -2) == LUA_TSTRING);
  CHECK(lua_type(state, -1) == LUA_TSTRING);
  lua_pushliteral(state, "c-type-meta");
  CHECK(lua_rawequal(state, -2, -1));
  CHECK(lua_rawequal(state, -3, -1));
  lua_pop(state, 1);
  CHECK(lua_gettop(state) == 3);
  lua_pop(state, 3);
  lua_close(state);
  return 0;
}

static int call_broken(lua_State *state) {
  luaL_requiref(state, "broken", broken_opener, 1);
  return 1;
}

static int direct_openers(void) {
  for (unsigned i = 0; i < sizeof(libraries) / sizeof(libraries[0]); i++) {
    lua_State *state = luaL_newstate();
    CHECK(state != NULL);
    CHECK(lua_gettop(state) == 0);
    CHECK(libraries[i].opener(state) == 1);
    CHECK(lua_gettop(state) == 1 && lua_istable(state, -1));
    if (i != 0) {
      CHECK(lua_getglobal(state, libraries[i].name) == LUA_TNIL);
      lua_pop(state, 1);
    }
    if (i == 1) {
      CHECK(lua_getglobal(state, "require") == LUA_TFUNCTION);
      lua_pop(state, 1);
    }
    lua_close(state);
  }
  return 0;
}

static int loaded_cache_and_error(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  luaL_requiref(state, LUA_TABLIBNAME, luaopen_table, 1);
  CHECK(lua_gettop(state) == 1 && lua_istable(state, -1));
  luaL_requiref(state, LUA_TABLIBNAME, luaopen_table, 1);
  CHECK(lua_gettop(state) == 2 && lua_rawequal(state, -1, -2));
  lua_pop(state, 2);
  lua_pushcfunction(state, call_broken);
  CHECK(lua_pcall(state, 0, 1, 0) != LUA_OK);
  lua_pop(state, 1);
  CHECK(lua_gettop(state) == 0);
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  CHECK(lua_istable(state, -1));
  CHECK(lua_getfield(state, -1, "broken") == LUA_TNIL);
  lua_pop(state, 2);
  CHECK(lua_getglobal(state, "broken") == LUA_TNIL);
  lua_pop(state, 1);
  lua_close(state);
  return 0;
}

static int installer_failure_and_retry(void) {
  for (int point = 2; point <= 4; point += 2) {
    lua_State *state = luaL_newstate();
    CHECK(state != NULL);
    installer_failure_point = point;  /* 安裝配置與 C stack 保活 root。 */
    lua_pushcfunction(state, call_failing_table);
    CHECK(lua_pcall(state, 0, 1, 0) != LUA_OK);
    lua_pop(state, 1);
    CHECK(lua_gettop(state) == 0);
    lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
    CHECK(lua_istable(state, -1));
    CHECK(lua_getfield(state, -1, LUA_TABLIBNAME) == LUA_TNIL);
    lua_pop(state, 2);
    CHECK(lua_getglobal(state, LUA_TABLIBNAME) == LUA_TNIL);
    lua_pop(state, 1);
    luaL_requiref(state, LUA_TABLIBNAME, luaopen_table, 1);
    CHECK(lua_istable(state, -1));
    lua_pop(state, 1);
    lua_gc(state, LUA_GCCOLLECT, 0);
    CHECK(lua_gettop(state) == 0);
    lua_close(state);
  }
  return 0;
}

static int open_all_and_gc(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  CHECK(lua_getglobal(state, LUA_TABLIBNAME) == LUA_TNIL);
  lua_pop(state, 1);
  luaL_openlibs(state);
  CHECK(lua_gettop(state) == 0);
  for (unsigned i = 0; i < sizeof(libraries) / sizeof(libraries[0]); i++) {
    CHECK(lua_getglobal(state, libraries[i].name) == LUA_TTABLE);
    lua_pop(state, 1);
  }
  lua_getglobal(state, LUA_LOADLIBNAME);
  lua_getfield(state, -1, "loaded");
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  CHECK(lua_rawequal(state, -1, -2));
  lua_pop(state, 2);
  lua_getfield(state, -1, "preload");
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_PRELOAD_TABLE);
  CHECK(lua_rawequal(state, -1, -2));
  lua_pop(state, 3);
  lua_gc(state, LUA_GCCOLLECT, 0);
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  CHECK(lua_istable(state, -1));
  lua_getfield(state, -1, LUA_TABLIBNAME);
  CHECK(lua_istable(state, -1));
  lua_getglobal(state, LUA_TABLIBNAME);
  CHECK(lua_rawequal(state, -1, -2));
  lua_pop(state, 3);
  CHECK(lua_gettop(state) == 0);
  lua_close(state);
  return 0;
}

#if LUA_VERSION_NUM >= 505
static int selected_and_preloaded(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  luaL_openselectedlibs(state, LUA_GLIBK | LUA_LOADLIBK | LUA_TABLIBK,
                        LUA_STRLIBK | LUA_TABLIBK);
  CHECK(lua_gettop(state) == 0);
  CHECK(lua_getglobal(state, LUA_TABLIBNAME) == LUA_TTABLE);
  lua_pop(state, 1);
  CHECK(lua_getglobal(state, LUA_STRLIBNAME) == LUA_TNIL);
  lua_pop(state, 1);
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_PRELOAD_TABLE);
  CHECK(lua_istable(state, -1));
  CHECK(lua_getfield(state, -1, LUA_STRLIBNAME) == LUA_TFUNCTION);
  lua_pop(state, 1);
  CHECK(lua_getfield(state, -1, LUA_TABLIBNAME) == LUA_TNIL);
  lua_pop(state, 2);
  lua_getglobal(state, "require");
  lua_pushstring(state, LUA_STRLIBNAME);
  lua_call(state, 1, 1);
  CHECK(lua_istable(state, -1));
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  lua_getfield(state, -1, LUA_STRLIBNAME);
  CHECK(lua_rawequal(state, -1, -3));
  lua_pop(state, 3);
  CHECK(lua_gettop(state) == 0);
  lua_close(state);
  return 0;
}
#endif

int main(void) {
  int result = direct_resume_parent_yieldability();
  if (result != 0) return result;
  result = nested_yieldability_public_callbacks();
  if (result != 0) return result;
  result = main_callback_resumes_child();
  if (result != 0) return result;
  result = direct_openers();
  if (result != 0) return result;
  result = loaded_cache_and_error();
  if (result != 0) return result;
  result = installer_failure_and_retry();
  if (result != 0) return result;
  result = open_all_and_gc();
  if (result != 0) return result;
  result = capi_type_metatable_reaches_guest();
  if (result != 0) return result;
#if LUA_VERSION_NUM >= 505
  result = child_self_close_direct_resume();
  if (result != 0) return result;
  result = selected_and_preloaded();
  if (result != 0) return result;
#endif
  return 0;
}
