/* P16 固定 SDK 的真動態模組；marker 由 build argv 固定，不讀環境變數。 */
#include <lauxlib.h>
#include <lua.h>
#include <rivetlua_abi.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef RV_MARKER_PATH
#error "測試須固定 constructor marker 絕對路徑"
#endif
#ifndef RV_CASE_KIND
#define RV_CASE_KIND 0
#endif

#if RV_CASE_KIND == 0 || RV_CASE_KIND == 3 || RV_CASE_KIND == 5
static int rivetlua_fixture_callback(lua_State *state) {
#if RV_CASE_KIND == 5
  lua_newtable(state);
  return 1;
#else
  static const char raw_bytes[] = {0, (char)0xff, 'A'};
  lua_pushnil(state);
  lua_pushboolean(state, 0);
  lua_pushinteger(state, 123);
  lua_pushnumber(state, 1.25);
  lua_pushlstring(state, raw_bytes, sizeof(raw_bytes));
  return 5;
#endif
}
#endif

static void rivetlua_fixture_record(const char *path, const char *text) {
  FILE *file = fopen(path, "wb");
  if (file == NULL) return;
  (void)fputs(text, file);
  (void)fclose(file);
}

#if RV_CASE_KIND == 6
static void rivetlua_fixture_append_order(const char *text) {
  FILE *file = fopen(RV_MARKER_PATH ".order", "ab");
  if (file == NULL) return;
  (void)fputs(text, file);
  (void)fclose(file);
}

static int rivetlua_fixture_finalizer(lua_State *state) {
  (void)state;
  rivetlua_fixture_record(RV_MARKER_PATH ".finalizer", "finalizer\n");
  rivetlua_fixture_append_order("finalizer\n");
  return 0;
}
#endif

__attribute__((constructor)) static void rivetlua_fixture_constructor(void) {
  rivetlua_fixture_record(RV_MARKER_PATH, "constructor\n");
#if RV_CASE_KIND == 6
  rivetlua_fixture_append_order("constructor\n");
#endif
}

__attribute__((destructor)) static void rivetlua_fixture_destructor(void) {
  rivetlua_fixture_record(RV_MARKER_PATH ".dtor", "destructor\n");
#if RV_CASE_KIND == 6
  rivetlua_fixture_append_order("destructor\n");
#endif
}

#if RV_CASE_KIND == 1
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  (void)state;
  abort();
}
#elif RV_CASE_KIND == 2
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  (void)state;
  for (;;) { }
}
#elif RV_CASE_KIND == 3
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  (void)fputs("NOISY-NATIVE-STDOUT\n", stdout);
  (void)fflush(stdout);
  lua_pushcfunction(state, rivetlua_fixture_callback);
  return 1;
}
#elif RV_CASE_KIND == 4
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  (void)state;
  return 0;
}
#elif RV_CASE_KIND == 0 || RV_CASE_KIND == 5
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  lua_pushcfunction(state, rivetlua_fixture_callback);
  return 1;
}
#elif RV_CASE_KIND == 6
int luaopen_rivetlua_p16_fixture(lua_State *state) {
  (void)lua_newuserdatauv(state, 1, 0);
  lua_createtable(state, 0, 1);
  lua_pushcfunction(state, rivetlua_fixture_finalizer);
  lua_setfield(state, -2, "__gc");
  (void)lua_setmetatable(state, -2);
  return 1;
}
#else
#error "未知的測試模式"
#endif
