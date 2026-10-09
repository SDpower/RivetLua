#define LUA_COMPAT_APIINTCASTS
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>
#include <string.h>

/* 測試夾具只建立已驗證的 Lua closure 並注入單次配置失敗；行為仍走公開 C API。 */
extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);
extern int rivetlua_capi_test_inject_next_allocation_a2(lua_State *state);
extern uint64_t rivetlua_capi_test_current_ordinal_a4a(lua_State *state);

static int fail_next_name_allocation = 1;

static int increment_cell(lua_State *state) {
  int index = lua_upvalueindex(1);
  if (lua_type(state, lua_upvalueindex(2)) != LUA_TNONE) return 0;
  lua_pushvalue(state, lua_upvalueindex(2));
  if (lua_type(state, -1) != LUA_TNIL) return 0;
  lua_pop(state, 1);
  lua_Integer current = lua_tointeger(state, index);
  lua_pushinteger(state, current + 1);
  lua_copy(state, -1, index);
  lua_replace(state, index);
  lua_pushvalue(state, index);
  lua_setglobal(state, "a4b_live_capture");
  lua_settop(state, 0);
  lua_pushvalue(state, index);
  return 1;
}

static int invalid_destination(lua_State *state) {
  lua_pushinteger(state, 1);
  lua_copy(state, -1, lua_upvalueindex(256));
  return 0;
}

static int invalid_source(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(256));
  return 0;
}

static int plain_function_read(lua_State *state) {
  if (lua_type(state, lua_upvalueindex(1)) != LUA_TNONE) return 0;
  lua_pushvalue(state, lua_upvalueindex(1));
  if (lua_type(state, -1) != LUA_TNIL) return 0;
  return 1;
}

static int plain_function_write(lua_State *state) {
  lua_pushinteger(state, 9);
  lua_copy(state, -1, lua_upvalueindex(1));
  return 0;
}

static int edge_255(lua_State *state) {
  if (lua_type(state, lua_upvalueindex(1)) != LUA_TNUMBER) return 0;
  if (lua_type(state, lua_upvalueindex(255)) != LUA_TNUMBER) return 0;
  if (lua_type(state, lua_upvalueindex(256)) != LUA_TNONE) return 0;
  lua_pushvalue(state, lua_upvalueindex(255));
  return 1;
}

static int inner_cell(lua_State *state) {
  if (lua_tointeger(state, lua_upvalueindex(1)) != 41) return 0;
  lua_pushinteger(state, 42);
  lua_copy(state, -1, lua_upvalueindex(1));
  lua_pop(state, 1);
  return 0;
}

static int outer_cell(lua_State *state) {
  if (lua_tointeger(state, lua_upvalueindex(1)) != 17) return 0;
  lua_pushinteger(state, 41);
  lua_pushcclosure(state, inner_cell, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_OK) return 0;
  if (lua_tointeger(state, lua_upvalueindex(1)) != 17) return 0;
  lua_pushvalue(state, lua_upvalueindex(1));
  return 1;
}

static int scalar_cells(lua_State *state) {
#define CHECK_SCALAR(condition) do { if (!(condition)) return 0; } while (0)
  size_t length = 0;
  const char *number = luaL_checklstring(state, lua_upvalueindex(1), &length);
  const char *binary = luaL_checklstring(state, lua_upvalueindex(2), &length);
  CHECK_SCALAR(number != NULL && memcmp(number, "123", 3) == 0);
  CHECK_SCALAR(binary != NULL && length == 3 && memcmp(binary, "a\0b", 3) == 0);
  CHECK_SCALAR(lua_type(state, lua_upvalueindex(1)) == LUA_TSTRING);
  CHECK_SCALAR(!lua_isinteger(state, lua_upvalueindex(1)));
  CHECK_SCALAR(luaL_checknumber(state, lua_upvalueindex(1)) == 123.0);
  CHECK_SCALAR(luaL_checkinteger(state, lua_upvalueindex(1)) == 123);
#if LUA_VERSION_NUM < 505
  CHECK_SCALAR(lua_tounsignedx(state, lua_upvalueindex(1), NULL) == 123);
  CHECK_SCALAR(lua_tounsigned(state, lua_upvalueindex(1)) == 123);
#endif
  CHECK_SCALAR(luaL_optnumber(state, lua_upvalueindex(4), 7.0) == 7.0);
  CHECK_SCALAR(luaL_optinteger(state, lua_upvalueindex(4), 9) == 9);
  CHECK_SCALAR(strcmp(luaL_optstring(state, lua_upvalueindex(4), "default"), "default") == 0);
  CHECK_SCALAR(lua_toboolean(state, lua_upvalueindex(3)));
  CHECK_SCALAR(lua_topointer(state, lua_upvalueindex(2)) != NULL);
  lua_pushinteger(state, 1);
  return 1;
#undef CHECK_SCALAR
}

static int string_copy_history(lua_State *state) {
  size_t length = 0;
  lua_pushvalue(state, lua_upvalueindex(1)); /* A 的正式存活 root。 */
  const char *a = luaL_checklstring(state, lua_upvalueindex(1), &length);
  if (a == NULL || length != 5 || memcmp(a, "alpha", 5) != 0) return 0;
  uint64_t ordinal = rivetlua_capi_test_current_ordinal_a4a(state);
  for (int i = 0; i < 8; i++)
    if (luaL_checklstring(state, lua_upvalueindex(1), NULL) != a) return 0;
  if (rivetlua_capi_test_current_ordinal_a4a(state) != ordinal) return 0;
  lua_pushstring(state, "bravo");
  lua_copy(state, -1, lua_upvalueindex(1));
  lua_pop(state, 1);
  const char *b = luaL_checklstring(state, lua_upvalueindex(1), &length);
  if (b == NULL || b == a || length != 5 || memcmp(b, "bravo", 5) != 0 ||
      memcmp(a, "alpha", 5) != 0) return 0;
  ordinal = rivetlua_capi_test_current_ordinal_a4a(state);
  for (int i = 0; i < 8; i++)
    if (luaL_checklstring(state, lua_upvalueindex(1), NULL) != b) return 0;
  if (rivetlua_capi_test_current_ordinal_a4a(state) != ordinal) return 0;
  lua_settop(state, 0);
  lua_pushinteger(state, 1);
  return 1;
}

static int string_setup_history(lua_State *state) {
  size_t length = 0;
  lua_pushvalue(state, lua_upvalueindex(1)); /* 保住被替換的 A。 */
  const char *a = luaL_checklstring(state, lua_upvalueindex(1), &length);
  if (a == NULL || length != 5 || memcmp(a, "alpha", 5) != 0) return 0;
  lua_getglobal(state, "a4b_setup_history");
  lua_pushstring(state, "charlie");
  if (lua_setupvalue(state, -2, 1) == NULL) return 0;
  lua_pop(state, 1);
  const char *b = luaL_checklstring(state, lua_upvalueindex(1), &length);
  if (b == NULL || b == a || length != 7 || memcmp(b, "charlie", 7) != 0 ||
      memcmp(a, "alpha", 5) != 0) return 0;
  uint64_t ordinal = rivetlua_capi_test_current_ordinal_a4a(state);
  for (int i = 0; i < 8; i++)
    if (luaL_checklstring(state, lua_upvalueindex(1), NULL) != b) return 0;
  if (rivetlua_capi_test_current_ordinal_a4a(state) != ordinal) return 0;
  lua_settop(state, 0);
  lua_pushinteger(state, 1);
  return 1;
}

static int table_function(lua_State *state) {
  lua_pushinteger(state, 7);
  return 1;
}

static int function_value_cell(lua_State *state) {
  if (lua_type(state, lua_upvalueindex(1)) == LUA_TNUMBER) {
    lua_pushcfunction(state, table_function);
    lua_copy(state, -1, lua_upvalueindex(1));
    lua_pop(state, 1);
  }
  if (!lua_iscfunction(state, lua_upvalueindex(1)) ||
      lua_tocfunction(state, lua_upvalueindex(1)) != table_function) return 0;
  lua_pushvalue(state, lua_upvalueindex(1));
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 0;
  return 1;
}

static int thread_value_cell(lua_State *state) {
  if (lua_type(state, lua_upvalueindex(1)) != LUA_TTHREAD ||
      lua_topointer(state, lua_upvalueindex(1)) == NULL) return 0;
  lua_pushvalue(state, lua_upvalueindex(1));
  return 1;
}

static int table_cell(lua_State *state) {
  static const luaL_Reg functions[] = {{"f", table_function}, {NULL, NULL}};
#define CHECK_TABLE(condition) do { if (!(condition)) return 0; } while (0)
  int reference;
  CHECK_TABLE(lua_getfield(state, lua_upvalueindex(1), "a") == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);
  lua_pushstring(state, "a");
  CHECK_TABLE(lua_gettable(state, lua_upvalueindex(1)) == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);
  CHECK_TABLE(lua_geti(state, lua_upvalueindex(1), 1) == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 50);
  lua_pop(state, 1);
  lua_pushinteger(state, 43);
  lua_setfield(state, lua_upvalueindex(1), "a");
  lua_pushstring(state, "b");
  lua_pushinteger(state, 44);
  lua_settable(state, lua_upvalueindex(1));
  lua_pushinteger(state, 45);
  lua_seti(state, lua_upvalueindex(1), 2);
  CHECK_TABLE(luaL_getsubtable(state, lua_upvalueindex(1), "sub") == 0);
  lua_pop(state, 1);
  CHECK_TABLE(luaL_getsubtable(state, lua_upvalueindex(1), "sub") == 1);
  lua_pop(state, 1);
  lua_pushnil(state);
  lua_seti(state, lua_upvalueindex(1), 1);
  lua_pushinteger(state, 99);
  reference = luaL_ref(state, lua_upvalueindex(1));
  CHECK_TABLE(reference > 0);
  CHECK_TABLE(lua_rawgeti(state, lua_upvalueindex(1), reference) == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 99);
  lua_pop(state, 1);
  luaL_unref(state, lua_upvalueindex(1), reference);
  lua_pushvalue(state, lua_upvalueindex(1));
  luaL_setfuncs(state, functions, 0);
  lua_pop(state, 1);
  CHECK_TABLE(lua_getfield(state, lua_upvalueindex(1), "f") == LUA_TFUNCTION);
  CHECK_TABLE(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK_TABLE(lua_tointeger(state, -1) == 7);
  lua_pop(state, 1);
  lua_newtable(state);
  lua_pushinteger(state, 8);
  lua_setfield(state, -2, "__index");
  CHECK_TABLE(lua_setmetatable(state, lua_upvalueindex(1)) == 1);
  CHECK_TABLE(lua_getmetatable(state, lua_upvalueindex(1)) == 1);
  lua_pop(state, 1);
  CHECK_TABLE(luaL_getmetafield(state, lua_upvalueindex(1), "__index") == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 8);
  lua_pop(state, 1);
  CHECK_TABLE(lua_getfield(state, lua_upvalueindex(1), "a") == LUA_TNUMBER);
  CHECK_TABLE(lua_tointeger(state, -1) == 43);
  lua_pop(state, 1);
  lua_pushinteger(state, 1);
  return 1;
#undef CHECK_TABLE
}

static int userdata_cell(lua_State *state) {
  if (luaL_testudata(state, lua_upvalueindex(1), "a4b_userdata") == NULL) return 0;
  if (lua_getiuservalue(state, lua_upvalueindex(1), 1) != LUA_TNUMBER) return 0;
  if (lua_tointeger(state, -1) != 5) return 0;
  lua_pop(state, 1);
  lua_pushinteger(state, 6);
  if (lua_setiuservalue(state, lua_upvalueindex(1), 1) != 1) return 0;
  if (lua_getuservalue(state, lua_upvalueindex(1)) != LUA_TNUMBER) return 0;
  if (lua_tointeger(state, -1) != 6) return 0;
  lua_pop(state, 1);
  lua_pushinteger(state, 7);
  lua_setuservalue(state, lua_upvalueindex(1));
  if (lua_getuservalue(state, lua_upvalueindex(1)) != LUA_TNUMBER) return 0;
  if (lua_tointeger(state, -1) != 7) return 0;
  lua_pop(state, 1);
  if (lua_getmetatable(state, lua_upvalueindex(1)) != 1) return 0;
  lua_pop(state, 1);
  lua_pushinteger(state, 1);
  return 1;
}

static int invalid_join(lua_State *state) {
  lua_upvaluejoin(state, lua_upvalueindex(1), 1, lua_upvalueindex(1), 1);
  return 0;
}

static int invalid_lua_join(lua_State *state) {
  lua_upvaluejoin(state, lua_upvalueindex(1), 2,
                lua_upvalueindex(2), 1);
  return 0;
}

static int invalid_ref(lua_State *state) {
  lua_pushinteger(state, 99);
  (void)luaL_ref(state, lua_upvalueindex(1));
  return 0;
}

static int bad_check_string(lua_State *state) {
  (void)luaL_checklstring(state, lua_upvalueindex(1), NULL);
  return 0;
}

static int bad_check_number(lua_State *state) {
  (void)luaL_checknumber(state, lua_upvalueindex(1));
  return 0;
}

static int bad_check_integer(lua_State *state) {
  (void)luaL_checkinteger(state, lua_upvalueindex(1));
  return 0;
}

static int bad_opt_string(lua_State *state) {
  (void)luaL_optlstring(state, lua_upvalueindex(1), "default", NULL);
  return 0;
}

static int bad_opt_number(lua_State *state) {
  (void)luaL_optnumber(state, lua_upvalueindex(1), 7.0);
  return 0;
}

static int bad_opt_integer(lua_State *state) {
  (void)luaL_optinteger(state, lua_upvalueindex(1), 7);
  return 0;
}

static int captured_function_index(lua_State *state) {
  if (!lua_iscfunction(state, lua_upvalueindex(1)) ||
      lua_tocfunction(state, lua_upvalueindex(1)) != increment_cell) return 0;
  const char *name = lua_getupvalue(state, lua_upvalueindex(1), 1);
  if (name == NULL || name[0] != '\0') return 0;
  if (lua_tointeger(state, -1) != 17) return 0;
  lua_pop(state, 1);
  void *identity = lua_upvalueid(state, lua_upvalueindex(1), 1);
  if (identity == NULL || lua_upvalueid(state, lua_upvalueindex(1), 2) != NULL)
    return 0;
  int top = lua_gettop(state);
  if (lua_getupvalue(state, lua_upvalueindex(1), 2) != NULL ||
      lua_gettop(state) != top) return 0;
  lua_pushinteger(state, 29);
  if (lua_setupvalue(state, lua_upvalueindex(1), 2) != NULL ||
      lua_gettop(state) != top + 1) return 0;
  if (lua_setupvalue(state, lua_upvalueindex(1), 1) == NULL ||
      lua_gettop(state) != top) return 0;
  if (lua_upvalueid(state, lua_upvalueindex(1), 1) != identity) return 0;
  lua_pushvalue(state, lua_upvalueindex(1));
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_tointeger(state, -1) != 30) return 0;
  return 1;
}

static int named_lua_capture(lua_State *state) {
  if (fail_next_name_allocation) {
    fail_next_name_allocation = 0;
    if (!rivetlua_capi_test_inject_next_allocation_a2(state)) return 0;
  }
  if (lua_getupvalue(state, lua_upvalueindex(1), 1) == NULL) return 0;
  return 1;
}

static int check_aux_failure(lua_State *state, lua_CFunction function, int fraction) {
  if (fraction) lua_pushnumber(state, 1.5);
  else lua_pushboolean(state, 1);
  lua_pushcclosure(state, function, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 0;
  if (lua_type(state, -1) != LUA_TSTRING) return 0;
  if (fraction && strstr(lua_tostring(state, -1), "integer representation") == NULL)
    return 0;
  lua_settop(state, 0);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  int expected;
  if (state == NULL) return 1;
  lua_pushinteger(state, 17);
  lua_pushcclosure(state, increment_cell, 1);
  for (expected = 18; expected <= 19; expected++) {
    lua_pushvalue(state, 1);
    if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 2;
    if (lua_tointeger(state, -1) != expected) return 3;
    lua_settop(state, 1);
  }
  lua_pushcfunction(state, invalid_destination);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 4;
  if (lua_gettop(state) != 2 || lua_type(state, -1) != LUA_TSTRING) return 5;
  lua_settop(state, 1);
  lua_pushvalue(state, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 6;
  if (lua_tointeger(state, -1) != 20) return 7;
  lua_settop(state, 1);
  lua_pushcfunction(state, invalid_source);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 8;
  if (lua_gettop(state) != 2 || lua_type(state, -1) != LUA_TSTRING) return 9;
  lua_settop(state, 1);
  for (expected = 1; expected <= 255; expected++) lua_pushinteger(state, expected);
  lua_pushcclosure(state, edge_255, 255);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 10;
  if (lua_tointeger(state, -1) != 255) return 11;
  lua_settop(state, 0);
  if (lua_type(state, lua_upvalueindex(1)) != LUA_TNONE) return 41;
  lua_settop(state, 0);
  lua_pushcfunction(state, plain_function_read);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK || lua_type(state, -1) != LUA_TNIL)
    return 43;
  lua_settop(state, 0);
  lua_pushcfunction(state, plain_function_write);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN ||
      lua_type(state, -1) != LUA_TSTRING) return 44;
  lua_settop(state, 0);
  lua_pushinteger(state, 17);
  lua_pushcclosure(state, outer_cell, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 12;
  if (lua_tointeger(state, -1) != 17) return 13;
  lua_settop(state, 0);
  lua_pushinteger(state, 123);
  lua_pushlstring(state, "a\0b", 3);
  lua_pushboolean(state, 1);
  lua_pushcclosure(state, scalar_cells, 3);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 14;
  if (lua_tointeger(state, -1) != 1) return 15;
  lua_settop(state, 0);
  lua_pushstring(state, "alpha");
  lua_pushcclosure(state, string_copy_history, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK || lua_tointeger(state, -1) != 1)
    return 47;
  lua_settop(state, 0);
  lua_pushstring(state, "alpha");
  lua_pushcclosure(state, string_setup_history, 1);
  lua_pushvalue(state, 1);
  lua_setglobal(state, "a4b_setup_history");
  if (lua_pcall(state, 0, 1, 0) != LUA_OK || lua_tointeger(state, -1) != 1)
    return 48;
  lua_settop(state, 0);
  lua_pushnil(state);
  lua_setglobal(state, "a4b_setup_history");
  lua_newtable(state);
  lua_pushinteger(state, 42);
  lua_setfield(state, -2, "a");
  lua_pushinteger(state, 50);
  lua_seti(state, -2, 1);
  lua_pushcclosure(state, table_cell, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 16;
  if (lua_tointeger(state, -1) != 1) return 17;
  lua_settop(state, 0);
  if (luaL_newmetatable(state, "a4b_userdata") != 1) return 18;
  lua_pop(state, 1);
  if (lua_newuserdatauv(state, 4, 1) == NULL) return 19;
  luaL_setmetatable(state, "a4b_userdata");
  lua_pushinteger(state, 5);
  if (lua_setiuservalue(state, -2, 1) != 1) return 20;
  lua_pushcclosure(state, userdata_cell, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 21;
  if (lua_tointeger(state, -1) != 1) return 22;
  lua_settop(state, 0);
  lua_pushinteger(state, 1);
  lua_pushcclosure(state, increment_cell, 1);
  lua_pushcclosure(state, invalid_join, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 23;
  if (lua_gettop(state) != 1 || lua_type(state, -1) != LUA_TSTRING) return 24;
  lua_settop(state, 0);
  if (rivetlua_capi_test_push_lua_b4(state, 6) != 1 ||
      rivetlua_capi_test_push_lua_b4(state, 7) != 1) return 45;
  lua_pushcclosure(state, invalid_lua_join, 2);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN ||
      lua_type(state, -1) != LUA_TSTRING) return 46;
  lua_settop(state, 0);
  lua_newtable(state);
  lua_pushinteger(state, 50);
#if LUA_VERSION_NUM >= 505
  lua_seti(state, -2, 1);
#else
  lua_seti(state, -2, 3);
#endif
  lua_pushcclosure(state, invalid_ref, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 25;
  if (lua_gettop(state) != 1 || lua_type(state, -1) != LUA_TSTRING) return 26;
  lua_settop(state, 0);
  if (!check_aux_failure(state, bad_check_string, 0)) return 27;
  if (!check_aux_failure(state, bad_check_number, 0)) return 28;
  if (!check_aux_failure(state, bad_check_integer, 1)) return 29;
  if (!check_aux_failure(state, bad_opt_string, 0)) return 30;
  if (!check_aux_failure(state, bad_opt_number, 0)) return 31;
  if (!check_aux_failure(state, bad_opt_integer, 1)) return 32;
  lua_pushinteger(state, 17);
  lua_pushcclosure(state, increment_cell, 1);
  lua_pushcclosure(state, captured_function_index, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_tointeger(state, -1) != 30) return 33;
  lua_settop(state, 0);
  if (rivetlua_capi_test_push_lua_b4(state, 6) != 1) return 34;
  lua_pushcclosure(state, named_lua_capture, 1);
  lua_pushvalue(state, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_ERRMEM) return 35;
  if (lua_gettop(state) != 2 || lua_type(state, -1) != LUA_TSTRING) return 36;
  lua_settop(state, 1);
  lua_pushvalue(state, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_tointeger(state, -1) != 17) return 37;
  lua_settop(state, 0);
  lua_pushinteger(state, 1);
  lua_pushcclosure(state, function_value_cell, 1);
  for (expected = 0; expected < 2; expected++) {
    lua_pushvalue(state, 1);
    if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
        lua_tointeger(state, -1) != 7) return 38;
    lua_settop(state, 1);
  }
  lua_settop(state, 0);
  if (lua_newthread(state) == NULL) return 39;
  lua_pushcclosure(state, thread_value_cell, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_type(state, -1) != LUA_TTHREAD) return 40;
  lua_close(state);
  return 0;
}
