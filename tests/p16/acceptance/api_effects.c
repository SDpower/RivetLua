#include "lua.h"
#include "lauxlib.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static lua_State *state;
static int pointer_key;

static int failure(const char *name) {
  fprintf(stderr, "P16_C_EFFECT %s FAIL\n", name);
  lua_close(state);
  return 1;
}

#define CHECK(name, condition) do { \
  if (!(condition)) return failure(name); \
  printf("P16_C_EFFECT %s PASS\n", name); \
} while (0)

#define CLEAR() lua_settop(state, 0)

static int dummy(lua_State *L) {
  lua_pushinteger(L, 1);
  return 1;
}

static int bad_type(lua_State *L) {
  return luaL_typeerror(L, 1, "number");
}

static int bad_arg(lua_State *L) {
  return luaL_argerror(L, 1, "p16-arg");
}

static int bad_check(lua_State *L) {
  luaL_argcheck(L, 0, 1, "p16-check");
  return 0;
}

static int bad_expected(lua_State *L) {
  luaL_argexpected(L, 0, 1, "number");
  return 0;
}

static int bad_aux_error(lua_State *L) {
  return luaL_error(L, "p16-aux-error");
}

static int bad_error(lua_State *L) {
  lua_pushstring(L, "p16-error");
  return lua_error(L);
}

static int upvalue_echo(lua_State *L) {
  lua_pushvalue(L, lua_upvalueindex(1));
  return 1;
}

static int yielding(lua_State *L) {
  lua_pushinteger(L, 41);
  return lua_yield(L, 1);
}

static int yield_cont(lua_State *L, int status, lua_KContext ctx) {
  (void)status;
  lua_pushinteger(L, (lua_Integer)ctx);
  return 1;
}

static int yielding_k(lua_State *L) {
  lua_pushinteger(L, 42);
  return lua_yieldk(L, 1, 99, yield_cont);
}

static int check_stack_and_types(void) {
  int isnum = 0;
  size_t len = 0;
  const char *string;
  CLEAR();
  lua_pushinteger(state, 10);
  lua_pushinteger(state, 20);
  CHECK("lua_absindex", lua_absindex(state, -1) == 2);
  CHECK("lua_gettop", lua_gettop(state) == 2);
  lua_settop(state, 1);
  CHECK("lua_settop", lua_gettop(state) == 1);
  CHECK("lua_checkstack", lua_checkstack(state, 8) == 1 && lua_gettop(state) == 1);
  CHECK("lua_version", lua_version(state) == LUA_VERSION_NUM && lua_version(NULL) == LUA_VERSION_NUM);
  CHECK("lua_isnumber", lua_isnumber(state, 1) == 1);
  CHECK("lua_isstring", lua_isstring(state, 1) == 1);
  CHECK("lua_typename", strcmp(lua_typename(state, LUA_TNUMBER), "number") == 0);
  CHECK("luaL_typename", strcmp(luaL_typename(state, 1), "number") == 0);
  CHECK("lua_tonumber", lua_tonumber(state, 1) == 10.0);
  CHECK("lua_tointeger", lua_tointeger(state, 1) == 10);
  CHECK("lua_tonumberx", lua_tonumberx(state, 1, &isnum) == 10.0 && isnum == 1);
  isnum = 0;
  CHECK("lua_tointegerx", lua_tointegerx(state, 1, &isnum) == 10 && isnum == 1);
  CLEAR();
  lua_pushinteger(state, 123);
  string = lua_tolstring(state, -1, &len);
  CHECK("lua_tolstring", string != NULL && len == 3 && memcmp(string, "123", 3) == 0);
  CHECK("lua_tostring", strcmp(lua_tostring(state, -1), "123") == 0);
  CHECK("lua_strlen", lua_strlen(state, -1) == 3);
  CHECK("lua_objlen", lua_objlen(state, -1) == 3);
  CHECK("lua_rawlen", lua_rawlen(state, -1) == 3);
  CLEAR();
  lua_pushnil(state);
  CHECK("lua_isnil", lua_isnil(state, -1) == 1);
  CHECK("lua_isnone", lua_isnone(state, 2) == 1);
  CHECK("lua_isnoneornil", lua_isnoneornil(state, -1) == 1 && lua_isnoneornil(state, 2) == 1);
  CLEAR();
  lua_pushboolean(state, 1);
  CHECK("lua_isboolean", lua_isboolean(state, -1) == 1);
  CLEAR();
  lua_pushlightuserdata(state, &pointer_key);
  CHECK("lua_islightuserdata", lua_islightuserdata(state, -1) == 1);
  CHECK("lua_isuserdata", lua_isuserdata(state, -1) == 1);
  CLEAR();
  lua_newtable(state);
  CHECK("lua_newtable", lua_istable(state, -1) == 1);
  CHECK("lua_istable", lua_istable(state, -1) == 1);
  CLEAR();
  lua_pushcfunction(state, dummy);
  CHECK("lua_isfunction", lua_isfunction(state, -1) == 1);
  CLEAR();
  lua_pushthread(state);
  CHECK("lua_isthread", lua_isthread(state, -1) == 1);
  CLEAR();
  lua_pushglobaltable(state);
  CHECK("lua_pushglobaltable", lua_istable(state, -1) == 1);
  CLEAR();
  lua_pushliteral(state, "literal");
  CHECK("lua_pushliteral", strcmp(lua_tostring(state, -1), "literal") == 0);
  CLEAR();
  lua_pushlstring(state, "a\0b", 3);
  CHECK("lua_pushlstring", lua_rawlen(state, -1) == 3);
  CLEAR();
  lua_pushstring(state, "p16");
  CHECK("lua_pushstring", strcmp(lua_tostring(state, -1), "p16") == 0);
  {
    unsigned char marker = 0xa5;
    unsigned char observed = 0;
    if (LUA_EXTRASPACE < sizeof(marker)) return failure("lua_getextraspace");
    memcpy(lua_getextraspace(state), &marker, sizeof(marker));
    memcpy(&observed, lua_getextraspace(state), sizeof(observed));
    CHECK("lua_getextraspace", observed == marker && lua_gettop(state) == 1 && lua_type(state, -1) == LUA_TSTRING);
  }
  CLEAR();
  lua_pushinteger(state, 4);
  lua_pushinteger(state, 4);
  CHECK("lua_rawequal", lua_rawequal(state, -1, -2) == 1);
  return 0;
}

static int check_raw_tables(void) {
  CLEAR();
  lua_createtable(state, 0, 4);
  CHECK("lua_createtable", lua_istable(state, 1) == 1);
  lua_pushstring(state, "key");
  lua_pushinteger(state, 11);
  lua_rawset(state, 1);
  lua_pushstring(state, "key");
  CHECK("lua_rawset", lua_rawget(state, 1) == LUA_TNUMBER && lua_tointeger(state, -1) == 11);
  lua_pop(state, 1);
  lua_pushstring(state, "key");
  CHECK("lua_rawget", lua_rawget(state, 1) == LUA_TNUMBER && lua_tointeger(state, -1) == 11);
  lua_pop(state, 1);
  lua_pushinteger(state, 23);
  lua_rawseti(state, 1, 7);
  CHECK("lua_rawseti", lua_rawgeti(state, 1, 7) == LUA_TNUMBER && lua_tointeger(state, -1) == 23);
  lua_pop(state, 1);
  CHECK("lua_rawgeti", lua_rawgeti(state, 1, 7) == LUA_TNUMBER && lua_tointeger(state, -1) == 23);
  lua_pop(state, 1);
  lua_pushinteger(state, 31);
  lua_rawsetp(state, 1, &pointer_key);
  CHECK("lua_rawsetp", lua_rawgetp(state, 1, &pointer_key) == LUA_TNUMBER && lua_tointeger(state, -1) == 31);
  lua_pop(state, 1);
  CHECK("lua_rawgetp", lua_rawgetp(state, 1, &pointer_key) == LUA_TNUMBER && lua_tointeger(state, -1) == 31);
  return 0;
}

static int check_auxiliary(void) {
  static const luaL_Reg functions[] = {{"dummy", dummy}, {NULL, NULL}};
  luaL_Buffer buffer;
  char *destination;
  CLEAR();
  lua_pushinteger(state, 23);
  CHECK("luaL_checkunsigned", luaL_checkunsigned(state, 1) == 23);
  CHECK("luaL_optunsigned", luaL_optunsigned(state, 2, 17) == 17);
  CHECK("luaL_checkint", luaL_checkint(state, 1) == 23);
  CHECK("luaL_optint", luaL_optint(state, 2, 17) == 17);
  CHECK("luaL_checklong", luaL_checklong(state, 1) == 23);
  CHECK("luaL_optlong", luaL_optlong(state, 2, 17) == 17);
  CHECK("luaL_opt", luaL_opt(state, luaL_checkinteger, 2, 17) == 17);
  CLEAR();
  lua_pushstring(state, "hello");
  CHECK("luaL_checkstring", strcmp(luaL_checkstring(state, 1), "hello") == 0);
  CHECK("luaL_optstring", strcmp(luaL_optstring(state, 2, "fallback"), "fallback") == 0);
  CLEAR();
  luaL_newlibtable(state, functions);
  CHECK("luaL_newlibtable", lua_istable(state, -1) == 1);
  CLEAR();
  luaL_newmetatable(state, "p16.api_effects");
  luaL_getmetatable(state, "p16.api_effects");
  CHECK("luaL_getmetatable", lua_rawequal(state, -1, -2) == 1);
  CLEAR();
  luaL_buffinit(state, &buffer);
  CHECK("luaL_buffinit", luaL_bufflen(&buffer) == 0);
  destination = luaL_buffaddr(&buffer);
  CHECK("luaL_buffaddr", destination != NULL);
  memcpy(destination, "abc", 3);
  luaL_addsize(&buffer, 3);
  CHECK("luaL_addsize", luaL_bufflen(&buffer) == 3);
  CHECK("luaL_bufflen", luaL_bufflen(&buffer) == 3);
  luaL_buffsub(&buffer, 1);
  CHECK("luaL_buffsub", luaL_bufflen(&buffer) == 2);
  luaL_pushresult(&buffer);
  CHECK("luaL_buffer_result", lua_rawlen(state, -1) == 2 && memcmp(lua_tostring(state, -1), "ab", 2) == 0);
  CLEAR();
  errno = ENOENT;
  CHECK("luaL_fileresult", luaL_fileresult(state, 0, "p16-missing") == 3 && lua_isnil(state, -3) && lua_isstring(state, -2) && lua_isinteger(state, -1));
  CLEAR();
  CHECK("luaL_execresult", luaL_execresult(state, 0) == 3 && lua_toboolean(state, -3) && lua_isstring(state, -2) && lua_tointeger(state, -1) == 0);
#if LUA_VERSION_NUM >= 505
  {
    unsigned char *data = (unsigned char *)luaL_alloc(NULL, NULL, 0, 16);
    unsigned char *grown;
    CHECK("luaL_alloc", data != NULL);
    data[0] = 0x5a;
    grown = (unsigned char *)luaL_alloc(NULL, data, 16, 32);
    if (grown == NULL) {
      luaL_alloc(NULL, data, 16, 0);
      return failure("luaL_alloc_resize");
    }
    data = grown;
    CHECK("luaL_alloc_resize", data != NULL && data[0] == 0x5a);
    luaL_alloc(NULL, data, 32, 0);
  }
  {
    int before = lua_gettop(state);
    (void)luaL_makeseed(state);
    CHECK("luaL_makeseed", lua_gettop(state) == before);
  }
#endif
  return 0;
}

static int check_special(void) {
  int nresult;
  lua_State *thread;
  CLEAR();
  lua_pushinteger(state, 42);
  CHECK("lua_stringtonumber", lua_stringtonumber(state, "12.5") > 0 && lua_tonumber(state, -1) == 12.5);
#if LUA_VERSION_NUM >= 505
  {
    char text[LUA_N2SBUFFSZ];
    CLEAR();
    lua_pushnumber(state, 3.5);
    CHECK("lua_numbertocstring", lua_numbertocstring(state, -1, text) > 0 && strcmp(text, "3.5") == 0);
  }
#endif
  CLEAR();
  lua_pushinteger(state, 9);
  lua_setglobal(state, "p16-api-effect");
  CHECK("lua_getglobal", lua_getglobal(state, "p16-api-effect") == LUA_TNUMBER && lua_tointeger(state, -1) == 9);
  CLEAR();
  lua_pushinteger(state, 2);
  lua_pushinteger(state, 3);
  CHECK("lua_equal", lua_equal(state, 1, 1) == 1 && lua_equal(state, 1, 2) == 0);
  CHECK("lua_lessthan", lua_lessthan(state, 1, 2) == 1 && lua_lessthan(state, 2, 1) == 0);
  CLEAR();
  lua_pushcfunction(state, bad_type);
  lua_pushnil(state);
  CHECK("luaL_typeerror", lua_pcall(state, 1, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "number") != NULL);
  CLEAR();
  lua_pushcfunction(state, bad_arg);
  CHECK("luaL_argerror", lua_pcall(state, 0, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "p16-arg") != NULL);
  CLEAR();
  lua_pushcfunction(state, bad_check);
  CHECK("luaL_argcheck", lua_pcall(state, 0, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "p16-check") != NULL);
  CLEAR();
  lua_pushcfunction(state, bad_expected);
  lua_pushnil(state);
  CHECK("luaL_argexpected", lua_pcall(state, 1, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "number") != NULL);
  CLEAR();
  lua_pushcfunction(state, bad_aux_error);
  CHECK("luaL_error", lua_pcall(state, 0, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "p16-aux-error") != NULL);
  CLEAR();
  lua_pushcfunction(state, bad_error);
  CHECK("lua_error", lua_pcall(state, 0, 0, 0) == LUA_ERRRUN && lua_isstring(state, -1) && strstr(lua_tostring(state, -1), "p16-error") != NULL);
  CLEAR();
  lua_pushcfunction(state, dummy);
  lua_call(state, 0, 1);
  CHECK("lua_call", lua_gettop(state) == 1 && lua_tointeger(state, -1) == 1);
  CLEAR();
  lua_pushcfunction(state, dummy);
  CHECK("lua_pcall", lua_pcall(state, 0, 1, 0) == LUA_OK && lua_gettop(state) == 1 && lua_tointeger(state, -1) == 1);
  CLEAR();
  lua_pushinteger(state, 73);
  lua_pushcclosure(state, upvalue_echo, 1);
  CHECK("lua_upvalueindex", lua_pcall(state, 0, 1, 0) == LUA_OK && lua_tointeger(state, -1) == 73);
  CLEAR();
  thread = lua_newthread(state);
  if (thread == NULL) return failure("lua_yield");
  lua_pushcfunction(thread, yielding);
  CHECK("lua_yield", lua_resume(thread, state, 0, &nresult) == LUA_YIELD && nresult == 1 && lua_tointeger(thread, -1) == 41);
  CLEAR();
  thread = lua_newthread(state);
  if (thread == NULL) return failure("lua_yieldk");
  lua_pushcfunction(thread, yielding_k);
  if (lua_resume(thread, state, 0, &nresult) != LUA_YIELD || nresult != 1 || lua_tointeger(thread, -1) != 42) return failure("lua_yieldk");
  CHECK("lua_yieldk", lua_resume(thread, state, 0, &nresult) == LUA_OK && nresult == 1 && lua_tointeger(thread, -1) == 99);
#if LUA_VERSION_NUM == 504
  CLEAR();
  CHECK("lua_setcstacklimit", lua_setcstacklimit(state, 200) != 0);
#endif
  return 0;
}

int main(void) {
  state = luaL_newstate();
  if (state == NULL) return 1;
  if (check_stack_and_types() || check_raw_tables() || check_auxiliary() || check_special()) return 1;
  lua_close(state);
  return 0;
}
