#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lua.h"
#include "lauxlib.h"

extern int rivetlua_capi_test_inject_next_allocation_a2(lua_State *state);
extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);

static int panic_pipe = -1;
static int newindex_seen;

static int panic_returns(lua_State *state) {
  (void)state;
  if (panic_pipe >= 0) {
    const char marker = 'p';
    (void)write(panic_pipe, &marker, 1);
  }
  return 0;
}

static int index_ok(lua_State *state) {
  lua_pushinteger(state, lua_gettop(state) == 2 ? 42 : -42);
  return 1;
}

static int index_binary_error(lua_State *state) {
  lua_pushlstring(state, "index\0failure", 13);
  return lua_error(state);
}

static int newindex_ok(lua_State *state) {
  if (lua_gettop(state) == 3)
    newindex_seen = (int)lua_tointeger(state, 3);
  return 0;
}

static int newindex_binary_error(lua_State *state) {
  lua_pushlstring(state, "set\0failure", 11);
  return lua_error(state);
}

static int public_get(lua_State *state) {
  lua_getfield(state, 1, "missing");
  return 1;
}

static int public_get_fault(lua_State *state) {
  if (rivetlua_capi_test_inject_next_allocation_a2(state) != 1)
    return 0;
  lua_getfield(state, 1, "missing");
  return 1;
}

static int public_set(lua_State *state) {
  lua_pushinteger(state, 71);
  lua_setfield(state, 1, "missing");
  return 0;
}

static int public_callmeta(lua_State *state) {
  return luaL_callmeta(state, 1, "__answer");
}

static int callmeta_error(lua_State *state) {
  lua_pushlstring(state, "meta\0failure", 12);
  return lua_error(state);
}

static int argerror_call(lua_State *state) {
  return luaL_argerror(state, 1, "bad value");
}

static int noop(lua_State *state) {
  (void)state;
  return 0;
}

static void push_indexed(lua_State *state, lua_CFunction callback) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushcfunction(state, callback);
  lua_setfield(state, -2, "__index");
  (void)lua_setmetatable(state, -2);
}

static void replace_event(lua_State *state, int target,
                          const char *name, lua_CFunction callback) {
  (void)lua_getmetatable(state, target);
  lua_pushcfunction(state, callback);
  lua_setfield(state, -2, name);
  lua_pop(state, 1);
}

static int check_no_checkpoint_failstop(void) {
  int pipes[2];
  if (pipe(pipes) != 0) return 1;
  pid_t child = fork();
  if (child < 0) return 2;
  if (child == 0) {
    close(pipes[0]);
    panic_pipe = pipes[1];
    lua_State *state = luaL_newstate();
    if (state == NULL) _exit(3);
    lua_atpanic(state, panic_returns);
    lua_pushinteger(state, 17);
    (void)lua_getfield(state, 1, "missing");
    _exit(4);
  }
  close(pipes[1]);
  char marker = 0;
  ssize_t read_count = read(pipes[0], &marker, 1);
  close(pipes[0]);
  int status = 0;
  if (waitpid(child, &status, 0) != child) return 5;
  if (read_count != 1 || marker != 'p') return 6;
  if (!WIFSIGNALED(status) || WTERMSIG(status) != SIGABRT) return 7;
  return 0;
}

#define CHECK(expression) do { \
  if (!(expression)) { \
    fprintf(stderr, "A4a C fixture line %d failed: %s\n", __LINE__, #expression); \
    return __LINE__; \
  } \
} while (0)

int main(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);

  push_indexed(state, index_ok);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);

  replace_event(state, 1, "__index", index_binary_error);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  size_t length = 0;
  const char *error = lua_tolstring(state, -1, &length);
  CHECK(error != NULL && length == 13 &&
        memcmp(error, "index\0failure", 13) == 0);
  lua_pop(state, 1);
  replace_event(state, 1, "__index", index_ok);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);

  lua_pushcfunction(state, public_get_fault);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRMEM);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);

  lua_pushcfunction(state, public_callmeta);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_OK);
  CHECK(lua_type(state, -1) == LUA_TNIL);
  lua_pop(state, 1);
  replace_event(state, 1, "__answer", callmeta_error);
  lua_pushcfunction(state, public_callmeta);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  error = lua_tolstring(state, -1, &length);
  CHECK(error != NULL && length == 12 &&
        memcmp(error, "meta\0failure", 12) == 0);
  lua_pop(state, 1);
  lua_settop(state, 0);

  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 2);
  lua_pushcfunction(state, index_ok);
  lua_setfield(state, 2, "__call");
  CHECK(rivetlua_capi_test_push_lua_b4(state, 1) == 1);
  lua_setfield(state, 2, "__answer");
  CHECK(lua_setmetatable(state, 1) == 1);
  lua_pushcfunction(state, public_callmeta);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 42);
  lua_pop(state, 1);
  CHECK(lua_getmetatable(state, 1) == 1);
  lua_pushnil(state);
  lua_setfield(state, -2, "__call");
  CHECK(rivetlua_capi_test_push_lua_b4(state, 3) == 1);
  lua_setfield(state, -2, "__answer");
  lua_pop(state, 1);
  lua_pushcfunction(state, public_callmeta);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  lua_settop(state, 0);

  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushcfunction(state, newindex_ok);
  lua_setfield(state, 2, "__newindex");
  CHECK(lua_setmetatable(state, 1) == 1);
  lua_pushcfunction(state, public_set);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 0, 0) == LUA_OK);
  CHECK(newindex_seen == 71 && lua_gettop(state) == 1);
  replace_event(state, 1, "__newindex", newindex_binary_error);
  lua_pushcfunction(state, public_set);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 0, 0) == LUA_ERRRUN);
  error = lua_tolstring(state, -1, &length);
  CHECK(error != NULL && length == 11 &&
        memcmp(error, "set\0failure", 11) == 0);
  lua_pop(state, 1);
  replace_event(state, 1, "__newindex", newindex_ok);
  const luaL_Reg functions[] = {{"f", noop}, {NULL, NULL}};
  luaL_setfuncs(state, functions, 0);
  CHECK(newindex_seen == 0 && lua_gettop(state) == 1);
  lua_settop(state, 0);

  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushvalue(state, 1);
  lua_setfield(state, 2, "__index");
  CHECK(lua_setmetatable(state, 1) == 1);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  error = lua_tostring(state, -1);
  CHECK(error != NULL && strstr(error, "chain too long") != NULL);
  lua_settop(state, 0);

  lua_pushinteger(state, 17);
  lua_pushcfunction(state, public_get);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2);
  lua_settop(state, 0);

  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushcfunction(state, argerror_call);
  lua_setfield(state, 2, "__call");
  CHECK(lua_setmetatable(state, 1) == 1);
  lua_pushvalue(state, 1);
  CHECK(lua_pcall(state, 0, 0, 0) == LUA_ERRRUN);
  error = lua_tostring(state, -1);
#if LUA_VERSION_NUM >= 505
  CHECK(error != NULL && strstr(error, "extra argument #1") != NULL);
#else
  CHECK(error != NULL && strstr(error, "bad argument #1") != NULL);
#endif
  lua_settop(state, 0);

  CHECK(check_no_checkpoint_failstop() == 0);
  lua_close(state);
  return 0;
}
