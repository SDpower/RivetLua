#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include "lua.h"
#include "lauxlib.h"

extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);
extern int rivetlua_capi_test_inject_next_allocation_a2(lua_State *state);
extern int rivetlua_capi_test_raise_class_a2(lua_State *state, int class_code);
extern int32_t rivetlua_capi_error_consume_a1(void *state, int32_t *class_code);
typedef struct { int32_t kind; int32_t value; } action_a2;
typedef action_a2 (*action_fn_a2)(void *, uint64_t, uint64_t, void *);
extern action_a2 rivetlua_capi_trampoline_protect_a1(
    void *state, action_fn_a2 action, void *context);

static const void *error_identity;
static int continuation_calls;
static int panic_pipe = -1;
static int lower_close_seen;
static int replacement_seen;
static int typed_error_class;

static int panic_returns(lua_State *state) {
  (void)state;
  const char marker = 'p';
  if (panic_pipe >= 0) (void)write(panic_pipe, &marker, 1);
  return 0;
}

static int panic_preflight(lua_State *state) {
  const char marker = lua_gettop(state) == 19 &&
      lua_type(state, -1) == LUA_TSTRING ? 'm' : 'x';
  if (panic_pipe >= 0) (void)write(panic_pipe, &marker, 1);
  return 0;
}

static int plus_one(lua_State *state) {
  lua_Integer value = lua_tointeger(state, 1);
  lua_pushinteger(state, value + 1);
  return 1;
}

static int error_table(lua_State *state) {
  lua_createtable(state, 0, 0);
  error_identity = lua_topointer(state, -1);
  return lua_error(state);
}

static int error_handler(lua_State *state) {
  if (lua_topointer(state, 1) != error_identity) return 0;
  lua_pushlstring(state, "handled\0bytes", 13);
  return 1;
}

static int error_again(lua_State *state) {
  lua_pushstring(state, "handler failed");
  return lua_error(state);
}

static int binary_error(lua_State *state) {
  lua_pushlstring(state, "bad\0bytes", 9);
  return lua_error(state);
}

static int captured_plus_one(lua_State *state) {
  lua_Integer captured = lua_tointeger(state, lua_upvalueindex(1));
  lua_pushinteger(state, captured + lua_tointeger(state, 1) + 1);
  return 1;
}

static int gc_then_error(lua_State *state) {
  if (lua_gc(state, LUA_GCCOLLECT) != 0) return 0;
  lua_pushlstring(state, "gc\0error", 8);
  return lua_error(state);
}

static int nested_unprotected(lua_State *state) {
  lua_pushcfunction(state, binary_error);
  lua_call(state, 0, 0);
  return 0;
}

static int nested_allocation(lua_State *state) {
  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 41);
  if (rivetlua_capi_test_inject_next_allocation_a2(state) != 1)
    return 0;
  lua_call(state, 1, 1);
  return 1;
}

static int nested_preflight_allocation(lua_State *state) {
  lua_settop(state, 18);
  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 41);
  if (rivetlua_capi_test_inject_next_allocation_a2(state) != 1)
    return 0;
  lua_call(state, 1, 1);
  return 1;
}

static int typed_error(lua_State *state) {
  lua_pushinteger(state, typed_error_class);
  return rivetlua_capi_test_raise_class_a2(state, typed_error_class);
}

static action_a2 outer_typed_call(void *raw, uint64_t generation,
                                  uint64_t token, void *context) {
  (void)generation;
  (void)token;
  (void)context;
  lua_State *state = (lua_State *)raw;
  lua_pushcfunction(state, typed_error);
  lua_call(state, 0, 0);
  return (action_a2){0, 99};
}

static int lower_close(lua_State *state) {
  lower_close_seen++;
  size_t length = 0;
  const char *value = lua_tolstring(state, 2, &length);
  replacement_seen = value != NULL && length == 17 &&
      memcmp(value, "close replacement", 17) == 0;
  return 0;
}

static int high_close_error(lua_State *state) {
  lua_pushstring(state, "close replacement");
  return lua_error(state);
}

static void push_marked(lua_State *state, lua_CFunction closer) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushstring(state, "__close");
  lua_pushcfunction(state, closer);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) __builtin_trap();
  lua_toclose(state, -1);
}

static int error_with_closers(lua_State *state) {
  push_marked(state, lower_close);
  push_marked(state, high_close_error);
  lua_pushstring(state, "original error");
  return lua_error(state);
}

static int continuation(lua_State *state, int status, lua_KContext context) {
  (void)state;
  (void)status;
  (void)context;
  continuation_calls++;
  return 0;
}

static int nested_protected(lua_State *state) {
  lua_pushcfunction(state, error_table);
  if (lua_pcall(state, 0, 1, 0) != LUA_ERRRUN) return 0;
  if (lua_topointer(state, -1) != error_identity) return 0;
  lua_pop(state, 1);
  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 8);
  lua_call(state, 1, 1);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 41);
  lua_call(state, 1, 1);
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != 42) return 2;
  lua_pop(state, 1);

  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 2);
  if (lua_pcallk(state, 1, LUA_MULTRET, 0, 77, continuation) != LUA_OK)
    return 3;
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != 3 ||
      continuation_calls != 0)
    return 4;
  lua_pop(state, 1);

  lua_pushcfunction(state, error_table);
  if (lua_pcall(state, 0, 1, 0) != LUA_ERRRUN) return 5;
  if (lua_gettop(state) != 1 || lua_topointer(state, -1) != error_identity)
    return 6;
  lua_pop(state, 1);

  lua_pushcfunction(state, error_handler);
  lua_pushcfunction(state, error_table);
  if (lua_pcall(state, 0, 1, -2) != LUA_ERRRUN) return 7;
  size_t length = 0;
  const char *message = lua_tolstring(state, -1, &length);
  if (length != 13 || message == NULL ||
      memcmp(message, "handled\0bytes", length) != 0)
    return 8;
  lua_pop(state, 2);

  lua_pushcfunction(state, error_again);
  lua_pushcfunction(state, error_table);
  if (lua_pcall(state, 0, 1, -2) != LUA_ERRERR) return 9;
  if (lua_gettop(state) != 2) return 10;
  lua_pop(state, 2);

  lua_pushcfunction(state, error_with_closers);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN ||
      lower_close_seen != 1 || !replacement_seen) return 30;
  size_t close_length = 0;
  const char *close_message = lua_tolstring(state, -1, &close_length);
  if (close_message == NULL || close_length != 17 ||
      memcmp(close_message, "close replacement", 17) != 0) return 31;
  lua_pop(state, 1);

  lua_pushinteger(state, 40);
  lua_pushcclosure(state, captured_plus_one, 1);
  lua_pushinteger(state, 1);
  lua_call(state, 1, 1);
  if (lua_tointeger(state, -1) != 42) return 15;
  lua_pop(state, 1);

  lua_pushcfunction(state, binary_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 16;
  size_t binary_length = 0;
  const char *binary = lua_tolstring(state, -1, &binary_length);
  if (binary == NULL || binary_length != 9 ||
      memcmp(binary, "bad\0bytes", 9) != 0) return 17;
  lua_pop(state, 1);

  lua_pushcfunction(state, nested_unprotected);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 18;
  if (lua_gettop(state) != 1) return 19;
  lua_pop(state, 1);

  lua_pushcfunction(state, nested_allocation);
  if (lua_pcall(state, 0, 1, 0) != LUA_ERRMEM ||
      lua_gettop(state) != 1) return 32;
  lua_pop(state, 1);

  lua_State *preflight_state = luaL_newstate();
  if (preflight_state == NULL) return 38;
  lua_pushcfunction(preflight_state, nested_preflight_allocation);
  if (lua_pcall(preflight_state, 0, 1, 0) != LUA_ERRMEM ||
      lua_gettop(preflight_state) != 1 ||
      lua_type(preflight_state, -1) != LUA_TSTRING)
    return 38;
  lua_close(preflight_state);

  /* P16 共用 C/Rust 錯誤碼：Host=3、Policy=4、Aborted=6。 */
  const int typed_classes[] = {3, 4, 6};
  for (size_t index = 0; index < sizeof(typed_classes) / sizeof(typed_classes[0]); index++) {
    typed_error_class = typed_classes[index];
    action_a2 result = rivetlua_capi_trampoline_protect_a1(
        state, outer_typed_call, NULL);
    int32_t observed = 0;
    if (result.kind != 1 ||
        rivetlua_capi_error_consume_a1(state, &observed) != 0 ||
        observed != typed_error_class ||
        lua_tointeger(state, -1) != typed_error_class) return 33;
    lua_pop(state, 1);
  }

  lua_pushcfunction(state, error_handler);
  lua_pushcfunction(state, error_table);
  if (lua_pcall(state, 0, 1, 1) != LUA_ERRRUN) return 20;
  lua_pop(state, 2);

  lua_pushcfunction(state, error_table);
  int before_invalid = lua_gettop(state);
  if (lua_pcall(state, 0, 0, 9000) == LUA_OK ||
      lua_gettop(state) != before_invalid) return 21;
  lua_pop(state, 1);

  if (lua_gc(state, LUA_GCINC, 0, 0, 0) < 0) return 22;
  lua_pushcfunction(state, gc_then_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 23;
  size_t gc_length = 0;
  const char *gc_error = lua_tolstring(state, -1, &gc_length);
  if (gc_length != 8 || gc_error == NULL ||
      memcmp(gc_error, "gc\0error", 8) != 0) return 24;
  lua_pop(state, 1);
  if (lua_gc(state, LUA_GCGEN, 0, 0) < 0) return 25;
  lua_pushcfunction(state, gc_then_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 26;
  lua_pop(state, 1);

  lua_pushcfunction(state, nested_protected);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK) return 11;
  if (lua_tointeger(state, -1) != 9) return 12;
  lua_pop(state, 1);

  if (rivetlua_capi_test_push_lua_b4(state, 1) != 1) return 13;
  lua_pushcfunction(state, plus_one);
  lua_pushinteger(state, 41);
  lua_call(state, 2, 1);
  if (lua_tointeger(state, -1) != 42) return 14;
  lua_pop(state, 1);

  lua_CFunction installed = lua_atpanic(state, NULL);
  if (installed == NULL || lua_atpanic(state, installed) != NULL) return 34;
  int default_fds[2];
  if (pipe(default_fds) != 0) return 35;
  pid_t default_child = fork();
  if (default_child < 0) return 36;
  if (default_child == 0) {
    close(default_fds[0]);
    if (dup2(default_fds[1], STDERR_FILENO) < 0) _exit(97);
    close(default_fds[1]);
    lua_pushstring(state, "default panic");
    lua_error(state);
    _exit(98);
  }
  close(default_fds[1]);
  char default_message[128] = {0};
  ssize_t default_size = read(default_fds[0], default_message,
                              sizeof(default_message) - 1);
  close(default_fds[0]);
  int default_status = 0;
  if (waitpid(default_child, &default_status, 0) != default_child ||
      default_size <= 0 || !WIFSIGNALED(default_status) ||
      WTERMSIG(default_status) != SIGABRT ||
      strstr(default_message,
             "PANIC: unprotected error in call to Lua API (default panic)\n") == NULL)
    return 37;

  int fds[2];
  if (pipe(fds) != 0) return 27;
  pid_t child = fork();
  if (child < 0) return 28;
  if (child == 0) {
    close(fds[0]);
    panic_pipe = fds[1];
    (void)lua_atpanic(state, panic_returns);
    lua_pushstring(state, "unprotected panic");
    lua_error(state);
    _exit(99);
  }
  close(fds[1]);
  char marker = 0;
  ssize_t seen = read(fds[0], &marker, 1);
  close(fds[0]);
  int child_status = 0;
  if (waitpid(child, &child_status, 0) != child || seen != 1 ||
      marker != 'p' || !WIFSIGNALED(child_status) ||
      WTERMSIG(child_status) != SIGABRT) return 29;

  lua_State *panic_state = luaL_newstate();
  if (panic_state == NULL) return 39;
  int preflight_fds[2];
  if (pipe(preflight_fds) != 0) return 40;
  pid_t preflight_child = fork();
  if (preflight_child < 0) return 41;
  if (preflight_child == 0) {
    close(preflight_fds[0]);
    panic_pipe = preflight_fds[1];
    (void)lua_atpanic(panic_state, panic_preflight);
    lua_settop(panic_state, 18);
    lua_pushcfunction(panic_state, plus_one);
    lua_pushinteger(panic_state, 41);
    if (rivetlua_capi_test_inject_next_allocation_a2(panic_state) != 1)
      _exit(98);
    lua_call(panic_state, 1, 1);
    _exit(99);
  }
  close(preflight_fds[1]);
  char preflight_marker = 0;
  ssize_t preflight_seen = read(preflight_fds[0], &preflight_marker, 1);
  close(preflight_fds[0]);
  int preflight_status = 0;
  if (waitpid(preflight_child, &preflight_status, 0) != preflight_child ||
      preflight_seen != 1 || preflight_marker != 'm' ||
      !WIFSIGNALED(preflight_status) ||
      WTERMSIG(preflight_status) != SIGABRT) return 42;
  lua_close(panic_state);
  lua_close(state);
  return 0;
}
